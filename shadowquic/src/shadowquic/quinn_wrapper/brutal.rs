//! Congestion controller that can switch between a base algorithm and Brutal
//! while the connection is running, for mihomo-compatible Brutal negotiation.

use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use brutal_core::{BrutalConfigCore, BrutalCore};
use quinn::congestion::{Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;
use tracing::trace;

use crate::quic::BrutalSendMode;

/// Shared mode values. Any other value is a Brutal rate in bits per second.
const MODE_CONFIGURED: u64 = 0;
const MODE_BASE: u64 = u64::MAX;

fn encode_mode(mode: BrutalSendMode) -> u64 {
    match mode {
        BrutalSendMode::Configured => MODE_CONFIGURED,
        BrutalSendMode::Base => MODE_BASE,
        BrutalSendMode::Brutal(bps) => bps.clamp(1, MODE_BASE - 1),
    }
}

/// Factory of [`Negotiable`] controllers.
pub struct NegotiableConfig {
    base: Arc<dyn ControllerFactory + Send + Sync>,
    brutal: BrutalConfigCore,
    /// Configured Brutal send rate. `None` starts with the base controller.
    up_bps: Option<u64>,
    /// Receive rate reported to the peer during negotiation.
    down_bps: Option<u64>,
}

impl NegotiableConfig {
    pub fn new(
        base: Arc<dyn ControllerFactory + Send + Sync>,
        brutal: BrutalConfigCore,
        up_bps: Option<u64>,
        down_bps: Option<u64>,
    ) -> Self {
        Self {
            base,
            brutal,
            up_bps,
            down_bps,
        }
    }
}

impl ControllerFactory for NegotiableConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        trace!(
            event = "recovery:controller_created",
            up_bps = ?self.up_bps,
            down_bps = ?self.down_bps,
            mtu = current_mtu,
            "negotiable brutal controller created"
        );
        let mut controller = Negotiable {
            base: self.base.clone().build(now, current_mtu),
            brutal: None,
            brutal_config: self.brutal.clone(),
            up_bps: self.up_bps,
            down_bps: self.down_bps,
            mtu: current_mtu,
            mode: Arc::new(AtomicU64::new(MODE_CONFIGURED)),
            applied_mode: MODE_CONFIGURED,
        };
        controller.apply(MODE_CONFIGURED, now);
        Box::new(controller)
    }
}

/// Controller of one connection. It uses Brutal when a send rate is
/// configured or negotiated, and the base controller otherwise.
///
/// `mode` is shared with every clone of the controller, including the
/// snapshot returned by `quinn::Connection::congestion_state`, so the
/// negotiated mode reaches the live connection on its next callback.
pub struct Negotiable {
    base: Box<dyn Controller>,
    brutal: Option<BrutalCore>,
    brutal_config: BrutalConfigCore,
    up_bps: Option<u64>,
    down_bps: Option<u64>,
    mtu: u16,
    mode: Arc<AtomicU64>,
    applied_mode: u64,
}

impl Clone for Negotiable {
    fn clone(&self) -> Self {
        Self {
            base: self.base.clone_box(),
            brutal: self.brutal.clone(),
            brutal_config: self.brutal_config.clone(),
            up_bps: self.up_bps,
            down_bps: self.down_bps,
            mtu: self.mtu,
            mode: self.mode.clone(),
            applied_mode: self.applied_mode,
        }
    }
}

impl Negotiable {
    /// Configured send rate in bits per second.
    pub fn configured_up_bps(&self) -> Option<u64> {
        self.up_bps
    }

    /// Configured receive rate in bits per second.
    pub fn configured_down_bps(&self) -> Option<u64> {
        self.down_bps
    }

    /// Changes how the live connection sends.
    pub fn set_send_mode(&self, mode: BrutalSendMode) {
        self.mode.store(encode_mode(mode), Ordering::Relaxed);
    }

    /// Whether Brutal is in use, for tests.
    #[cfg(test)]
    fn brutal_rate(&self) -> Option<u64> {
        self.brutal.as_ref().map(BrutalCore::target_bps)
    }

    fn sync(&mut self, now: Instant) {
        let mode = self.mode.load(Ordering::Relaxed);
        if mode != self.applied_mode {
            self.apply(mode, now);
        }
    }

    fn apply(&mut self, mode: u64, now: Instant) {
        self.applied_mode = mode;
        let rate = match mode {
            MODE_CONFIGURED => self.up_bps,
            MODE_BASE => None,
            bps => Some(bps),
        };
        match (rate, self.brutal.as_mut()) {
            (None, _) => self.brutal = None,
            (Some(bps), Some(brutal)) => brutal.set_peer_bandwidth_hint(Some(bps)),
            (Some(bps), None) => {
                let mut config = self.brutal_config.clone();
                config.default_bandwidth_bps = bps;
                self.brutal = Some(BrutalCore::new(config, now, self.mtu));
            }
        }
        trace!(
            event = "recovery:controller_mode_changed",
            brutal_bps = ?rate,
            "congestion controller mode applied"
        );
    }
}

impl Controller for Negotiable {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.sync(now);
        match self.brutal.as_mut() {
            Some(brutal) => brutal.on_sent(bytes),
            None => self.base.on_sent(now, bytes, last_packet_number),
        }
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        match self.brutal.as_mut() {
            Some(brutal) => brutal.on_ack_bytes(bytes, rtt.get()),
            None => self.base.on_ack(now, sent, bytes, app_limited, rtt),
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.sync(now);
        match self.brutal.as_mut() {
            Some(brutal) => brutal.on_end_acks(now),
            None => self
                .base
                .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked),
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        is_ecn: bool,
        lost_bytes: u64,
    ) {
        match self.brutal.as_mut() {
            Some(brutal) => brutal.on_loss_bytes(lost_bytes),
            None => self.base.on_congestion_event(
                now,
                sent,
                is_persistent_congestion,
                is_ecn,
                lost_bytes,
            ),
        }
    }

    fn on_spurious_congestion_event(&mut self) {
        if self.brutal.is_none() {
            self.base.on_spurious_congestion_event();
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
        self.base.on_mtu_update(new_mtu);
        if let Some(brutal) = self.brutal.as_mut() {
            brutal.on_mtu_update(new_mtu);
        }
    }

    fn window(&self) -> u64 {
        match self.brutal.as_ref() {
            Some(brutal) => brutal.window_cached(),
            None => self.base.window(),
        }
    }

    fn metrics(&self) -> ControllerMetrics {
        match self.brutal.as_ref() {
            Some(brutal) => {
                let mut metrics = ControllerMetrics::default();
                metrics.congestion_window = brutal.window_cached();
                metrics.bandwidth_estimate = Some(brutal.target_bps());
                metrics
            }
            None => self.base.metrics(),
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        match self.brutal.as_ref() {
            Some(brutal) => brutal.initial_window(),
            None => self.base.initial_window(),
        }
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::congestion::BbrConfig;

    fn controller(up: Option<u64>, down: Option<u64>) -> Box<dyn Controller> {
        let brutal = BrutalConfigCore {
            min_window: 1,
            cwnd_gain: 1.0,
            ..Default::default()
        };
        Arc::new(NegotiableConfig::new(
            Arc::new(BbrConfig::default()),
            brutal,
            up,
            down,
        ))
        .build(Instant::now(), 1200)
    }

    fn snapshot(controller: &dyn Controller) -> Box<Negotiable> {
        // `quinn::Connection::congestion_state` hands out a clone like this one.
        controller.clone_box().into_any().downcast().unwrap()
    }

    #[test]
    fn starts_with_brutal_when_rate_is_configured() {
        let controller = controller(Some(10_000_000), Some(42));
        let snapshot = snapshot(&*controller);
        assert_eq!(snapshot.brutal_rate(), Some(10_000_000));
        assert_eq!(snapshot.configured_up_bps(), Some(10_000_000));
        assert_eq!(snapshot.configured_down_bps(), Some(42));
    }

    #[test]
    fn starts_with_base_without_rate() {
        let controller = controller(None, None);
        assert_eq!(snapshot(&*controller).brutal_rate(), None);
    }

    #[test]
    fn brutal_rate_change_reaches_controller_through_clone() {
        let mut controller = controller(Some(10_000_000), None);
        let initial = controller.window();
        snapshot(&*controller).set_send_mode(BrutalSendMode::Brutal(100_000_000));

        controller.on_sent(Instant::now(), 1200, 0);
        assert_eq!(controller.window(), initial * 10);
    }

    #[test]
    fn switches_from_base_to_brutal_and_back() {
        let mut controller = controller(None, None);
        let base_window = controller.window();

        snapshot(&*controller).set_send_mode(BrutalSendMode::Brutal(50_000_000));
        controller.on_sent(Instant::now(), 1200, 0);
        assert_eq!(snapshot(&*controller).brutal_rate(), Some(50_000_000));

        snapshot(&*controller).set_send_mode(BrutalSendMode::Base);
        controller.on_sent(Instant::now(), 1200, 1);
        assert_eq!(snapshot(&*controller).brutal_rate(), None);
        assert_eq!(controller.window(), base_window);
    }

    #[test]
    fn configured_mode_restores_configured_rate() {
        let mut controller = controller(Some(10_000_000), None);
        snapshot(&*controller).set_send_mode(BrutalSendMode::Base);
        controller.on_sent(Instant::now(), 1200, 0);
        assert_eq!(snapshot(&*controller).brutal_rate(), None);

        snapshot(&*controller).set_send_mode(BrutalSendMode::Configured);
        controller.on_sent(Instant::now(), 1200, 1);
        assert_eq!(snapshot(&*controller).brutal_rate(), Some(10_000_000));
    }
}
