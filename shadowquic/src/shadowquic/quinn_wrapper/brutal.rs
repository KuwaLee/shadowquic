use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use brutal_core::{BrutalConfigCore, BrutalCore};
use quinn::congestion::{Controller, ControllerFactory};
use quinn_proto::RttEstimator;
use tracing::trace;

#[derive(Debug, Clone, Default)]
pub struct BrutalConfig {
    core: BrutalConfigCore,
    /// Receive bandwidth in bits per second, reported to the peer during
    /// mihomo Brutal negotiation.
    down_bps: Option<u64>,
}

impl BrutalConfig {
    pub fn new(
        default_bandwidth_bps: u64,
        min_window: u64,
        cwnd_gain: f64,
        min_ack_rate: f64,
        min_sample_count: u64,
        enable_ack_rate_compensation: bool,
    ) -> Self {
        Self {
            core: BrutalConfigCore::new(
                default_bandwidth_bps,
                min_window,
                cwnd_gain,
                min_ack_rate,
                min_sample_count,
                enable_ack_rate_compensation,
            ),
            down_bps: None,
        }
    }

    pub fn with_down(mut self, down_bps: Option<u64>) -> Self {
        self.down_bps = down_bps;
        self
    }

    #[allow(unused)]
    pub fn inner(&self) -> &BrutalConfigCore {
        &self.core
    }

    #[allow(unused)]
    pub fn inner_mut(&mut self) -> &mut BrutalConfigCore {
        &mut self.core
    }
}

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let cfg = self.core.clone();

        trace!(
            event = "recovery:controller_created",
            "[brutal] build called: default_bandwidth_bps={}, initial_rtt_ms={}, min_window={}, cwnd_gain={}, min_ack_rate={}, min_sample_count={}, enable_ack_rate_compensation={}, mtu={}",
            cfg.default_bandwidth_bps,
            cfg.initial_rtt.as_millis(),
            cfg.min_window,
            cfg.cwnd_gain,
            cfg.min_ack_rate,
            cfg.min_sample_count,
            cfg.enable_ack_rate_compensation,
            current_mtu,
        );

        Box::new(Brutal {
            core: BrutalCore::new(cfg, now, current_mtu),
            down_bps: self.down_bps,
            rate: Arc::new(AtomicU64::new(NO_RATE_OVERRIDE)),
            applied_rate: NO_RATE_OVERRIDE,
        })
    }
}

const NO_RATE_OVERRIDE: u64 = 0;

/// Brutal controller for one connection.
///
/// `rate` is shared with every clone of the controller, including the
/// snapshot returned by `quinn::Connection::congestion_state`, so the
/// negotiated send rate can be changed after the connection is created.
#[derive(Debug, Clone)]
pub struct Brutal {
    core: BrutalCore,
    down_bps: Option<u64>,
    rate: Arc<AtomicU64>,
    applied_rate: u64,
}

impl Brutal {
    /// Configured send rate in bits per second, before negotiation.
    pub fn configured_up_bps(&self) -> u64 {
        self.core.config.default_bandwidth_bps
    }

    /// Configured receive rate in bits per second.
    pub fn configured_down_bps(&self) -> Option<u64> {
        self.down_bps
    }

    /// Overrides the send rate of the live connection. The controller picks
    /// it up on its next callback.
    pub fn set_send_rate(&self, bps: u64) {
        self.rate.store(bps.max(1), Ordering::Relaxed);
    }

    fn sync_rate(&mut self) {
        let rate = self.rate.load(Ordering::Relaxed);
        if rate != self.applied_rate {
            self.applied_rate = rate;
            self.core
                .set_peer_bandwidth_hint((rate != NO_RATE_OVERRIDE).then_some(rate));
        }
    }
}

impl Controller for Brutal {
    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }

    fn initial_window(&self) -> u64 {
        self.core.initial_window()
    }

    fn window(&self) -> u64 {
        self.core.window_cached()
    }

    fn on_sent(&mut self, _now: Instant, bytes: u64, _last_packet_number: u64) {
        self.sync_rate();
        self.core.on_sent(bytes);
    }

    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.core.on_ack_bytes(bytes, rtt.get());
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        _in_flight: u64,
        _app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
        self.sync_rate();
        self.core.on_end_acks(now);
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _is_ecn: bool,
        lost_bytes: u64,
    ) {
        self.core.on_loss_bytes(lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.core.on_mtu_update(new_mtu);
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_override_reaches_controller_through_clone() {
        let factory = Arc::new(BrutalConfig::new(10_000_000, 1, 1.0, 0.8, 50, false));
        let mut controller = factory.build(Instant::now(), 1200);
        let initial = controller.window();

        // `quinn::Connection::congestion_state` hands out a clone like this one.
        let snapshot = controller
            .clone_box()
            .into_any()
            .downcast::<Brutal>()
            .unwrap();
        assert_eq!(snapshot.configured_up_bps(), 10_000_000);
        snapshot.set_send_rate(100_000_000);

        controller.on_sent(Instant::now(), 1200, 0);
        assert_eq!(controller.window(), initial * 10);
    }

    #[test]
    fn down_rate_is_exposed_by_controller() {
        let factory = Arc::new(BrutalConfig::default().with_down(Some(42)));
        let controller = factory.build(Instant::now(), 1200);
        let brutal = controller.into_any().downcast::<Brutal>().unwrap();
        assert_eq!(brutal.configured_down_bps(), Some(42));
    }
}
