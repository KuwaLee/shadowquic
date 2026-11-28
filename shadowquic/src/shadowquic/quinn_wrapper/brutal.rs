//! Congestion controller that can switch between a base algorithm and Brutal
//! while the connection is running, for mihomo-compatible Brutal negotiation.
//!
//! Brutal works like Hysteria2's (`core/internal/congestion/brutal` in
//! apernet/hysteria, also used by mihomo and Xray): packets are paced at the
//! target rate divided by the ACK rate, whatever the RTT, and the window of
//! twice the bandwidth-delay product only bounds the data in flight. The
//! pacing rate reaches quinn through `Controller::pacing_rate`.

use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

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

/// Brutal window before the first RTT sample, as in Hysteria2.
const INITIAL_WINDOW: u64 = 10240;

/// Number of one-second slots the ACK rate is computed from, as in Hysteria2.
const ACK_RATE_SLOTS: usize = 5;

/// Seconds between ACK rate trace events.
const ACK_RATE_TRACE_INTERVAL: u64 = 2;

/// Brutal parameters. The defaults are Hysteria2's.
#[derive(Debug, Clone, PartialEq)]
pub struct BrutalConfig {
    /// Window in multiples of the bandwidth-delay product.
    pub cwnd_gain: f64,
    /// Smallest window in bytes; the window is never below one datagram.
    pub min_window: u64,
    /// Whether to raise the send rate by the loss rate, to keep the goodput
    /// at the target.
    pub ack_compensate: bool,
    /// Lowest ACK rate compensated for, which caps the send rate at
    /// `target / min_ack_rate`.
    pub min_ack_rate: f64,
    /// Packets acknowledged or lost over the last [`ACK_RATE_SLOTS`] seconds
    /// needed before compensating.
    pub min_sample_count: u64,
}

impl Default for BrutalConfig {
    fn default() -> Self {
        Self {
            cwnd_gain: 2.0,
            min_window: 0,
            ack_compensate: true,
            min_ack_rate: 0.8,
            min_sample_count: 50,
        }
    }
}

/// Packets acknowledged and lost within one second.
#[derive(Debug, Clone, Copy, Default)]
struct AckSlot {
    second: u64,
    acked: u64,
    lost: u64,
}

/// Brutal state of a connection.
#[derive(Debug, Clone)]
struct Brutal {
    config: BrutalConfig,
    /// Target send rate in bytes per second.
    rate: u64,
    /// Fraction of recent packets that were acknowledged, in
    /// `[min_ack_rate, 1]`; 1 without compensation.
    ack_rate: f64,
    slots: [AckSlot; ACK_RATE_SLOTS],
    last_trace: Option<u64>,
}

impl Brutal {
    fn new(config: BrutalConfig, bps: u64) -> Self {
        Self {
            config,
            rate: bytes_per_second(bps),
            ack_rate: 1.0,
            slots: [AckSlot::default(); ACK_RATE_SLOTS],
            last_trace: None,
        }
    }

    fn set_rate(&mut self, bps: u64) {
        self.rate = bytes_per_second(bps);
    }

    /// Target send rate in bits per second.
    fn target_bps(&self) -> u64 {
        self.rate.saturating_mul(8)
    }

    /// Pacing rate in bytes per second: the target, raised to make up for
    /// packet loss.
    fn pacing_rate(&self) -> u64 {
        (self.rate as f64 / self.ack_rate) as u64
    }

    /// Hysteria2's congestion window: the bytes in flight up to which
    /// another packet may be sent.
    fn cwnd(&self, smoothed_rtt: Option<Duration>, mtu: u16) -> u64 {
        let Some(rtt) = smoothed_rtt.filter(|rtt| !rtt.is_zero()) else {
            return INITIAL_WINDOW;
        };
        let window = self.rate as f64 * rtt.as_secs_f64() * self.config.cwnd_gain / self.ack_rate;
        (window as u64)
            .max(self.config.min_window)
            .max(u64::from(mtu))
    }

    /// Counts packets in the slot of `second`, resetting it if it holds an
    /// older second.
    fn record(&mut self, second: u64, acked: u64, lost: u64) {
        let slot = &mut self.slots[(second % ACK_RATE_SLOTS as u64) as usize];
        if slot.second == second {
            slot.acked += acked;
            slot.lost += lost;
        } else {
            *slot = AckSlot {
                second,
                acked,
                lost,
            };
        }
    }

    fn update_ack_rate(&mut self, second: u64, smoothed_rtt: Option<Duration>) {
        if !self.config.ack_compensate {
            return;
        }
        // The current second and the four before it. Hysteria2 resets the
        // current slot first; the slot may still hold the second five before
        // when nothing was counted in this one yet.
        let oldest = second.saturating_sub(ACK_RATE_SLOTS as u64 - 1);
        let (acked, lost) = self
            .slots
            .iter()
            .filter(|slot| slot.second >= oldest)
            .fold((0, 0), |(acked, lost), slot| {
                (acked + slot.acked, lost + slot.lost)
            });
        let total = acked + lost;
        self.ack_rate = if total < self.config.min_sample_count || total == 0 {
            1.0
        } else {
            (acked as f64 / total as f64).max(self.config.min_ack_rate)
        };
        if self
            .last_trace
            .is_none_or(|last| second >= last + ACK_RATE_TRACE_INTERVAL)
        {
            self.last_trace = Some(second);
            trace!(
                event = "recovery:brutal_ack_rate",
                ack_rate = self.ack_rate,
                acked,
                lost,
                target_bps = self.target_bps(),
                pacing_bps = self.pacing_rate().saturating_mul(8),
                rtt_ms = smoothed_rtt.map(|rtt| rtt.as_secs_f64() * 1000.0),
                "brutal ack rate updated"
            );
        }
    }
}

/// Converts bits per second to bytes per second, at least 1.
fn bytes_per_second(bps: u64) -> u64 {
    (bps / 8).max(1)
}

/// Factory of [`Negotiable`] controllers.
pub struct NegotiableConfig {
    base: Arc<dyn ControllerFactory + Send + Sync>,
    brutal: BrutalConfig,
    /// Configured Brutal send rate. `None` starts with the base controller.
    up_bps: Option<u64>,
    /// Receive rate reported to the peer during negotiation.
    down_bps: Option<u64>,
}

impl NegotiableConfig {
    pub fn new(
        base: Arc<dyn ControllerFactory + Send + Sync>,
        brutal: BrutalConfig,
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
            base_factory: self.base.clone(),
            brutal: None,
            brutal_config: self.brutal.clone(),
            up_bps: self.up_bps,
            down_bps: self.down_bps,
            mtu: current_mtu,
            smoothed_rtt: None,
            epoch: now,
            mode: Arc::new(AtomicU64::new(MODE_CONFIGURED)),
            applied_mode: MODE_CONFIGURED,
        };
        controller.apply(MODE_CONFIGURED);
        Box::new(controller)
    }
}

/// Controller of one connection. It uses Brutal when a send rate is
/// configured or negotiated, and the base controller otherwise.
///
/// Brutal paces at the target rate divided by the ACK rate of the last
/// [`ACK_RATE_SLOTS`] seconds, and its window is `cwnd_gain` times the
/// bandwidth-delay product from quinn's smoothed RTT, divided by the ACK rate.
/// Like Hysteria2, nothing lowers the rate when the RTT grows, so a target
/// above the path capacity fills the bottleneck queue.
///
/// `mode` is shared with every clone of the controller, including the
/// snapshot returned by `quinn::Connection::congestion_state` and the
/// controller of a new path, so the negotiated mode reaches the live
/// connection on its next callback.
pub struct Negotiable {
    base: Box<dyn Controller>,
    base_factory: Arc<dyn ControllerFactory + Send + Sync>,
    brutal: Option<Brutal>,
    brutal_config: BrutalConfig,
    up_bps: Option<u64>,
    down_bps: Option<u64>,
    mtu: u16,
    /// quinn's smoothed RTT as of the last ACK, `None` before any.
    smoothed_rtt: Option<Duration>,
    /// Start of the seconds the ACK rate slots are keyed by.
    epoch: Instant,
    mode: Arc<AtomicU64>,
    applied_mode: u64,
}

impl Clone for Negotiable {
    fn clone(&self) -> Self {
        Self {
            base: self.base.clone_box(),
            base_factory: self.base_factory.clone(),
            brutal: self.brutal.clone(),
            brutal_config: self.brutal_config.clone(),
            up_bps: self.up_bps,
            down_bps: self.down_bps,
            mtu: self.mtu,
            smoothed_rtt: self.smoothed_rtt,
            epoch: self.epoch,
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

    /// Brutal target rate in bits per second, `None` with the base controller.
    #[cfg(test)]
    fn brutal_rate(&self) -> Option<u64> {
        self.brutal.as_ref().map(Brutal::target_bps)
    }

    fn second(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.epoch).as_secs()
    }

    fn on_brutal_ack(&mut self, now: Instant) {
        let second = self.second(now);
        if let Some(brutal) = self.brutal.as_mut() {
            brutal.record(second, 1, 0);
        }
    }

    fn on_brutal_loss(&mut self, now: Instant, lost: u64) {
        let second = self.second(now);
        if let Some(brutal) = self.brutal.as_mut() {
            brutal.record(second, 0, lost);
            brutal.update_ack_rate(second, self.smoothed_rtt);
        }
    }

    fn update_brutal_ack_rate(&mut self, now: Instant) {
        let second = self.second(now);
        if let Some(brutal) = self.brutal.as_mut() {
            brutal.update_ack_rate(second, self.smoothed_rtt);
        }
    }

    fn sync(&mut self) {
        let mode = self.mode.load(Ordering::Relaxed);
        if mode != self.applied_mode {
            self.apply(mode);
        }
    }

    fn apply(&mut self, mode: u64) {
        self.applied_mode = mode;
        let rate = match mode {
            MODE_CONFIGURED => self.up_bps,
            MODE_BASE => None,
            bps => Some(bps),
        };
        match (rate, self.brutal.as_mut()) {
            (None, _) => self.brutal = None,
            (Some(bps), Some(brutal)) => brutal.set_rate(bps),
            (Some(bps), None) => self.brutal = Some(Brutal::new(self.brutal_config.clone(), bps)),
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
        self.sync();
        if self.brutal.is_none() {
            self.base.on_sent(now, bytes, last_packet_number);
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
        self.smoothed_rtt = Some(rtt.get());
        if self.brutal.is_some() {
            self.on_brutal_ack(now);
        } else {
            self.base.on_ack(now, sent, bytes, app_limited, rtt);
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.sync();
        if self.brutal.is_some() {
            self.update_brutal_ack_rate(now);
        } else {
            self.base
                .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
        }
    }

    fn on_packets_lost(&mut self, now: Instant, lost_packets: u64) {
        if self.brutal.is_some() {
            self.on_brutal_loss(now, lost_packets);
        } else {
            self.base.on_packets_lost(now, lost_packets);
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
        // Brutal counts losses in `on_packets_lost`, and ignores ECN like
        // Hysteria2.
        if self.brutal.is_none() {
            self.base
                .on_congestion_event(now, sent, is_persistent_congestion, is_ecn, lost_bytes);
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
    }

    fn window(&self) -> u64 {
        match self.brutal.as_ref() {
            // quinn sends a packet only if it fits in the window, while
            // Hysteria2 sends whenever the bytes in flight are within it, so
            // one more datagram fits.
            Some(brutal) => brutal
                .cwnd(self.smoothed_rtt, self.mtu)
                .saturating_add(u64::from(self.mtu)),
            None => self.base.window(),
        }
    }

    fn pacing_rate(&self) -> Option<u64> {
        self.brutal.as_ref().map(Brutal::pacing_rate)
    }

    fn metrics(&self) -> ControllerMetrics {
        match self.brutal.as_ref() {
            Some(brutal) => {
                let mut metrics = ControllerMetrics::default();
                metrics.congestion_window = self.window();
                metrics.pacing_rate = Some(brutal.pacing_rate().saturating_mul(8));
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
            Some(_) => INITIAL_WINDOW + u64::from(self.mtu),
            None => self.base.initial_window(),
        }
    }

    fn for_new_path(&self, now: Instant, current_mtu: u16) -> Option<Box<dyn Controller>> {
        // Hysteria2 servers follow a client to a new address without
        // resetting congestion control, so Brutal keeps its rate, ACK rate
        // and RTT. Only the base controller starts over.
        trace!(
            event = "recovery:controller_path_changed",
            brutal_bps = self.brutal.as_ref().map(Brutal::target_bps),
            mtu = current_mtu,
            "congestion controller carried over to a new path"
        );
        let mut controller = self.clone();
        controller.base = self.base_factory.clone().build(now, current_mtu);
        controller.mtu = current_mtu;
        Some(Box::new(controller))
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::congestion::BbrConfig;

    const MTU: u16 = 1200;

    fn controller_with(
        brutal: BrutalConfig,
        up: Option<u64>,
        down: Option<u64>,
    ) -> Box<dyn Controller> {
        Arc::new(NegotiableConfig::new(
            Arc::new(BbrConfig::default()),
            brutal,
            up,
            down,
        ))
        .build(Instant::now(), MTU)
    }

    fn controller(up: Option<u64>, down: Option<u64>) -> Box<dyn Controller> {
        controller_with(BrutalConfig::default(), up, down)
    }

    fn snapshot(controller: &dyn Controller) -> Box<Negotiable> {
        // `quinn::Connection::congestion_state` hands out a clone like this one.
        controller.clone_box().into_any().downcast().unwrap()
    }

    /// Brutal at 80 Mbit/s = 10 MB/s with a 20ms smoothed RTT.
    fn brutal_80m(config: BrutalConfig) -> Box<Negotiable> {
        let mut brutal = snapshot(&*controller_with(config, Some(80_000_000), None));
        brutal.smoothed_rtt = Some(Duration::from_millis(20));
        brutal
    }

    /// Reports `acked` and `lost` packets within the same second, the way
    /// quinn does after an ACK frame.
    fn exchange(brutal: &mut Negotiable, now: Instant, acked: u64, lost: u64) {
        for _ in 0..acked {
            brutal.on_brutal_ack(now);
        }
        brutal.on_end_acks(now, 0, false, None);
        if lost > 0 {
            // Small packets: Brutal counts packets, not bytes.
            brutal.on_packets_lost(now, lost);
            brutal.on_congestion_event(now, now, false, false, lost * 100);
        }
    }

    #[test]
    fn brutal_paces_at_target_rate() {
        let brutal = brutal_80m(BrutalConfig::default());
        assert_eq!(brutal.pacing_rate(), Some(10_000_000));
        let metrics = brutal.metrics();
        assert_eq!(metrics.pacing_rate, Some(80_000_000));
        assert_eq!(metrics.bandwidth_estimate, Some(80_000_000));
    }

    #[test]
    fn base_controller_leaves_pacing_to_quinn() {
        let base = snapshot(&*controller(None, None));
        assert_eq!(base.pacing_rate(), None);
    }

    /// quinn's window for a Hysteria2 congestion window: one more datagram.
    fn quinn_window(cwnd: u64) -> u64 {
        cwnd + u64::from(MTU)
    }

    #[test]
    fn brutal_window_is_twice_bdp() {
        let brutal = brutal_80m(BrutalConfig::default());
        // 10 MB/s * 20ms * 2
        assert_eq!(brutal.window(), quinn_window(400_000));
    }

    #[test]
    fn brutal_window_before_rtt_sample() {
        let brutal = snapshot(&*controller(Some(80_000_000), None));
        assert_eq!(brutal.window(), quinn_window(INITIAL_WINDOW));
        assert_eq!(brutal.initial_window(), quinn_window(INITIAL_WINDOW));
    }

    #[test]
    fn brutal_window_follows_queueing_delay() {
        // A standing queue adds 200ms: the window grows with it and the
        // pacing rate stays at the target, as in Hysteria2.
        let mut brutal = brutal_80m(BrutalConfig::default());
        brutal.smoothed_rtt = Some(Duration::from_millis(220));
        assert_eq!(brutal.window(), quinn_window(4_400_000));
        assert_eq!(brutal.pacing_rate(), Some(10_000_000));
    }

    #[test]
    fn brutal_window_has_a_floor() {
        // As in Hysteria2, a second datagram may be sent while one is in
        // flight, so a receiver that acknowledges every other packet does
        // not wait for its ACK delay.
        let mut brutal = brutal_80m(BrutalConfig::default());
        brutal.smoothed_rtt = Some(Duration::from_micros(1));
        assert_eq!(brutal.window(), 2 * u64::from(MTU));

        let mut brutal = brutal_80m(BrutalConfig {
            min_window: 16 * 1024,
            ..Default::default()
        });
        brutal.smoothed_rtt = Some(Duration::from_micros(1));
        assert_eq!(brutal.window(), quinn_window(16 * 1024));
    }

    #[test]
    fn brutal_window_saturates() {
        // A client may ask a server without `bandwidth` for any rate.
        let mut brutal = snapshot(&*controller(Some(u64::MAX), None));
        brutal.smoothed_rtt = Some(Duration::from_secs(10));
        assert_eq!(brutal.window(), u64::MAX);

        let mut brutal = brutal_80m(BrutalConfig {
            min_window: u64::MAX,
            ..Default::default()
        });
        brutal.smoothed_rtt = Some(Duration::from_millis(20));
        assert_eq!(brutal.window(), u64::MAX);
    }

    #[test]
    fn loss_raises_pacing_rate_and_window() {
        let mut brutal = brutal_80m(BrutalConfig::default());
        let now = brutal.epoch + Duration::from_secs(1);
        exchange(&mut brutal, now, 90, 10);
        let ack_rate = brutal.brutal.as_ref().unwrap().ack_rate;
        assert!((ack_rate - 0.9).abs() < 1e-9, "{ack_rate}");
        assert_eq!(brutal.pacing_rate(), Some(11_111_111));
        assert_eq!(brutal.window(), quinn_window(444_444));
    }

    #[test]
    fn loss_compensation_is_capped_by_min_ack_rate() {
        let mut brutal = brutal_80m(BrutalConfig::default());
        let now = brutal.epoch + Duration::from_secs(1);
        exchange(&mut brutal, now, 50, 50);
        assert_eq!(brutal.pacing_rate(), Some(12_500_000));
    }

    #[test]
    fn loss_compensation_needs_enough_samples() {
        let mut brutal = brutal_80m(BrutalConfig::default());
        let now = brutal.epoch + Duration::from_secs(1);
        exchange(&mut brutal, now, 20, 20);
        assert_eq!(brutal.pacing_rate(), Some(10_000_000));
    }

    #[test]
    fn loss_compensation_forgets_old_seconds() {
        let mut brutal = brutal_80m(BrutalConfig::default());
        let start = brutal.epoch + Duration::from_secs(1);
        exchange(&mut brutal, start, 90, 10);
        assert_eq!(brutal.pacing_rate(), Some(11_111_111));

        // Four seconds later the losses still count: 190 of 200 acknowledged.
        exchange(&mut brutal, start + Duration::from_secs(4), 100, 0);
        assert_eq!(brutal.pacing_rate(), Some(10_526_315));

        // After five seconds their slot is reused.
        exchange(&mut brutal, start + Duration::from_secs(5), 100, 0);
        assert_eq!(brutal.pacing_rate(), Some(10_000_000));
    }

    #[test]
    fn loss_compensation_forgets_old_seconds_without_new_samples() {
        let mut brutal = brutal_80m(BrutalConfig::default());
        let start = brutal.epoch + Duration::from_secs(1);
        exchange(&mut brutal, start, 90, 10);
        assert_eq!(brutal.pacing_rate(), Some(11_111_111));

        // Five seconds later, an ACK frame that acknowledges nothing new
        // leaves the old slot in place, but it is out of the window.
        exchange(&mut brutal, start + Duration::from_secs(5), 0, 0);
        assert_eq!(brutal.pacing_rate(), Some(10_000_000));
    }

    #[test]
    fn ecn_does_not_change_brutal() {
        let mut brutal = brutal_80m(BrutalConfig::default());
        let now = brutal.epoch + Duration::from_secs(1);
        exchange(&mut brutal, now, 100, 0);
        brutal.on_congestion_event(now, now, false, true, 0);
        assert_eq!(brutal.pacing_rate(), Some(10_000_000));
        assert_eq!(brutal.window(), quinn_window(400_000));
    }

    #[test]
    fn loss_compensation_can_be_disabled() {
        let mut brutal = brutal_80m(BrutalConfig {
            ack_compensate: false,
            ..Default::default()
        });
        let now = brutal.epoch + Duration::from_secs(1);
        exchange(&mut brutal, now, 50, 50);
        assert_eq!(brutal.pacing_rate(), Some(10_000_000));
        assert_eq!(brutal.window(), quinn_window(400_000));
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
        assert_eq!(controller.pacing_rate(), Some(1_250_000));
        snapshot(&*controller).set_send_mode(BrutalSendMode::Brutal(100_000_000));

        controller.on_sent(Instant::now(), 1200, 0);
        assert_eq!(controller.pacing_rate(), Some(12_500_000));
    }

    #[test]
    fn negotiated_rate_survives_path_change() {
        // A server without `bandwidth` negotiates 40 Mbit/s, then the client
        // moves to a new address that quinn does not treat as a NAT rebinding.
        let mut controller = controller(None, None);
        let negotiated = snapshot(&*controller);
        negotiated.set_send_mode(BrutalSendMode::Brutal(40_000_000));
        controller.on_sent(Instant::now(), 1200, 0);
        let mut moved = controller.for_new_path(Instant::now(), 1300).unwrap();
        assert_eq!(moved.pacing_rate(), Some(5_000_000));
        assert_eq!(snapshot(&*moved).mtu, 1300);

        // Later negotiation results still reach the controller of the new path.
        negotiated.set_send_mode(BrutalSendMode::Brutal(80_000_000));
        moved.on_sent(Instant::now(), 1200, 1);
        assert_eq!(moved.pacing_rate(), Some(10_000_000));
    }

    #[test]
    fn negotiated_base_survives_path_change() {
        // A server with `bandwidth` that ignored the client's rate keeps its
        // base controller on the new path instead of restarting Brutal.
        let mut controller = controller(Some(10_000_000), None);
        snapshot(&*controller).set_send_mode(BrutalSendMode::Base);
        controller.on_sent(Instant::now(), 1200, 0);
        let moved = controller.for_new_path(Instant::now(), MTU).unwrap();
        assert_eq!(moved.pacing_rate(), None);
        assert_eq!(snapshot(&*moved).brutal_rate(), None);
    }

    #[test]
    fn switches_from_base_to_brutal_and_back() {
        let mut controller = controller(None, None);
        let base_window = controller.window();

        snapshot(&*controller).set_send_mode(BrutalSendMode::Brutal(50_000_000));
        controller.on_sent(Instant::now(), 1200, 0);
        assert_eq!(snapshot(&*controller).brutal_rate(), Some(50_000_000));
        assert_eq!(controller.pacing_rate(), Some(6_250_000));

        snapshot(&*controller).set_send_mode(BrutalSendMode::Base);
        controller.on_sent(Instant::now(), 1200, 1);
        assert_eq!(snapshot(&*controller).brutal_rate(), None);
        assert_eq!(controller.pacing_rate(), None);
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
