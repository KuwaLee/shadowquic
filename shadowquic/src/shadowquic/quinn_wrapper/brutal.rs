//! Congestion controller that can switch between a base algorithm and Brutal
//! while the connection is running, for mihomo-compatible Brutal negotiation.

use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

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

/// Length of the windowed minimum RTT filter, as in BBR.
const MIN_RTT_WINDOW: Duration = Duration::from_secs(10);

/// Minimum RTT sample over the last [`MIN_RTT_WINDOW`] to
/// `2 * MIN_RTT_WINDOW`, so the estimate follows a path whose base RTT grows.
#[derive(Debug, Clone, Copy, Default)]
struct MinRttFilter {
    current: Option<(Duration, Instant)>,
    previous: Option<Duration>,
}

impl MinRttFilter {
    fn update(&mut self, sample: Duration, now: Instant) {
        match &mut self.current {
            Some((min, start)) if now.saturating_duration_since(*start) < MIN_RTT_WINDOW => {
                *min = (*min).min(sample);
            }
            current => {
                self.previous = current.map(|(min, _)| min);
                *current = Some((sample, now));
            }
        }
    }

    fn get(&self) -> Option<Duration> {
        let current = self.current.map(|(min, _)| min);
        match (current, self.previous) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

/// Cap of the RTT Brutal sizes its window from, in multiples of the windowed
/// minimum RTT. Samples below the cap follow jitter, while the cap stops a
/// standing queue from growing the window.
const MAX_RTT_OVER_MIN: u32 = 2;

/// How often Brutal drains its queue to measure the base RTT, as BBR's
/// PROBE_RTT. Shorter than [`MIN_RTT_WINDOW`] so every window gets a sample.
const PROBE_RTT_INTERVAL: Duration = Duration::from_secs(8);
/// How long the window stays drained once in flight data is down.
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);
/// Window while probing, in packets.
const PROBE_RTT_PACKETS: u64 = 4;

/// PROBE_RTT state of the Brutal controller.
#[derive(Debug, Clone, Copy)]
enum ProbeRtt {
    /// Sending normally until the next probe.
    Idle { next: Instant },
    /// Window cut, waiting for in flight data to drop.
    Draining,
    /// Drained; samples now see the base RTT.
    Probing { until: Instant },
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
            min_rtt: MinRttFilter::default(),
            probe_rtt: ProbeRtt::Idle {
                next: now + PROBE_RTT_INTERVAL,
            },
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
/// Brutal sizes its window from RTT samples capped at [`MAX_RTT_OVER_MIN`]
/// times the windowed minimum RTT. quinn paces from the
/// window, so the send rate is `window / RTT`: once a bottleneck queue pushes
/// the RTT past the cap, the rate drops below the target instead of the window
/// growing with the queue, which bounds the queueing delay when the target
/// exceeds the path capacity. Jitter below the cap does not shrink the window.
/// Every [`PROBE_RTT_INTERVAL`] the window briefly drops to a few packets to
/// drain the queue, so a long-standing queue is never taken for the base RTT.
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
    min_rtt: MinRttFilter,
    probe_rtt: ProbeRtt,
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
            min_rtt: self.min_rtt,
            probe_rtt: self.probe_rtt,
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

    /// Feeds an ACK to Brutal with its RTT sample capped at
    /// [`MAX_RTT_OVER_MIN`] times the windowed minimum RTT. The raw sample,
    /// unlike quinn's smoothed RTT, includes the peer's ACK delay, which is
    /// what the window has to cover. BrutalCore smooths the samples.
    fn on_brutal_ack(&mut self, now: Instant, sent: Instant, bytes: u64) {
        let sample = now.saturating_duration_since(sent);
        self.min_rtt.update(sample, now);
        let cap = self
            .min_rtt
            .get()
            .map_or(sample, |min| min * MAX_RTT_OVER_MIN);
        if let Some(brutal) = self.brutal.as_mut() {
            brutal.on_ack_bytes(bytes, sample.min(cap));
        }
    }

    fn probe_window(&self) -> u64 {
        PROBE_RTT_PACKETS * u64::from(self.mtu)
    }

    fn probing(&self) -> bool {
        !matches!(self.probe_rtt, ProbeRtt::Idle { .. })
    }

    fn update_probe_rtt(&mut self, now: Instant, in_flight: u64) {
        self.probe_rtt = match self.probe_rtt {
            ProbeRtt::Idle { next } if now >= next => ProbeRtt::Draining,
            ProbeRtt::Draining if in_flight <= self.probe_window() => ProbeRtt::Probing {
                until: now + PROBE_RTT_DURATION,
            },
            ProbeRtt::Probing { until } if now >= until => ProbeRtt::Idle {
                next: now + PROBE_RTT_INTERVAL,
            },
            state => state,
        };
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
                self.probe_rtt = ProbeRtt::Idle {
                    next: now + PROBE_RTT_INTERVAL,
                };
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
        if self.brutal.is_some() {
            self.on_brutal_ack(now, sent, bytes);
        } else {
            self.min_rtt
                .update(now.saturating_duration_since(sent), now);
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
        self.sync(now);
        match self.brutal.as_mut() {
            Some(brutal) => {
                brutal.on_end_acks(now);
                self.update_probe_rtt(now, in_flight);
            }
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
            Some(brutal) if self.probing() => brutal.window_cached().min(self.probe_window()),
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
    fn min_rtt_filter_keeps_minimum_within_window() {
        let start = Instant::now();
        let mut filter = MinRttFilter::default();
        assert_eq!(filter.get(), None);
        filter.update(Duration::from_millis(30), start);
        filter.update(Duration::from_millis(20), start + Duration::from_secs(1));
        filter.update(Duration::from_millis(400), start + Duration::from_secs(2));
        assert_eq!(filter.get(), Some(Duration::from_millis(20)));
    }

    #[test]
    fn min_rtt_filter_follows_a_higher_base_rtt() {
        let start = Instant::now();
        let mut filter = MinRttFilter::default();
        filter.update(Duration::from_millis(20), start);
        // The path changes: every sample is now 50ms.
        filter.update(Duration::from_millis(50), start + MIN_RTT_WINDOW);
        assert_eq!(filter.get(), Some(Duration::from_millis(20)));
        filter.update(Duration::from_millis(50), start + MIN_RTT_WINDOW * 2);
        assert_eq!(filter.get(), Some(Duration::from_millis(50)));
    }

    #[test]
    fn queueing_delay_does_not_grow_brutal_window() {
        let mut brutal = snapshot(&*controller(Some(80_000_000), None));
        let mut now = Instant::now();
        let exchange = |brutal: &mut Negotiable, now: &mut Instant, rtt_ms: u64, i: u64| {
            let sent = *now;
            *now += Duration::from_millis(rtt_ms);
            brutal.on_sent(sent, 1200, i);
            brutal.on_brutal_ack(*now, sent, 1200);
            // Large in flight data keeps the probe draining.
            brutal.on_end_acks(*now, u64::MAX, false, Some(i));
        };
        for i in 0..100 {
            exchange(&mut brutal, &mut now, 20, i);
        }
        brutal.probe_rtt = ProbeRtt::Idle {
            next: now + Duration::from_secs(3600),
        };
        let window = brutal.window();
        // 80 Mbit/s * 20ms = 200 kB.
        assert!((190_000..=210_000).contains(&window), "{window}");
        // A standing queue adds 200ms to every sample. Within the filter
        // window the RTT Brutal uses stays at twice the minimum; longer queues
        // are drained by PROBE_RTT.
        for i in 100..140 {
            exchange(&mut brutal, &mut now, 220, i);
        }
        let capped = brutal.window();
        assert!(
            (window * 19 / 10..=window * 21 / 10).contains(&capped),
            "{window} -> {capped}"
        );
    }

    #[test]
    fn probe_rtt_drains_then_restores_window() {
        let mut brutal = snapshot(&*controller(Some(80_000_000), None));
        let start = Instant::now();
        let full = brutal.window();
        assert!(full > brutal.probe_window());

        // Due: the window drops to a few packets until in flight data follows.
        let due = start + PROBE_RTT_INTERVAL;
        brutal.on_end_acks(due, full, false, Some(0));
        assert_eq!(brutal.window(), brutal.probe_window());
        brutal.on_end_acks(due, full, false, Some(1));
        assert!(matches!(brutal.probe_rtt, ProbeRtt::Draining));

        let drained = due + Duration::from_millis(30);
        brutal.on_end_acks(drained, 0, false, Some(2));
        assert!(matches!(brutal.probe_rtt, ProbeRtt::Probing { .. }));
        assert_eq!(brutal.window(), brutal.probe_window());

        brutal.on_end_acks(drained + PROBE_RTT_DURATION, 0, false, Some(3));
        assert!(matches!(brutal.probe_rtt, ProbeRtt::Idle { .. }));
        assert_eq!(brutal.window(), full);
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
