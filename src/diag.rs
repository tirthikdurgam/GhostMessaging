//! Hidden Diagnostic Mode (`--diag`).
//!
//! Records METADATA ONLY (timings, path type, RTTs) - never message content -
//! and keeps it in RAM. Nothing touches disk unless `--diag-out <file>` is
//! given explicitly. NOTE for the paper: diag output is outside the zero-trace
//! envelope, so benchmark runs and "forensic" runs must be separate experiments.
//!
//! Events recorded for research (all metadata):
//!   * join_started / join_timeout / join_failed / subscribe_and_join_ms
//!   * first_contact_from_peer (first frame of ANY kind) and first_msg_rx
//!   * conn_type transitions (variant name only - peer addresses are NOT logged)
//!   * path class transitions with QUIC latency
//!   * rtt_us for every gossip pong

use std::{
    collections::{BTreeMap, HashMap},
    time::Instant,
};

use serde::Serialize;

#[derive(Default, Serialize, Clone)]
pub struct RttStats {
    pub sent: u64,
    pub received: u64,
    pub loss_pct: f64,
    pub min_ms: f64,
    pub mean_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub max_ms: f64,
    pub jitter_ms: f64,
}

#[derive(Serialize)]
pub struct Report<'a> {
    pub os: &'static str,
    pub arch: &'static str,
    pub role: &'a str,
    pub exit_reason: &'a str,
    pub marks_ms: &'a BTreeMap<String, f64>,
    pub derived_ms: BTreeMap<String, f64>,
    pub rtt: RttStats,
    pub events: &'a [(f64, String)],
}

pub struct Diag {
    pub enabled: bool,
    t0: Instant,
    marks: BTreeMap<String, f64>,
    /// Named measurements that are durations rather than timeline marks
    /// (e.g. subscribe_and_join_ms). Merged into the report's derived values.
    extra: BTreeMap<String, f64>,
    events: Vec<(f64, String)>,
    rtts: Vec<f64>,
    pending: HashMap<u64, Instant>,
    sent: u64,
    next_id: u64,
    pub path: String,
    pub conn_type: String,
    pub quic_latency_ms: Option<f64>,
}

impl Diag {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            t0: Instant::now(),
            marks: BTreeMap::new(),
            extra: BTreeMap::new(),
            events: Vec::new(),
            rtts: Vec::new(),
            pending: HashMap::new(),
            sent: 0,
            next_id: 1,
            path: "none".into(),
            conn_type: "none".into(),
            quic_latency_ms: None,
        }
    }

    fn now_ms(&self) -> f64 {
        self.t0.elapsed().as_secs_f64() * 1000.0
    }

    pub fn event(&mut self, s: impl Into<String>) {
        if self.enabled {
            let t = self.now_ms();
            self.events.push((t, s.into()));
        }
    }

    /// Named milestone; first occurrence wins (later calls are ignored and add no event,
    /// so it is cheap to call on every received frame).
    pub fn mark(&mut self, name: impl Into<String>) {
        if !self.enabled {
            return;
        }
        let name = name.into();
        if self.marks.contains_key(&name) {
            return;
        }
        let t = self.now_ms();
        self.marks.insert(name.clone(), t);
        self.events.push((t, format!("mark:{name}")));
    }

    /// Record a named measurement (a duration in ms) and log it as an event.
    pub fn record(&mut self, name: &str, value_ms: f64) {
        if !self.enabled {
            return;
        }
        self.extra.insert(name.to_string(), value_ms);
        self.event(format!("{name} = {value_ms:.1}"));
    }

    /// Path class (lan/direct/relay/mixed) with the current QUIC latency.
    pub fn observe_path(&mut self, class: &str, quic_latency_ms: Option<f64>) {
        if !self.enabled {
            return;
        }
        self.quic_latency_ms = quic_latency_ms;
        if class != self.path {
            let lat = quic_latency_ms
                .map(|x| format!("{x:.1} ms"))
                .unwrap_or_else(|| "-".into());
            self.event(format!("path {} -> {} (quic latency {})", self.path, class, lat));
            self.path = class.to_string();
            self.mark(format!("path_{class}"));
        }
    }

    /// Raw iroh connection-type variant name ("Direct", "Relay", "Mixed", "None").
    /// Logged whenever it changes. Only the variant is stored, never the addresses.
    pub fn observe_conn_type(&mut self, variant: &str) {
        if !self.enabled || variant == self.conn_type {
            return;
        }
        self.event(format!("conn_type {} -> {}", self.conn_type, variant));
        self.conn_type = variant.to_string();
    }

    pub fn ping_start(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.sent += 1;
        self.pending.insert(id, Instant::now());
        id
    }

    pub fn pong(&mut self, id: u64) {
        if let Some(t) = self.pending.remove(&id) {
            let el = t.elapsed();
            self.rtts.push(el.as_secs_f64() * 1000.0);
            self.event(format!("rtt_us id={id} {}", el.as_micros()));
        }
    }

    pub fn rtt_stats(&self) -> RttStats {
        let n = self.rtts.len();
        if n == 0 {
            return RttStats { sent: self.sent, ..Default::default() };
        }
        let mut s = self.rtts.clone();
        s.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let pct = |p: f64| s[((n - 1) as f64 * p).round() as usize];
        let jitter = if n > 1 {
            self.rtts.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (n - 1) as f64
        } else {
            0.0
        };
        RttStats {
            sent: self.sent,
            received: n as u64,
            loss_pct: 100.0 * (self.sent - n as u64) as f64 / self.sent.max(1) as f64,
            min_ms: s[0],
            mean_ms: s.iter().sum::<f64>() / n as f64,
            p50_ms: pct(0.5),
            p95_ms: pct(0.95),
            max_ms: s[n - 1],
            jitter_ms: jitter,
        }
    }

    fn derived(&self) -> BTreeMap<String, f64> {
        let mut d = BTreeMap::new();
        let m = &self.marks;
        if let (Some(a), Some(b)) = (m.get("endpoint_bound"), m.get("peer_joined")) {
            d.insert("bind_to_peer_joined".into(), b - a);
        }
        if let (Some(a), Some(b)) = (m.get("join_started"), m.get("peer_joined")) {
            d.insert("handshake_join_to_neighbor_up".into(), b - a);
        }
        if let (Some(a), Some(b)) = (m.get("path_relay"), m.get("path_direct").or(m.get("path_lan"))) {
            if b >= a {
                d.insert("relay_to_direct_upgrade".into(), b - a);
            }
        }
        if let (Some(a), Some(b)) = (m.get("peer_joined"), m.get("first_contact_from_peer")) {
            if b >= a {
                d.insert("peer_joined_to_first_contact".into(), b - a);
            }
        }
        if let (Some(a), Some(b)) = (m.get("peer_joined"), m.get("first_msg_rx")) {
            d.insert("peer_joined_to_first_msg".into(), b - a);
        }
        for (k, v) in &self.extra {
            d.insert(k.clone(), *v);
        }
        d
    }

    pub fn report<'a>(&'a self, role: &'a str, exit_reason: &'a str) -> Report<'a> {
        Report {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            role,
            exit_reason,
            marks_ms: &self.marks,
            derived_ms: self.derived(),
            rtt: self.rtt_stats(),
            events: &self.events,
        }
    }

    pub fn report_text(&self, role: &str, exit_reason: &str) -> String {
        let r = self.report(role, exit_reason);
        let mut out = String::new();
        out += &format!("== GhostTerm diagnostics ({} / {}, role={}, exit={}) ==\n", r.os, r.arch, role, exit_reason);
        let mut marks: Vec<_> = r.marks_ms.iter().collect();
        marks.sort_by(|a, b| a.1.partial_cmp(b.1).unwrap());
        for (k, v) in marks {
            out += &format!("  {:<32} {:>10.1} ms\n", k, v);
        }
        for (k, v) in &r.derived_ms {
            out += &format!("  [derived] {:<22} {:>10.1} ms\n", k, v);
        }
        let s = &r.rtt;
        out += &format!(
            "  gossip RTT: n={}/{} loss={:.1}% min={:.1} mean={:.1} p50={:.1} p95={:.1} max={:.1} jitter={:.1} ms\n",
            s.received, s.sent, s.loss_pct, s.min_ms, s.mean_ms, s.p50_ms, s.p95_ms, s.max_ms, s.jitter_ms
        );
        out
    }

    pub fn panel_lines(&self) -> Vec<String> {
        let s = self.rtt_stats();
        let last = self.rtts.last().copied().unwrap_or(0.0);
        let mut v = vec![
            format!("path        : {}", self.path),
            format!("conn_type   : {}", self.conn_type),
            format!(
                "QUIC latency: {}",
                self.quic_latency_ms.map(|x| format!("{x:.1} ms")).unwrap_or("-".into())
            ),
            format!("gossip RTT  : last {last:.1} ms"),
            format!("  mean {:.1}  p95 {:.1}  max {:.1}", s.mean_ms, s.p95_ms, s.max_ms),
            format!("  jitter {:.1} ms  loss {:.1}%", s.jitter_ms, s.loss_pct),
            "-- milestones (ms) --".into(),
        ];
        let mut marks: Vec<_> = self.marks.iter().collect();
        marks.sort_by(|a, b| a.1.partial_cmp(b.1).unwrap());
        for (k, t) in marks {
            v.push(format!("{k}: {t:.0}"));
        }
        v
    }
}
