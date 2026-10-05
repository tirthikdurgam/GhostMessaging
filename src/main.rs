mod diag;
mod secure;
mod stego;
mod wire;

use std::{
    borrow::Cow,
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use crossterm::event::{Event as TermEvent, EventStream, KeyCode, KeyEventKind, KeyModifiers};
use futures_lite::StreamExt;
use iroh::{protocol::Router, Endpoint, NodeId};
use iroh_gossip::{
    net::{Event as GEvent, Gossip, GossipEvent, GossipReceiver, GossipSender},
    proto::TopicId,
    ALPN as GOSSIP_ALPN,
};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    DefaultTerminal, Frame,
};
use zeroize::{Zeroize, Zeroizing};

use diag::Diag;
use secure::SecureStore;
use wire::{Frame as WireFrame, Ticket, Wire, WIRE_VERSION};

const HEARTBEAT: Duration = Duration::from_secs(2);
const ABOUT_INTERVAL: Duration = Duration::from_secs(3);
const SILENCE_LIMIT: Duration = Duration::from_secs(6);
const SILENCE_AFTER_NEIGHBOR_DOWN: Duration = Duration::from_secs(3);
const KICK_DELAY: Duration = Duration::from_secs(3);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

// ------------------------------------------------------------------------ CLI

#[derive(Parser)]
#[command(name = "ghostterm", version, about = "Serverless, ephemeral P2P terminal chat")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Also discover peers on the local network (mDNS). Off by default so the
    /// node does not broadcast itself on untrusted networks.
    #[arg(long, global = true)]
    lan: bool,
    /// Hidden: record handshake / path / RTT diagnostics (metadata only).
    #[arg(long, global = true, hide = true)]
    diag: bool,
    /// Hidden: also write the diagnostics report as JSON to this file (leaves a disk trace!).
    #[arg(long, global = true, hide = true)]
    diag_out: Option<PathBuf>,
    /// Hidden: Linux only - mlockall + disable core dumps for the whole process.
    /// Also enables the extra input-buffer scrubbing on every backspace.
    #[arg(long, global = true, hide = true)]
    harden: bool,
    /// Hidden: number of messages kept in RAM; older ones are zeroized.
    #[arg(long, global = true, hide = true, default_value_t = 50)]
    retain: usize,
}

#[derive(Subcommand)]
enum Cmd {
    Host {
        #[arg(long)]
        name: String,
        /// Print the ticket hidden inside a harmless-looking sentence (zero-width
        /// characters). Obscurity only - not a security feature.
        #[arg(long)]
        hide_ticket: bool,
    },
    Join {
        #[arg(long)]
        ticket: String,
        #[arg(long)]
        name: String,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Host,
    Client,
}

// ------------------------------------------------------------------ app state

enum Phase {
    Connecting,
    Connected,
    /// Peer sent Bye or went silent: show banner, then terminate.
    PeerLeft { at: Instant, why: String },
    Failed(String),
}

enum ExitReason {
    Local,
    Signal,
    PeerLeft(String),
    Failed(String),
}

impl ExitReason {
    fn label(&self) -> String {
        match self {
            ExitReason::Local => "local_exit".into(),
            ExitReason::Signal => "terminal_closed_or_signal".into(),
            ExitReason::PeerLeft(w) => format!("peer_left:{w}"),
            ExitReason::Failed(w) => format!("failed:{w}"),
        }
    }
}

struct App {
    role: Role,
    name: String,
    phase: Phase,
    store: SecureStore,
    diag: Diag,
    peer: Option<NodeId>,
    /// NodeId -> display name learned from `AboutMe`. Values are zeroized on drop.
    peer_names: HashMap<NodeId, Zeroizing<String>>,
    last_rx: Instant,
    neighbor_down_at: Option<Instant>,
    started: Instant,
    scroll: usize,
    show_diag: bool,
    hardening: Vec<String>,
}

impl App {
    fn on_tick(&mut self) -> Option<ExitReason> {
        let mut new_phase = None;
        let mut exit = None;
        match &self.phase {
            Phase::Connecting => {
                if self.role == Role::Client && self.started.elapsed() > CONNECT_TIMEOUT {
                    self.diag.event("connect timeout");
                    new_phase = Some(Phase::Failed(
                        "Could not reach the host within 30 s. Check the ticket, the host's \
                         firewall (allow UDP), and NAT. Press Esc to quit."
                            .into(),
                    ));
                }
            }
            Phase::Connected => {
                let limit = if self.neighbor_down_at.is_some() {
                    SILENCE_AFTER_NEIGHBOR_DOWN
                } else {
                    SILENCE_LIMIT
                };
                let silent = self.last_rx.elapsed();
                if silent > limit {
                    self.diag
                        .event(format!("peer silent {} ms -> declared lost", silent.as_millis()));
                    new_phase = Some(Phase::PeerLeft {
                        at: Instant::now(),
                        why: "connection lost".into(),
                    });
                }
            }
            Phase::PeerLeft { at, why } => {
                if at.elapsed() >= KICK_DELAY {
                    exit = Some(ExitReason::PeerLeft(why.clone()));
                }
            }
            Phase::Failed(_) => {}
        }
        if let Some(p) = new_phase {
            self.phase = p;
        }
        exit
    }
}

// --------------------------------------------------------------------- helpers

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

async fn send_wire(sender: &GossipSender, w: Wire<'_>) -> Result<()> {
    // Serialization buffer is zeroized on drop. (The `Bytes` copy handed to iroh is not ours to wipe.)
    let buf = Zeroizing::new(serde_json::to_vec(&WireFrame { v: WIRE_VERSION, w })?);
    sender.broadcast(Bytes::copy_from_slice(&buf)).await?;
    Ok(())
}

/// Announce our display name (identity is separate from chat content).
async fn send_about(name: &str, sender: &GossipSender) -> Result<()> {
    send_wire(sender, Wire::AboutMe { name: Cow::Borrowed(name) }).await
}

fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_link_local() || v.is_loopback(),
        IpAddr::V6(v) => {
            v.is_loopback() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Classify iroh's connection type from its Debug output so we don't depend on variant names.
/// lan = direct path to a private address (mDNS / same subnet); direct = hole-punched public path.
fn classify_path(dbg: &str) -> &'static str {
    if let Some(rest) = dbg.strip_prefix("Direct(") {
        return match rest.trim_end_matches(')').parse::<SocketAddr>() {
            Ok(a) if is_local(a.ip()) => "lan",
            _ => "direct",
        };
    }
    if dbg.starts_with("Relay") {
        "relay"
    } else if dbg.starts_with("Mixed") {
        "mixed"
    } else {
        "none"
    }
}

/// Resolves when the terminal window is closed / process is asked to stop.
#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut hup = signal(SignalKind::hangup()).expect("sighup");
    let mut term = signal(SignalKind::terminate()).expect("sigterm");
    tokio::select! { _ = hup.recv() => {}, _ = term.recv() => {} }
}

#[cfg(windows)]
async fn shutdown_signal() {
    use tokio::signal::windows;
    let mut a = windows::ctrl_close().expect("ctrl_close");
    let mut b = windows::ctrl_shutdown().expect("ctrl_shutdown");
    let mut c = windows::ctrl_logoff().expect("ctrl_logoff");
    tokio::select! { _ = a.recv() => {}, _ = b.recv() => {}, _ = c.recv() => {} }
}

// ------------------------------------------------------------------------ main

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut diag = Diag::new(cli.diag);

    let hardening = if cli.harden { secure::harden_process() } else { vec![] };
    let mut store = SecureStore::new(cli.retain);
    store.harden_input = cli.harden;
    if cli.diag {
        let ok = store.self_test();
        diag.event(format!("arena mlock={} (err={:?})", store.is_locked(), store.lock_error));
        diag.event(format!("arena canary write/wipe/verify self-test: {}", if ok { "PASS" } else { "FAIL" }));
        for h in &hardening {
            diag.event(format!("harden: {h}"));
        }
    }

    // ---- network bring-up -------------------------------------------------
    // Restrictive by default: n0 discovery only. mDNS (LAN broadcast) is opt-in via --lan.
    let mut builder = Endpoint::builder().discovery_n0(); // API-CHECK (0.33)
    if cli.lan {
        builder = builder.discovery_local_network(); // API-CHECK: must ADD to n0 discovery, not replace it
        diag.event("LAN (mDNS) discovery enabled");
    }
    let endpoint = builder.bind().await?;
    diag.mark("endpoint_bound");

    let gossip = Gossip::builder().spawn(endpoint.clone()).await?; // API-CHECK (0.33 signature)
    let router = Router::builder(endpoint.clone())
        .accept(GOSSIP_ALPN, gossip.clone())
        .spawn()
        .await?; // API-CHECK (0.33 signature)
    diag.mark("gossip_ready");

    let (role, name, topic, bootstrap): (Role, String, TopicId, Vec<NodeId>) = match cli.cmd {
        Cmd::Host { name, hide_ticket } => {
            let topic = TopicId::from_bytes(rand::random());
            let mut addr = endpoint.node_addr().await?; // API-CHECK
            let deadline = Instant::now() + Duration::from_secs(3);
            while addr.relay_url.is_none() && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(100)).await;
                addr = endpoint.node_addr().await?;
            }
            // --- ADD THIS EXACT BLOCK RIGHT HERE ---
            let local_ports: Vec<u16> = addr.direct_addresses.iter().map(|a| a.port()).collect();
            for port in local_ports {
                if let Ok(local_addr) = format!("127.0.0.1:{}", port).parse() {
                    addr.direct_addresses.insert(local_addr);
                }
            }
            if addr.relay_url.is_some() {
                diag.mark("home_relay_ready");
            } else {
                diag.event("no relay reachable");
                eprintln!(
                    "warning: no relay server reachable - the ticket will only work for peers \
                     that can reach this machine directly (same network / open UDP)."
                );
            }
            let plain = Ticket::new(addr, topic).encode();
            let shown = if hide_ticket { stego::hide(&plain) } else { plain };
            println!("\nGhost Ticket (share out-of-band):\n\n{shown}\n");
            if hide_ticket {
                println!("(hidden ticket: copy the whole line above, including the invisible part)\n");
            }
            println!("Press ENTER to open the dashboard...");
            tokio::task::spawn_blocking(|| {
                let mut s = String::new();
                let _ = std::io::stdin().read_line(&mut s);
            })
            .await?;
            (Role::Host, name, topic, vec![])
        }
        Cmd::Join { ticket, name } => {
            // Accept both plain and stego-hidden tickets.
            let raw = stego::reveal(&ticket).unwrap_or_else(|| ticket.clone());
            let t = Ticket::decode(&raw).map_err(|e| anyhow!("ticket decode error: {e}"))?;
            endpoint.add_node_addr(t.node.clone())?; // API-CHECK
            diag.mark("join_started");
            (Role::Client, name, t.topic, vec![t.node.node_id])
        }
    };

    // ---- subscribe / join ---------------------------------------------------
    // Host: plain subscribe (nobody to wait for yet).
    // Client: subscribe_and_join under an explicit timeout so we never hang silently.
    let (handle, initial_phase, initial_peer) = if role == Role::Client {
        let host_id = bootstrap[0];
        println!("Connecting to host (up to {} s)...", CONNECT_TIMEOUT.as_secs());
        let t0 = Instant::now();
        let res = tokio::time::timeout(CONNECT_TIMEOUT, gossip.subscribe_and_join(topic, bootstrap)).await; // API-CHECK
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        match res {
            Ok(Ok(h)) => {
                diag.record("subscribe_and_join_ms", ms);
                diag.mark("peer_joined");
                // subscribe_and_join may already have consumed the NeighborUp event, so the
                // peer is fixed here (two-party lock: the host we were given in the ticket).
                (h, Phase::Connected, Some(host_id))
            }
            Ok(Err(e)) => {
                diag.event(format!("join error after {ms:.0} ms: {e}"));
                diag.mark("join_failed");
                let h = gossip.subscribe(topic, vec![])?;
                (h, Phase::Failed(format!("Could not join the session: {e}. Press Esc to quit.")), None)
            }
            Err(_) => {
                diag.event(format!("join timeout after {ms:.0} ms"));
                diag.mark("join_timeout");
                let h = gossip.subscribe(topic, vec![])?;
                (
                    h,
                    Phase::Failed(
                        "Could not reach the host within 30 s (no relay reachable or host \
                         offline). Check the ticket, the host's firewall (allow UDP), and NAT. \
                         Press Esc to quit."
                            .into(),
                    ),
                    None,
                )
            }
        }
    } else {
        (gossip.subscribe(topic, vec![])?, Phase::Connecting, None) // API-CHECK
    };
    let (sender, receiver) = handle.split();

    let mut app = App {
        role,
        name,
        phase: initial_phase,
        store,
        diag,
        peer: initial_peer,
        peer_names: HashMap::new(),
        last_rx: Instant::now(),
        neighbor_down_at: None,
        started: Instant::now(),
        scroll: 0,
        show_diag: cli.diag,
        hardening,
    };

    // ---- TUI ----------------------------------------------------------------
    let mut terminal = ratatui::init();
    let reason = run(&mut terminal, &mut app, &endpoint, &sender, receiver).await;

    // Graceful local exit / closed window: tell the peer to terminate too.
    if matches!(reason, ExitReason::Local | ExitReason::Signal) {
        let _ = send_wire(&sender, Wire::Bye).await;
        tokio::time::sleep(Duration::from_millis(300)).await; // let the frame leave
    }
    let _ = router.shutdown().await;

    // Overwrite both Ratatui frame buffers, then leave the alternate screen.
    for _ in 0..2 {
        let _ = terminal.draw(|f| f.render_widget(Clear, f.area()));
    }
    ratatui::restore();

    // Explicit, verified erasure of the message arena.
    app.store.wipe();
    let verified = app.store.verify_zeroed();

    // Auxiliary buffers: peer names are `Zeroizing<String>` (wiped when dropped); our own
    // display name is zeroized explicitly.
    app.peer_names.clear();
    app.name.zeroize();

    println!(
        "Session ended ({}). Memory arena wiped: {}.",
        reason.label(),
        if verified { "verified" } else { "VERIFICATION FAILED" }
    );

    if app.diag.enabled {
        let role_s = if app.role == Role::Host { "host" } else { "client" };
        println!("\n{}", app.diag.report_text(role_s, &reason.label()));
        if let Some(p) = &cli.diag_out {
            let json = serde_json::to_string_pretty(&app.diag.report(role_s, &reason.label()))?;
            std::fs::write(p, json)?;
            println!("(diagnostics JSON written to {} - this is a disk trace)", p.display());
        }
    }
    if let ExitReason::Failed(w) = &reason {
        return Err(anyhow!(w.clone()));
    }
    Ok(())
}

// ------------------------------------------------------------------- main loop

async fn run(
    terminal: &mut DefaultTerminal,
    app: &mut App,
    endpoint: &Endpoint,
    sender: &GossipSender,
    mut receiver: GossipReceiver,
) -> ExitReason {
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let mut hb = tokio::time::interval(HEARTBEAT);
    let mut about_iv = tokio::time::interval(ABOUT_INTERVAL);
    let mut ping_iv = tokio::time::interval(Duration::from_secs(2));
    let mut path_iv = tokio::time::interval(Duration::from_millis(500));
    let diag_on = app.diag.enabled;
    let mut shutdown = Box::pin(shutdown_signal());
    let mut dirty = true;

    // Client joins before the TUI starts: introduce ourselves right away.
    if matches!(app.phase, Phase::Connected) {
        let _ = send_about(&app.name, sender).await;
        let _ = send_wire(sender, Wire::Hb).await;
    }

    loop {
        if dirty {
            let _ = terminal.draw(|f| ui(f, app));
            dirty = false;
        }

        tokio::select! {
            _ = &mut shutdown => return ExitReason::Signal,

            ev = events.next() => {
                dirty = true;
                let Some(Ok(TermEvent::Key(key))) = ev else { continue };
                if key.kind != KeyEventKind::Press { continue; }
                let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
                match key.code {
                    KeyCode::Esc => {
                        return match &app.phase {
                            Phase::Failed(w) => ExitReason::Failed(w.clone()),
                            Phase::PeerLeft { why, .. } => ExitReason::PeerLeft(why.clone()),
                            _ => ExitReason::Local,
                        };
                    }
                    KeyCode::Char('c') if ctrl => return ExitReason::Local,
                    KeyCode::F(2) => app.show_diag = !app.show_diag && diag_on,
                    KeyCode::Up => app.scroll = (app.scroll + 1).min(app.store.len().saturating_sub(1)),
                    KeyCode::Down => app.scroll = app.scroll.saturating_sub(1),
                    _ if !matches!(app.phase, Phase::Connected | Phase::Connecting) => {}
                    KeyCode::Backspace => app.store.input_pop(),
                    KeyCode::Char(c) if !ctrl => { app.store.input_push(c); }
                    KeyCode::Enter if matches!(app.phase, Phase::Connected) => {
                        let ts = now_ms();
                        let mut sent = false;
                        {
                            let body = app.store.input_str();
                            if !body.is_empty() {
                                // Chat content only: identity travels separately in AboutMe.
                                let w = Wire::Msg { body: Cow::Borrowed(body), ts };
                                match send_wire(sender, w).await {
                                    Ok(()) => sent = true,
                                    Err(e) => app.diag.event(format!("send error: {e}")),
                                }
                            }
                        }
                        if sent {
                            let name = app.name.clone();
                            app.store.commit_input(&name, ts);
                            app.scroll = 0;
                        }
                    }
                    _ => {}
                }
            }

            gev = receiver.next() => {
                dirty = true;
                match gev {
                    Some(Ok(ev)) => on_gossip(app, ev, sender).await,
                    Some(Err(e)) => app.diag.event(format!("gossip error: {e}")),
                    None => {
                        if matches!(app.phase, Phase::Connected | Phase::Connecting) {
                            app.phase = Phase::PeerLeft { at: Instant::now(), why: "gossip stream closed".into() };
                        }
                    }
                }
            }

            _ = tick.tick() => {
                if matches!(app.phase, Phase::Connecting | Phase::PeerLeft { .. }) { dirty = true; }
                if let Some(r) = app.on_tick() { return r; }
            }

            _ = hb.tick() => {
                if matches!(app.phase, Phase::Connected) {
                    let _ = send_wire(sender, Wire::Hb).await;
                }
            }

            _ = about_iv.tick() => {
                if matches!(app.phase, Phase::Connected) {
                    let _ = send_about(&app.name, sender).await;
                }
            }

            _ = ping_iv.tick(), if diag_on => {
                if matches!(app.phase, Phase::Connected) {
                    let id = app.diag.ping_start();
                    let _ = send_wire(sender, Wire::Ping { id }).await;
                }
            }

            _ = path_iv.tick(), if diag_on => {
                if let Some(peer) = app.peer {
                    if let Some(info) = endpoint.remote_info(peer) { // API-CHECK
                        let dbg = format!("{:?}", info.conn_type);
                        let class = classify_path(&dbg);
                        // Variant name only (e.g. "Direct"); the peer's address is never logged.
                        let variant = dbg.split('(').next().unwrap_or("none");
                        let lat = info.latency.map(|d| d.as_secs_f64() * 1000.0);
                        app.diag.observe_conn_type(variant);
                        app.diag.observe_path(class, lat);
                        dirty = true;
                    }
                }
            }
        }
    }
}

async fn on_gossip(app: &mut App, ev: GEvent, sender: &GossipSender) {
    let GEvent::Gossip(g) = ev else { return };
    match g {
        GossipEvent::NeighborUp(id) => {
            if app.peer.is_none() {
                app.peer = Some(id);
                app.phase = Phase::Connected;
                app.last_rx = Instant::now();
                app.diag.mark("peer_joined");
                let _ = send_wire(sender, Wire::Hb).await;
                let _ = send_about(&app.name, sender).await;
            } else if app.peer == Some(id) {
                app.neighbor_down_at = None;
                app.diag.event("peer neighbor re-up");
            } else {
                // Two-party lock: a third node holding the ticket is ignored.
                app.diag.event(format!("extra neighbor {} ignored", id.fmt_short()));
            }
        }
        GossipEvent::NeighborDown(id) => {
            if app.peer == Some(id) {
                app.neighbor_down_at = Some(Instant::now());
                app.diag.event("peer neighbor down");
            }
        }
        GossipEvent::Received(msg) => {
            let from = msg.delivered_from;
            
            // 1. Auto-adopt the peer if we somehow missed the initial connection event
            if app.peer.is_none() {
                app.peer = Some(from);
                app.phase = Phase::Connected;
                app.last_rx = Instant::now();
                app.diag.mark("peer_joined");
            } else if app.peer != Some(from) {
                return;
            }

            // 2. FIX: Convert to string first so serde can borrow it without crashing
            let buf = Zeroizing::new(msg.content.to_vec());
            let text = match std::str::from_utf8(&buf) {
                Ok(t) => t,
                Err(e) => { 
                    app.diag.event(format!("dropped frame: utf8 error {}", e)); 
                    return; 
                }
            };

            let frame = match serde_json::from_str::<WireFrame>(text) {
                Ok(f) => f,
                Err(e) => { 
                    app.diag.event(format!("dropped frame: json error {}", e)); 
                    return; 
                }
            };

            if frame.v != WIRE_VERSION {
                app.diag.event(format!("dropped frame with unsupported version {}", frame.v));
                return;
            }
            app.last_rx = Instant::now();
            app.diag.mark("first_contact_from_peer"); 
            match frame.w {
                Wire::AboutMe { name } => {
                    let n = secure::trunc(&name, secure::MAX_NAME);
                    let unchanged = app.peer_names.get(&from).map(|s| s.as_str() == n).unwrap_or(false);
                    if !unchanged {
                        app.peer_names.insert(from, Zeroizing::new(n.to_string()));
                        app.diag.mark("peer_name_known");
                    }
                }
                Wire::Msg { body, ts } => {
                    app.diag.mark("first_msg_rx");
                    let name = app.peer_names.get(&from).map(|s| s.as_str()).unwrap_or("peer");
                    app.store.push(name, &body, ts, false);
                    app.scroll = 0;
                }
                Wire::Ping { id } => {
                    let _ = send_wire(sender, Wire::Pong { id }).await;
                }
                Wire::Pong { id } => app.diag.pong(id),
                Wire::Hb => {}
                Wire::Bye => {
                    app.diag.event("received Bye");
                    if matches!(app.phase, Phase::Connected | Phase::Connecting) {
                        app.phase = Phase::PeerLeft { at: Instant::now(), why: "peer exited".into() };
                    }
                }
            }
        }
        _ => {}
    }
}

// -------------------------------------------------------------------------- UI

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect::new(area.x + (area.width - w) / 2, area.y + (area.height - h) / 2, w, h)
}

fn ui(f: &mut Frame, app: &App) {
    let area = f.area();
    let main = if app.show_diag && app.diag.enabled {
        let cols = Layout::horizontal([Constraint::Min(30), Constraint::Length(44)]).split(area);
        let lines: Vec<Line> = app.diag.panel_lines().into_iter().map(Line::from).collect();
        f.render_widget(
            Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" diagnostics (F2) ")),
            cols[1],
        );
        cols[0]
    } else {
        area
    };

    let [status, msgs, input] =
        Layout::vertical([Constraint::Length(3), Constraint::Min(3), Constraint::Length(3)]).areas(main);

    // ---- status bar (security-relevant state: lock status + erased count)
    let (ptxt, pcol) = match &app.phase {
        Phase::Connecting => ("connecting...", Color::Yellow),
        Phase::Connected => ("connected", Color::Green),
        Phase::PeerLeft { .. } => ("peer left", Color::Red),
        Phase::Failed(_) => ("failed", Color::Red),
    };
    let lock = if app.store.is_locked() { "RAM-locked" } else { "NOT locked" };
    let role = if app.role == Role::Host { "host" } else { "client" };
    let peer = app
        .peer
        .and_then(|id| app.peer_names.get(&id))
        .map(|s| s.as_str())
        .unwrap_or("-");
    let status_line = Line::from(vec![
        Span::styled(" GHOSTTERM ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(format!("| {role} | peer: {peer} | ")),
        Span::styled(ptxt, Style::default().fg(pcol)),
        Span::raw(format!(" | {lock} | erased: {}", app.store.erased_total)),
    ]);
    f.render_widget(Paragraph::new(status_line).block(Block::default().borders(Borders::ALL)), status);

    // ---- messages (strings are borrowed straight from the locked arena)
    // Own messages are right-aligned, the peer's left-aligned.
    let inner_w = msgs.width.saturating_sub(2).max(1) as usize;
    let inner_h = msgs.height.saturating_sub(2) as usize;
    let all: Vec<(Line, usize)> = app
        .store
        .view()
        .map(|(e, name, body)| {
            let t = chrono::DateTime::from_timestamp_millis(e.ts)
                .map(|d| d.with_timezone(&chrono::Local).format("%H:%M:%S").to_string())
                .unwrap_or_default();
            let col = if e.mine { Color::Cyan } else { Color::Magenta };
            let chars = t.len() + name.chars().count() + body.chars().count() + 5;
            let h = chars.div_ceil(inner_w).max(1);
            let align = if e.mine { Alignment::Right } else { Alignment::Left };
            let line = Line::from(vec![
                Span::styled(format!("[{t}] "), Style::default().fg(Color::DarkGray)),
                Span::styled(name, Style::default().fg(col).add_modifier(Modifier::BOLD)),
                Span::raw(": "),
                Span::raw(body),
            ])
            .alignment(align);
            (line, h)
        })
        .collect();
    let mut shown: Vec<Line> = Vec::new();
    let mut used = 0usize;
    for (line, h) in all.into_iter().rev().skip(app.scroll) {
        if used + h > inner_h && !shown.is_empty() {
            break;
        }
        used += h;
        shown.push(line);
    }
    shown.reverse();
    if shown.is_empty() {
        let hint = match app.phase {
            Phase::Connecting if app.role == Role::Host => "Waiting for the peer to join with your ticket...",
            Phase::Connecting => "Connecting to host...",
            _ => "No messages. Everything here is erased when the session ends.",
        };
        shown.push(Line::styled(hint, Style::default().fg(Color::DarkGray)));
    }
    f.render_widget(
        Paragraph::new(shown)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(" messages (Up/Down scroll) ")),
        msgs,
    );

    // ---- input
    let s = app.store.input_str();
    let max = (input.width as usize).saturating_sub(3);
    let n = s.chars().count();
    let tail: &str = if n > max {
        let idx = s.char_indices().nth(n - max).map(|(i, _)| i).unwrap_or(0);
        &s[idx..]
    } else {
        s
    };
    f.render_widget(
        Paragraph::new(tail).block(Block::default().borders(Borders::ALL).title(" Enter send | Esc quit ")),
        input,
    );
    f.set_cursor_position((input.x + 1 + tail.chars().count() as u16, input.y + 1));

    // ---- kick / failure banners
    match &app.phase {
        Phase::PeerLeft { at, why } => {
            let left = KICK_DELAY.saturating_sub(at.elapsed()).as_secs() + 1;
            let r = centered(area, 52, 7);
            f.render_widget(Clear, r);
            let txt = vec![
                Line::styled("YOUR PEER HAS LEFT", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                Line::from(format!("Reason: {why}")),
                Line::from(""),
                Line::from("Session terminated. Wiping memory..."),
                Line::from(format!("Closing in {left} s (Esc to close now)")),
            ];
            f.render_widget(
                Paragraph::new(txt)
                    .alignment(Alignment::Center)
                    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Red))),
                r,
            );
        }
        Phase::Failed(w) => {
            let r = centered(area, 60, 8);
            f.render_widget(Clear, r);
            f.render_widget(
                Paragraph::new(w.as_str())
                    .wrap(Wrap { trim: true })
                    .block(Block::default().borders(Borders::ALL).title(" connection failed ")
                        .border_style(Style::default().fg(Color::Red))),
                r,
            );
        }
        _ => {}
    }
}
