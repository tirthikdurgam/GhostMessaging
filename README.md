# GhostMessaging

![Version](https://img.shields.io/badge/version-0.2.0-blue.svg?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge)
![Built With](https://img.shields.io/badge/built%20with-Rust-orange?style=for-the-badge)

**GhostMessaging** is a serverless, ephemeral, peer-to-peer messaging terminal designed for secure, low-latency communication and absolute privacy.

Built on the **Iroh** networking stack, GhostMessaging bypasses centralized servers entirely. It utilizes local mesh discovery and gossip protocols to establish direct, end-to-end encrypted tunnels between nodes. The interface is a high-performance TUI (Terminal User Interface) focused on minimalism, distraction-free operation, and provable memory erasure.

---

## Key Features

* **Serverless Architecture:** No central database, no logs, no middleman. Communication happens directly between peers via the Iroh Gossip protocol.
* **Event-Driven Stability:** Built on a streamlined, native event-driven model without artificial background timers or heartbeats, ensuring rock-solid connectivity across complex real-world network routing.
* **Zero-Trace Ephemerality:** Chat history exists strictly in RAM. Once the terminal is closed, memory arenas are cryptographically wiped and verified.
* **Synchronized Poison Pill (`ESC`):** Pressing the Escape key triggers a mutual session teardown, instantly alerting the peer and securely terminating both endpoints.
* **Local & Global Discovery:** Seamlessly connects via LAN (`--lan`) or WAN relay depending on peer availability and network topology.
* **Zen TUI:** A professional, resource-efficient terminal interface built with `Ratatui`, featuring smart scrolling, live diagnostics, and presence monitoring.

---

## Installation & Building from Source

Ensure you have the latest **Rust Toolchain** installed (`rustup update`) and Cargo.

### 1. Clone the Repository
```bash
git clone [https://github.com/tirthikdurgam/GhostMessaging.git](https://github.com/tirthikdurgam/GhostMessaging.git)
cd GhostMessaging

```

### 2. Compile the Release Binary

To ensure a clean, optimized release build from scratch:

```powershell
cargo clean
cargo build --release

```

### 3. Locate the Artifact

The optimized binary will be located at:
`./target/release/GhostMessaging.exe` (on Windows).

---

## Usage

### 1. Start a Session (Host)

To initialize a new secure channel on the local network/mesh:

```powershell
cargo run --release -- --lan host --name "YourName"

```

* This will generate a **Ghost Ticket**.
* Press **ENTER** to open the secure dashboard and wait for the peer.
* Share the ticket string out-of-band with your peer.

### 2. Join a Session (Client)

To connect to an existing mesh using the ticket provided by the host:

```powershell
cargo run --release -- --lan join --ticket "[Ghost: ...]" --name "YourName"

```

* **--ticket**: Paste the full ticket string provided by the host.
* The application will auto-negotiate NAT traversal and establish the encrypted P2P tunnel.

---

## Architecture

GhostMessaging is composed of three core layers:

1. **The Network Layer (Iroh):** Handles peer discovery, NAT hole-punching, and the ALPN handshake via `iroh-gossip`.
2. **The Security Layer (Zeroizing):** Ensures all sensitive message bodies and identities are aggressively wiped from memory upon exit.
3. **The Presentation Layer (Ratatui):** Renders the double-buffered TUI, handling asynchronous keyboard inputs and network event streams concurrently via `tokio::select!`.

---

*GhostMessaging is a research-grade tool for secure, decentralized communication. Use responsibly.*
