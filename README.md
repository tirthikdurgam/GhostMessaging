# GhostTerm

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge)
![Built With](https://img.shields.io/badge/built%20with-Rust-orange?style=for-the-badge)

**GhostTerm** is a serverless, ephemeral, peer-to-peer messaging terminal designed for secure, low-latency communication.

Built on the **Iroh** networking stack, GhostTerm bypasses centralized servers entirely. It utilizes local mesh discovery (mDNS) and gossip protocols to establish direct, end-to-end encrypted tunnels between nodes. The interface is a high-performance TUI (Terminal User Interface) focused on minimalism and distraction-free operation.

---

## Key Features

* **Serverless Architecture:** No central database, no logs, no middleman. Communication happens directly between peers via the Iroh Gossip protocol.
* **Zero-Trace Ephemerality:** Chat history exists only in RAM. Once the terminal is closed, the conversation is cryptographically erased.
* **Steganographic Invites:** Connection tickets are compressed using binary serialization (`bincode`) and wrapped in a stealth format to prevent automated scraping.
* **Local & Global Discovery:** Seamlessly connects via LAN (Local Network) or WAN (Relay) depending on peer availability.
* **Zen TUI:** A professional, resource-efficient terminal interface built with `Ratatui`, featuring smart-scrolling, presence monitoring, and timestamps.

---

## Installation

GhostTerm is distributed as a standalone portable executable. No installation or runtime dependencies (like Python or Node.js) are required.

1.  Navigate to the **[Releases](../../releases)** page.
2.  Download the latest `GhostTerm_v1.zip`.
3.  Extract the archive and run `ghostterm.exe` via your terminal.

---

## Usage

### 1. Start a Session (Host)
To initialize a new secure channel:

```powershell
ghostterm host --name "YourName"

```

* This will generate a **Ghost Ticket**.
* Share this ticket securely with your peer.
* Press **ENTER** to initialize the secure dashboard.

### 2. Join a Session (Client)

To connect to an existing mesh:

```powershell
ghostterm join --ticket "[Ghost: ... ]" --name "YourName"

```

* **--ticket**: Paste the full ticket string provided by the host.
* The application will auto-negotiate the NAT traversal and handshake.

---

## Building from Source

If you wish to modify the protocol or compile for a different architecture (e.g., Linux/macOS), ensure you have the latest **Rust Toolchain** installed.

### Prerequisites

* Rust 1.75+ (`rustup update`)
* Cargo

### Build Steps

1. **Clone the repository**
```bash
git clone [https://github.com/YOUR_USERNAME/GhostTerm.git](https://github.com/YOUR_USERNAME/GhostTerm.git)
cd GhostTerm

```


2. **Compile the Release Binary**
```bash
cargo build --release

```


3. **Locate the Artifact**
The optimized binary will be located at:
`./target/release/ghostterm` (or `ghostterm.exe` on Windows).

*(Note: Windows builds automatically embed the custom application icon via `build.rs`.)*

---

## Architecture

GhostTerm is composed of three core layers:

1. **The Network Layer (Iroh):** Handles peer discovery, NAT hole-punching, and the ALPN (Application-Layer Protocol Negotiation) handshake.
2. **The Data Layer (Bincode/Base64):** Serializes invite tickets into compact binary formats to minimize transmission overhead.
3. **The Presentation Layer (Ratatui):** Renders the double-buffered TUI, handling async events for keyboard input and network packets concurrently via `tokio::select!`.

---

*GhostTerm is a proof-of-concept for secure, decentralized communication. Use responsibly.*

```
