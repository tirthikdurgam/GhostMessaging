use std::borrow::Cow;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use iroh::NodeAddr;
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};

// Two deliberately separate schemas:
//   * PUBLIC  - `Ticket`: leaves the process out-of-band (bincode + Base64).
//   * INTERNAL - `Frame`/`Wire`: only ever travels inside the encrypted gossip session (JSON).
// Each carries its own version so they can evolve independently.

/// Bump when the `Ticket` layout changes.
pub const TICKET_VERSION: u8 = 1;
/// Bump when `Wire` / `Frame` change in an incompatible way.
pub const WIRE_VERSION: u8 = 1;

/// Gossip frame body. Externally tagged on purpose: serde can then BORROW strings
/// from the receive buffer (no intermediate heap String holding plaintext).
///
/// Identity (`AboutMe`) is separated from chat content (`Msg`): the sender's name is
/// NOT repeated in every message; the receiver maps NodeId -> name.
#[derive(Serialize, Deserialize)]
pub enum Wire<'a> {
    /// Identity announcement. Sent right after connect and then periodically.
    AboutMe {
        #[serde(borrow)]
        name: Cow<'a, str>,
    },
    /// Chat content only.
    Msg {
        #[serde(borrow)]
        body: Cow<'a, str>,
        ts: i64,
    },
    /// Diagnostic RTT probe / echo.
    Ping { id: u64 },
    Pong { id: u64 },
    /// Liveness beacon (every 2 s). Lets us detect crashed / killed peers.
    Hb,
    /// Graceful goodbye: tells the other side to terminate its session.
    Bye,
}

/// Versioned envelope around every gossip payload.
#[derive(Serialize, Deserialize)]
pub struct Frame<'a> {
    pub v: u8,
    #[serde(borrow)]
    pub w: Wire<'a>,
}

#[derive(Serialize, Deserialize)]
pub struct Ticket {
    pub v: u8,
    pub node: NodeAddr,
    pub topic: TopicId,
}

impl Ticket {
    pub fn new(node: NodeAddr, topic: TopicId) -> Self {
        Self { v: TICKET_VERSION, node, topic }
    }

    pub fn encode(&self) -> String {
        let bin = bincode::serialize(self).expect("ticket serialize");
        format!("[Ghost: {}]", B64.encode(bin))
    }

    pub fn decode(s: &str) -> Result<Self> {
        let inner = s
            .trim()
            .strip_prefix("[Ghost:")
            .and_then(|x| x.strip_suffix(']'))
            .ok_or_else(|| anyhow!("ticket must look like [Ghost: ...]"))?
            .trim();
        let bin = B64.decode(inner)?;
        let t: Ticket = bincode::deserialize(&bin)?;
        if t.v != TICKET_VERSION {
            return Err(anyhow!(
                "unsupported ticket version {} (this build understands {})",
                t.v,
                TICKET_VERSION
            ));
        }
        Ok(t)
    }
}
