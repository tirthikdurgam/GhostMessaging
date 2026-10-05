//! Optional ticket-hiding wrapper (`ghostterm host --hide-ticket`).
//!
//! This is ONLY an encoding layer around the normal `[Ghost: ...]` ticket: the ticket
//! text is turned into invisible zero-width characters appended to an innocent-looking
//! cover sentence. It is obscurity, NOT security - do not rely on it for protection.
//!
//! Caveat: some chat apps / editors strip zero-width characters when you paste or send
//! text. If the peer's `join` fails with a decode error, send the plain ticket instead.

const ZERO: char = '\u{200B}'; // zero-width space      -> bit 0
const ONE: char = '\u{200C}'; // zero-width non-joiner -> bit 1

const COVERS: [&str; 4] = [
    "see you at the usual place later",
    "here is that link we talked about",
    "dinner on friday still works for me",
    "sending the notes from earlier",
];

/// Hide a ticket string inside a harmless cover sentence.
pub fn hide(ticket: &str) -> String {
    let cover = COVERS[rand::random::<usize>() % COVERS.len()];
    let mut out = String::from(cover);
    for b in ticket.bytes() {
        for i in (0..8).rev() {
            out.push(if (b >> i) & 1 == 1 { ONE } else { ZERO });
        }
    }
    out
}

/// Recover a hidden ticket. Returns `None` if the text contains no hidden payload
/// (e.g. it is already a plain ticket), so callers can fall back to the raw input.
pub fn reveal(s: &str) -> Option<String> {
    let bits: Vec<u8> = s
        .chars()
        .filter_map(|c| match c {
            ZERO => Some(0u8),
            ONE => Some(1u8),
            _ => None,
        })
        .collect();
    if bits.is_empty() || bits.len() % 8 != 0 {
        return None;
    }
    let bytes: Vec<u8> = bits
        .chunks(8)
        .map(|c| c.iter().fold(0u8, |acc, b| (acc << 1) | b))
        .collect();
    String::from_utf8(bytes).ok()
}
