//! Anti-forensic message storage.
//!
//! Design: ALL chat plaintext (received messages, sent messages, the input line)
//! lives in ONE page-aligned arena that is
//!   * locked into physical RAM (mlock / VirtualLock)  -> never paged to swap/pagefile
//!   * excluded from core dumps on Linux (MADV_DONTDUMP)
//!   * explicitly zeroed (volatile writes via `zeroize`) when a message is evicted,
//!     and in full on wipe()/Drop.
//! Messages are stored in fixed-size slots, so there is NO reallocation and
//! therefore no stray, un-zeroed copies left behind by Vec/String growth.
//!
//! The input line is a fixed-capacity buffer inside the same arena (never a `String`),
//! so backspace can never leave `String::pop`-style plaintext fragments on the heap.
//! With `harden_input` (set by `--harden`) every backspace additionally scrubs the
//! whole unused tail of the input slot.
//!
//! Known residual copies (documented, measured in the paper, not hidden):
//!   * iroh/QUIC internal packet buffers (`Bytes`) and kernel socket buffers
//!   * Ratatui's frame buffers + the terminal emulator's own memory
//!     (mitigated at exit by `scrub_terminal` in main.rs)

use std::collections::VecDeque;

use region::{Allocation, LockGuard, Protection};
use zeroize::Zeroize;

pub const SLOT_SIZE: usize = 1088; // 1 (name_len) + 32 (name) + 1024 (body) + slack
pub const SLOTS: usize = 128; // message slots; one extra slot is the input line
pub const MAX_NAME: usize = 32;
pub const MAX_BODY: usize = 1024;

pub struct Entry {
    slot: usize,
    name_len: u8,
    body_len: u16,
    pub ts: i64,
    pub mine: bool,
}

pub struct SecureStore {
    alloc: Allocation,
    _guard: Option<LockGuard>,
    pub lock_error: Option<String>,
    entries: VecDeque<Entry>,
    free: Vec<usize>,
    input_len: usize,
    /// Erasure policy: at most `retain` messages stay in RAM; older ones are zeroed.
    pub retain: usize,
    pub erased_total: u64,
    /// `--harden`: scrub the entire input slot tail on every backspace.
    pub harden_input: bool,
}

/// Truncate to at most `max` bytes without splitting a UTF-8 character.
pub fn trunc(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut i = max;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    &s[..i]
}

impl SecureStore {
    pub fn new(retain: usize) -> Self {
        let total = (SLOTS + 1) * SLOT_SIZE;
        let mut alloc = region::alloc(total, Protection::READ_WRITE)
            .expect("failed to allocate secure arena");
        let ptr = alloc.as_mut_ptr::<u8>();
        let len = alloc.len();

        let (guard, lock_error) = match region::lock(ptr as *const u8, len) {
            Ok(g) => (Some(g), None),
            Err(e) => (None, Some(e.to_string())),
        };

        #[cfg(target_os = "linux")]
        unsafe {
            libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DONTDUMP);
        }

        Self {
            alloc,
            _guard: guard,
            lock_error,
            entries: VecDeque::new(),
            free: (0..SLOTS).rev().collect(),
            input_len: 0,
            retain: retain.clamp(1, SLOTS),
            erased_total: 0,
            harden_input: false,
        }
    }

    pub fn is_locked(&self) -> bool {
        self._guard.is_some()
    }

    fn raw(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.alloc.as_ptr::<u8>(), self.alloc.len()) }
    }

    fn raw_mut(&mut self) -> &mut [u8] {
        let len = self.alloc.len();
        unsafe { std::slice::from_raw_parts_mut(self.alloc.as_mut_ptr::<u8>(), len) }
    }

    // ---------------------------------------------------------------- messages

    fn take_slot(&mut self) -> usize {
        if self.free.is_empty() {
            self.evict_oldest();
        }
        self.free.pop().expect("slot available")
    }

    fn evict_oldest(&mut self) {
        if let Some(e) = self.entries.pop_front() {
            let base = e.slot * SLOT_SIZE;
            self.raw_mut()[base..base + SLOT_SIZE].zeroize();
            self.free.push(e.slot);
            self.erased_total += 1;
        }
    }

    fn enforce_retention(&mut self) {
        while self.entries.len() > self.retain {
            self.evict_oldest();
        }
    }

    /// Store a received message.
    pub fn push(&mut self, name: &str, body: &str, ts: i64, mine: bool) {
        let name = trunc(name, MAX_NAME);
        let body = trunc(body, MAX_BODY);
        let slot = self.take_slot();
        let base = slot * SLOT_SIZE;
        let raw = self.raw_mut();
        raw[base] = name.len() as u8;
        raw[base + 1..base + 1 + name.len()].copy_from_slice(name.as_bytes());
        raw[base + 1 + name.len()..base + 1 + name.len() + body.len()]
            .copy_from_slice(body.as_bytes());
        self.entries.push_back(Entry {
            slot,
            name_len: name.len() as u8,
            body_len: body.len() as u16,
            ts,
            mine,
        });
        self.enforce_retention();
    }

    /// Move the input line into a message slot (no heap copy) and clear the input.
    pub fn commit_input(&mut self, name: &str, ts: i64) -> bool {
        let len = self.input_len;
        if len == 0 {
            return false;
        }
        let name = trunc(name, MAX_NAME);
        let slot = self.take_slot();
        let base = slot * SLOT_SIZE;
        let in_base = SLOTS * SLOT_SIZE;
        let raw = self.raw_mut();
        raw[base] = name.len() as u8;
        raw[base + 1..base + 1 + name.len()].copy_from_slice(name.as_bytes());
        raw.copy_within(in_base..in_base + len, base + 1 + name.len());
        self.entries.push_back(Entry {
            slot,
            name_len: name.len() as u8,
            body_len: len as u16,
            ts,
            mine: true,
        });
        self.input_clear();
        self.enforce_retention();
        true
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Iterate (entry, name, body) as borrowed &str straight out of the arena.
    pub fn view(&self) -> impl Iterator<Item = (&Entry, &str, &str)> {
        let raw = self.raw();
        self.entries.iter().map(move |e| {
            let base = e.slot * SLOT_SIZE;
            let n = e.name_len as usize;
            let l = e.body_len as usize;
            let name = std::str::from_utf8(&raw[base + 1..base + 1 + n]).unwrap_or("");
            let body = std::str::from_utf8(&raw[base + 1 + n..base + 1 + n + l]).unwrap_or("");
            (e, name, body)
        })
    }

    // ------------------------------------------------------------------- input

    pub fn input_str(&self) -> &str {
        let base = SLOTS * SLOT_SIZE;
        std::str::from_utf8(&self.raw()[base..base + self.input_len]).unwrap_or("")
    }

    pub fn input_push(&mut self, c: char) -> bool {
        let mut tmp = [0u8; 4];
        let s = c.encode_utf8(&mut tmp);
        let n = s.len();
        let ok = self.input_len + n <= MAX_BODY;
        if ok {
            let at = SLOTS * SLOT_SIZE + self.input_len;
            self.raw_mut()[at..at + n].copy_from_slice(&tmp[..n]);
            self.input_len += n;
        }
        tmp.zeroize();
        ok
    }

    pub fn input_pop(&mut self) {
        if self.input_len == 0 {
            return;
        }
        let base = SLOTS * SLOT_SIZE;
        let mut start = self.input_len - 1;
        while start > 0 && (self.raw()[base + start] & 0xC0) == 0x80 {
            start -= 1;
        }
        let end = self.input_len;
        self.raw_mut()[base + start..base + end].zeroize();
        self.input_len = start;
        if self.harden_input {
            // Defence in depth: scrub everything after the new end of the line, so no
            // fragment of a deleted character can survive anywhere in the input slot.
            self.raw_mut()[base + start..base + SLOT_SIZE].zeroize();
        }
    }

    pub fn input_clear(&mut self) {
        let base = SLOTS * SLOT_SIZE;
        self.raw_mut()[base..base + SLOT_SIZE].zeroize();
        self.input_len = 0;
    }

    // ------------------------------------------------------------------- erase

    /// Zero the entire arena. Idempotent.
    pub fn wipe(&mut self) {
        self.raw_mut().zeroize();
        self.entries.clear();
        self.free = (0..SLOTS).rev().collect();
        self.input_len = 0;
    }

    /// Read back the whole arena and confirm every byte is zero.
    pub fn verify_zeroed(&self) -> bool {
        self.raw().iter().all(|&b| b == 0)
    }

    /// Write a canary, wipe, verify. Used by diagnostic mode / tests.
    pub fn self_test(&mut self) -> bool {
        self.push("canary", "GHOSTTERM-CANARY-0123456789", 0, false);
        let present = self.raw().windows(8).any(|w| w == b"GHOSTTER");
        self.wipe();
        present && self.verify_zeroed()
    }
}

impl Drop for SecureStore {
    fn drop(&mut self) {
        self.wipe();
    }
}

// ------------------------------------------------------------ process hardening

/// Optional, Linux only (`--harden`): the strongest "coverage" setting.
/// mlockall pins EVERY page of the process (heap copies, Ratatui buffers, iroh).
/// Each step is reported (with the OS error on failure); main.rs logs every line
/// as a diagnostic event.
#[cfg(target_os = "linux")]
pub fn harden_process() -> Vec<String> {
    fn step(name: &str, rc: i32) -> String {
        if rc == 0 {
            format!("{name}: ok")
        } else {
            format!("{name}: FAILED ({})", std::io::Error::last_os_error())
        }
    }

    let mut r = Vec::new();
    unsafe {
        let lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        let rc = libc::setrlimit(libc::RLIMIT_CORE, &lim);
        r.push(step("RLIMIT_CORE=0", rc));

        let rc = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        r.push(step("PR_SET_DUMPABLE=0", rc));

        let rc = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
        r.push(step("mlockall(CURRENT|FUTURE)", rc));
    }
    r
}

#[cfg(not(target_os = "linux"))]
pub fn harden_process() -> Vec<String> {
    vec!["process-wide hardening is Linux-only; arena-level VirtualLock is still active".into()]
}
