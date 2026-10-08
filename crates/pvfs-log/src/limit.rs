//! Rate limits for records a stranger can cause (PVOS D222b decision 9): a
//! flood of bad handshakes must not become a flood of log lines.
//!
//! Per (event, key) — the key is the peer's address, or the principal when
//! there is none — the first [`PER_MINUTE`] records in a minute go out, the
//! rest are counted, and the next one that goes out carries the count
//! (`suppressed = n`). At most [`MAX_KEYS`] keys are tracked; past that the
//! least recently seen is forgotten.

use std::collections::HashMap;
use std::sync::Mutex;

pub const PER_MINUTE: u32 = 10;
pub const MAX_KEYS: usize = 4096;
const WINDOW_MS: u64 = 60_000;

struct Slot {
    window_start_ms: u64,
    sent: u32,
    dropped: u64,
    last_ms: u64,
}

#[derive(Default)]
pub struct Limiter {
    slots: HashMap<String, Slot>,
}

impl Limiter {
    pub fn new() -> Limiter {
        Limiter::default()
    }

    /// `Some(dropped since the last one that went out)` when this record may
    /// go out, `None` when it is over the limit.
    pub fn check(&mut self, now_ms: u64, event: &str, key: &str) -> Option<u64> {
        let k = format!("{event}\u{0}{key}");
        if !self.slots.contains_key(&k) && self.slots.len() >= MAX_KEYS {
            if let Some(oldest) = self.slots.iter().min_by_key(|(_, s)| s.last_ms).map(|(k, _)| k.clone()) {
                self.slots.remove(&oldest);
            }
        }
        let slot = self.slots.entry(k).or_insert(Slot { window_start_ms: now_ms, sent: 0, dropped: 0, last_ms: now_ms });
        slot.last_ms = now_ms;
        if now_ms.saturating_sub(slot.window_start_ms) >= WINDOW_MS {
            slot.window_start_ms = now_ms;
            slot.sent = 0;
        }
        if slot.sent < PER_MINUTE {
            slot.sent += 1;
            Some(std::mem::take(&mut slot.dropped))
        } else {
            slot.dropped += 1;
            None
        }
    }

    pub fn keys(&self) -> usize {
        self.slots.len()
    }
}

/// The process-wide limiter: `if let Some(n) = limit("pvfs.auth.refused", &addr) { … suppressed = n … }`.
pub fn limit(event: &str, key: &str) -> Option<u64> {
    static L: Mutex<Option<Limiter>> = Mutex::new(None);
    let mut g = L.lock().unwrap_or_else(|p| p.into_inner());
    g.get_or_insert_with(Limiter::new).check(crate::time::now_ms(), event, key)
}
