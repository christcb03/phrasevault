//! D145 — a drain asks before it discards. `resolve` lets a staging copy go
//! only when a library copy of the same bytes is confirmed now; for a library
//! region on another box this is the check: some other announced box serves
//! the last chunk of those bytes by content hash, and it matches ours. The
//! owner holds no bytes and answers `not_found`; a box whose file was deleted
//! or changed since its last scan cannot serve the range, or serves other
//! bytes. Every failure is a "no" — the copy stays and the next pass asks
//! again.

use pvfs_core::{DrainCheck, ReplicaSource};

/// Whether a box in `sources` (the caller leaves this box out) holds the
/// bytes `check` describes, judged by their last chunk read back over the
/// wire.
pub fn confirm_held(sources: &[ReplicaSource], check: &DrainCheck) -> bool {
    sources.iter().any(|src| {
        let Ok(mut client) = crate::follow::dial_source(src) else {
            return false;
        };
        let mut buf: Vec<u8> = Vec::with_capacity(check.tail_len as usize);
        match client.cat_hash_range(&check.hash, check.tail_offset, check.tail_len, &mut buf) {
            Ok(n) => {
                n == check.tail_len
                    && buf.len() as u64 == check.tail_len
                    && *blake3::hash(&buf).as_bytes() == check.tail_hash
            }
            Err(_) => false,
        }
    })
}
