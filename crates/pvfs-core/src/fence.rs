//! PVOS D182 — the owner's fence, and the rule that sets it.
//!
//! A follower only ever copies the owner. So a follower whose log is LONGER
//! than the owner's is proof the owner is stale — restored from an older image
//! or copy, or replaced by a promotion elsewhere (doc 28) — and such an owner
//! must write nothing: every event it appends lands at a seq the fleet already
//! holds differently. That is a fork the up-to-date followers refuse, and one
//! a lagging follower (one that never saw the promotion) would happily follow.
//!
//! The fence is that refusal made durable: a small file in the data dir,
//! checked by [`crate::engine::Engine`]'s one append choke point, set by
//! whoever holds the evidence (a routed write carrying a longer tip, or the
//! owner's health job reading a peer's), and cleared only by a person — `pvfs
//! forest fence`. Its PRESENCE is the fence: a file that cannot be read still
//! fences, and says so.
//!
//! **Whose word counts (D182 §3.3a).** The owner cannot check rows it does not
//! hold, so a longer tip is only a claim. It fences only when the claim comes
//! from a key holding admin (`a`) on the forest root — one that could revoke
//! this owner's device outright, so believing it adds no authority. A longer
//! tip from anyone else is refused, not believed (the callers say what that
//! means for them). Proof cannot replace this: a restored owner may have lost
//! only member-authored rows, which another member could forge.
//!
//! The other verdict, [`TipVerdict::Diverged`], is about the PEER, not this
//! box: a follower on another branch is refused and reported, and the owner
//! keeps writing — one bad follower must not stop the forest.

use std::path::{Path, PathBuf};

use crate::error::{PvfsError, Result};

pub const FENCE_FILE: &str = "fenced";
const HEADER: &str = "pvfs-fence 1";

/// How a peer's top-log tip compares with this owner's log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipVerdict {
    /// The same chain, at or behind this owner — a normal (maybe lagging)
    /// follower.
    Consistent,
    /// The peer holds more of the log than this owner: this owner is stale.
    Ahead,
    /// At the peer's tip (≤ this owner's), the chains differ: that peer is on
    /// another branch.
    Diverged,
}

/// The rule (D182 §3.3). `own_hash_at_peer_seq` is this owner's chain hash at
/// the peer's tip seq — `None` when the owner does not hold that seq (only
/// possible when the peer is ahead) or the peer's seq is 0.
pub fn judge(
    own_tip: u64,
    own_hash_at_peer_seq: Option<&[u8]>,
    peer_seq: u64,
    peer_hash: &[u8],
) -> TipVerdict {
    if peer_seq > own_tip {
        return TipVerdict::Ahead;
    }
    if peer_seq == 0 {
        // An empty log (a replica that has fetched nothing) agrees with any.
        return TipVerdict::Consistent;
    }
    match own_hash_at_peer_seq {
        Some(h) if h == peer_hash => TipVerdict::Consistent,
        _ => TipVerdict::Diverged,
    }
}

/// What set the fence, kept so the person who clears it can see why.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Fence {
    /// One plain sentence.
    pub reason: String,
    /// Who holds the longer log: an address, or a key when that is all the
    /// owner knows (a routed write's author).
    pub peer: String,
    pub peer_seq: u64,
    pub peer_hash: String,
    pub own_seq: u64,
    pub own_hash: String,
    pub at_ms: u64,
}

impl Fence {
    /// The evidence as one sentence, for a log line, a notification, a refusal.
    pub fn evidence_sentence(peer: &str, peer_seq: u64, own_seq: u64) -> String {
        format!(
            "{peer} holds the forest's log to seq {peer_seq}, this box only to seq {own_seq} — \
             this box was restored from an older copy, or another box was promoted to owner"
        )
    }

    /// What every refused write says. Worded without the words a routed
    /// writer retries on (`advertise::scan_remote_err`: busy, locked, reset,
    /// refused, closed, …) — a fenced owner must not be hammered.
    pub fn refusal(&self) -> String {
        format!(
            "this owner is fenced: {}. Nothing is written here until a person looks \
             (pvfs forest fence)",
            self.reason
        )
    }

    fn render(&self) -> String {
        // One value per line; the reason is last and kept to one line.
        format!(
            "{HEADER}\nat_ms {}\npeer {}\npeer_seq {}\npeer_hash {}\nown_seq {}\nown_hash {}\nreason {}\n",
            self.at_ms,
            one_line(&self.peer),
            self.peer_seq,
            one_line(&self.peer_hash),
            self.own_seq,
            one_line(&self.own_hash),
            one_line(&self.reason),
        )
    }

    fn parse(text: &str) -> Fence {
        let mut lines = text.lines();
        if lines.next() != Some(HEADER) {
            return unreadable();
        }
        let mut f = Fence::default();
        for line in lines {
            if let Some(v) = line.strip_prefix("at_ms ") {
                f.at_ms = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("peer_seq ") {
                f.peer_seq = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("peer_hash ") {
                f.peer_hash = v.into();
            } else if let Some(v) = line.strip_prefix("peer ") {
                f.peer = v.into();
            } else if let Some(v) = line.strip_prefix("own_seq ") {
                f.own_seq = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("own_hash ") {
                f.own_hash = v.into();
            } else if let Some(v) = line.strip_prefix("reason ") {
                f.reason = v.into();
            }
        }
        if f.reason.is_empty() {
            f.reason = "the fence file gives no reason".into();
        }
        f
    }
}

fn one_line(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

fn unreadable() -> Fence {
    Fence {
        reason: "the fence file is unreadable; it fences all the same".into(),
        ..Fence::default()
    }
}

pub fn fence_path(data_dir: &Path) -> PathBuf {
    data_dir.join(FENCE_FILE)
}

/// Set the fence for an `Ahead` verdict from a `trusted` source (a key with
/// admin on the forest root, §3.3a) — never on a replica (it writes nothing
/// anyway, and a replica's peers are not its evidence). Says so in the journal
/// the first time; an untrusted `Ahead` is logged and changes nothing.
#[allow(clippy::too_many_arguments)]
pub(crate) fn fence_if_ahead(
    data_dir: &Path,
    is_replica: bool,
    verdict: TipVerdict,
    trusted: bool,
    peer: &str,
    peer_seq: u64,
    peer_hash: &[u8],
    own_seq: u64,
    own_hash: &[u8],
) -> Result<()> {
    if verdict != TipVerdict::Ahead || is_replica {
        return Ok(());
    }
    if !trusted {
        eprintln!(
            "pvfs: {peer} claims the log reaches seq {peer_seq} (this owner holds {own_seq}) but \
             holds no admin on the forest root — not believed, not fenced"
        );
        return Ok(());
    }
    let fence = Fence {
        reason: Fence::evidence_sentence(peer, peer_seq, own_seq),
        peer: peer.to_string(),
        peer_seq,
        peer_hash: hex::encode(peer_hash),
        own_seq,
        own_hash: hex::encode(own_hash),
        at_ms: crate::engine::now_ms(),
    };
    if set(data_dir, &fence)? {
        eprintln!("pvfs: FENCED — {}", fence.reason);
    }
    Ok(())
}

/// PVOS D182 — judge a peer's tip against this data dir's log without opening
/// an engine (read-only, safe beside a running daemon — the health job's
/// path), fencing an owner when the peer is ahead and `trusted` (its endpoint
/// was announced by a key with admin on the forest root, §3.3a). Returns the
/// verdict and this log's tip seq.
pub fn check_peer(
    data_dir: &Path,
    peer: &str,
    peer_seq: u64,
    peer_hash: &[u8],
    trusted: bool,
) -> Result<(TipVerdict, u64)> {
    use rusqlite::{Connection, OpenFlags};
    let conn = Connection::open_with_flags(data_dir.join("log.db"), OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(crate::error::map_db("open log read-only"))?;
    let (own_seq, own_hash) = crate::log_store::tip_in(&conn, "main")?;
    let at = if peer_seq > 0 && peer_seq <= own_seq {
        crate::log_store::hash_at_in(&conn, "main", peer_seq)?
    } else {
        None
    };
    let verdict = judge(own_seq, at.as_deref(), peer_seq, peer_hash);
    let is_replica = crate::replica::marker_path(data_dir).exists();
    fence_if_ahead(data_dir, is_replica, verdict, trusted, peer, peer_seq, peer_hash, own_seq, &own_hash)?;
    Ok((verdict, own_seq))
}

/// The fence, if this data dir is fenced. Presence is what counts: a file
/// that cannot be read still fences.
pub fn load(data_dir: &Path) -> Option<Fence> {
    let p = fence_path(data_dir);
    match std::fs::read_to_string(&p) {
        Ok(text) => Some(Fence::parse(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => Some(unreadable()),
    }
}

/// Set the fence — unless one is already set: the FIRST evidence is kept, so
/// what a person reads is what stopped the writes. Written beside and renamed
/// over, so a reader never sees half a file. Returns whether this call set it.
pub fn set(data_dir: &Path, fence: &Fence) -> Result<bool> {
    let p = fence_path(data_dir);
    if p.exists() {
        return Ok(false);
    }
    let tmp = data_dir.join(format!("{FENCE_FILE}.tmp-{}", std::process::id()));
    std::fs::write(&tmp, fence.render()).map_err(|e| PvfsError::io("write fence", e))?;
    std::fs::rename(&tmp, &p).map_err(|e| PvfsError::io("place fence", e))?;
    Ok(true)
}

/// Lift the fence (a person's act). Returns what it said, or `None` when there
/// was none.
pub fn clear(data_dir: &Path) -> Result<Option<Fence>> {
    let old = load(data_dir);
    match std::fs::remove_file(fence_path(data_dir)) {
        Ok(()) => Ok(old),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(PvfsError::io("remove fence", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn judge_follows_the_rule() {
        let h = [7u8; 32];
        let other = [9u8; 32];
        assert_eq!(judge(10, None, 11, &h), TipVerdict::Ahead);
        assert_eq!(judge(10, Some(&h), 10, &h), TipVerdict::Consistent);
        assert_eq!(judge(10, Some(&h), 4, &h), TipVerdict::Consistent);
        assert_eq!(judge(10, Some(&h), 4, &other), TipVerdict::Diverged);
        assert_eq!(judge(10, Some(&h), 10, &other), TipVerdict::Diverged);
        assert_eq!(judge(10, None, 0, &[]), TipVerdict::Consistent);
        // A seq the owner should hold but cannot read is not "consistent".
        assert_eq!(judge(10, None, 5, &h), TipVerdict::Diverged);
    }

    #[test]
    fn set_keeps_the_first_evidence_and_clear_lifts_it() {
        let d = tempfile::tempdir().unwrap();
        assert!(load(d.path()).is_none());
        let first = Fence {
            reason: Fence::evidence_sentence("192.168.1.142:7435", 3480, 3472),
            peer: "192.168.1.142:7435".into(),
            peer_seq: 3480,
            peer_hash: "ab".repeat(32),
            own_seq: 3472,
            own_hash: "cd".repeat(32),
            at_ms: 1_790_000_000_000,
        };
        assert!(set(d.path(), &first).unwrap());
        let second = Fence { reason: "later".into(), ..first.clone() };
        assert!(!set(d.path(), &second).unwrap(), "a set fence keeps its first evidence");
        assert_eq!(load(d.path()).unwrap(), first);
        assert_eq!(clear(d.path()).unwrap(), Some(first));
        assert!(load(d.path()).is_none());
        assert_eq!(clear(d.path()).unwrap(), None);
    }

    #[test]
    fn an_unreadable_fence_still_fences() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(fence_path(d.path()), "garbage").unwrap();
        let f = load(d.path()).expect("present means fenced");
        assert!(f.reason.contains("unreadable"));
    }

    #[test]
    fn the_refusal_avoids_the_words_routed_writers_retry_on() {
        let f = Fence {
            reason: Fence::evidence_sentence("192.168.1.142:7435", 3480, 3472),
            ..Fence::default()
        };
        let text = format!("forbidden: write — {}", f.refusal()).to_ascii_lowercase();
        for word in [
            "busy", "locked", "timeout", "timed out", "connection", "broken pipe", "reset",
            "refused", "unreachable", "eof", "closed",
        ] {
            assert!(!text.contains(word), "refusal contains {word:?}: {text}");
        }
    }
}
