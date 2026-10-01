//! F5.4's follower loop, shared (P5.1, doc 18 §5): one implementation drives
//! both `pvfs replica follow` (ad-hoc, stderr progress) and the pvfsd
//! `follow` job (continuous, status rows). Long-poll the source's tail,
//! chain-verify + ingest, fold — reconnect with backoff, tolerate a busy
//! store (a local command folding concurrently), and stop promptly when told.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use pvfs_core::log_store::EventRow;
use pvfs_core::{crypto, identity, Engine, PvfsError, ReplicaSource, ReplicaStore};

use crate::Client;

/// How many events the CLI's follower asks for at a time.
const BATCH: u32 = 512;

/// PVOS D199 — how many the daemon's follower asks for at a time: each batch
/// is one ingest step and one fold step of the daemon's writer, so a long
/// backlog after an outage lands in short holds (a fold costs per event).
pub const SHARED_BATCH: u32 = 128;

/// Reconnect/backoff delay between failed sessions: 2 s doubling to 30 s
/// (PVOS D196). It was a flat 2 s, so a follower pointed at a fenced or
/// behind owner, or at another branch, dialled 1,800 times an hour (D182).
/// 30 s keeps a reconnect after an owner restart within half a minute.
const RETRY_MIN: Duration = Duration::from_secs(2);
const RETRY_MAX: Duration = Duration::from_secs(30);

/// PVOS D196 — the follower's retry delay. Contact that proves the session —
/// a batch landed, or an empty long-poll that found us current — puts it back
/// to the minimum; a connect alone does not (D159: a socket is not a
/// session, the next request can still fail).
#[derive(Debug)]
struct Backoff(Duration);

impl Backoff {
    fn new() -> Self {
        Backoff(RETRY_MIN)
    }

    /// The wait after a failure; the one after it doubles, up to `RETRY_MAX`.
    fn next(&mut self) -> Duration {
        let d = self.0;
        self.0 = (self.0 * 2).min(RETRY_MAX);
        d
    }

    fn reset(&mut self) {
        self.0 = RETRY_MIN;
    }
}
/// How finely a sleep checks the stop flag.
const STOP_SLICE: Duration = Duration::from_millis(250);

/// Progress callbacks: stderr lines in the CLI, status-row updates in pvfsd.
pub enum FollowEvent<'a> {
    /// A session connected to the source.
    Connected { target: &'a str },
    /// New events ingested and folded; the store is at `tip`.
    CaughtUp { tip: u64 },
    /// D146 — connected and current: a long-poll came back empty with the
    /// source's tip at ours (`tip`; a source BEHIND ours is an error since
    /// PVOS D182 — a stale or replaced owner). `CaughtUp` only fires when
    /// events land, so on a quiet log this is the follower's only proof of
    /// health — without it the status row froze at the last event and the
    /// stall detector called a caught-up follower "overdue" forever.
    UpToDate { tip: u64 },
    /// A transient failure; the loop retries after backoff.
    Retrying { reason: String },
}

/// Dial a replica source signed with this box's **client identity** — the
/// network principal (doc 18 §4; forest device keys never dial).
pub fn dial_source(src: &ReplicaSource) -> Result<Client, PvfsError> {
    let mn = identity::client_identity_mnemonic()?;
    let key = identity::device_key(&mn, "", 0)?;
    let pubkey = crypto::pubkey_bytes(&key);
    let sign = |d: &[u8; 32]| crypto::sign_digest(&key, d).unwrap_or_default();
    // D146 — say what failed: a dial that cannot connect is an I/O error
    // naming the target, not "invalid input for follow" (which the health
    // probe and `receive` both borrowed, since they dial through here too).
    let dial_err = |e: crate::ClientError| match e {
        crate::ClientError::Io(source) => PvfsError::Io {
            op: format!("dial {}", src.target),
            source,
        },
        crate::ClientError::Server { code, message } if code == "forbidden" => PvfsError::Forbidden {
            action: format!("dial {}", src.target),
            reason: message,
        },
        other => PvfsError::BadInput {
            field: format!("dial {}", src.target),
            reason: other.to_string(),
        },
    };
    match src.transport.as_str() {
        "tcp" => Client::connect_tcp_signed(&src.target, &src.pin, &pubkey, sign).map_err(dial_err),
        _ => Client::connect_signed(Path::new(&src.target), &pubkey, sign).map_err(dial_err),
    }
}

pub(crate) fn wire_rows(events: &[pvfs_proto::LogEventWire]) -> Result<Vec<EventRow>, PvfsError> {
    events
        .iter()
        .map(|w| {
            let not_hex = |what: &str| PvfsError::BadInput {
                field: "replica".into(),
                reason: format!("shipped {what} not hex"),
            };
            Ok(EventRow {
                seq: w.seq,
                kind: w.kind.clone(),
                body: hex::decode(&w.body).map_err(|_| not_hex("event body"))?,
                chain_hash: hex::decode(&w.chain_hash).map_err(|_| not_hex("chain hash"))?,
                written_at: w.written_at,
            })
        })
        .collect()
}

/// Sleep `total`, waking early if `stop` is set.
fn stop_sleep(total: Duration, stop: &AtomicBool) {
    let deadline = std::time::Instant::now() + total;
    while std::time::Instant::now() < deadline && !stop.load(Ordering::SeqCst) {
        std::thread::sleep(STOP_SLICE);
    }
}

/// Run the follower until `stop` is set (Ok) or setup is impossible (Err —
/// not a replica, no client identity). `poll_ms` is the per-request long-poll
/// window: the CLI uses a long one; the daemon job a short one so disable/
/// shutdown are honored promptly.
///
/// This follower ingests on a connection of its own and folds by opening an
/// engine (the CLI's `pvfs replica follow`); the daemon's follow job runs
/// [`run_shared`] (PVOS D199).
pub fn run(
    data_dir: &Path,
    poll_ms: u64,
    stop: &AtomicBool,
    notify: impl FnMut(FollowEvent),
) -> Result<(), PvfsError> {
    let dial = ReplicaSource::load(data_dir)?;
    follow(data_dir, &dial, poll_ms, BATCH, stop, notify, &mut OwnStore { data_dir })
}

/// PVOS D199 — the daemon's follower, on its one writer: each batch the
/// source ships (≤512 events) is one ingest step and one fold step, and the
/// long-poll holds nothing. It used to ingest on a `ReplicaStore` connection
/// of its own — whose `BEGIN IMMEDIATE` took `index.db`'s write lock too, so
/// a catalogue install on the NAS made it fail — and to open (and fold, and
/// close) an engine per batch. The tip is read on a view of its own.
pub fn run_shared(
    writer: std::sync::Arc<pvfs_core::Writer>,
    poll_ms: u64,
    stop: &AtomicBool,
    notify: impl FnMut(FollowEvent),
) -> Result<(), PvfsError> {
    let data_dir = writer.data_dir().to_path_buf();
    let dial = ReplicaSource::load(&data_dir)?;
    let view = writer.read_view()?;
    let mut store = SharedStore { writer, view, fold_due: false, said: None };
    follow(&data_dir, &dial, poll_ms, SHARED_BATCH, stop, notify, &mut store)
}

/// Where a follower lands what it is shipped, and how it folds it.
trait Ingest {
    /// The local log's tip.
    fn tip(&mut self) -> Result<u64, PvfsError>;
    /// Append shipped rows (chain-verified); the new tip.
    fn append(&mut self, rows: &[EventRow]) -> Result<u64, PvfsError>;
    /// Fold what was appended, so local reads and a serving daemon see it
    /// (best-effort: what cannot be folded now is folded later).
    fn fold(&mut self);
    /// Called on every quiet tick: a fold that could not run earlier runs now.
    fn settle(&mut self) {}
}

/// A store of the follower's own (the CLI): a `ReplicaStore` per request and
/// an engine opened to fold.
struct OwnStore<'a> {
    data_dir: &'a Path,
}

impl Ingest for OwnStore<'_> {
    fn tip(&mut self) -> Result<u64, PvfsError> {
        ReplicaStore::open(self.data_dir).and_then(|s| s.tip())
    }

    fn append(&mut self, rows: &[EventRow]) -> Result<u64, PvfsError> {
        ReplicaStore::open(self.data_dir).and_then(|mut s| s.append(rows))
    }

    fn fold(&mut self) {
        // fold now (best-effort), so local reads and any serving daemon see
        // it; the next open folds anyway
        let _ = Engine::open(self.data_dir).and_then(|e| e.close());
    }
}

/// PVOS D199 — the daemon's writer: an ingest step and a fold step per batch.
struct SharedStore {
    writer: std::sync::Arc<pvfs_core::Writer>,
    view: Engine,
    /// A fold that could not run (another process held the fold lock):
    /// every tick tries it again until it does.
    fold_due: bool,
    /// The last fold failure said, so a lasting one is said once.
    said: Option<String>,
}

impl Ingest for SharedStore {
    fn tip(&mut self) -> Result<u64, PvfsError> {
        self.view.log_tip()
    }

    fn append(&mut self, rows: &[EventRow]) -> Result<u64, PvfsError> {
        let tip = self.writer.step("follow: ingest", |e| e.ingest_log_rows(rows))?;
        self.fold_due = true;
        Ok(tip)
    }

    fn fold(&mut self) {
        match self.writer.step("follow: fold", |e| e.catch_up()) {
            Ok(_) => {
                self.fold_due = false;
                self.said = None;
            }
            Err(e) => {
                let e = e.to_string();
                if self.said.as_deref() != Some(e.as_str()) {
                    eprintln!("pvfsd: follow: the fold waits ({e}); the next tick tries again");
                    self.said = Some(e);
                }
            }
        }
    }

    fn settle(&mut self) {
        if self.fold_due {
            self.fold();
        }
    }
}

/// The follower's loop, whatever it lands in (PVOS D199 shares it between
/// [`run`] and [`run_shared`]).
fn follow(
    data_dir: &Path,
    dial: &ReplicaSource,
    poll_ms: u64,
    batch: u32,
    stop: &AtomicBool,
    mut notify: impl FnMut(FollowEvent),
    store: &mut dyn Ingest,
) -> Result<(), PvfsError> {
    let mut backoff = Backoff::new();
    while !stop.load(Ordering::SeqCst) {
        let mut client = match dial_source(dial) {
            Ok(c) => {
                notify(FollowEvent::Connected {
                    target: &dial.target,
                });
                c
            }
            Err(e) => {
                notify(FollowEvent::Retrying {
                    reason: e.to_string(),
                });
                stop_sleep(backoff.next(), stop);
                continue;
            }
        };
        while !stop.load(Ordering::SeqCst) {
            // transient lock contention (a local command folding concurrently)
            // must not kill the follower
            let from = match store.tip() {
                Ok(t) => t + 1,
                Err(e) => {
                    notify(FollowEvent::Retrying {
                        reason: format!("store busy ({e})"),
                    });
                    break; // back off + retry
                }
            };
            let (source_tip, events) = match client.log_wait(from, batch, poll_ms, "") {
                Ok(r) => r,
                Err(e) => {
                    notify(FollowEvent::Retrying {
                        reason: format!("connection lost ({e})"),
                    });
                    break; // reconnect
                }
            };
            if events.is_empty() {
                // Timeout tick — or a region-commit wake (P7.2b, doc 20 §2.4):
                // the source's top log is quiet but a region log may have
                // advanced. Sweep the generations; fold only if rows landed.
                let scope = (!dial.region.is_empty()).then_some(dial.region.as_str());
                match crate::regions::sync_generations(&mut client, data_dir, scope) {
                    // D146 — nothing new and the source is not ahead of us:
                    // current. Said on every quiet tick (the poll window), so
                    // "last ok" means "last confirmed current with the source".
                    // PVOS D182 — but only when the source is AT our tip. A
                    // source BEHIND this replica is not its owner as it was:
                    // it was restored from an older copy, or another box was
                    // promoted and this one is its ghost. That used to read as
                    // healthy; it is an error, so the fleet sees it.
                    Ok(0) if source_tip + 1 == from => {
                        store.settle();
                        backoff.reset();
                        notify(FollowEvent::UpToDate { tip: from - 1 })
                    }
                    Ok(0) if source_tip + 1 < from => {
                        notify(FollowEvent::Retrying {
                            reason: format!(
                                "the source ({}) is behind this replica: its log ends at seq {source_tip}, \
                                 this box holds {} — a stale or restored owner, or one another box has \
                                 replaced; nothing is taken from it",
                                dial.target,
                                from - 1
                            ),
                        });
                        break;
                    }
                    Ok(0) => store.settle(),
                    Ok(_) => {
                        store.fold();
                        let tip = store.tip().unwrap_or(0);
                        backoff.reset();
                        notify(FollowEvent::CaughtUp { tip });
                    }
                    Err(e) => {
                        notify(FollowEvent::Retrying {
                            reason: format!("region sweep failed ({e})"),
                        });
                        break;
                    }
                }
                continue;
            }
            let rows = match wire_rows(&events) {
                Ok(r) => r,
                Err(e) => {
                    notify(FollowEvent::Retrying {
                        reason: e.to_string(),
                    });
                    break;
                }
            };
            let tip = match store.append(&rows) {
                Ok(t) => t,
                // PVOS D182 — say what a broken chain means: the source is not
                // the writer this replica has been following.
                Err(e) => {
                    let reason = match &e {
                        PvfsError::LogChainBroken { seq, .. } => format!(
                            "the source ({})'s log differs from this replica's at seq {seq} — it is not \
                             the writer this box has been following (restored from the wrong copy, or \
                             replaced by a promotion), or this box followed one that was not; nothing \
                             is taken from it ({e})",
                            dial.target
                        ),
                        _ => format!("ingest failed ({e})"),
                    };
                    notify(FollowEvent::Retrying { reason });
                    break; // the next pass re-fetches from the real tip
                }
            };
            // New top rows may name new regions (a mark just arrived) —
            // sweep before folding so the fold sees complete logs.
            let scope = (!dial.region.is_empty()).then_some(dial.region.as_str());
            if let Err(e) = crate::regions::sync_generations(&mut client, data_dir, scope) {
                notify(FollowEvent::Retrying {
                    reason: format!("region sweep failed ({e})"),
                });
                break;
            }
            store.fold();
            backoff.reset();
            notify(FollowEvent::CaughtUp { tip });
        }
        stop_sleep(backoff.next(), stop);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PVOS D196 — 2 s doubling to 30 s, and back to 2 s after contact.
    #[test]
    fn the_retry_backs_off_to_thirty_seconds_and_contact_resets_it() {
        let mut b = Backoff::new();
        let waits: Vec<u64> = (0..7).map(|_| b.next().as_secs()).collect();
        assert_eq!(waits, vec![2, 4, 8, 16, 30, 30, 30]);
        b.reset();
        assert_eq!(b.next().as_secs(), 2);
        assert_eq!(b.next().as_secs(), 4);
    }
}
