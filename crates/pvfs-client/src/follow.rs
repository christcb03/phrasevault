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

/// Reconnect/backoff delay between failed sessions.
const RETRY: Duration = Duration::from_secs(2);
/// How finely a sleep checks the stop flag.
const STOP_SLICE: Duration = Duration::from_millis(250);

/// Progress callbacks: stderr lines in the CLI, status-row updates in pvfsd.
pub enum FollowEvent<'a> {
    /// A session connected to the source.
    Connected { target: &'a str },
    /// New events ingested and folded; the store is at `tip`.
    CaughtUp { tip: u64 },
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
    let dial_err = |e: crate::ClientError| PvfsError::BadInput {
        field: "follow".into(),
        reason: e.to_string(),
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
pub fn run(
    data_dir: &Path,
    poll_ms: u64,
    stop: &AtomicBool,
    mut notify: impl FnMut(FollowEvent),
) -> Result<(), PvfsError> {
    let dial = ReplicaSource::load(data_dir)?;
    while !stop.load(Ordering::SeqCst) {
        let mut client = match dial_source(&dial) {
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
                stop_sleep(RETRY, stop);
                continue;
            }
        };
        while !stop.load(Ordering::SeqCst) {
            // transient lock contention (a local command folding concurrently)
            // must not kill the follower
            let from = match ReplicaStore::open(data_dir).and_then(|s| s.tip()) {
                Ok(t) => t + 1,
                Err(e) => {
                    notify(FollowEvent::Retrying {
                        reason: format!("store busy ({e})"),
                    });
                    break; // back off + retry
                }
            };
            let (_tip, events) = match client.log_wait(from, 512, poll_ms, "") {
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
                    Ok(0) => {}
                    Ok(_) => {
                        let _ = Engine::open(data_dir).and_then(|e| e.close());
                        let tip = ReplicaStore::open(data_dir)
                            .and_then(|s| s.tip())
                            .unwrap_or(0);
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
            let tip = match ReplicaStore::open(data_dir).and_then(|mut s| s.append(&rows)) {
                Ok(t) => t,
                Err(e) => {
                    notify(FollowEvent::Retrying {
                        reason: format!("ingest failed ({e})"),
                    });
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
            // fold now (best-effort), so local reads and any serving daemon
            // see it; the next open folds anyway
            let _ = Engine::open(data_dir).and_then(|e| e.close());
            notify(FollowEvent::CaughtUp { tip });
        }
        stop_sleep(RETRY, stop);
    }
    Ok(())
}
