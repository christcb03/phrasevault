//! F5.5 (doc 17 §7.7): advertised holders. After `pvfs sync` lands
//! verified copies in the sync store, `advertise_pass` logs each one as
//! THIS box's `pvfs-host://<pin>/<store path>` location — the deliberate
//! act of becoming a fleet-visible holder (found needed by the D69 media
//! fleet: a NAS held the whole library and nobody could dial it).
//! `retract_pass` is the exit: when a subtree leaves `sync --advertise`
//! placement, the advertisement is retracted FIRST (write-through), and
//! bytes are deleted only when the catalog still records another live
//! location — a dangling advertisement is a lie the fleet would trust.
//!
//! Both passes are shared by the CLI and pvfsd's serve jobs (the P5.3
//! precedent), and both write through the same seam as every replica
//! mutation (F5.0): local engine on the owner, routed member-signed
//! daemon ops on a replica. No new wire ops — no PROTO_VERSION change.

use std::collections::HashSet;
use std::path::Path;

use pvfs_core::engine::Engine;
use pvfs_core::{storage, sync as psync, PvfsError};

use crate::Client;

type Result<T> = std::result::Result<T, PvfsError>;

/// How an advertisement write reaches the log: `None` = local engine (the
/// owner's own forest); `Some` = routed through the replica's source,
/// member-signed (F5.0's write-through client).
pub type Route<'a> = Option<(&'a mut Client, &'a dyn Fn(&[u8; 32]) -> Vec<u8>)>;

/// An owned signing closure (the boxed flavor `replica_route` returns).
// `Send` because the FUSE mount carries a route across threads (D71 W2).
pub type BoxedSign = Box<dyn Fn(&[u8; 32]) -> Vec<u8> + Send>;

#[derive(Debug, Default)]
pub struct AdvertiseReport {
    pub advertised: u64,
    /// `(label-or-id, reason)` — per-file failures never abort the pass.
    pub skipped: Vec<(String, String)>,
}

#[derive(Debug, Default)]
pub struct RetractReport {
    pub retracted: u64,
    pub freed_bytes: u64,
    pub skipped: Vec<(String, String)>,
}

fn remote_err(e: impl std::fmt::Display) -> PvfsError {
    PvfsError::BadInput { field: "advertise".into(), reason: e.to_string() }
}

/// The routed write client for a replica's advertise/retract writes —
/// the same shape as every F5.0 write-through (member-signed, dialed at
/// the replica's recorded source). `None` when this forest is not a
/// replica (the owner writes locally). Shared by the CLI and the daemon's
/// serve jobs so neither reimplements the seam.
pub fn replica_route(
    data_dir: &Path,
    is_replica: bool,
) -> Result<Option<(Client, BoxedSign)>> {
    use pvfs_core::{crypto, identity};
    if !is_replica {
        return Ok(None);
    }
    let src = pvfs_core::ReplicaSource::load(data_dir)?;
    let mn = identity::client_identity_mnemonic()?;
    let key = identity::device_key(&mn, "", 0)?;
    let pubkey = crypto::pubkey_bytes(&key);
    let sign_key = identity::device_key(&mn, "", 0)?;
    let client = match src.transport.as_str() {
        "tcp" => Client::connect_tcp_signed(&src.target, &src.pin, &pubkey, move |d| {
            crypto::sign_digest(&key, d).unwrap_or_default()
        }),
        _ => Client::connect_signed(std::path::Path::new(&src.target), &pubkey, move |d| {
            crypto::sign_digest(&key, d).unwrap_or_default()
        }),
    }
    .map_err(remote_err)?;
    // PVOS D182 — every write through this route carries this replica's own
    // tip, so an owner that is behind it (restored, or replaced by a
    // promotion) fences itself instead of forking the forest. Unreadable
    // here means only that the check is skipped: the write is the same.
    let mut client = client;
    client.set_write_tip(pvfs_core::mount::peek_tip(data_dir).ok());
    // PVOS D196 — an owner that answers but is FENCED (D182: a follower holds
    // more of the log) takes no write, so a route through it is no route: say
    // so, as a dial that failed would. The watch then catalogues here, as it
    // does for an unreachable owner (D183), instead of failing every pass
    // against the refusal — which is what a box `promote.yml` missed would
    // do after a promotion. Asked of `serve status`: the owner's own
    // structured word, not the refusal's text (D158). An owner too old to
    // report a fence, or a status this key may not read, counts as unfenced;
    // its writes still refuse, as before.
    if let Ok(status) = client.serve_status_full() {
        if let Some(f) = status.fenced {
            return Err(PvfsError::Forbidden {
                action: format!("write through the owner at {}", src.target),
                reason: format!("the owner is fenced ({})", f.reason),
            });
        }
    }
    let sign: BoxedSign =
        Box::new(move |d| crypto::sign_digest(&sign_key, d).unwrap_or_default());
    Ok(Some((client, sign)))
}

/// The box's own pin, or the doc 17 §7.7 refusal: an unreachable holder
/// must not advertise.
fn own_pin(data_dir: &Path) -> Result<String> {
    storage::host_pin(data_dir).ok_or_else(|| PvfsError::BadInput {
        field: "advertise".into(),
        reason: "this box has no transport pin yet — run `pvfsd --listen <addr>` once so \
                 other instances can dial these bytes (doc 17 §7.7)"
            .into(),
    })
}

/// Log an own-pin location for every sync-store copy under the subtrees
/// placed `sync --advertise`. Idempotent: an already-logged URI is skipped,
/// so re-runs are catch-up (files fetched before the placement flag, or
/// before a pin existed, gain their advertisement now).
pub fn advertise_pass(data_dir: &Path, mut route: Route<'_>) -> Result<AdvertiseReport> {
    let mut report = AdvertiseReport::default();
    let roots = psync::load_advertise(data_dir)?;
    if roots.is_empty() {
        return Ok(report);
    }
    let pin = own_pin(data_dir)?;
    let mut engine = Engine::open(data_dir)?;
    for root in &roots {
        for entry in engine.walk(root)? {
            let id = entry.node.id.clone();
            // The store is the filter: only fetched-and-verified copies
            // advertise (folders and unfetched files have no store entry).
            let Some(store_path) = psync::sync_store_lookup(data_dir, &id)? else {
                continue;
            };
            let label = if entry.label.is_empty() { id.clone() } else { entry.label.clone() };
            let abs = match std::fs::canonicalize(&store_path) {
                Ok(a) => a,
                Err(e) => {
                    report.skipped.push((label, format!("resolve store path: {e}")));
                    continue;
                }
            };
            let uri = storage::host_uri(&pin, &abs)?;
            let locs = engine.locations(&id)?;
            if locs.iter().any(|l| l == &uri) {
                continue; // already advertised — idempotence
            }
            let wrote = match &mut route {
                None => engine.add_location(&id, &uri).map(|_| ()),
                Some((client, sign)) => client
                    .add_location(&id, &uri, |d| sign(d))
                    .map(|_| ())
                    .map_err(remote_err),
            };
            match wrote {
                Ok(()) => report.advertised += 1,
                Err(e) => report.skipped.push((label, e.to_string())),
            }
        }
    }
    engine.close()?;
    // Read-your-writes (the F5.0 loc-add precedent): fold the routed tail
    // NOW, or the next pass re-advertises everything it just wrote.
    if report.advertised > 0 {
        if let Some((client, _)) = &mut route {
            catch_up(data_dir, client);
        }
    }
    Ok(report)
}

/// Pull + fold the source tail after routed writes — the same shape as the
/// CLI's post-write catch-up: ship rows, sync region generations, and
/// reopen the engine so the projection folds immediately.
pub fn catch_up(data_dir: &Path, client: &mut Client) {
    let _ = (|| -> Result<()> {
        let mut store = pvfs_core::ReplicaStore::open(data_dir)?;
        let mut from = store.tip()? + 1;
        loop {
            let (_tip, events) = client.log_read(from, 256, "").map_err(remote_err)?;
            if events.is_empty() {
                break;
            }
            let rows: Vec<pvfs_core::log_store::EventRow> = events
                .iter()
                .map(|w| -> Result<pvfs_core::log_store::EventRow> {
                    Ok(pvfs_core::log_store::EventRow {
                        seq: w.seq,
                        kind: w.kind.clone(),
                        body: hex_decode(&w.body)?,
                        chain_hash: hex_decode(&w.chain_hash)?,
                        written_at: w.written_at,
                    })
                })
                .collect::<Result<_>>()?;
            from = store.append(&rows)? + 1;
        }
        drop(store);
        let scope = pvfs_core::ReplicaSource::load(data_dir)
            .map(|s| s.region)
            .unwrap_or_default();
        let scope = if scope.is_empty() { None } else { Some(scope) };
        crate::regions::sync_generations(client, data_dir, scope.as_deref())?;
        Engine::open(data_dir)?.close()?;
        Ok(())
    })();
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    hex::decode(s).map_err(|e| PvfsError::BadInput {
        field: "advertise".into(),
        reason: format!("bad hex from source: {e}"),
    })
}

/// Retract-and-reclaim for advertised copies whose subtree is NO LONGER
/// placed `sync --advertise`: retract the own-pin location first (write-
/// through), then delete the store bytes — and only when the catalog still
/// records another live location. Unreachable source, no other location,
/// or a failed retraction all SKIP the file with a reason; bytes are never
/// deleted under a live advertisement.
pub fn retract_pass(data_dir: &Path, mut route: Route<'_>) -> Result<RetractReport> {
    let mut report = RetractReport::default();
    // No pin = this box never advertised anything; nothing to retract.
    let Ok(pin) = own_pin(data_dir) else {
        return Ok(report);
    };
    let own_prefix = format!("pvfs-host://{pin}/");
    let mut engine = Engine::open(data_dir)?;
    // Everything still covered by an advertise placement stays.
    let mut keep: HashSet<String> = HashSet::new();
    for root in psync::load_advertise(data_dir)? {
        for entry in engine.walk(&root)? {
            keep.insert(entry.node.id.clone());
        }
    }
    let mut retracted_any = false;
    for id in store_ids(data_dir)? {
        if keep.contains(&id) {
            continue;
        }
        let Some(store_path) = psync::sync_store_lookup(data_dir, &id)? else {
            continue;
        };
        let abs = match std::fs::canonicalize(&store_path) {
            Ok(a) => a,
            Err(_) => continue,
        };
        let uri = storage::host_uri(&pin, &abs)?;
        // A node this forest no longer knows (or never advertised) is not
        // ours to touch — plain private cache stays for `evict`'s rules.
        let locs = match engine.locations(&id) {
            Ok(l) => l,
            Err(_) => continue,
        };
        if !locs.iter().any(|l| l == &uri) {
            continue;
        }
        // "Another live location" must be a copy that ISN'T us: the
        // synthesized pvfs-sync:/// row is this very store file, and any
        // own-pin row is still our disk — neither justifies deleting.
        let others_live = locs
            .iter()
            .any(|l| !l.starts_with("pvfs-sync:///") && !l.starts_with(&own_prefix));
        if !others_live {
            report
                .skipped
                .push((id.clone(), "no other live location — the advertisement stays".into()));
            continue;
        }
        // Retract FIRST; delete only after the log says we're not a holder.
        let retracted = match &mut route {
            None => engine.remove_location(&id, &uri).map(|_| ()),
            Some((client, sign)) => client
                .remove_location(&id, &uri, |d| sign(d))
                .map(|_| ())
                .map_err(remote_err),
        };
        if let Err(e) = retracted {
            report.skipped.push((id.clone(), format!("retraction failed, bytes kept: {e}")));
            continue;
        }
        let size = std::fs::metadata(&abs).map(|m| m.len()).unwrap_or(0);
        match std::fs::remove_file(&abs) {
            Ok(()) => {
                let _ = std::fs::remove_file(psync::manifest_sidecar_path(&abs));
                report.retracted += 1;
                report.freed_bytes += size;
                retracted_any = true;
            }
            Err(e) => report.skipped.push((id.clone(), format!("delete after retract: {e}"))),
        }
    }
    engine.close()?;
    if retracted_any {
        if let Some((client, _)) = &mut route {
            catch_up(data_dir, client);
        }
    }
    Ok(report)
}

/// Node ids present in the sync store (the two-level `ab/<id>` layout;
/// manifest sidecars skipped).
fn store_ids(data_dir: &Path) -> Result<Vec<String>> {
    let root = psync::sync_store_dir(data_dir)?;
    let mut out = Vec::new();
    let outer = match std::fs::read_dir(&root) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(PvfsError::io("read sync store", e)),
    };
    for shard in outer.flatten() {
        if !shard.path().is_dir() {
            continue;
        }
        for f in std::fs::read_dir(shard.path())
            .map_err(|e| PvfsError::io("read sync store shard", e))?
            .flatten()
        {
            let name = f.file_name().to_string_lossy().to_string();
            if psync::is_sidecar_name(&name) || !f.path().is_file() {
                continue;
            }
            out.push(name);
        }
    }
    Ok(out)
}

/// D141 — how many times a routed write waits out a busy owner before the
/// pass is failed, and the cap on one wait. 100 ms doubling to 4 s, six
/// retries: ~14 s in total, which covers a 30 000-row catalogue snapshot
/// being installed on the other side (the case that stalled feederbox's
/// staging head for 40 minutes on cutover day — PVOS D140 finding 6). The
/// same shape as the hash write's retry in `pvfs_core::fs`.
const ROUTED_WRITE_RETRIES: u32 = 6;
const ROUTED_WRITE_BACKOFF_MAX_MS: u64 = 4_000;

/// Run one routed write, retrying while the owner is merely busy.
///
/// A transient failure used to fail the WHOLE pass on the first `SQLITE_BUSY`;
/// the watcher then came back after 5 s doubling to 300 s — and on an owner
/// re-installing a large snapshot every minute, every retry met the next one.
/// Retrying the single write here costs seconds; failing the pass cost the
/// head. Anything but a busy owner returns at once ([`routed_fault`]).
pub(crate) fn retry_routed<T>(
    mut call: impl FnMut() -> std::result::Result<T, crate::ClientError>,
) -> pvfs_core::Result<T> {
    let mut attempt = 0u32;
    loop {
        match call() {
            Ok(v) => return Ok(v),
            Err(e) => {
                let err = scan_remote_err(e);
                if matches!(err, PvfsError::Busy { .. }) && attempt < ROUTED_WRITE_RETRIES {
                    attempt += 1;
                    let ms = (100u64 << attempt).min(ROUTED_WRITE_BACKOFF_MAX_MS);
                    std::thread::sleep(std::time::Duration::from_millis(ms));
                    continue;
                }
                return Err(err.with_retries(attempt));
            }
        }
    }
}

/// PVOS D200 — what one routed write's failure means to the pass that made
/// it, judged by the error's TYPE: the client's own (`Io`, `Protocol`) or the
/// code the owner sent. Never by words in the message: those lists missed
/// the ordinary network failures (this client's own idle timeout reads
/// `Resource temporarily unavailable` on Linux, an EOF inside a frame `failed
/// to fill whole buffer`), took them for refusals, and retried any refusal
/// that happened to contain a word (D182 worded the fence's around them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoutedFault {
    /// The owner answered `busy` (SQLite busy, or an owner that has just
    /// started and holds network writes, D185): wait, and try this write
    /// again on the same connection (D141).
    Wait,
    /// The connection failed or is out of step (`Io`, `Protocol`), or the
    /// owner hit trouble of its own (`internal`, `io`: its disk, its
    /// database). Not this write's fault, and nothing to retry on this
    /// connection — it may be dead, and after a timeout a late reply would be
    /// read as the answer to the retry. The pass fails; the watch drops the
    /// route and dials again at its next pass.
    Pass,
    /// Any other code: the owner refused THIS write (`bad_input`,
    /// `forbidden` — a fenced owner's refusal included — `not_found`,
    /// `already_exists`, `integrity`, or a code this client does not know).
    /// Permanent: a node-model scan quarantines the file, a head commit fails
    /// its pass (D71 W4).
    Refused,
}

fn routed_fault(e: &crate::ClientError) -> RoutedFault {
    use crate::ClientError;
    match e {
        ClientError::Io(_) | ClientError::Protocol(_) => RoutedFault::Pass,
        ClientError::Server { code, .. } => match code.as_str() {
            "busy" => RoutedFault::Wait,
            "internal" | "io" => RoutedFault::Pass,
            _ => RoutedFault::Refused,
        },
    }
}

/// A routed write's failure as the scan reads it (`pvfs_core`'s
/// `is_transient`): `Busy` to wait out, `Io` to fail the pass, `BadInput`
/// for a refusal — its text as before, `<code>: <message>`, which is what
/// [`crate::watch::commit_pending_heads`] reads "does not advance" from.
fn scan_remote_err(e: crate::ClientError) -> PvfsError {
    match routed_fault(&e) {
        RoutedFault::Wait => PvfsError::Busy { op: "routed scan write".into(), retries: 0 },
        RoutedFault::Pass => PvfsError::Io {
            op: "routed write".into(),
            source: match e {
                crate::ClientError::Io(source) => source,
                other => std::io::Error::other(other.to_string()),
            },
        },
        RoutedFault::Refused => PvfsError::BadInput { field: "scan".into(), reason: e.to_string() },
    }
}

/// A [`ScanWriter`] that sends a replica's scan writes to the owner's daemon
/// (D71 W4).
///
/// The scan writes exactly four things and `Client` already speaks all four,
/// so this needs no new wire op and no `PROTO_VERSION` bump — which is what
/// keeps a binding change a per-box, rolling upgrade rather than a fleet-wide
/// one.
pub struct RoutedScanWriter<'a> {
    client: &'a mut Client,
    sign: &'a dyn Fn(&[u8; 32]) -> Vec<u8>,
    /// This box's transport pin, so the locations it writes say WHOSE disk the
    /// bytes are on.
    pin: Option<String>,
}

impl<'a> RoutedScanWriter<'a> {
    pub fn new(
        data_dir: &Path,
        client: &'a mut Client,
        sign: &'a dyn Fn(&[u8; 32]) -> Vec<u8>,
    ) -> Self {
        Self { client, sign, pin: pvfs_core::storage::host_pin(data_dir) }
    }

    /// A scan finds files by local path, but the row is being written into the
    /// OWNER's catalog — where `file:///mnt/local/...` names a path that does
    /// not exist. Qualify it with this box's pin so the fleet knows who holds
    /// the bytes, exactly as the retired arr hook's `loc add --here` did.
    ///
    /// Caught on the lab by reading the row back: the first version wrote a
    /// bare `file://` and the owner would have tried to `tier` from its own
    /// non-existent path.
    fn own(&self, uri: &str) -> String {
        match (&self.pin, uri.strip_prefix("file://")) {
            (Some(pin), Some(path)) => format!("pvfs-host://{pin}{path}"),
            _ => uri.to_string(),
        }
    }
}

impl pvfs_core::ScanWriter for RoutedScanWriter<'_> {
    fn add_folder(&mut self, parent: &str, label: &str) -> pvfs_core::Result<String> {
        retry_routed(|| self.client.mkdir(parent, label, |d| (self.sign)(d)))
    }

    fn add_file(
        &mut self,
        parent: &str,
        label: &str,
        size: u64,
        mime: &str,
        content_hash: &str,
    ) -> pvfs_core::Result<String> {
        retry_routed(|| {
            self.client.add_file(parent, label, size, mime, content_hash, |d| (self.sign)(d))
        })
    }

    fn set_content_hash(
        &mut self,
        file: &str,
        content_hash: &str,
        size: u64,
    ) -> pvfs_core::Result<String> {
        retry_routed(|| self.client.set_content_hash(file, content_hash, size, |d| (self.sign)(d)))
    }

    fn add_location(&mut self, file: &str, uri: &str) -> pvfs_core::Result<()> {
        let uri = self.own(uri);
        retry_routed(|| self.client.add_location(file, &uri, |d| (self.sign)(d))).map(|_| ())
    }

    fn remove_link(&mut self, link_id: &str) -> pvfs_core::Result<()> {
        // D105 — routed like every other replica write. The wire op already
        // existed (Op::Unlink), so this needs no protocol change.
        retry_routed(|| self.client.unlink(link_id, |d| (self.sign)(d))).map(|_| ())
    }

    fn remove_location(&mut self, file: &str, uri: &str) -> pvfs_core::Result<()> {
        let uri = self.own(uri);
        retry_routed(|| self.client.remove_location(file, &uri, |d| (self.sign)(d))).map(|_| ())
    }

    fn commit_region_head(&mut self, region: &str, seq: u64, hash: &str) -> pvfs_core::Result<()> {
        retry_routed(|| self.client.commit_region_head(region, seq, hash, |d| (self.sign)(d)))
            .map(|_| ())
    }
}

#[cfg(test)]
mod routed_retry_tests {
    //! PVOS D200 — a routed write's failure is judged by its type. These pass
    //! `ClientError` values, which the generic `retry_routed` before D200 also
    //! accepted, so they can be run against it to see which it gets wrong.
    use super::retry_routed;
    use crate::ClientError;
    use pvfs_core::PvfsError;
    use std::io;

    fn server(code: &str, message: &str) -> ClientError {
        ClientError::Server { code: code.into(), message: message.into() }
    }

    /// Transient for the scan (`pvfs_core`'s `is_transient`: everything but a
    /// refusal, a bad input or an identity failure) — the pass fails and the
    /// file is never quarantined for it.
    fn fails_the_pass(e: &PvfsError) -> bool {
        !matches!(e, PvfsError::Forbidden { .. } | PvfsError::BadInput { .. } | PvfsError::Identity { .. })
    }

    #[test]
    fn a_busy_owner_is_waited_out_and_the_count_is_honest() {
        let mut calls = 0u32;
        let r: pvfs_core::Result<u8> = retry_routed(|| {
            calls += 1;
            if calls < 3 { Err(server("busy", "SQLite is busy/locked during fold event (retried 4x)")) } else { Ok(7) }
        });
        assert_eq!(r.unwrap(), 7);
        assert_eq!(calls, 3, "two busy answers, then the write");
    }

    #[test]
    fn an_owner_busy_for_too_long_fails_with_the_retry_count() {
        let mut calls = 0u32;
        let r: pvfs_core::Result<u8> = retry_routed(|| {
            calls += 1;
            Err::<u8, _>(server(
                "busy",
                "the owner has just started and hears its followers' logs before it takes a write",
            ))
        });
        match r {
            Err(PvfsError::Busy { retries, .. }) => assert_eq!(retries, super::ROUTED_WRITE_RETRIES),
            other => panic!("expected Busy, got {other:?}"),
        }
        assert_eq!(calls, super::ROUTED_WRITE_RETRIES + 1);
    }

    /// Every failure of the connection fails the pass at once, whatever its
    /// text says — including the ones no word matched: this client's own idle
    /// timeout (`SO_RCVTIMEO` fails a read with EAGAIN on Linux), an EOF inside
    /// a frame, a host with no route. None is retried on the same connection.
    #[test]
    fn a_connection_failure_fails_the_pass_once_whatever_it_says() {
        let failures: Vec<fn() -> ClientError> = vec![
            || ClientError::Io(io::Error::from_raw_os_error(11)),
            || ClientError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer")),
            || ClientError::Io(io::Error::from_raw_os_error(113)),
            || ClientError::Io(io::Error::new(io::ErrorKind::InvalidData, "received fatal alert: DecryptError")),
            || ClientError::Protocol("expected Committed, got Ls { children: [] }".into()),
            || ClientError::Protocol("connection closed".into()),
        ];
        for make in failures {
            let text = make().to_string();
            let mut calls = 0u32;
            let r: pvfs_core::Result<u8> = retry_routed(|| {
                calls += 1;
                Err::<u8, _>(make())
            });
            let e = r.expect_err("a failed connection is no write");
            assert!(fails_the_pass(&e), "{text}: must fail the pass, not quarantine a file — got {e:?}");
            assert!(!matches!(e, PvfsError::Busy { .. }), "{text}: a dead connection is not a busy owner — got {e:?}");
            assert_eq!(calls, 1, "{text}: nothing is retried on a failed connection");
        }
    }

    /// The owner's own trouble (its disk, its database) is not this write's:
    /// the pass fails, as a local writer's I/O error does (D162's full disk
    /// reached a routed writer as `internal`).
    #[test]
    fn the_owners_own_trouble_fails_the_pass() {
        let mut calls = 0u32;
        let r: pvfs_core::Result<u8> = retry_routed(|| {
            calls += 1;
            Err::<u8, _>(server("internal", "database error during fold event: database or disk is full"))
        });
        let e = r.expect_err("no write");
        assert!(fails_the_pass(&e) && !matches!(e, PvfsError::Busy { .. }), "{e:?}");
        assert!(e.to_string().contains("database or disk is full"), "the owner's words are kept: {e}");
        assert_eq!(calls, 1);
    }

    /// A refusal is never retried, whatever words it happens to contain — the
    /// fence's own, with every word the old list retried on appended.
    #[test]
    fn a_refusal_is_never_retried_whatever_its_words() {
        let fence = pvfs_core::fence::Fence {
            reason: pvfs_core::fence::Fence::evidence_sentence("192.168.1.142:7435", 3480, 3472),
            ..Default::default()
        };
        let words = "busy locked timeout timed out connection broken pipe reset refused unreachable eof closed";
        for (code, message) in [
            ("forbidden", format!("{} ({words})", fence.refusal())),
            ("not_found", format!("node not found: ab12 ({words})")),
            ("a_code_from_a_newer_owner", format!("something new ({words})")),
        ] {
            let mut calls = 0u32;
            let r: pvfs_core::Result<u8> = retry_routed(|| {
                calls += 1;
                Err::<u8, _>(server(code, &message))
            });
            assert!(matches!(r, Err(PvfsError::BadInput { .. })), "{code}: a refusal is permanent — got {r:?}");
            assert_eq!(calls, 1, "{code}: a refusal is not retried");
        }
    }

    /// D183's `commit_pending_heads` reads a settled head from a refusal's
    /// text; the refusal keeps it.
    #[test]
    fn a_refusal_keeps_its_text() {
        let r: pvfs_core::Result<u8> = retry_routed(|| {
            Err::<u8, _>(server("bad_input", "invalid input for region head: head 3 does not advance past 5"))
        });
        match r {
            Err(PvfsError::BadInput { reason, .. }) => {
                assert!(reason.contains("does not advance"), "{reason}");
                assert!(reason.starts_with("bad_input: "), "{reason}");
            }
            other => panic!("expected BadInput, got {other:?}"),
        }
    }
}
