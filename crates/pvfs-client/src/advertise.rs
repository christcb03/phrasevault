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
pub type BoxedSign = Box<dyn Fn(&[u8; 32]) -> Vec<u8>>;

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
            let label = if entry.node.label.is_empty() { id.clone() } else { entry.node.label.clone() };
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
fn catch_up(data_dir: &Path, client: &mut Client) {
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
            if name.ends_with(".manifest") || !f.path().is_file() {
                continue;
            }
            out.push(name);
        }
    }
    Ok(out)
}
