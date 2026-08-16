//! F3 — placement policy & the sync store (doc 17 §6): the pointer-vs-sync
//! knob. A subtree placed `sync` gets its file bytes **pulled local**; the
//! bytes land in a managed, node-id-addressed store under the data dir
//! (`<data_dir>/synced/<id[..2]>/<id>`), verified against the node's content
//! hash while they stream in.
//!
//! Deliberately **no catalog writes and no projection state**: the store's
//! filesystem layout *is* the record — the read path synthesizes a
//! `pvfs-sync:///<id>` location whenever the store holds the file, so synced
//! bytes survive projection rebuilds by construction and the whole mechanism
//! works on read-only replicas (which is where it matters: an owned forest
//! already holds its bytes). Placement policy is likewise a plain deployment
//! file (`<data_dir>/placement`), like bindings and the replica marker —
//! never log events, because two replicas legitimately pin different
//! subtrees (doc 17 §6).

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::engine::{bad, fetch_node, Engine};
use crate::error::{IntegrityReason, PvfsError, Result};
use crate::link::LINK_CONTAINS;
use crate::node::{FilePayload, NodeId, TYPE_FILE};

/// Scheme of a synthesized managed-store location.
pub const SYNC_URI_PREFIX: &str = "pvfs-sync:///";
const SYNC_DIR: &str = "synced";
const PLACEMENT_FILE: &str = "placement";
const PLACEMENT_HEADER: &str = "pvfs-placement 1";

const STORE_FILE: &str = "sync.store";
const STORE_HEADER: &str = "pvfs-sync-store 1";

fn shard_of(id: &str) -> &str {
    if id.len() >= 2 {
        &id[..2]
    } else {
        "xx"
    }
}

/// The default (in-data-dir) store location for a file.
fn default_store_path(data_dir: &Path, id: &str) -> PathBuf {
    data_dir.join(SYNC_DIR).join(shard_of(id)).join(id)
}

pub fn store_config_path(data_dir: &Path) -> PathBuf {
    data_dir.join(STORE_FILE)
}

/// The configured sync-store root, if any (P6.1, doc 19 §3): `pvfs sync
/// --to <dir>` records it — deployment state, never log events. A corrupt
/// file refuses loudly rather than silently landing bytes elsewhere.
pub fn sync_store_root(data_dir: &Path) -> Result<Option<PathBuf>> {
    let text = match std::fs::read_to_string(store_config_path(data_dir)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(PvfsError::io("read sync.store", e)),
    };
    let mut lines = text.lines();
    if lines.next() != Some(STORE_HEADER) {
        return Err(bad("sync", "unrecognized sync.store file"));
    }
    match lines.map(str::trim).find(|l| !l.is_empty()) {
        Some(dir) => Ok(Some(PathBuf::from(dir))),
        None => Err(bad("sync", "sync.store names no directory")),
    }
}

/// Set (Some) or clear (None) the store root.
pub fn set_sync_store_root(data_dir: &Path, root: Option<&Path>) -> Result<()> {
    match root {
        Some(r) => crate::storage::atomic_overwrite(
            &store_config_path(data_dir),
            format!("{STORE_HEADER}\n{}\n", r.display()).as_bytes(),
        ),
        None => match std::fs::remove_file(store_config_path(data_dir)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(PvfsError::io("clear sync.store", e)),
        },
    }
}

/// Where a **new** fetch lands: the configured root when set, else the
/// default store under the data dir.
pub fn sync_store_path(data_dir: &Path, id: &str) -> Result<PathBuf> {
    Ok(match sync_store_root(data_dir)? {
        Some(root) => root.join(shard_of(id)).join(id),
        None => default_store_path(data_dir, id),
    })
}

/// The store's base directory (P10.0 space preflight, doc 23 §8.3): the
/// configured root when set, else the default in-data-dir store.
pub fn sync_store_dir(data_dir: &Path) -> Result<PathBuf> {
    Ok(match sync_store_root(data_dir)? {
        Some(root) => root,
        None => data_dir.join(SYNC_DIR),
    })
}

/// Where an **existing** synced file is, if anywhere: the configured root
/// first, then the default store — files fetched before a `--to` move keep
/// serving with no migration pass (doc 19 §3).
pub fn sync_store_lookup(data_dir: &Path, id: &str) -> Result<Option<PathBuf>> {
    if let Some(root) = sync_store_root(data_dir)? {
        let p = root.join(shard_of(id)).join(id);
        if p.is_file() {
            return Ok(Some(p));
        }
    }
    let p = default_store_path(data_dir, id);
    Ok(if p.is_file() { Some(p) } else { None })
}

/// The synthesized location URI for a store-resident file.
pub fn sync_uri(id: &str) -> String {
    format!("{SYNC_URI_PREFIX}{id}")
}

/// Parse a `pvfs-sync:///<id>` URI back to the node id.
pub fn parse_sync_uri(uri: &str) -> Option<&str> {
    uri.strip_prefix(SYNC_URI_PREFIX)
        .filter(|id| !id.is_empty() && !id.contains('/') && !id.contains(".."))
}

// ---- chunk manifests (P9, doc 22) --------------------------------------------
//
// UNSIGNED and advisory: per-chunk BLAKE3 steers parallel pulls, early
// bad-holder rejection, and resume. The catalog hash stays the only trust
// anchor — the whole-file verify-then-rename gate below is unchanged.

/// Swarm chunk size (doc 22 §3).
pub const SWARM_CHUNK: u64 = 8 * 1024 * 1024;
const MANIFEST_HEADER: &str = "pvfs-manifest 1";

/// The sidecar next to a stored/served file.
pub fn manifest_sidecar_path(file: &Path) -> PathBuf {
    let mut os = file.as_os_str().to_os_string();
    os.push(".manifest");
    PathBuf::from(os)
}

/// Compute a file's chunk manifest by reading it.
pub fn compute_manifest(path: &Path) -> Result<Vec<[u8; 32]>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|e| PvfsError::io("open for manifest", e))?;
    let mut hashes = Vec::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut hasher = blake3::Hasher::new();
    let mut in_chunk: u64 = 0;
    loop {
        let n = f.read(&mut buf).map_err(|e| PvfsError::io("read for manifest", e))?;
        if n == 0 {
            break;
        }
        let mut off = 0usize;
        while off < n {
            let room = (SWARM_CHUNK - in_chunk) as usize;
            let take = room.min(n - off);
            hasher.update(&buf[off..off + take]);
            in_chunk += take as u64;
            off += take;
            if in_chunk == SWARM_CHUNK {
                hashes.push(*hasher.finalize().as_bytes());
                hasher = blake3::Hasher::new();
                in_chunk = 0;
            }
        }
    }
    if in_chunk > 0 {
        hashes.push(*hasher.finalize().as_bytes());
    }
    Ok(hashes)
}

/// The attested root over a chunk-hash list (doc 22 §2/§3).
pub fn manifest_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"pvfs:manifest:v1:");
    for c in hashes {
        h.update(c);
    }
    *h.finalize().as_bytes()
}

/// One read, both answers: the whole-file hash (hex) and the chunk manifest —
/// what the hashing paths use so attestation costs no second read (P9.1).
pub fn hash_with_manifest(path: &Path) -> Result<(String, Vec<[u8; 32]>)> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|e| PvfsError::io("open for hash", e))?;
    let mut whole = blake3::Hasher::new();
    let mut hashes = Vec::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut hasher = blake3::Hasher::new();
    let mut in_chunk: u64 = 0;
    loop {
        let n = f.read(&mut buf).map_err(|e| PvfsError::io("read for hash", e))?;
        if n == 0 {
            break;
        }
        whole.update(&buf[..n]);
        let mut off = 0usize;
        while off < n {
            let take = ((SWARM_CHUNK - in_chunk) as usize).min(n - off);
            hasher.update(&buf[off..off + take]);
            in_chunk += take as u64;
            off += take;
            if in_chunk == SWARM_CHUNK {
                hashes.push(*hasher.finalize().as_bytes());
                hasher = blake3::Hasher::new();
                in_chunk = 0;
            }
        }
    }
    if in_chunk > 0 {
        hashes.push(*hasher.finalize().as_bytes());
    }
    Ok((whole.finalize().to_hex().to_string(), hashes))
}

pub(crate) fn write_manifest_sidecar(file: &Path, hashes: &[[u8; 32]]) -> Result<()> {
    let mut text = format!("{MANIFEST_HEADER}\n{SWARM_CHUNK}\n");
    for h in hashes {
        text.push_str(&hex::encode(h));
        text.push('\n');
    }
    crate::storage::atomic_overwrite(&manifest_sidecar_path(file), text.as_bytes())
}

fn read_manifest_sidecar(file: &Path) -> Option<Vec<[u8; 32]>> {
    let text = std::fs::read_to_string(manifest_sidecar_path(file)).ok()?;
    let mut lines = text.lines();
    if lines.next() != Some(MANIFEST_HEADER) {
        return None;
    }
    if lines.next()?.parse::<u64>().ok()? != SWARM_CHUNK {
        return None; // chunk size changed — recompute
    }
    let mut out = Vec::new();
    for l in lines.filter(|l| !l.trim().is_empty()) {
        let bytes = hex::decode(l.trim()).ok()?;
        out.push(<[u8; 32]>::try_from(bytes.as_slice()).ok()?);
    }
    Some(out)
}

/// A served file's manifest: the sidecar when present and plausible for the
/// file's size, else computed and cached (best-effort — a read-only store
/// still answers, just without the cache).
pub fn manifest_for(path: &Path) -> Result<Vec<[u8; 32]>> {
    let size = std::fs::metadata(path)
        .map_err(|e| PvfsError::io("stat for manifest", e))?
        .len();
    let expect = if size == 0 { 0 } else { size.div_ceil(SWARM_CHUNK) } as usize;
    if let Some(m) = read_manifest_sidecar(path) {
        if m.len() == expect {
            return Ok(m);
        }
    }
    let m = compute_manifest(path)?;
    let _ = write_manifest_sidecar(path, &m);
    Ok(m)
}

/// The resumable swarm partial for a fetch (doc 22 §3). Deliberately NOT a
/// `.tmp` name — the startup sweep leaves it alone, which is what makes
/// kill-anywhere resume free.
pub fn swarm_part_path(data_dir: &Path, id: &str) -> Result<PathBuf> {
    let dest = sync_store_path(data_dir, id)?;
    Ok(dest.with_file_name(format!(".{id}.swarmpart")))
}

// ---- placement policy (deployment file) -------------------------------------

pub fn placement_path(data_dir: &Path) -> PathBuf {
    data_dir.join(PLACEMENT_FILE)
}

/// Per-instance placement state: `sync` subtrees keep their bytes local;
/// `central` subtrees (owner-side, F5.3) must hold a verified copy in the
/// named directory — the mover enforces it. A subtree has one mode; pointer
/// entries are simply absent.
#[derive(Debug, Default)]
pub struct Placement {
    pub sync: Vec<NodeId>,
    /// F5.5 (doc 17 §7.7): sync + ADVERTISE — fetched copies are logged as
    /// this box's `pvfs-host://` locations so the fleet can dial them.
    pub sync_advertise: Vec<NodeId>,
    pub central: Vec<(NodeId, PathBuf)>,
    /// P8 (doc 21): `central-keep` — the mirror mode. The mover lands and
    /// logs the verified central copy but NEVER retires the source, so the
    /// space keeps its bytes and the tree gains a backup replica (and a
    /// future swarm seed, doc 20 §6).
    pub central_keep: Vec<(NodeId, PathBuf)>,
    /// F5.5: `(subtree, instance name, that instance's path for the store)`
    /// — the mover logs central copies as the named instance's pvfs-host://
    /// locations (the NAS serves its own store) alongside the local file://.
    pub served_by: Vec<(NodeId, String, PathBuf)>,
}

pub fn load_placement_full(data_dir: &Path) -> Result<Placement> {
    let text = match std::fs::read_to_string(placement_path(data_dir)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Placement::default()),
        Err(e) => return Err(PvfsError::io("read placement", e)),
    };
    let mut lines = text.lines();
    if lines.next() != Some(PLACEMENT_HEADER) {
        return Err(bad("placement", "unrecognized placement file"));
    }
    let mut out = Placement::default();
    for line in lines.filter(|l| !l.trim().is_empty()) {
        if let Some(id) = line.strip_prefix("sync-advertise ") {
            out.sync_advertise.push(id.to_string());
        } else if let Some(id) = line.strip_prefix("sync ") {
            out.sync.push(id.to_string());
        } else if let Some(rest) = line.strip_prefix("served-by ") {
            // `served-by <id> <instance> <path…>` — the path is the REST so
            // store paths with spaces survive (instance names cannot have
            // spaces; the registry enforces that).
            let mut it = rest.splitn(3, ' ');
            match (it.next(), it.next(), it.next()) {
                (Some(id), Some(inst), Some(path)) => {
                    out.served_by.push((id.to_string(), inst.to_string(), PathBuf::from(path)))
                }
                _ => return Err(bad("placement", &format!("corrupt placement line: {line:?}"))),
            }
        } else if let Some(rest) = line.strip_prefix("central-keep ") {
            match rest.split_once(' ') {
                Some((id, dir)) => out.central_keep.push((id.to_string(), PathBuf::from(dir))),
                None => return Err(bad("placement", &format!("corrupt placement line: {line:?}"))),
            }
        } else if let Some(rest) = line.strip_prefix("central ") {
            match rest.split_once(' ') {
                Some((id, dir)) => out.central.push((id.to_string(), PathBuf::from(dir))),
                None => return Err(bad("placement", &format!("corrupt placement line: {line:?}"))),
            }
        } else {
            return Err(bad("placement", &format!("corrupt placement line: {line:?}")));
        }
    }
    Ok(out)
}

/// Node ids of subtrees placed `sync` — advertised or not (both fetch;
/// F5.5 only adds the advertisement step on top).
pub fn load_placement(data_dir: &Path) -> Result<Vec<NodeId>> {
    let p = load_placement_full(data_dir)?;
    let mut out = p.sync;
    out.extend(p.sync_advertise);
    Ok(out)
}

/// F5.5: just the advertised sync subtrees.
pub fn load_advertise(data_dir: &Path) -> Result<Vec<NodeId>> {
    Ok(load_placement_full(data_dir)?.sync_advertise)
}

/// Subtrees placed `central` with their store directories (owner-side).
pub fn load_central(data_dir: &Path) -> Result<Vec<(NodeId, PathBuf)>> {
    Ok(load_placement_full(data_dir)?.central)
}

/// Every mover-walked subtree: `(root, store, keep)` — `keep` = the mirror
/// mode (`central-keep`, P8): copy + log, never retire.
pub fn load_central_all(data_dir: &Path) -> Result<Vec<(NodeId, PathBuf, bool)>> {
    let p = load_placement_full(data_dir)?;
    let mut out: Vec<(NodeId, PathBuf, bool)> = Vec::new();
    for (id, dir) in p.central {
        out.push((id, dir, false));
    }
    for (id, dir) in p.central_keep {
        out.push((id, dir, true));
    }
    Ok(out)
}

fn save_placement(data_dir: &Path, p: &Placement) -> Result<()> {
    let mut text = String::from(PLACEMENT_HEADER);
    text.push('\n');
    for r in &p.sync {
        text.push_str(&format!("sync {r}\n"));
    }
    for r in &p.sync_advertise {
        text.push_str(&format!("sync-advertise {r}\n"));
    }
    for (r, inst, path) in &p.served_by {
        text.push_str(&format!("served-by {r} {inst} {}\n", path.display()));
    }
    for (r, d) in &p.central {
        text.push_str(&format!("central {r} {}\n", d.display()));
    }
    for (r, d) in &p.central_keep {
        text.push_str(&format!("central-keep {r} {}\n", d.display()));
    }
    crate::storage::atomic_overwrite(&placement_path(data_dir), text.as_bytes())
}

/// Place `id` as `sync` (true) or back to `pointer` (false). Either way any
/// `central` entry for the subtree is cleared — one mode per subtree.
pub fn set_placement(data_dir: &Path, id: &NodeId, sync: bool) -> Result<()> {
    set_sync_mode(data_dir, id, sync, false)
}

/// F5.5: the full sync-mode setter — `advertise` logs fetched copies as
/// this box's locations. One mode per subtree, as ever.
pub fn set_sync_mode(data_dir: &Path, id: &NodeId, sync: bool, advertise: bool) -> Result<()> {
    let mut p = load_placement_full(data_dir)?;
    p.sync.retain(|r| r != id);
    p.sync_advertise.retain(|r| r != id);
    p.central.retain(|(r, _)| r != id);
    p.central_keep.retain(|(r, _)| r != id);
    p.served_by.retain(|(r, _, _)| r != id);
    if sync && advertise {
        p.sync_advertise.push(id.clone());
    } else if sync {
        p.sync.push(id.clone());
    }
    save_placement(data_dir, &p)
}

/// Place `id` as `central` with its store directory (owner-side, F5.3).
/// `keep` = the P8 mirror mode: the mover copies + logs but never retires.
pub fn set_central(data_dir: &Path, id: &NodeId, dest: &Path, keep: bool) -> Result<()> {
    set_central_served(data_dir, id, dest, keep, None)
}

/// F5.5: central placement with an optional serving instance — the mover
/// then logs store copies as `(instance, remote_prefix)`'s pvfs-host://
/// locations alongside the owner-local file:// row (doc 17 §7.7.2).
pub fn set_central_served(
    data_dir: &Path,
    id: &NodeId,
    dest: &Path,
    keep: bool,
    served_by: Option<(&str, &Path)>,
) -> Result<()> {
    let mut p = load_placement_full(data_dir)?;
    p.sync.retain(|r| r != id);
    p.sync_advertise.retain(|r| r != id);
    p.central.retain(|(r, _)| r != id);
    p.central_keep.retain(|(r, _)| r != id);
    p.served_by.retain(|(r, _, _)| r != id);
    if keep {
        p.central_keep.push((id.clone(), dest.to_path_buf()));
    } else {
        p.central.push((id.clone(), dest.to_path_buf()));
    }
    if let Some((inst, prefix)) = served_by {
        p.served_by.push((id.clone(), inst.to_string(), prefix.to_path_buf()));
    }
    save_placement(data_dir, &p)
}

// ---- edge eviction (F5.3's reclaim half; shared by CLI and daemon, P5.3) ----

/// What one evict pass did. `skipped` carries `(uri, reason)` — expected
/// holds (no other live location) and real failures alike; the caller
/// decides how loudly to surface them.
#[derive(Debug, Default)]
pub struct EvictReport {
    pub evicted: u64,
    pub freed_bytes: u64,
    pub skipped: Vec<(String, String)>,
}

/// Delete local bytes whose catalog location was retired by the mover —
/// only ever when the catalog records another **live** location (synthesized
/// sync-store entries never count: they aren't catalog truth).
pub fn evict_pass(engine: &Engine) -> Result<EvictReport> {
    let mut report = EvictReport::default();
    // P8 (doc 21): retired plain file:// locations are evictable ONLY under a
    // migrate-kind binding's source dir — that binding consented to draining
    // at enrollment. A manually retracted (`loc rm`) in-place location must
    // never cost the user their file, even with a live copy elsewhere.
    let staging_prefixes: Vec<String> = load_central_all(engine.data_dir())?
        .into_iter()
        .filter(|(_, _, keep)| !keep)
        .filter_map(|(root, _, _)| engine.binding_for(&root).ok().flatten())
        .map(|b| format!("{}/", b.source_uri.trim_end_matches('/')))
        .collect();
    for (id, uri, path) in engine.retired_own_host_locations()? {
        if uri.starts_with("file://") && !staging_prefixes.iter().any(|p| uri.starts_with(p)) {
            continue; // not a migrate-kind staging location — never touch it
        }
        let live_elsewhere = engine
            .locations(&id)?
            .iter()
            .any(|u| !u.starts_with(SYNC_URI_PREFIX));
        if !live_elsewhere {
            report
                .skipped
                .push((uri, "no other live location recorded".into()));
            continue;
        }
        match std::fs::symlink_metadata(&path) {
            Ok(md) if md.file_type().is_file() => {
                let size = md.len();
                match std::fs::remove_file(&path) {
                    Ok(()) => {
                        report.evicted += 1;
                        report.freed_bytes += size;
                    }
                    Err(e) => report.skipped.push((uri, e.to_string())),
                }
            }
            Ok(_) => report.skipped.push((uri, "not a regular file".into())),
            Err(_) => {} // already gone — nothing to reclaim
        }
    }
    Ok(report)
}

// ---- the sync sink ----------------------------------------------------------

/// An in-flight fetch into the sync store: hashes while bytes stream in;
/// [`Engine::sync_commit`] verifies and publishes atomically. Dropping an
/// uncommitted sink removes the partial file.
pub struct SyncSink {
    id: NodeId,
    tmp: PathBuf,
    dest: PathBuf,
    file: Option<std::fs::File>,
    hasher: blake3::Hasher,
    written: u64,
    expected_hash: String,
    expected_size: u64,
    /// P9 (doc 22): chunk hashes computed INLINE while bytes stream — the
    /// sidecar costs no second read of the published file.
    chunk_hasher: blake3::Hasher,
    in_chunk: u64,
    chunk_hashes: Vec<[u8; 32]>,
}

impl Write for SyncSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let f = self
            .file
            .as_mut()
            .ok_or_else(|| std::io::Error::other("sync sink already finished"))?;
        f.write_all(buf)?;
        self.hasher.update(buf);
        self.written += buf.len() as u64;
        let mut off = 0usize;
        while off < buf.len() {
            let take = ((SWARM_CHUNK - self.in_chunk) as usize).min(buf.len() - off);
            self.chunk_hasher.update(&buf[off..off + take]);
            self.in_chunk += take as u64;
            off += take;
            if self.in_chunk == SWARM_CHUNK {
                self.chunk_hashes.push(*self.chunk_hasher.finalize().as_bytes());
                self.chunk_hasher = blake3::Hasher::new();
                self.in_chunk = 0;
            }
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self.file.as_mut() {
            Some(f) => f.flush(),
            None => Ok(()),
        }
    }
}

impl Drop for SyncSink {
    fn drop(&mut self) {
        if self.file.take().is_some() {
            let _ = std::fs::remove_file(&self.tmp);
        }
    }
}

/// Remove orphaned fetch tmps (`.{id}.tmp`) from the sync store. A process
/// killed mid-fetch (SIGKILL, power loss) never runs its sink's Drop, and a
/// tmp for a file that is never re-fetched would leak its disk forever.
/// Sinks are process-local, so nothing legitimately holds a tmp across a
/// daemon restart — pvfsd sweeps unconditionally at startup, before any job
/// can begin a fetch. Returns how many files were removed.
pub fn sweep_orphan_tmps(data_dir: &Path) -> Result<u64> {
    let mut removed = sweep_store_tmps(&data_dir.join(SYNC_DIR))?;
    // a configured root (P6.1) collects the same litter
    if let Some(root) = sync_store_root(data_dir)? {
        removed += sweep_store_tmps(&root)?;
    }
    Ok(removed)
}

fn sweep_store_tmps(store: &Path) -> Result<u64> {
    let shards = match std::fs::read_dir(store) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(PvfsError::io("scan sync store", e)),
    };
    let mut removed = 0;
    for shard in shards {
        let shard = shard.map_err(|e| PvfsError::io("scan sync store", e))?;
        let is_dir = shard
            .file_type()
            .map_err(|e| PvfsError::io("scan sync store", e))?
            .is_dir();
        if !is_dir {
            continue;
        }
        let entries =
            std::fs::read_dir(shard.path()).map_err(|e| PvfsError::io("scan sync shard", e))?;
        for entry in entries {
            let entry = entry.map_err(|e| PvfsError::io("scan sync shard", e))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let is_file = entry.file_type().map(|t| t.is_file()).unwrap_or(false);
            if !is_fetch_tmp_name(name) || !is_file {
                continue;
            }
            match std::fs::remove_file(entry.path()) {
                Ok(()) => removed += 1,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(PvfsError::io("remove orphaned sync tmp", e)),
            }
        }
    }
    Ok(removed)
}

/// `.{64-hex}.tmp` — exactly the names [`Engine::sync_begin`] mints for
/// in-flight fetches; anything else in the store is content, never touched.
fn is_fetch_tmp_name(name: &str) -> bool {
    name.strip_prefix('.')
        .and_then(|n| n.strip_suffix(".tmp"))
        .is_some_and(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
}

impl Engine {
    /// Begin fetching `id`'s bytes into the managed sync store. The caller
    /// streams into the returned sink (it implements `Write`) and then calls
    /// [`sync_commit`](Self::sync_commit).
    pub fn sync_begin(&self, id: &NodeId) -> Result<SyncSink> {
        let n = fetch_node(&self.conn, id)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: id.clone(),
        })?;
        if n.node_type != TYPE_FILE {
            return Err(bad("sync", "sync fetches file nodes"));
        }
        let payload = FilePayload::decode(&n.payload)?;
        let dest = sync_store_path(&self.data_dir, id)?;
        if let Some(dir) = dest.parent() {
            std::fs::create_dir_all(dir).map_err(|e| PvfsError::io("create sync store", e))?;
        }
        let tmp = dest.with_file_name(format!(".{id}.tmp"));
        let file = std::fs::File::create(&tmp).map_err(|e| PvfsError::io("create sync tmp", e))?;
        Ok(SyncSink {
            id: id.clone(),
            tmp,
            dest,
            file: Some(file),
            hasher: blake3::Hasher::new(),
            written: 0,
            expected_hash: payload.content_hash,
            expected_size: payload.size_bytes,
            chunk_hasher: blake3::Hasher::new(),
            in_chunk: 0,
            chunk_hashes: Vec::new(),
        })
    }

    /// P9 (doc 22): a file's chunk manifest, served from any readable local
    /// copy (sidecar-cached). Errors NotFound when this box holds no bytes.
    pub fn chunk_manifest(&self, id: &NodeId) -> Result<(u64, u64, Vec<[u8; 32]>)> {
        let path = self.readable_path(id)?.ok_or(PvfsError::NotFound {
            kind: "file bytes",
            id: id.clone(),
        })?;
        let size = std::fs::metadata(&path)
            .map_err(|e| PvfsError::io("stat for manifest", e))?
            .len();
        Ok((size, SWARM_CHUNK, manifest_for(&path)?))
    }

    /// P9 (doc 22): verify and publish an assembled swarm partial — the SAME
    /// trust gate as [`sync_commit`](Self::sync_commit): whole-file hash (or
    /// size for unhashed nodes) against the catalog, then the atomic rename.
    /// On failure the partial is LEFT IN PLACE for resume.
    pub fn swarm_commit(
        &mut self,
        id: &NodeId,
        part: &Path,
        manifest: &[[u8; 32]],
    ) -> Result<PathBuf> {
        let n = fetch_node(&self.conn, id)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: id.clone(),
        })?;
        let payload = FilePayload::decode(&n.payload)?;
        let dest = sync_store_path(&self.data_dir, id)?;
        let mut f = std::fs::File::open(part).map_err(|e| PvfsError::io("open swarm part", e))?;
        let mut hasher = blake3::Hasher::new();
        std::io::copy(&mut f, &mut hasher).map_err(|e| PvfsError::io("hash swarm part", e))?;
        drop(f);
        let actual = hasher.finalize().to_hex().to_string();
        if payload.content_hash.is_empty() {
            // the fetcher only swarms hashed files; refuse a bypass
            return Err(bad("sync", "swarm publish requires a hashed file"));
        }
        if actual != payload.content_hash {
            return Err(PvfsError::Integrity {
                kind: "sync",
                id: id.clone(),
                reason: IntegrityReason::IdMismatch {
                    expected: payload.content_hash,
                    actual,
                },
            });
        }
        std::fs::rename(part, &dest).map_err(|e| PvfsError::io("publish swarm file", e))?;
        // every chunk was verified against this manifest during assembly and
        // the whole just passed the catalog gate — cache it without a re-read
        let _ = write_manifest_sidecar(&dest, manifest);
        self.conn
            .execute(
                "DELETE FROM location_quarantine WHERE file_id = ?1 AND uri = ?2",
                rusqlite::params![id, sync_uri(id)],
            )
            .map_err(crate::error::map_db("lift sync quarantine"))?;
        Ok(dest)
    }

    /// Verify and publish a completed fetch. With a known content hash the
    /// bytes must match it; a lazy (unhashed) node is checked against its
    /// recorded size instead. On success the store file appears atomically
    /// and any stale quarantine of the sync location is lifted.
    pub fn sync_commit(&mut self, mut sink: SyncSink) -> Result<PathBuf> {
        let file = sink
            .file
            .take()
            .ok_or_else(|| bad("sync", "sink already finished"))?;
        file.sync_all().map_err(|e| PvfsError::io("flush sync tmp", e))?;
        drop(file);

        let ok = if !sink.expected_hash.is_empty() {
            sink.hasher.finalize().to_hex().to_string() == sink.expected_hash
        } else {
            sink.expected_size == 0 || sink.written == sink.expected_size
        };
        if !ok {
            let _ = std::fs::remove_file(&sink.tmp);
            return Err(PvfsError::Integrity {
                kind: "sync",
                id: sink.id.clone(),
                reason: IntegrityReason::IdMismatch {
                    expected: if sink.expected_hash.is_empty() {
                        format!("{} bytes", sink.expected_size)
                    } else {
                        sink.expected_hash.clone()
                    },
                    actual: if sink.expected_hash.is_empty() {
                        format!("{} bytes", sink.written)
                    } else {
                        sink.hasher.finalize().to_hex().to_string()
                    },
                },
            });
        }
        std::fs::rename(&sink.tmp, &sink.dest).map_err(|e| PvfsError::io("publish sync file", e))?;
        // P9 (doc 22): the sidecar comes from the hashes computed INLINE as
        // the bytes streamed — a 3 GiB publish must not cost a 3 GiB re-read
        // (found by the fleet's view-refresh window). Best-effort.
        let mut chunks = std::mem::take(&mut sink.chunk_hashes);
        if sink.in_chunk > 0 {
            chunks.push(*sink.chunk_hasher.finalize().as_bytes());
        }
        let _ = write_manifest_sidecar(&sink.dest, &chunks);
        // A prior copy may have been quarantined (verify-on-read); fresh
        // verified bytes lift it. Projection-local — fine on a replica.
        self.conn
            .execute(
                "DELETE FROM location_quarantine WHERE file_id = ?1 AND uri = ?2",
                rusqlite::params![sink.id, sync_uri(&sink.id)],
            )
            .map_err(crate::error::map_db("lift sync quarantine"))?;
        Ok(sink.dest.clone())
    }

    /// File nodes under `root` (contains-closure) with **no readable local
    /// location** — the pointer-without-bytes set a sync pass fetches.
    /// Returns `(id, label)` pairs in tree order.
    pub fn missing_bytes(&self, root: &NodeId) -> Result<Vec<(NodeId, String)>> {
        let mut out = Vec::new();
        for entry in self.walk(root)?.entries {
            if entry.node.node_type != TYPE_FILE {
                continue;
            }
            // files reached via ref links belong to another subtree's policy
            if entry.link_type != LINK_CONTAINS && entry.depth > 0 {
                continue;
            }
            if self.readable_path(&entry.node.id)?.is_none() {
                out.push((entry.node.id, entry.node.label));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod store_root_tests {
    use super::*;

    #[test]
    fn root_config_round_trip_and_paths() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path();
        let id = "ab".repeat(32);
        // unset: default store, nothing found
        assert!(sync_store_root(data).unwrap().is_none());
        assert_eq!(
            sync_store_path(data, &id).unwrap(),
            data.join("synced").join("ab").join(&id)
        );
        assert!(sync_store_lookup(data, &id).unwrap().is_none());
        // configured: new-fetch path moves to the root
        let big = dir.path().join("big disk");
        set_sync_store_root(data, Some(&big)).unwrap();
        assert_eq!(sync_store_root(data).unwrap().as_deref(), Some(big.as_path()));
        assert_eq!(
            sync_store_path(data, &id).unwrap(),
            big.join("ab").join(&id)
        );
        // lookup prefers the configured root, falls back to default
        std::fs::create_dir_all(data.join("synced").join("ab")).unwrap();
        std::fs::write(data.join("synced").join("ab").join(&id), b"old").unwrap();
        assert_eq!(
            sync_store_lookup(data, &id).unwrap().unwrap(),
            data.join("synced").join("ab").join(&id),
            "pre-move files keep serving from the default store"
        );
        std::fs::create_dir_all(big.join("ab")).unwrap();
        std::fs::write(big.join("ab").join(&id), b"new").unwrap();
        assert_eq!(
            sync_store_lookup(data, &id).unwrap().unwrap(),
            big.join("ab").join(&id),
            "the configured root wins when both hold the file"
        );
        // clear: back to default, idempotent
        set_sync_store_root(data, None).unwrap();
        set_sync_store_root(data, None).unwrap();
        assert!(sync_store_root(data).unwrap().is_none());
        // corrupt file refuses loudly
        std::fs::write(store_config_path(data), "not-a-store-file\n").unwrap();
        assert!(sync_store_root(data).is_err());
        assert!(sync_store_path(data, &id).is_err());
    }

    #[test]
    fn sweep_covers_a_configured_root() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path();
        let big = dir.path().join("big");
        set_sync_store_root(data, Some(&big)).unwrap();
        let id = "cd".repeat(32);
        std::fs::create_dir_all(big.join("cd")).unwrap();
        std::fs::write(big.join("cd").join(format!(".{id}.tmp")), b"partial").unwrap();
        std::fs::write(big.join("cd").join(&id), b"content").unwrap();
        assert_eq!(sweep_orphan_tmps(data).unwrap(), 1);
        assert!(big.join("cd").join(&id).exists(), "content never touched");
    }
}
