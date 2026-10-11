//! P7.3 (doc 20 §3) — the read-only streaming mount: browse a forest (or a
//! replica) as a real filesystem. Directories come from the projection;
//! opening a file resolves its bytes live — a local location, the sync
//! store, else a verified read-through fetch (F5.2) — and reads are served
//! straight from the resolved file with kernel-native offsets.
//!
//! Deliberately read-only for BYTES: the catalog's write model belongs to the
//! CLI and daemon. Writes/xattrs/mtimes: refused/synthetic (doc 20 §3). The
//! namespace is another matter — an arr upgrades, renames and tidies what it
//! did not just create: D71 W2 (the node mount), D169 and D170 (the view).

mod overlay;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use fuser::{ReplyEmpty, 
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyEntry, ReplyOpen, ReplyStatfs, Request,
};
use pvfs_client::fetch::{Fetcher, SwarmProgress};
use overlay::{GoneDir, Move, Overlay};
use pvfs_client::hash_cache::{CacheOpts, HashCache, HashFetch, Opened, RenameCopy};
use pvfs_core::{Engine, FilePayload, NodeId, PvfsError, ReplicaSource, TYPE_FILE};
use pvfs_log::{content, pv_error, pv_info, pv_warn};

const TTL: Duration = Duration::from_secs(1);

pub struct PvfsFs {
    engine: Engine,
    fetcher: Fetcher,
    uid: u32,
    gid: u32,
    ino_to_node: HashMap<u64, NodeId>,
    node_to_ino: HashMap<NodeId, u64>,
    next_ino: u64,
    /// Open handles: fh → the resolved on-disk file serving reads.
    handles: HashMap<u64, std::fs::File>,
    /// P9.1 (doc 22 §2): handles streaming while a background chunked fetch
    /// verifies — reads wait per-range on the shared progress.
    streaming: HashMap<u64, Arc<SwarmProgress>>,
    /// One background fetch per node, shared across its open handles.
    active: HashMap<NodeId, Arc<SwarmProgress>>,
    /// This box's transport pin, read once — used to tell OUR pin-qualified
    /// locations from another holder's (D82).
    own_pin: Option<String>,
    /// P10.1 (doc 23 §11): handles proxying an IN-FLIGHT ingest file — each
    /// read forwards as a ranged `Cat` to the serving daemon, which waits
    /// for chunk coverage and registers our demand as a hot range.
    proxy: HashMap<u64, ProxyRead>,
    data_dir: std::path::PathBuf,
    next_fh: u64,
    /// D71 W2: on a replica the catalog has no local writer, so namespace
    /// changes route to the owner's daemon — the same seam the scan uses.
    route: Option<(pvfs_client::Client, pvfs_client::advertise::BoxedSign)>,
    /// D82 — `statfs`'s answer, and when it was computed. The byte total needs
    /// every file payload decoded, and a library scan can call `statfs` in a
    /// loop, so it is worth not recomputing per call.
    capacity: Option<((u64, u64), std::time::Instant)>,
    /// PVOS D233 — a writable view's free space, and when it was measured.
    space: Option<(pvfs_core::WritableSpace, std::time::Instant)>,
    /// D130 (doc 26 phase 6) — the VIEW mount: inodes are relative paths in
    /// the merged view, not nodes. `view` picks the mode for every handler.
    view: bool,
    /// D217 tier 1 — edits are allowed for files whose bytes this box already
    /// holds in a region bound here. Off unless the mount was told otherwise:
    /// a write to a file held elsewhere still gets `EROFS`, because the honest
    /// alternative is copying the whole file across the network to change a
    /// header, and a person should ask for that explicitly.
    writable: bool,
    /// D217 — handles opened for writing, so `write`/`setattr` cannot touch a
    /// read handle, and `read` keeps its existing path. PVOS D233: with the
    /// view path each was opened at, so the overlay knows when the last one
    /// on a file closes.
    write_handles: HashMap<u64, WriteHandle>,
    ino_to_path: HashMap<u64, String>,
    path_to_ino: HashMap<String, u64>,
    /// Directory listings, cached briefly: a library scan issues thousands
    /// of lookups and the view is a query, not a table.
    view_cache: HashMap<String, (std::time::Instant, Vec<pvfs_core::ViewEntry>)>,
    /// D165 — the view's read-through cache (pieces by demand, kept a while,
    /// bounded), and the handles on it: a read-through's fetch, or the hash
    /// of a kept file, so the cache knows when the application is done.
    hash_cache: Option<HashCache>,
    hash_streams: HashMap<u64, HashStream>,
    hash_pins: HashMap<u64, String>,
    /// PVOS D220 — a view file open here: its attributes as they were at the
    /// open, and how many handles hold it (by inode); and each handle's
    /// inode. `getattr` answers from these once the path has gone from the
    /// view, as `fstat` on an open file does on a disk after its unlink —
    /// the kernel asks at a read that reaches the end of the file.
    open_attrs: HashMap<u64, (FileAttr, usize)>,
    open_inos: HashMap<u64, u64>,
    /// D169 — the boxes a view delete asks (tests, the lab); `None` = the
    /// fleet's announced endpoints.
    view_sources: Option<Vec<ReplicaSource>>,
    /// D169 — paths deleted through THIS mount, with the hashes that were
    /// trashed: hidden at once, because the catalogue takes the holder's
    /// pass and our fetch to agree, and an arr creates the new file at the
    /// same path within the second (against a still-listed read-only file
    /// that create is an open-for-write, and `EROFS`).
    tombstones: Tombstones,
    /// D170 — the renames, made folders and removed folders done through
    /// THIS mount that the catalogue has not caught up with, and when the
    /// catalogue was last asked whether it has.
    overlay: Arc<std::sync::Mutex<Overlay>>,
    overlay_pruned: std::time::Instant,
}

type Tombstones = Arc<std::sync::Mutex<HashMap<String, Tomb>>>;

/// PVOS D233 — one handle open for writing: the real file, and the view path.
struct WriteHandle {
    file: std::fs::File,
    rel: String,
}

/// One path deleted through this mount: the hashes that went to the trash,
/// when, and — per region — the catalogue seq this box held at that moment.
#[derive(Clone)]
struct Tomb {
    dead: HashSet<String>,
    at: std::time::Instant,
    held: HashMap<String, u64>,
    /// How long it is trusted: [`TOMBSTONE_TTL`] for a delete through this
    /// mount, [`GONE_TTL`] for a copy a read found gone (PVOS D219).
    ttl: Duration,
}

/// How long a tombstone hides a path the catalogue still lists. It only has
/// to cover the holder's next pass and our fetch of it (a minute or two); the
/// arr's replacement lands on the union's local branch within seconds and
/// shadows this branch anyway. It was an hour, and the lab showed the cost:
/// a file restored from the trash seconds after its delete — before any new
/// head — stayed hidden on the box that had deleted it.
const TOMBSTONE_TTL: Duration = Duration::from_secs(600);

/// PVOS D219 — how long a copy a READ found gone (every box asked said it
/// holds no such bytes) stays hidden at most. Shorter than a delete's: this
/// box did not make the change, it only saw its effect, so the catalogue
/// should overtake it within a minute (the holder's watch pass plus our
/// nudged fetch take seconds) — and if the box was wrong, the file is back
/// soon.
const GONE_TTL: Duration = Duration::from_secs(120);

/// PVOS D219 — hide `hash` at `rel`: a read found that every box asked holds
/// no such bytes (deleted or replaced since this box's catalogue last moved).
/// `held` is what this box held of the copies' regions at the open; a head
/// beyond it that still lists the copy brings it back (D169's rule). Joins a
/// tombstone already there. Callable off the session thread.
fn bury_gone(tombs: &Tombstones, rel: &str, hash: &str, held: &HashMap<String, u64>) {
    let mut t = tombs.lock().unwrap();
    match t.get_mut(rel) {
        Some(tomb) if tomb.dead.contains(hash) => {}
        Some(tomb) => {
            tomb.dead.insert(hash.to_string());
            for (r, q) in held {
                tomb.held.entry(r.clone()).or_insert(*q);
            }
        }
        None => {
            t.insert(
                rel.to_string(),
                Tomb {
                    dead: HashSet::from([hash.to_string()]),
                    at: std::time::Instant::now(),
                    held: held.clone(),
                    ttl: GONE_TTL,
                },
            );
            pv_info!("pvfs.mount.gone", path = content(rel), hash = &hash[..hash.len().min(8)];
                "mount: {rel} is gone ({}) — hidden until this box's catalogue catches up",
                &hash[..hash.len().min(8)]
            );
        }
    }
}

/// One handle on a read-through: its fetch, and the file it reads from,
/// opened once (the partial becomes the kept file by rename — one inode).
struct HashStream {
    fetch: Arc<HashFetch>,
    file: Option<std::fs::File>,
    /// PVOS D219 — the view path it was opened at, and what this box held of
    /// the regions of the copies with its hash then: a read that finds the
    /// bytes gone hides that copy ([`bury_gone`]).
    rel: String,
    held: HashMap<String, u64>,
}

/// How long a read waits for its pieces before it is an I/O error.
const READ_WAIT: Duration = Duration::from_secs(120);

/// One in-flight proxy handle: the connection is reused across reads.
struct ProxyRead {
    node: NodeId,
    declared: u64,
    client: pvfs_client::Client,
}

impl PvfsFs {
    pub fn new(data_dir: &Path, target: &NodeId) -> Result<PvfsFs, PvfsError> {
        let engine = Engine::open(data_dir)?;
        let engine_is_replica = engine.is_replica();
        let fetcher = Fetcher::with_memory(&engine, data_dir);
        let mut fs = PvfsFs {
            engine,
            fetcher,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            ino_to_node: HashMap::new(),
            node_to_ino: HashMap::new(),
            next_ino: 2,
            handles: HashMap::new(),
            writable: false,
            write_handles: HashMap::new(),
            streaming: HashMap::new(),
            active: HashMap::new(),
            own_pin: pvfs_core::storage::host_pin(data_dir),
            proxy: HashMap::new(),
            data_dir: data_dir.to_path_buf(),
            next_fh: 1,
            route: {
                let is_replica = engine_is_replica;
                pvfs_client::advertise::replica_route(data_dir, is_replica).unwrap_or(None)
            },
            capacity: None,
            space: None,
            view: false,
            ino_to_path: HashMap::new(),
            path_to_ino: HashMap::new(),
            view_cache: HashMap::new(),
            hash_cache: None,
            hash_streams: HashMap::new(),
            hash_pins: HashMap::new(),
            open_attrs: HashMap::new(),
            open_inos: HashMap::new(),
            view_sources: None,
            tombstones: Arc::new(std::sync::Mutex::new(HashMap::new())),
            overlay: Arc::new(std::sync::Mutex::new(Overlay::default())),
            overlay_pruned: std::time::Instant::now(),
        };
        fs.ino_to_node.insert(1, target.clone());
        fs.node_to_ino.insert(target.clone(), 1);
        Ok(fs)
    }

    /// D82 — what this filesystem HOLDS: total bytes, and how many files.
    ///
    /// Sizes live in each file node's payload, not a column, so this decodes
    /// every one. That is milliseconds at library scale and `statfs` is rare,
    /// but an arr walking the tree can still call it repeatedly, so the answer
    /// is cached for a minute. A stale byte total is harmless; the numbers that
    /// have to be exact are the zeroes below, and those are constants.
    fn capacity(&mut self) -> (u64, u64) {
        const TTL: Duration = Duration::from_secs(60);
        if let Some((v, at)) = self.capacity {
            if at.elapsed() < TTL {
                return v;
            }
        }
        let v = if self.view {
            // D130: what the view serves — admitted files, their served sizes.
            self.engine
                .view_paths()
                .map(|ps| {
                    ps.iter()
                        .filter(|e| e.kind != "dir" && Self::view_shown(e))
                        .fold((0u64, 0u64), |(b, n), e| {
                            (b + Self::view_served(e).map(|(_, s, _)| s).unwrap_or(0), n + 1)
                        })
                })
                .unwrap_or((0, 0))
        } else {
            self.engine.total_file_bytes().unwrap_or((0, 0))
        };
        self.capacity = Some((v, std::time::Instant::now()));
        v
    }

    /// PVOS D233 — [`Engine::writable_space`], cached for a minute like the
    /// byte total: a copy can call `statfs` per file.
    fn writable_space(&mut self) -> pvfs_core::WritableSpace {
        const TTL: Duration = Duration::from_secs(60);
        if let Some((v, at)) = self.space {
            if at.elapsed() < TTL {
                return v;
            }
        }
        let v = self.engine.writable_space().unwrap_or_default();
        self.space = Some((v, std::time::Instant::now()));
        v
    }

    fn ino_of(&mut self, node: &NodeId) -> u64 {
        if let Some(i) = self.node_to_ino.get(node) {
            return *i;
        }
        let i = self.next_ino;
        self.next_ino += 1;
        self.ino_to_node.insert(i, node.clone());
        self.node_to_ino.insert(node.clone(), i);
        i
    }

    fn attr_for(&mut self, node: &NodeId) -> Result<FileAttr, PvfsError> {
        let ino = self.ino_of(node);
        let entry = self.engine.node(node)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: node.clone(),
        })?;
        // punch D: catalog timestamps, not "when you mounted" — mtime-based
        // tools (rsync -u, make) then judge freshness meaningfully.
        let ts = SystemTime::UNIX_EPOCH + Duration::from_millis(entry.created_at);
        let (kind, size, perm) = if entry.node_type == TYPE_FILE {
            let size = FilePayload::decode(&entry.payload)
                .map(|p| p.size_bytes)
                .unwrap_or(0);
            (FileType::RegularFile, size, 0o444)
        } else {
            (FileType::Directory, 0, 0o555)
        };
        Ok(FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: ts,
            mtime: ts,
            ctime: ts,
            crtime: ts,
            kind,
            perm,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 512,
            flags: 0,
        })
    }

    /// The on-disk path serving this file's bytes: local/synced, else a
    /// verified read-through fetch (blocks for the fetch; doc 20 §7 notes
    /// serve-while-fetching as the deferred refinement).
    /// P10.1: is `node` an in-flight ingest file this mount can proxy? An
    /// unhashed pointer (empty content hash) qualifies; the connection dials
    /// the replica's recorded source, or the forest's own conventional
    /// socket signed with the device key. Returns the declared size and a
    /// connected client, or `None` to fall through to the blocking path.
    fn ingest_proxy(&self, node: &NodeId) -> Option<(u64, pvfs_client::Client)> {
        let n = self.engine.node(node).ok().flatten()?;
        if n.node_type != TYPE_FILE {
            return None;
        }
        let p = FilePayload::decode(&n.payload).ok()?;
        if !p.content_hash.is_empty() {
            return None; // hashed files use the attested streaming/swarm paths
        }
        let client = if pvfs_core::replica::marker_path(&self.data_dir).exists() {
            let src = pvfs_core::replica::ReplicaSource::load(&self.data_dir).ok()?;
            pvfs_client::follow::dial_source(&src).ok()?
        } else {
            let sock =
                pvfs_core::mount::daemon_socket_path(&self.engine.identity.forest_id);
            let key = pvfs_core::identity::DeviceKeyCache::load(&self.data_dir)
                .ok()?
                .signing_key;
            let pubkey = pvfs_core::crypto::pubkey_bytes(&key);
            pvfs_client::Client::connect_signed(&sock, &pubkey, |d| {
                pvfs_core::crypto::sign_digest(&key, d).unwrap_or_default()
            })
            .ok()?
        };
        Some((p.size_bytes, client))
    }

    fn resolve_bytes(&mut self, node: &NodeId) -> Result<PathBuf, PvfsError> {
        if let Some(p) = self.engine.readable_path(node)? {
            return Ok(p);
        }
        self.fetcher
            .fetch(&mut self.engine, node)
            .map_err(|e| PvfsError::NotFound {
                kind: "bytes",
                id: format!("{node}: {e}"),
            })?;
        self.engine
            .readable_path(node)?
            .ok_or(PvfsError::NotFound {
                kind: "bytes",
                id: node.clone(),
            })
    }
}

/// How long a cached view listing is trusted (D130 §3.1).
const VIEW_TTL: Duration = Duration::from_secs(5);

impl PvfsFs {
    /// D130 — the VIEW mount over `data_dir`'s merged view (doc 26 §6): one
    /// entry per relative path across every catalogue region this box
    /// knows; bytes from its own disk, the hash store, or a read-through.
    pub fn new_view(data_dir: &Path) -> Result<PvfsFs, PvfsError> {
        PvfsFs::new_view_with(data_dir, CacheOpts::default(), None)
    }

    /// [`PvfsFs::new_view`] with the read-through cache's knobs (D165), and
    /// — for tests and the lab — the boxes to ask instead of the fleet's
    /// announced endpoints.
    pub fn new_view_with(
        data_dir: &Path,
        cache: CacheOpts,
        sources: Option<Vec<ReplicaSource>>,
    ) -> Result<PvfsFs, PvfsError> {
        // A node mount of the forest root, then switched: the shared fields
        // (engine, fetcher, pins, routes) are built the same way.
        let root = Engine::open(data_dir)?.identity.root_node_id.clone();
        let mut fs = PvfsFs::new(data_dir, &root)?;
        fs.view = true;
        fs.ino_to_node.clear();
        fs.node_to_ino.clear();
        fs.ino_to_path.insert(1, String::new());
        fs.path_to_ino.insert(String::new(), 1);
        fs.view_sources = sources.clone();
        let cache = match sources {
            Some(s) => HashCache::with_sources(data_dir, cache, s),
            None => HashCache::new(data_dir, cache),
        };
        cache.start_janitor();
        fs.hash_cache = Some(cache);
        Ok(fs)
    }

    fn view_ino(&mut self, rel: &str) -> u64 {
        if let Some(i) = self.path_to_ino.get(rel) {
            return *i;
        }
        let i = self.next_ino;
        self.next_ino += 1;
        self.ino_to_path.insert(i, rel.to_string());
        self.path_to_ino.insert(rel.to_string(), i);
        i
    }

    /// What the mount shows (D130 §3.1): directories, admitted files, and
    /// hash conflicts that have a served copy. Unhashed files and kind
    /// conflicts are not admitted (doc 26 §6) and stay in `pvfs view ls`.
    fn view_shown(e: &pvfs_core::ViewEntry) -> bool {
        use pvfs_core::ViewState;
        e.kind == "dir"
            || matches!(e.state, ViewState::Admitted)
            || (matches!(e.state, ViewState::ConflictHashes(_))
                && Engine::served_copy(e, &pvfs_core::media::Rules::default()).is_some())
    }

    fn view_list(&mut self, dir: &str) -> Result<Vec<pvfs_core::ViewEntry>, PvfsError> {
        if let Some((at, list)) = self.view_cache.get(dir) {
            if at.elapsed() < VIEW_TTL {
                // the cache holds what the catalogue says; a delete through
                // this mount hides its path at once (D169)
                return Ok(list.clone().into_iter().filter_map(|e| self.without_the_deleted(e)).collect());
            }
        }
        let ov = Arc::clone(&self.overlay);
        let o = ov.lock().unwrap();
        let list: Vec<pvfs_core::ViewEntry> = if o.is_empty() {
            self.engine.merged_view(dir)?.into_iter().filter(Self::view_shown).collect()
        } else {
            // D170 — rows the catalogue still lists at a path renamed through
            // this mount show at the new one: list `dir`, the folders `dir`
            // was before the pending moves, and the folders files moved out
            // of; keep what lands in `dir`.
            let mut dirs = o.origins(dir);
            for m in &o.moves {
                let p = overlay::parent_of(&m.from).to_string();
                if !dirs.contains(&p) {
                    dirs.push(p);
                }
            }
            let mut landed: BTreeMap<String, Vec<pvfs_core::ViewEntry>> = BTreeMap::new();
            for d in dirs {
                for e in self.engine.merged_view(&d)? {
                    for piece in o.place(e) {
                        if overlay::parent_of(&piece.rel_path) == dir {
                            landed.entry(piece.rel_path.clone()).or_default().push(piece);
                        }
                    }
                }
            }
            let mut list: Vec<pvfs_core::ViewEntry> = landed
                .into_iter()
                .filter_map(|(rel, pieces)| Overlay::merge(&rel, pieces))
                .filter(Self::view_shown)
                .collect();
            for d in o.remembered_dirs_in(dir) {
                if !list.iter().any(|e| e.rel_path == d) {
                    list.push(overlay::remembered_dir(&d));
                }
            }
            // D217 — a file created through this mount is in the listing from
            // the moment it exists, not from the moment the watch job hashes
            // it: `ls` right after a write has to show it.
            for f in o.remembered_files_in(dir) {
                // PVOS D233 — a catalogued entry at the path hides the file
                // made here only while it is still shown: one a delete or a
                // rename onto it buried is not (the new file was invisible
                // until the catalogue caught up).
                if list.iter().any(|e| e.rel_path == f && self.without_the_deleted(e.clone()).is_some()) {
                    continue;
                }
                if let Some(path) = o.remembers_file(&f) {
                    if let Ok(m) = std::fs::metadata(&path) {
                        let mtime_ms = m
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_millis() as u64)
                            .unwrap_or(0);
                        list.push(overlay::remembered_file(&f, m.len(), mtime_ms));
                    }
                }
            }
            list.retain(|e| !o.is_gone(&e.rel_path));
            list.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
            list
        };
        drop(o);
        self.view_cache
            .insert(dir.to_string(), (std::time::Instant::now(), list.clone()));
        // A tombstone has done its work once the catalogue no longer lists
        // the path: drop it, so that a file which comes BACK — restored from
        // the trash, same hash — is not hidden by the memory of its delete.
        {
            let listed: HashSet<&str> = list.iter().map(|e| e.rel_path.as_str()).collect();
            let prefix = if dir.is_empty() { String::new() } else { format!("{dir}/") };
            self.tombstones.lock().unwrap().retain(|path, _| {
                let here = path.strip_prefix(&prefix).is_some_and(|rest| !rest.contains('/'));
                !here || listed.contains(path.as_str())
            });
        }
        Ok(list.into_iter().filter_map(|e| self.without_the_deleted(e)).collect())
    }

    fn view_entry_of(&mut self, rel: &str) -> Option<pvfs_core::ViewEntry> {
        let ov = Arc::clone(&self.overlay);
        let o = ov.lock().unwrap();
        let found = if o.is_empty() {
            self.engine.view_entry(rel).ok().flatten()
        } else if o.is_gone(rel) {
            return None; // a folder removed through this mount (D170)
        } else {
            let mut pieces = Vec::new();
            for q in o.origins(rel) {
                if let Some(e) = self.engine.view_entry(&q).ok().flatten() {
                    pieces.extend(o.place(e).into_iter().filter(|p| p.rel_path == rel));
                }
            }
            Overlay::merge(rel, pieces)
        };
        // D217 — a file this mount created, before the watch job has it.
        let made = |o: &Overlay| {
            let path = o.remembers_file(rel)?;
            let m = std::fs::metadata(&path).ok()?;
            let mtime_ms = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            Some(overlay::remembered_file(rel, m.len(), mtime_ms))
        };
        let Some(e) = found.filter(Self::view_shown) else {
            self.tombstones.lock().unwrap().remove(rel); // the catalogue has caught up
            return made(&o).or_else(|| o.remembers_dir(rel).then(|| overlay::remembered_dir(rel)));
        };
        // PVOS D233 — a catalogued file deleted (or renamed onto) through this
        // mount and a new file made at its path: the new one shows, not
        // nothing. D217 answered ENOENT for a file created where one had just
        // been deleted — an arr's delete-then-write of a subtitle.
        self.without_the_deleted(e).or_else(|| made(&o))
    }

    /// D170 — bring the session thread's tables up to date with what the
    /// overlay learned on other threads (a remote rename finishes on its
    /// own), and ask the catalogue — at most every two seconds — whether it
    /// has caught up with what is remembered.
    fn sync_overlay(&mut self) {
        let ov = Arc::clone(&self.overlay);
        let mut o = ov.lock().unwrap();
        if o.is_empty() && o.ino_moves.is_empty() && !o.dirty {
            return;
        }
        if self.overlay_pruned.elapsed() > Duration::from_secs(2) {
            o.prune(&self.engine);
            self.overlay_pruned = std::time::Instant::now();
        }
        let ino_moves = std::mem::take(&mut o.ino_moves);
        let dirty = std::mem::take(&mut o.dirty);
        drop(o);
        for (from, to) in &ino_moves {
            self.move_inodes(from, to);
        }
        if dirty || !ino_moves.is_empty() {
            self.view_cache.clear();
        }
    }

    /// The kernel's inode for a renamed path is still the file: the table
    /// follows the rename, a folder's whole subtree with it.
    fn move_inodes(&mut self, from: &str, to: &str) {
        let moved: Vec<(String, String, u64)> = self
            .path_to_ino
            .iter()
            .filter_map(|(p, i)| overlay::rebase(p, from, to).map(|n| (p.clone(), n, *i)))
            .collect();
        for (old, new, ino) in moved {
            self.path_to_ino.remove(&old);
            if let Some(replaced) = self.path_to_ino.insert(new.clone(), ino) {
                if replaced != ino {
                    self.ino_to_path.remove(&replaced);
                }
            }
            self.ino_to_path.insert(ino, new);
        }
    }

    /// D169 — an entry minus the copies a delete through this mount already
    /// sent to the trash: gone when none is left, and otherwise judged on
    /// what remains (a new file at the path — another hash — shows).
    fn without_the_deleted(&self, mut e: pvfs_core::ViewEntry) -> Option<pvfs_core::ViewEntry> {
        if e.kind == "dir" {
            return Some(e);
        }
        let mut tombs = self.tombstones.lock().unwrap();
        let Some(tomb) = tombs.get(&e.rel_path).cloned() else {
            return Some(e);
        };
        let is_dead = |c: &pvfs_core::ViewCopy| c.content_hash.as_ref().is_some_and(|h| tomb.dead.contains(h));
        let lingering: Vec<&pvfs_core::ViewCopy> = e.sources.iter().filter(|c| is_dead(c)).collect();
        // A holder that has PUBLISHED since the delete and still lists the
        // file has the file: it was restored (or the delete never reached
        // it). What this box held at the delete is the mark to beat.
        let republished = !lingering.is_empty() && {
            let now: HashMap<String, u64> = self
                .engine
                .catalogue_status()
                .map(|s| s.into_iter().filter_map(|r| r.held_seq.map(|q| (r.region, q))).collect())
                .unwrap_or_default();
            lingering
                .iter()
                .any(|c| now.get(&c.region).copied().unwrap_or(0) > tomb.held.get(&c.region).copied().unwrap_or(u64::MAX))
        };
        if lingering.is_empty() || republished || tomb.at.elapsed() > tomb.ttl {
            tombs.remove(&e.rel_path); // the catalogue has caught up, the file is back, or it is too old to trust
            return Some(e);
        }
        e.sources.retain(|c| !is_dead(c));
        // judged again on what remains: a file renamed onto this path (D170)
        // is one admitted copy, not a conflict with the file it replaced
        Engine::view_entry_of_copies(&e.rel_path, &e.sources).filter(Self::view_shown)
    }

    /// D169 — `unlink` in the view: every copy the view shows at the path
    /// goes to ITS region's trash, on the box that holds it — soft, kept for
    /// the region's retention, restorable (`pvfs trash restore`). Ours here
    /// and now; the others are asked off the session thread (D165).
    fn view_unlink(&mut self, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(parent_path) = self.ino_to_path.get(&parent).cloned() else {
            return reply.error(libc::ENOENT);
        };
        let Some(name) = name.to_str() else {
            return reply.error(libc::ENOENT);
        };
        let rel = Self::view_join(&parent_path, name);
        let Some(entry) = self.view_entry_of(&rel) else {
            return reply.error(libc::ENOENT);
        };
        if entry.kind == "dir" {
            return reply.error(libc::EISDIR);
        }
        // PVOS D233 — a file this mount WROTE (made here, or edited since the
        // catalogue last hashed it) goes to its region's trash from where it
        // is, whatever the catalogue says of its bytes: a just-created file
        // has no row to check it against, and an edited one no longer matches
        // its row. D217 unlinked a just-created file outright — no trash, for
        // as long as it was uncatalogued (D218 §2.1 item 4); every other
        // deletion through PVFS is soft (D145, D169).
        let mut dead: HashSet<String> = HashSet::new();
        let written = self.overlay.lock().unwrap().written(&rel);
        if let Some(w) = &written {
            if std::fs::symlink_metadata(&w.path).is_ok() {
                match pvfs_core::sync::move_to_trash_with_sidecar(&w.root, &w.path) {
                    Ok(to) => {
                        pv_info!("pvfs.mount.deleted", path = content(&rel), trash_path = content(to.display());
                            "mount: delete of {rel} — the file written here is in the trash at {}", to.display());
                    }
                    Err(e) => {
                        pv_error!("pvfs.mount.delete_failed", path = content(&rel), error = content(&e);
                            "mount: delete of {rel} failed: {e}");
                        return reply.error(libc::EIO);
                    }
                }
            }
            // what the catalogue still lists for it there is dead too
            dead.extend(entry.sources.iter().filter(|c| c.region == w.region).filter_map(|c| c.content_hash.clone()));
            self.overlay.lock().unwrap().forget_written(&rel);
            self.view_cache.clear();
        }
        let copies: Vec<(String, String)> = entry
            .sources
            .iter()
            .filter(|c| c.kind == "file")
            .filter(|c| written.as_ref().is_none_or(|w| w.region != c.region))
            .filter_map(|c| c.content_hash.clone().map(|h| (c.region.clone(), h)))
            .collect();
        if copies.is_empty() && written.is_none() {
            return reply.error(libc::EIO);
        }
        let mut elsewhere: Vec<(String, String)> = Vec::new();
        for (region, hash) in copies {
            match self.engine.trash_region_path(&region, &rel, &hash) {
                Ok(pvfs_core::TrashedHere::Trashed(to)) => {
                    pv_info!("pvfs.mount.deleted", path = content(&rel), trash_path = content(to.display());
                        "mount: delete of {rel} — this box's copy is in the trash at {}", to.display());
                    dead.insert(hash);
                }
                Ok(pvfs_core::TrashedHere::Gone) => {
                    dead.insert(hash);
                }
                Ok(pvfs_core::TrashedHere::NotHere) => elsewhere.push((region, hash)),
                Ok(pvfs_core::TrashedHere::Changed) | Err(_) => {
                    pv_warn!("pvfs.mount.delete_refused", path = content(&rel), error_kind = "data:changed";
                        "mount: delete of {rel} refused — this box's copy is not the file the view showed");
                    return reply.error(libc::EIO);
                }
            }
        }
        let tombs = Arc::clone(&self.tombstones);
        let held: HashMap<String, u64> = self
            .engine
            .catalogue_status()
            .map(|s| s.into_iter().filter_map(|r| r.held_seq.map(|q| (r.region, q))).collect())
            .unwrap_or_default();
        let bury = move |rel: String, dead: HashSet<String>| {
            let tomb = Tomb {
                dead,
                at: std::time::Instant::now(),
                held,
                ttl: TOMBSTONE_TTL,
            };
            tombs.lock().unwrap().insert(rel, tomb);
        };
        if elsewhere.is_empty() {
            bury(rel, dead);
            return reply.ok();
        }
        let sources = self.view_sources.clone();
        let data_dir = self.data_dir.clone();
        std::thread::spawn(move || {
            let sources = sources.unwrap_or_else(|| pvfs_client::hash_cache::announced_sources(&data_dir));
            match pvfs_client::hash_cache::trash_elsewhere(&sources, &rel, &elsewhere) {
                Ok(()) => {
                    pv_info!("pvfs.mount.deleted", path = content(&rel), copies = elsewhere.len();
                        "mount: delete of {rel} — {} copy(ies) moved to their boxes' trash", elsewhere.len());
                    dead.extend(elsewhere.into_iter().map(|(_, h)| h));
                    bury(rel, dead);
                    reply.ok();
                }
                Err(e) => {
                    pv_error!("pvfs.mount.delete_failed", path = content(&rel), error = content(&e);
                        "mount: delete of {rel} failed: {e}");
                    reply.error(libc::EIO);
                }
            }
        });
    }

    /// D170 — `rename` in the view: every copy the view shows at `from` is
    /// renamed by the box that holds it, on its own disk (ours here and now;
    /// the others off the session thread); a file already at `to` goes to
    /// the trash first, as `unlink` sends it. Then this mount REMEMBERS the
    /// move until the catalogue agrees — a verified move stats the target
    /// within the second, and the catalogue takes the holder's pass and our
    /// fetch.
    #[allow(clippy::too_many_arguments)]
    fn view_rename(&mut self, parent: u64, name: &OsStr, newparent: u64, newname: &OsStr, flags: u32, reply: ReplyEmpty) {
        let (Some(from_dir), Some(to_dir)) =
            (self.ino_to_path.get(&parent).cloned(), self.ino_to_path.get(&newparent).cloned())
        else {
            return reply.error(libc::ENOENT);
        };
        let (Some(name), Some(newname)) = (name.to_str(), newname.to_str()) else {
            return reply.error(libc::EINVAL);
        };
        let (from, to) = (Self::view_join(&from_dir, name), Self::view_join(&to_dir, newname));
        if flags & libc::RENAME_EXCHANGE != 0 {
            return reply.error(libc::EINVAL);
        }
        let Some(entry) = self.view_entry_of(&from) else {
            return reply.error(libc::ENOENT);
        };
        if from == to {
            return reply.ok();
        }
        let is_dir = entry.kind == "dir";
        if is_dir && overlay::rebase(&to, &from, &from).is_some() {
            return reply.error(libc::EINVAL); // into itself
        }
        if pvfs_core::sync::is_own_name(newname, is_dir) || pvfs_core::sync::is_litter_name(newname) {
            pv_warn!("pvfs.mount.rename_refused", path = content(&from), name = content(newname), error_kind = "data:reserved_name";
                "mount: rename of {from} refused — `{newname}` is a name the catalogue passes over");
            return reply.error(libc::EPERM);
        }
        // PVOS D233 — a file this mount wrote (made, or edited since the last
        // hash) moves on its own disk with no check of its bytes against a
        // row: a just-created file has none, and an edited one no longer
        // matches its own. D217 answered EIO, and every write-a-temp-then-
        // rename tool failed and left its temp behind (D218 §2.1 item 5).
        let written_from = if is_dir { None } else { self.overlay.lock().unwrap().written(&from) };
        // What is at `to`.
        let mut replaced: Vec<(String, String)> = Vec::new();
        let mut written_to: Option<(overlay::Written, HashSet<String>)> = None;
        if let Some(target) = self.view_entry_of(&to) {
            if flags & libc::RENAME_NOREPLACE != 0 {
                return reply.error(libc::EEXIST);
            }
            match (is_dir, target.kind == "dir") {
                (true, false) => return reply.error(libc::ENOTDIR),
                (false, true) => return reply.error(libc::EISDIR),
                (true, true) => {
                    // Only a folder nobody holds (made here, still empty) is replaced.
                    let empty = self.view_list(&to).map(|l| l.is_empty()).unwrap_or(false);
                    if !target.sources.is_empty() || !empty {
                        return reply.error(libc::ENOTEMPTY);
                    }
                }
                (false, false) => {
                    // PVOS D233 — a file written here goes to its region's
                    // trash from where it is (the rows there are dead too).
                    written_to = self.overlay.lock().unwrap().written(&to).map(|w| {
                        let dead: HashSet<String> = target
                            .sources
                            .iter()
                            .filter(|c| c.region == w.region)
                            .filter_map(|c| c.content_hash.clone())
                            .collect();
                        (w, dead)
                    });
                    replaced = target
                        .sources
                        .iter()
                        .filter(|c| c.kind == "file")
                        .filter(|c| written_to.as_ref().is_none_or(|(w, _)| w.region != c.region))
                        .filter_map(|c| c.content_hash.clone().map(|h| (c.region.clone(), h)))
                        .collect();
                    if replaced.is_empty() && written_to.is_none() {
                        return reply.error(libc::EIO);
                    }
                }
            }
        }
        let copies: Vec<RenameCopy> = if is_dir {
            let mut v: Vec<RenameCopy> =
                entry.sources.iter().filter(|c| c.kind == "dir").map(|c| (c.region.clone(), None)).collect();
            // PVOS D233 — and every region holding a file written here under
            // it, which the catalogue may not list the folder in yet: the
            // file must move with its folder (as `rmdir` reaches `made_regions`).
            for r in self.overlay.lock().unwrap().written_regions_under(&from) {
                if !v.iter().any(|c| c.0 == r) {
                    v.push((r, None));
                }
            }
            v
        } else {
            entry
                .sources
                .iter()
                .filter(|c| c.kind == "file")
                .filter(|c| written_from.as_ref().is_none_or(|w| w.region != c.region))
                .filter_map(|c| c.content_hash.clone().map(|h| (c.region.clone(), Some((h, c.size_bytes)))))
                .collect()
        };
        // A file move carries the hashes that moved, so a NEW file at the old
        // name is not dragged along; a folder takes everything under it.
        // PVOS D233 — a written file's own rows move with it (the rows follow
        // the rename on disk), so its hash is one that moved, not one buried.
        let moved_hashes: Option<HashSet<String>> = (!is_dir).then(|| {
            let mut hs: HashSet<String> = copies.iter().filter_map(|c| c.1.as_ref().map(|(h, _)| h.clone())).collect();
            if let Some(w) = &written_from {
                hs.extend(entry.sources.iter().filter(|c| c.region == w.region).filter_map(|c| c.content_hash.clone()));
            }
            hs
        });
        let moved_regions: HashSet<String> = copies.iter().map(|c| c.0.clone()).collect();
        let overlay = Arc::clone(&self.overlay);
        if copies.is_empty() && written_from.is_none() {
            if !is_dir {
                return reply.error(libc::EIO);
            }
            // A folder only this mount remembers: nobody to ask.
            let mut o = overlay.lock().unwrap();
            o.rename_made_dirs(&from, &to);
            o.ino_moves.push((from, to));
            o.dirty = true;
            return reply.ok();
        }
        let expect = |c: &RenameCopy| match &c.1 {
            Some((hash, size)) => pvfs_core::RenameExpect::File { hash: hash.clone(), size: *size },
            None => pvfs_core::RenameExpect::Dir,
        };

        // 1. What is in the way goes to the trash (ours now).
        let mut dead: HashSet<String> = HashSet::new();
        if let Some((w, rows)) = &written_to {
            if std::fs::symlink_metadata(&w.path).is_ok() {
                if let Err(e) = pvfs_core::sync::move_to_trash_with_sidecar(&w.root, &w.path) {
                    pv_error!("pvfs.mount.rename_failed", path = content(&from), new_path = content(&to), error = content(&e);
                        "mount: rename of {from} failed — the file written at {to} could not be trashed: {e}");
                    return reply.error(libc::EIO);
                }
            }
            dead.extend(rows.iter().cloned());
            overlay.lock().unwrap().forget_written(&to);
        }
        let mut replaced_elsewhere: Vec<(String, String)> = Vec::new();
        for (region, hash) in replaced {
            match self.engine.trash_region_path(&region, &to, &hash) {
                Ok(pvfs_core::TrashedHere::Trashed(_) | pvfs_core::TrashedHere::Gone) => {
                    dead.insert(hash);
                }
                Ok(pvfs_core::TrashedHere::NotHere) => replaced_elsewhere.push((region, hash)),
                Ok(pvfs_core::TrashedHere::Changed) | Err(_) => {
                    pv_warn!("pvfs.mount.rename_refused", new_path = content(&to), error_kind = "data:changed";
                        "mount: rename onto {to} refused — this box's copy there is not the file the view showed");
                    return reply.error(libc::EIO);
                }
            }
        }
        // 2. Our own copies — a file written here first.
        let mut done_here: Vec<RenameCopy> = Vec::new();
        let mut elsewhere: Vec<RenameCopy> = Vec::new();
        let mut moved_any = false;
        let mut written_moved: Option<overlay::Written> = None;
        if let Some(w) = &written_from {
            match self.engine.rename_written_path(&w.region, &w.root, &from, &to) {
                Ok(pvfs_core::RenamedHere::Moved | pvfs_core::RenamedHere::AlreadyDone) => {
                    moved_any = true;
                    written_moved = Some(w.clone());
                }
                Ok(pvfs_core::RenamedHere::Gone) => {}
                other => {
                    pv_warn!("pvfs.mount.rename_refused", path = content(&from), error = content(format!("{other:?}"));
                        "mount: rename of {from} refused here: {other:?}");
                    return reply.error(libc::EIO);
                }
            }
        }
        for c in copies {
            match self.engine.rename_region_path(&c.0, &from, &to, &expect(&c)) {
                Ok(pvfs_core::RenamedHere::Moved) => {
                    moved_any = true;
                    done_here.push(c);
                }
                Ok(pvfs_core::RenamedHere::AlreadyDone) => moved_any = true,
                Ok(pvfs_core::RenamedHere::Gone) => {}
                Ok(pvfs_core::RenamedHere::NotHere) => elsewhere.push(c),
                other => {
                    pv_warn!("pvfs.mount.rename_refused", path = content(&from), error = content(format!("{other:?}"));
                        "mount: rename of {from} refused here: {other:?}");
                    for d in &done_here {
                        let _ = self.engine.rename_region_path(&d.0, &to, &from, &expect(d));
                    }
                    if let Some(w) = &written_moved {
                        let _ = self.engine.rename_written_path(&w.region, &w.root, &to, &from);
                    }
                    return reply.error(libc::EIO);
                }
            }
        }
        let held = overlay::held_seqs(&self.engine);
        let tombs = Arc::clone(&self.tombstones);
        let written_was_moved = written_moved.is_some();
        let remember = {
            let (from, to) = (from.clone(), to.clone());
            move |mut dead: HashSet<String>| {
                if let Some(moved) = &moved_hashes {
                    dead.retain(|h| !moved.contains(h)); // its twin: the same bytes, showing either is right
                }
                if !dead.is_empty() {
                    let tomb = Tomb { dead, at: std::time::Instant::now(), held: held.clone(), ttl: TOMBSTONE_TTL };
                    tombs.lock().unwrap().insert(to.clone(), tomb);
                }
                if moved_hashes.is_none() {
                    // a delete remembered under the old name is one under the new
                    overlay::rekey(&mut tombs.lock().unwrap(), &from, &to);
                }
                let mut o = overlay.lock().unwrap();
                if moved_hashes.is_none() {
                    o.rename_made_dirs(&from, &to);
                    o.rename_written_under(&from, &to);
                } else if written_was_moved {
                    o.rename_written(&from, &to);
                }
                o.made_dirs.remove(&to);
                // the holders made the folders on the way to `to`: a folder
                // made here is real on their disks now
                o.moved_into(&to, &moved_regions);
                o.moves.push(Move { from: from.clone(), to: to.clone(), hashes: moved_hashes, at: std::time::Instant::now(), held });
                o.ino_moves.push((from, to));
                o.dirty = true;
            }
        };
        if elsewhere.is_empty() && replaced_elsewhere.is_empty() {
            if !moved_any {
                return reply.error(libc::ENOENT); // the catalogue lists it; no disk has it
            }
            remember(dead);
            return reply.ok();
        }
        // 3. The rest, on the boxes that hold them — off the session thread (D165).
        let sources = self.view_sources.clone();
        let data_dir = self.data_dir.clone();
        std::thread::spawn(move || {
            let sources = sources.unwrap_or_else(|| pvfs_client::hash_cache::announced_sources(&data_dir));
            let put_back_here = |done_here: &[RenameCopy]| {
                if done_here.is_empty() && written_moved.is_none() {
                    return;
                }
                if let Ok(engine) = Engine::open(&data_dir) {
                    for d in done_here {
                        let _ = engine.rename_region_path(&d.0, &to, &from, &expect(d));
                    }
                    if let Some(w) = &written_moved {
                        let _ = engine.rename_written_path(&w.region, &w.root, &to, &from);
                    }
                }
            };
            if let Err(e) = pvfs_client::hash_cache::trash_elsewhere(&sources, &to, &replaced_elsewhere) {
                pv_error!("pvfs.mount.rename_failed", path = content(&from), new_path = content(&to), error = content(&e);
                    "mount: rename of {from} failed — what is at {to} could not be trashed: {e}");
                put_back_here(&done_here);
                return reply.error(libc::EIO);
            }
            dead.extend(replaced_elsewhere.into_iter().map(|(_, h)| h));
            match pvfs_client::hash_cache::rename_elsewhere(&sources, &from, &to, &elsewhere) {
                Ok(()) => {
                    pv_info!("pvfs.mount.renamed", path = content(&from), new_path = content(&to), copies = elsewhere.len();
                        "mount: rename of {from} → {to} — {} copy(ies) renamed on their boxes", elsewhere.len());
                    remember(dead);
                    reply.ok();
                }
                Err((why, done)) => {
                    pv_error!("pvfs.mount.rename_failed", path = content(&from), error = content(&why);
                        "mount: rename of {from} failed: {why}");
                    if done > 0 {
                        if let Err((e, _)) = pvfs_client::hash_cache::rename_elsewhere(&sources, &to, &from, &elsewhere[..done]) {
                            pv_error!("pvfs.mount.rename_unrolled", copies = done, error = content(&e);
                                "mount: and {done} copy(ies) already renamed could not be put back: {e}");
                        }
                    }
                    put_back_here(&done_here);
                    reply.error(libc::EIO);
                }
            }
        });
    }

    /// D170 — `mkdir` in the view: a folder this mount remembers, and nobody
    /// holds. mergerfs clones a rename's target path onto the source's
    /// branch first, and an arr's new season folder exists on `/mnt/local`
    /// only; the holder makes the real folder when a file is renamed into it.
    fn view_mkdir(&mut self, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let Some(parent_path) = self.ino_to_path.get(&parent).cloned() else {
            return reply.error(libc::ENOENT);
        };
        let Some(name) = name.to_str() else {
            return reply.error(libc::EINVAL);
        };
        if pvfs_core::sync::is_own_name(name, true) || pvfs_core::sync::is_litter_name(name) {
            return reply.error(libc::EPERM);
        }
        let rel = Self::view_join(&parent_path, name);
        if self.view_entry_of(&rel).is_some() {
            return reply.error(libc::EEXIST);
        }
        self.overlay.lock().unwrap().made(&rel);
        self.view_cache.clear();
        let attr = self.view_attr(&overlay::remembered_dir(&rel));
        reply.entry(&TTL, &attr, 0)
    }

    /// D170 — `rmdir` in the view: a folder the view shows as empty is
    /// removed on every box that has it (what the view hides — PVFS's own
    /// names, litter — goes to that box's trash); then hidden here until the
    /// catalogue agrees.
    fn view_rmdir(&mut self, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(parent_path) = self.ino_to_path.get(&parent).cloned() else {
            return reply.error(libc::ENOENT);
        };
        let Some(name) = name.to_str() else {
            return reply.error(libc::ENOENT);
        };
        let rel = Self::view_join(&parent_path, name);
        let Some(entry) = self.view_entry_of(&rel) else {
            return reply.error(libc::ENOENT);
        };
        if entry.kind != "dir" {
            return reply.error(libc::ENOTDIR);
        }
        match self.view_list(&rel) {
            Ok(l) if l.is_empty() => {}
            Ok(_) => return reply.error(libc::ENOTEMPTY),
            Err(_) => return reply.error(libc::EIO),
        }
        // Every region the view shows the folder in — and, for a folder made
        // here, every region whose holder made it real when something was
        // renamed into it (the catalogue does not say so yet).
        let mut regions: Vec<String> = entry.sources.iter().map(|c| c.region.clone()).collect();
        for r in self.overlay.lock().unwrap().made_regions(&rel) {
            if !regions.contains(&r) {
                regions.push(r);
            }
        }
        let mut elsewhere: Vec<String> = Vec::new();
        for region in regions.iter().cloned() {
            match self.engine.remove_region_dir(&region, &rel) {
                Ok(pvfs_core::DirRemovedHere::Removed | pvfs_core::DirRemovedHere::Gone) => {}
                Ok(pvfs_core::DirRemovedHere::NotHere) => elsewhere.push(region),
                Ok(pvfs_core::DirRemovedHere::NotEmpty) => return reply.error(libc::ENOTEMPTY),
                Err(e) => {
                    pv_error!("pvfs.mount.rmdir_failed", path = content(&rel), error = content(&e);
                        "mount: rmdir of {rel} failed here: {e}");
                    return reply.error(libc::EIO);
                }
            }
        }
        let overlay = Arc::clone(&self.overlay);
        let held = if regions.is_empty() { HashMap::new() } else { overlay::held_seqs(&self.engine) };
        let listed = !regions.is_empty();
        let forget = move |rel: String| {
            let mut o = overlay.lock().unwrap();
            o.made_dirs.remove(&rel);
            if listed {
                o.gone_dirs.insert(rel, GoneDir { at: std::time::Instant::now(), held });
            }
            o.dirty = true;
        };
        if elsewhere.is_empty() {
            forget(rel);
            return reply.ok();
        }
        let sources = self.view_sources.clone();
        let data_dir = self.data_dir.clone();
        std::thread::spawn(move || {
            let sources = sources.unwrap_or_else(|| pvfs_client::hash_cache::announced_sources(&data_dir));
            match pvfs_client::hash_cache::rmdir_elsewhere(&sources, &rel, &elsewhere) {
                Ok(()) => {
                    pv_info!("pvfs.mount.dir_removed", path = content(&rel);
                        "mount: rmdir of {rel} — removed on the box(es) that held it");
                    forget(rel);
                    reply.ok();
                }
                Err(e) if e.contains(": not_empty: ") => {
                    pv_warn!("pvfs.mount.rmdir_refused", path = content(&rel), error = content(&e);
                        "mount: rmdir of {rel} refused: {e}");
                    reply.error(libc::ENOTEMPTY);
                }
                Err(e) => {
                    pv_error!("pvfs.mount.rmdir_failed", path = content(&rel), error = content(&e);
                        "mount: rmdir of {rel} failed: {e}");
                    reply.error(libc::EIO);
                }
            }
        });
    }

    /// The copy a file entry serves: hash, size, mtime.
    fn view_served(e: &pvfs_core::ViewEntry) -> Option<(String, u64, u64)> {
        Engine::served_copy(e, &pvfs_core::media::Rules::default())
            .and_then(|c| c.content_hash.clone().map(|h| (h, c.size_bytes, c.mtime_ms)))
    }

    fn view_attr(&mut self, e: &pvfs_core::ViewEntry) -> FileAttr {
        let ino = self.view_ino(&e.rel_path);
        // D170 — 0755 / 0644, not 0555 / 0444: the namespace takes renames and
        // deletes now, and the bits should say so. An arr (.NET) reads a file
        // without its owner's write bit as ReadOnly and chmods it before every
        // move; a file manager greys the operations out. Bytes still do not
        // come through: a write-open is refused whatever the mode says.
        let (kind, size, mtime, perm) = if e.kind == "dir" {
            (FileType::Directory, 0, e.mtime_ms, 0o755)
        } else {
            // PVOS D233 — a file written through this mount answers from its
            // disk until the catalogue has caught up with it: the catalogue's
            // size is the bytes before the write, and the kernel takes it
            // again after `TTL` — an append read back a second later came
            // back cut to the old length.
            let (size, mtime) = self
                .written_attrs(&e.rel_path)
                .or_else(|| Self::view_served(e).map(|(_, s, m)| (s, m)))
                .unwrap_or((e.size_bytes, e.mtime_ms));
            (FileType::RegularFile, size, mtime, 0o644)
        };
        self.plain_attr(ino, kind, size, mtime, perm)
    }

    /// PVOS D233 — the size and mtime (ms) on disk of a file this mount wrote
    /// and the catalogue has not caught up with.
    fn written_attrs(&self, rel: &str) -> Option<(u64, u64)> {
        let o = self.overlay.lock().unwrap();
        if o.made_files.is_empty() && o.edited_files.is_empty() {
            return None;
        }
        let w = o.written(rel)?;
        drop(o);
        let m = std::fs::metadata(&w.path).ok()?;
        let mtime_ms = m
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Some((m.len(), mtime_ms))
    }

    fn plain_attr(&self, ino: u64, kind: FileType, size: u64, mtime_ms: u64, perm: u16) -> FileAttr {
        let ts = SystemTime::UNIX_EPOCH + Duration::from_millis(mtime_ms);
        FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: ts,
            mtime: ts,
            ctime: ts,
            crtime: ts,
            kind,
            perm,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }

    fn view_join(parent: &str, name: &str) -> String {
        if parent.is_empty() {
            name.to_string()
        } else {
            format!("{parent}/{name}")
        }
    }

    /// PVOS D210 — the boxes that hold `hash` for this entry, as endpoint
    /// addresses: each copy with that hash names its region, and the
    /// catalogue knows which box serves that region's manifest (in the
    /// view's order of the copies). Empty when the catalogue does not know —
    /// the read then asks the fleet in turn, as before.
    fn holders_of(&self, entry: &pvfs_core::ViewEntry, hash: &str) -> Vec<String> {
        let Ok(by_region) = self.engine.region_holders() else {
            return Vec::new();
        };
        let mut out: Vec<String> = Vec::new();
        for c in entry.sources.iter().filter(|c| c.content_hash.as_deref() == Some(hash)) {
            if let Some(addr) = by_region.get(&c.region) {
                if !out.contains(addr) {
                    out.push(addr.clone());
                }
            }
        }
        out
    }

    /// PVOS D220 — remember an open view file's attributes for `getattr`
    /// (see `open_attrs`).
    fn note_open(&mut self, ino: u64, fh: u64) {
        let Some(rel) = self.ino_to_path.get(&ino).cloned() else { return };
        let Some(entry) = self.view_entry_of(&rel) else { return };
        let attr = self.view_attr(&entry);
        self.open_attrs.entry(ino).or_insert((attr, 0)).1 += 1;
        self.open_inos.insert(fh, ino);
    }

    /// D130 §3.2 — open a view file: this box's own disk, the hash store,
    /// else a read-through. D165: the read-through fetches the pieces a
    /// read asks for, not the file — `open` starts nothing.
    fn view_open(&mut self, rel: &str) -> Result<u64, i32> {
        let entry = self.view_entry_of(rel).ok_or(libc::ENOENT)?;
        if entry.kind == "dir" {
            return Err(libc::EISDIR);
        }
        // D217 — a file created through this mount has no catalogued hash yet;
        // its bytes are where `create` put them. PVOS D233 — and a file edited
        // through it reads from itself until the catalogue has hashed it again.
        let written = self.overlay.lock().unwrap().written(rel);
        if let Some(w) = written {
            match std::fs::File::open(&w.path) {
                Ok(f) => {
                    let fh = self.next_fh;
                    self.next_fh += 1;
                    self.handles.insert(fh, f);
                    return Ok(fh);
                }
                Err(_) if w.made => return Err(libc::EIO),
                Err(_) => {} // gone from its disk: the catalogue's copies answer
            }
        }
        let (hash, size, _) = Self::view_served(&entry).ok_or(libc::EIO)?;
        let fh = self.next_fh;
        // PVOS D233 — this box's own copy AT THIS PATH first (when it is still
        // the catalogued bytes), then any file here with the same bytes.
        let local = self
            .engine
            .local_copy_at(rel, &hash)
            .ok()
            .flatten()
            .filter(|lb| lb.size == size)
            .or_else(|| self.engine.local_path_for_hash(&hash).ok().flatten());
        if let Some(lb) = local {
            let f = std::fs::File::open(&lb.path).map_err(|_| libc::EIO)?;
            self.next_fh += 1;
            self.handles.insert(fh, f);
            return Ok(fh);
        }
        let prefer = self.holders_of(&entry, &hash);
        // PVOS D219 — what this box holds of the regions the read may find gone.
        let held: HashMap<String, u64> = {
            let fetched = self.engine.fetched_seqs().unwrap_or_default();
            entry
                .sources
                .iter()
                .filter(|c| c.content_hash.as_deref() == Some(hash.as_str()))
                .filter_map(|c| fetched.get(&c.region).map(|q| (c.region.clone(), *q)))
                .collect()
        };
        let cache = self.hash_cache.as_ref().ok_or(libc::EIO)?;
        match cache.open_preferring(&hash, size, &prefer).map_err(|_| libc::EIO)? {
            Opened::Local(path) => {
                let f = match std::fs::File::open(&path) {
                    Ok(f) => f,
                    Err(_) => {
                        cache.close_local(&hash);
                        return Err(libc::EIO);
                    }
                };
                self.handles.insert(fh, f);
                self.hash_pins.insert(fh, hash);
            }
            Opened::Stream(fetch) => {
                self.hash_streams.insert(fh, HashStream { fetch, file: None, rel: rel.to_string(), held });
            }
        }
        self.next_fh += 1;
        Ok(fh)
    }
}

fn reply_read_at(f: &std::fs::File, offset: u64, size: u32, reply: ReplyData) {
    use std::os::unix::fs::FileExt;
    let mut buf = vec![0u8; size as usize];
    match f.read_at(&mut buf, offset) {
        Ok(n) => {
            buf.truncate(n);
            reply.data(&buf);
        }
        Err(_) => reply.error(libc::EIO),
    }
}

/// PVOS D219 — the errno for a read-through read that failed: ENOENT when
/// every box said the bytes are gone (the copy is hidden from then on),
/// else EIO.
fn read_failed(tombs: &Tombstones, hs: &HashStream) -> i32 {
    if hs.fetch.gone() {
        bury_gone(tombs, &hs.rel, hs.fetch.hash(), &hs.held);
        libc::ENOENT
    } else {
        libc::EIO
    }
}

fn enoent<E>(_e: E) -> i32 {
    libc::ENOENT
}

impl Filesystem for PvfsFs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if self.view {
            self.sync_overlay();
            let Some(parent_path) = self.ino_to_path.get(&parent).cloned() else {
                return reply.error(libc::ENOENT);
            };
            let Some(name) = name.to_str() else {
                return reply.error(libc::ENOENT);
            };
            let rel = Self::view_join(&parent_path, name);
            return match self.view_entry_of(&rel) {
                Some(e) => {
                    let attr = self.view_attr(&e);
                    reply.entry(&TTL, &attr, 0)
                }
                None => reply.error(libc::ENOENT),
            };
        }
        let Some(parent_node) = self.ino_to_node.get(&parent).cloned() else {
            return reply.error(libc::ENOENT);
        };
        let Some(name) = name.to_str() else {
            return reply.error(libc::ENOENT);
        };
        let children = match self.engine.children(&parent_node) {
            Ok(c) => c,
            Err(e) => return reply.error(enoent(e)),
        };
        match children.into_iter().find(|c| c.label == name) {
            Some(c) => match self.attr_for(&c.node.id.clone()) {
                Ok(attr) => reply.entry(&TTL, &attr, 0),
                Err(e) => reply.error(enoent(e)),
            },
            None => reply.error(libc::ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        if self.view {
            self.sync_overlay();
            if ino == 1 {
                let attr = self.plain_attr(1, FileType::Directory, 0, 0, 0o755);
                return reply.attr(&TTL, &attr);
            }
            let Some(rel) = self.ino_to_path.get(&ino).cloned() else {
                return reply.error(libc::ENOENT);
            };
            return match self.view_entry_of(&rel) {
                Some(e) => {
                    let attr = self.view_attr(&e);
                    reply.attr(&TTL, &attr)
                }
                // PVOS D220 — gone from the view but open here: what it was.
                None => match self.open_attrs.get(&ino) {
                    Some((attr, _)) => reply.attr(&TTL, attr),
                    None => reply.error(libc::ENOENT),
                },
            };
        }
        let Some(node) = self.ino_to_node.get(&ino).cloned() else {
            return reply.error(libc::ENOENT);
        };
        match self.attr_for(&node) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => reply.error(enoent(e)),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if self.view {
            self.sync_overlay();
            let Some(dir) = self.ino_to_path.get(&ino).cloned() else {
                return reply.error(libc::ENOENT);
            };
            let list = match self.view_list(&dir) {
                Ok(l) => l,
                Err(_) => return reply.error(libc::EIO),
            };
            let mut entries: Vec<(u64, FileType, String)> = vec![
                (ino, FileType::Directory, ".".into()),
                (1, FileType::Directory, "..".into()),
            ];
            for e in &list {
                let kind = if e.kind == "dir" { FileType::Directory } else { FileType::RegularFile };
                let child_ino = self.view_ino(&e.rel_path);
                let name = e.rel_path.rsplit('/').next().unwrap_or(&e.rel_path).to_string();
                entries.push((child_ino, kind, name));
            }
            for (i, (child_ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
                if reply.add(child_ino, (i + 1) as i64, kind, name) {
                    break;
                }
            }
            return reply.ok();
        }
        let Some(node) = self.ino_to_node.get(&ino).cloned() else {
            return reply.error(libc::ENOENT);
        };
        let children = match self.engine.children(&node) {
            Ok(c) => c,
            Err(e) => return reply.error(enoent(e)),
        };
        let mut entries: Vec<(u64, FileType, String)> = vec![
            (ino, FileType::Directory, ".".into()),
            (1, FileType::Directory, "..".into()),
        ];
        for c in children {
            let kind = if c.node.node_type == TYPE_FILE {
                FileType::RegularFile
            } else {
                FileType::Directory
            };
            let child_ino = self.ino_of(&c.node.id);
            entries.push((child_ino, kind, c.label));
        }
        for (i, (child_ino, kind, name)) in
            entries.into_iter().enumerate().skip(offset as usize)
        {
            if reply.add(child_ino, (i + 1) as i64, kind, name) {
                break; // buffer full
            }
        }
        reply.ok();
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        if flags & libc::O_ACCMODE != libc::O_RDONLY {
            // D217 tier 1 — an edit is allowed only where this box already
            // holds the bytes: the write then goes straight to the real file
            // and the `watch` job re-hashes it, with no fetch and no copy-up.
            // Anything else stays EROFS, deliberately (see D217 §4).
            return match self.open_for_write(ino) {
                Ok(fh) => {
                    self.note_open(ino, fh);
                    reply.opened(fh, 0)
                }
                Err(e) => reply.error(e),
            };
        }
        if self.view {
            self.sync_overlay();
            let Some(rel) = self.ino_to_path.get(&ino).cloned() else {
                return reply.error(libc::ENOENT);
            };
            return match self.view_open(&rel) {
                Ok(fh) => {
                    self.note_open(ino, fh);
                    reply.opened(fh, 0)
                }
                Err(code) => reply.error(code),
            };
        }
        let Some(node) = self.ino_to_node.get(&ino).cloned() else {
            return reply.error(libc::ENOENT);
        };
        // P9.1 (doc 22 §2): an unfetched file with an OWNER-ATTESTED chunk
        // layout streams — the open returns immediately, a background chunked
        // fetch verifies, and each read waits only for its own range.
        // Unattested files keep the safe block-until-verified path.
        let local = self.engine.readable_path(&node).ok().flatten();
        if local.is_none()
            && self
                .engine
                .attested_manifest_root(&node)
                .ok()
                .flatten()
                .is_some()
        {
            // A FAILED background fetch must not stick: evict it so this
            // open retries, instead of every later reader inheriting the
            // cached error until remount (P9.1 wart, doc 22).
            if self.active.get(&node).is_some_and(|p| p.failed()) {
                self.active.remove(&node);
            }
            let progress = match self.active.get(&node) {
                Some(p) => Arc::clone(p),
                None => {
                    pv_info!("pvfs.mount.streaming", node = &node;
                        "mount: streaming {node} while its fetch verifies (doc 22 §2)");
                    let p: Arc<SwarmProgress> = Arc::new(SwarmProgress::default());
                    let bg = Arc::clone(&p);
                    let dir = self.data_dir.clone();
                    let id = node.clone();
                    std::thread::spawn(move || {
                        pvfs_client::fetch::fetch_streaming(&dir, &id, &bg);
                    });
                    self.active.insert(node.clone(), Arc::clone(&p));
                    p
                }
            };
            let fh = self.next_fh;
            self.next_fh += 1;
            self.streaming.insert(fh, progress);
            return reply.opened(fh, 0);
        }
        // P10.1 (doc 23 §11): an unhashed pointer node with no local bytes
        // is an in-flight ingest — proxy reads through the serving daemon's
        // ranged Cat (it enforces the early-serve license, waits for chunk
        // coverage, and registers our demand as a hot range).
        // D82 — the proxy is for an IN-FLIGHT INGEST on this box, and "unhashed
        // with no local bytes" is too loose a test for that. A file whose bytes
        // live on ANOTHER host is not being ingested here; it is simply
        // elsewhere, and taking the proxy path for it dials the local daemon,
        // fails, and returns EIO — never reaching the resolve below, which
        // would have fetched it.
        //
        // Found staging the presentation layer: every file held only by the NAS
        // was unreadable through the mount, while `pvfs cat` on the same node
        // succeeded. Under a mount that has to serve Plex, that is the whole
        // library returning I/O errors.
        let held_elsewhere = self
            .engine
            .locations(&node)
            .map(|ls| pvfs_core::storage::held_on_another_host(&ls, self.own_pin.as_deref()))
            .unwrap_or(false);
        if local.is_none() && !held_elsewhere {
            if let Some((declared, client)) = self.ingest_proxy(&node) {
                pv_info!("pvfs.mount.ingest_stream", node = &node;
                    "mount: ingest-stream {node} — reads proxy ranged Cat (doc 23 §11)");
                let fh = self.next_fh;
                self.next_fh += 1;
                self.proxy.insert(
                    fh,
                    ProxyRead {
                        node: node.clone(),
                        declared,
                        client,
                    },
                );
                return reply.opened(fh, 0);
            }
        }
        let path = match local.map(Ok).unwrap_or_else(|| self.resolve_bytes(&node)) {
            Ok(p) => p,
            Err(_) => return reply.error(libc::EIO),
        };
        match std::fs::File::open(&path) {
            Ok(f) => {
                let fh = self.next_fh;
                self.next_fh += 1;
                self.handles.insert(fh, f);
                reply.opened(fh, 0);
            }
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        use std::os::unix::fs::FileExt;
        // P10.1 proxy handle: forward as a ranged Cat — the serving daemon
        // waits for chunk coverage server-side. One retry rides out a
        // wait-cap expiry on a slow ingest.
        if let Some(pr) = self.proxy.get_mut(&fh) {
            if offset as u64 >= pr.declared {
                return reply.data(&[]);
            }
            let len = (size as u64).min(pr.declared - offset as u64);
            let mut buf: Vec<u8> = Vec::with_capacity(len as usize);
            for attempt in 0..2 {
                buf.clear();
                match pr.client.cat_range(&pr.node, offset as u64, len, &mut buf) {
                    Ok(_) => return reply.data(&buf),
                    Err(_) if attempt == 0 => continue,
                    Err(_) => break,
                }
            }
            return reply.error(libc::EIO);
        }
        // D165 — a view read-through: bytes that are here are answered now.
        // A read that has to wait for the network does so OFF this thread
        // (fuser's session is one thread; a reply may be sent from any), so
        // `ls`, `stat` and every other read go on being answered meanwhile.
        if let Some(hs) = self.hash_streams.get_mut(&fh) {
            let (off, len) = (offset as u64, size as u64);
            if off >= hs.fetch.size() {
                return reply.data(&[]);
            }
            match hs.fetch.poll_range(off, len) {
                Some(Ok(path)) => {
                    if hs.file.is_none() {
                        hs.file = std::fs::File::open(&path).ok();
                    }
                    return match hs.file.as_ref() {
                        Some(f) => reply_read_at(f, off, size, reply),
                        None => reply.error(libc::EIO),
                    };
                }
                Some(Err(_)) => {
                    let errno = read_failed(&self.tombstones, hs);
                    return reply.error(errno);
                }
                None => {
                    let fetch = Arc::clone(&hs.fetch);
                    let tombs = Arc::clone(&self.tombstones);
                    let (rel, held) = (hs.rel.clone(), hs.held.clone());
                    std::thread::spawn(move || match fetch.wait_range(off, len, READ_WAIT) {
                        Ok(path) => match std::fs::File::open(&path) {
                            Ok(f) => reply_read_at(&f, off, size, reply),
                            Err(_) => reply.error(libc::EIO),
                        },
                        Err(_) if fetch.gone() => {
                            bury_gone(&tombs, &rel, fetch.hash(), &held);
                            reply.error(libc::ENOENT)
                        }
                        Err(_) => reply.error(libc::EIO),
                    });
                    return;
                }
            }
        }
        // streaming handle: wait for the covering chunks, then serve from
        // wherever the fetch says the verified bytes are right now
        if let Some(progress) = self.streaming.get(&fh) {
            let path = match progress.wait_range(
                offset as u64,
                size as u64,
                std::time::Duration::from_secs(120),
            ) {
                Ok(p) => p,
                Err(_) => return reply.error(libc::EIO),
            };
            let Ok(f) = std::fs::File::open(&path) else {
                return reply.error(libc::EIO);
            };
            let mut buf = vec![0u8; size as usize];
            return match f.read_at(&mut buf, offset as u64) {
                Ok(n) => {
                    buf.truncate(n);
                    reply.data(&buf);
                }
                Err(_) => reply.error(libc::EIO),
            };
        }
        let Some(f) = self.handles.get(&fh) else {
            return reply.error(libc::EBADF);
        };
        let mut buf = vec![0u8; size as usize];
        match f.read_at(&mut buf, offset as u64) {
            Ok(n) => {
                buf.truncate(n);
                reply.data(&buf);
            }
            Err(_) => reply.error(libc::EIO),
        }
    }

    /// D71 W2: Sonarr deleting a drained file must work. Byte writes stay
    /// refused — only the namespace is write-through.
    /// D82 — answer `statfs`, so anything asking about capacity gets the truth
    /// instead of the zeroes a default impl returns.
    ///
    /// The honest shape of this filesystem: it presents N files totalling X
    /// bytes, and NOTHING can be created in it — there is no `create`, `mknod`
    /// or `write` here, because the bytes live on holders and arrive by the
    /// mover. So free and available are 0, and that is a statement rather than
    /// a placeholder: in a mergerfs union it is what stops a create policy from
    /// ever choosing this branch, which is exactly right when the writable
    /// staging disk is the branch beside it.
    ///
    /// `unlink`/`rmdir`/`rename` still work — they retire catalog entries, and
    /// none of them needs free space.
    ///
    /// PVOS D233 — a WRITABLE view can be written to, and says how much: the
    /// free space of the disks `create` places on, net of their floors, and
    /// their free inodes. A tool that checks free space before it writes
    /// (an arr's import, a copy) was refused by the zeroes. mergerfs ignores
    /// this branch's statfs on mediabox (`statfs_ignore=nc`, the branch is
    /// `NC`), so it changes nothing there.
    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        const BSIZE: u32 = 512;
        let (bytes, files) = self.capacity();
        let space = if self.writable && self.view { self.writable_space() } else { Default::default() };
        let bfree = space.free_bytes / BSIZE as u64;
        let bavail = space.above_floor_bytes / BSIZE as u64;
        reply.statfs(
            bytes.div_ceil(BSIZE as u64).saturating_add(bfree), // blocks: what the tree holds, and the room
            bfree,                                        // bfree
            bavail,                                       // bavail — 0 unless writable
            files.saturating_add(space.free_files),       // inodes
            space.free_files,                             // ffree
            BSIZE,
            255, // NAME_MAX, matching the label cap the catalog enforces
            BSIZE,
        );
    }

    fn mkdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, _mode: u32, _umask: u32, reply: ReplyEntry) {
        if self.view {
            self.sync_overlay();
            return self.view_mkdir(parent, name, reply); // D170
        }
        reply.error(libc::ENOSYS)
    }

    /// D170 — the view's modes, owners and times are constants: a change to
    /// them is accepted and ignored, as the rclone mount this replaces did
    /// (an arr's "set permissions", mergerfs's path clone). A size change is
    /// a write, and writes do not come through the view.
    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        if !self.view {
            return reply.error(libc::ENOSYS);
        }
        if let Some(new_len) = size {
            // D217 tier 1 — truncate is an edit like any other, and gated the
            // same way: this box must already hold the bytes.
            match self.truncate_local(ino, new_len, fh) {
                Ok(()) => return self.getattr(_req, ino, reply),
                Err(e) => return reply.error(e),
            }
        }
        self.getattr(_req, ino, reply)
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        if self.view {
            self.sync_overlay();
            return self.view_unlink(parent, name, reply); // D169
        }
        match self.retire(parent, name, false) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        if self.view {
            self.sync_overlay();
            return self.view_rmdir(parent, name, reply); // D170
        }
        match self.retire(parent, name, true) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    /// `rename` — D71 W2, rewritten by D72.
    ///
    /// It used to be two genuinely different operations wearing one syscall,
    /// because **the node id was a hash that included the label**: moving kept
    /// the name and so kept the identity (unlink, link), while RENAMING could
    /// not be a relabel at all — it had to mint a successor node, copy every
    /// location onto it, retire the old one, and leave the mover to relocate
    /// the bytes. For a folder it was worse: a new folder node, every child
    /// re-linked, and every descendant's tree path changed with it.
    ///
    /// D72 moved labels onto LINKS, so a name is an attribute of the edge and a
    /// node's identity no longer depends on it. Locally that collapses all four
    /// cases into the same three primitives — nothing is minted, nothing is
    /// copied, and locations and content hashes are untouched throughout:
    ///
    /// | | same name | new name |
    /// |---|---|---|
    /// | **same parent** | nothing | relabel |
    /// | **new parent** | link + unlink | link + relabel + unlink |
    ///
    /// Renaming a show is now ONE event at the top of its subtree, whatever is
    /// beneath it.
    ///
    /// A **replica** still takes the old successor path for a name change: the
    /// relabel wire op does not exist, and adding one is a wire change rather
    /// than a log change, which Part A's tolerance does not cover. That is the
    /// gap D73 is for.
    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        flags: u32,
        reply: ReplyEmpty,
    ) {
        if self.view {
            self.sync_overlay();
            return self.view_rename(parent, name, newparent, newname, flags, reply); // D170
        }
        let (Some(from), Some(to)) = (
            self.ino_to_node.get(&parent).cloned(),
            self.ino_to_node.get(&newparent).cloned(),
        ) else {
            return reply.error(libc::ENOENT);
        };
        let (Some(name), Some(newname)) = (name.to_str(), newname.to_str()) else {
            return reply.error(libc::ENOENT);
        };
        let children = match self.engine.children(&from) {
            Ok(c) => c,
            Err(e) => return reply.error(enoent(e)),
        };
        let Some(entry) = children.into_iter().find(|c| c.label == name) else {
            return reply.error(libc::ENOENT);
        };

        // D72: locally, ALL FOUR cases are the same three primitives, because a
        // name is an attribute of the edge and a node's identity never depends
        // on it. Nothing is minted, nothing is copied, and the file's locations
        // and content hash are untouched in every case.
        //
        //   same parent, same name  → nothing
        //   same parent, new name   → relabel
        //   new parent,  same name  → link + unlink
        //   new parent,  new name   → link + relabel + unlink
        //
        // This replaced a "successor node" path that minted a new node, copied
        // every location onto it, retired the old one, and left the mover to
        // relocate the bytes — and, for a folder, re-linked every child so that
        // every descendant's tree path changed too.
        if self.route.is_none() {
            if from == to && name == newname {
                return reply.ok();
            }
            let res = (|| -> Result<(), PvfsError> {
                if from == to {
                    return self.engine.relabel_link(&entry.link_id, newname);
                }
                // ONE move, not link+unlink: the one-home rule means a node has
                // exactly one containing parent, so linking under the new one
                // first fails with `AlreadyContained`. `move_node` retires the
                // old edge and creates the new one in a single commit, with the
                // cycle and both-parents write checks that live there.
                self.engine.move_node(&entry.node.id, &to)?;
                if name != newname {
                    let moved = self
                        .engine
                        .children(&to)?
                        .into_iter()
                        .find(|c| c.node.id == entry.node.id)
                        .ok_or_else(|| PvfsError::NotFound {
                            kind: "moved node",
                            id: entry.node.id.clone(),
                        })?;
                    self.engine.relabel_link(&moved.link_id, newname)?;
                }
                Ok(())
            })();
            return match res {
                Ok(()) => reply.ok(),
                Err(e) => {
                    pv_error!("pvfs.mount.rename_failed", error = content(&e); "pvfs mount: rename failed: {e}");
                    reply.error(libc::EIO)
                }
            };
        }

        // D73: a REPLICA can take the cheap path too, when the owner is new
        // enough to understand it. Gated rather than assumed — the owner may be
        // older than this binary, and degrading to the successor path is
        // correct there, just expensive.
        if name != newname && from == to {
            let supported = matches!(&self.route, Some((c, _)) if c.supports_relabel());
            if supported {
                let res = (|| -> Result<(), PvfsError> {
                    let Some((client, sign)) = &mut self.route else {
                        unreachable!("route checked above")
                    };
                    client
                        .relabel(&entry.link_id, newname, |d| sign(d))
                        .map_err(|e| PvfsError::BadInput {
                            field: "rename".into(),
                            reason: e.to_string(),
                        })?;
                    pvfs_client::advertise::catch_up(&self.data_dir, client);
                    Ok(())
                })();
                return match res {
                    Ok(()) => reply.ok(),
                    Err(e) => {
                        pv_error!("pvfs.mount.rename_failed", error = content(&e); "pvfs mount: relabel failed: {e}");
                        reply.error(libc::EIO)
                    }
                };
            }
        }
        if name != newname {
            return match self.rename_to_new_name(&from, name, &to, newname) {
                Ok(()) => reply.ok(),
                Err(e) => reply.error(e),
            };
        }
        if from == to {
            return reply.ok();
        }
        let res = (|| -> Result<(), PvfsError> {
            let Some((client, sign)) = &mut self.route else {
                unreachable!("route checked above")
            };
            client
                .link(&to, &entry.node.id, pvfs_core::LINK_CONTAINS, "", |d| sign(d))
                .map_err(|e| PvfsError::BadInput {
                    field: "rename".into(),
                    reason: e.to_string(),
                })?;
            client
                .unlink(&entry.link_id, |d| sign(d))
                .map_err(|e| PvfsError::BadInput {
                    field: "rename".into(),
                    reason: e.to_string(),
                })?;
            pvfs_client::advertise::catch_up(&self.data_dir, client);
            Ok(())
        })();
        match res {
            Ok(()) => reply.ok(),
            Err(_) => reply.error(libc::EIO),
        }
    }

    /// D217 — create a new file through the view.
    ///
    /// This is the half that takes mergerfs out of the decision: the file is
    /// made on the disk D216's rule picks — the region that already holds its
    /// folder, else the emptiest with room — instead of on whichever branch
    /// happened to be writable. Until the `watch` job catalogues it, the
    /// overlay answers for it, so a tool that writes a subtitle and reads it
    /// straight back finds it.
    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        if !self.writable || !self.view {
            return reply.error(libc::EROFS);
        }
        let Some(name) = name.to_str() else { return reply.error(libc::EINVAL) };
        self.sync_overlay();
        let Some(dir) = self.ino_to_path.get(&parent).cloned() else {
            return reply.error(libc::ENOENT);
        };
        let rel = if dir.is_empty() { name.to_string() } else { format!("{dir}/{name}") };
        if !pvfs_core::Engine::safe_rel_path(&rel) {
            return reply.error(libc::EINVAL);
        }
        if self.view_entry_of(&rel).is_some() {
            return reply.error(libc::EEXIST);
        }
        let dests = match self.engine.writable_roots() {
            Ok(d) if !d.is_empty() => d,
            _ => return reply.error(libc::EROFS),
        };
        // PVOS D233 — nowhere when every disk is under its floor: the floor is
        // a floor (D218 §2.1 item 2), not a preference a full disk loses.
        let Some((region, root)) = self.engine.placement_for(&rel, &dests) else {
            pv_warn!("pvfs.mount.create_refused", path = content(&rel), error_kind = "disk:floor";
                "mount: create of {rel} refused — every disk it could go on is under its free-space floor (`pvfs region floor`)");
            return reply.error(libc::ENOSPC);
        };
        let path = root.join(&rel);
        if let Some(p) = path.parent() {
            if std::fs::create_dir_all(p).is_err() {
                return reply.error(libc::EIO);
            }
        }
        let f = match std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(&path) {
            Ok(f) => f,
            Err(e) => return reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
        };
        let fh = self.next_fh;
        self.next_fh += 1;
        self.write_handles.insert(fh, WriteHandle { file: f, rel: rel.clone() });
        self.overlay.lock().unwrap().remember_file(&rel, path, root, &region);
        let ino = self.view_ino(&rel);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let attr = self.plain_attr(ino, FileType::RegularFile, 0, now_ms, 0o644);
        reply.created(&TTL, &attr, 0, fh, 0);
    }

    /// D217 tier 1 — the write itself. The bytes go to the real file in the
    /// region this box holds, and the `watch` job re-hashes it afterwards:
    /// the catalogue is briefly stale rather than wrong, which is the same
    /// window any local edit outside PVFS already has.
    fn write(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyWrite,
    ) {
        use std::os::unix::fs::FileExt;
        let Some(h) = self.write_handles.get(&fh) else {
            return reply.error(libc::EBADF);
        };
        match h.file.write_at(data, offset as u64) {
            Ok(n) => reply.written(n as u32),
            Err(e) => reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
        }
    }

    /// PVOS D233 — off the session thread: syncing a large written file
    /// takes as long as the disk takes, and fuser's session is one thread —
    /// every Plex read waited behind it (D218 §2.1 item 7). A reply may be
    /// sent from any thread (D165).
    fn fsync(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, datasync: bool, reply: fuser::ReplyEmpty) {
        let Some(h) = self.write_handles.get(&fh) else {
            return reply.ok();
        };
        let f = match h.file.try_clone() {
            Ok(f) => f,
            Err(e) => return reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
        };
        std::thread::spawn(move || {
            match if datasync { f.sync_data() } else { f.sync_all() } {
                Ok(()) => reply.ok(),
                Err(e) => reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
            }
        });
    }

    /// PVOS D233 — a `close(2)` is not an `fsync(2)`, here as on any disk:
    /// the bytes are already in the real file (each `write` went to it), and
    /// a caller that wants them on the platter says so with `fsync`. D217
    /// synced here, on the session thread.
    fn flush(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _lock_owner: u64, reply: fuser::ReplyEmpty) {
        reply.ok()
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        // D217 — a write handle closes here too; the `watch` job picks the
        // changed bytes up and re-hashes them. PVOS D233 — the overlay may
        // forget the file once its last write handle is gone and the
        // catalogue has caught up.
        if let Some(h) = self.write_handles.remove(&fh) {
            self.overlay.lock().unwrap().closed(&h.rel);
        }
        if let Some(ino) = self.open_inos.remove(&fh) {
            if let Some((_, n)) = self.open_attrs.get_mut(&ino) {
                *n -= 1;
                if *n == 0 {
                    self.open_attrs.remove(&ino);
                }
            }
        }
        self.handles.remove(&fh);
        self.streaming.remove(&fh);
        self.proxy.remove(&fh);
        // D165 — "the application says it is done": a probe's fetch ends,
        // a completing one starts its grace, a kept file loses its pin.
        if let Some(hs) = self.hash_streams.remove(&fh) {
            hs.fetch.handle_closed();
        }
        if let (Some(hash), Some(cache)) = (self.hash_pins.remove(&fh), self.hash_cache.as_ref()) {
            cache.close_local(&hash);
        }
        reply.ok();
    }
}

/// Mount `target` (a node in the forest at `data_dir`) read-only at
/// `mountpoint`, blocking until unmounted (`fusermount3 -u`, or the process
/// ends with auto-unmount).
pub fn mount(
    data_dir: &Path,
    target: &NodeId,
    mountpoint: &Path,
    allow_other: bool,
) -> Result<(), PvfsError> {
    // AutoUnmount implies allow_other on fusermount, which stock
    // /etc/fuse.conf forbids for users — try the convenient shape first,
    // fall back to the universally-permitted one.
    //
    // `allow_other` asked for BY NAME is a different matter, and is never
    // quietly dropped. Inheriting it from AutoUnmount is what hid D82's
    // failure: fusermount3 refused the pair, the fallback mounted privately,
    // and a mount that looked healthy — right options in /proc/mounts, right
    // listing for the mounting user — was unreadable to root, so mergerfs saw
    // nothing. A mount no other user can read is useless to the union, and it
    // must say so at mount time rather than at read time.
    let fs = PvfsFs::new(data_dir, target)?;
    match fuser::mount2(fs, mountpoint, &opts(true, allow_other)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let fs = PvfsFs::new(data_dir, target)?;
            if allow_other {
                // Drop only AutoUnmount: this separates a fusermount3 that
                // dislikes auto-unmount from one that forbids allow_other.
                return fuser::mount2(fs, mountpoint, &opts(false, true)).map_err(allow_other_denied);
            }
            fuser::mount2(fs, mountpoint, &opts(false, false))
                .map_err(|e| PvfsError::io("fuse mount", e))
        }
        Err(e) => Err(PvfsError::io("fuse mount", e)),
    }
}

/// The one remedy worth naming: `allow_other` is gated by `/etc/fuse.conf`,
/// not by anything PVFS controls.
fn allow_other_denied(e: std::io::Error) -> PvfsError {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        PvfsError::io(
            "fuse mount with allow_other — add `user_allow_other` to /etc/fuse.conf \
             (needed so root and other users, e.g. mergerfs, can read this mount), \
             or mount without --allow-other to keep it private to this user",
            e,
        )
    } else {
        PvfsError::io("fuse mount", e)
    }
}

impl PvfsFs {
    /// D71 W2 — a name change, as a SUCCESSOR.
    ///
    /// The node id is a hash that includes the label (`node.rs`
    /// `compute_id_digest`), so a new name is unavoidably a new node. What
    /// makes it a rename rather than a re-import is that the successor
    /// **inherits the old node's locations**: the bytes are already accounted
    /// for, nothing is copied here, and the old node is retired.
    ///
    /// Two consequences worth knowing:
    ///
    /// * for a moment one file is referenced by both a dead node and a live
    ///   one — `orphaned_local_locations` refuses to reclaim a path any live
    ///   node still claims, which is what stops this becoming data loss;
    /// * under tree-layout placement the successor's path differs, so the
    ///   mover will relocate the bytes on its next pass. Today that is a copy;
    ///   a same-filesystem `rename` on the holder is the obvious optimisation
    ///   and is NOT done yet — for a 40 GB episode that difference is minutes
    ///   against milliseconds.
    fn rename_to_new_name(
        &mut self,
        from: &NodeId,
        name: &str,
        to: &NodeId,
        newname: &str,
    ) -> Result<(), i32> {
        let children = self.engine.children(from).map_err(|_| libc::EIO)?;
        let entry = children
            .into_iter()
            .find(|c| c.label == name)
            .ok_or(libc::ENOENT)?;
        if entry.node.node_type == pvfs_core::TYPE_FOLDER {
            return self.rename_folder(&entry, to, newname);
        }
        let payload = pvfs_core::FilePayload::decode(&entry.node.payload)
            .map_err(|_| libc::EIO)?;
        let locations = self.engine.locations(&entry.node.id).map_err(|_| libc::EIO)?;

        let res = (|| -> Result<(), PvfsError> {
            match &mut self.route {
                Some((client, sign)) => {
                    let new_id = client
                        .add_file(to, newname, payload.size_bytes, &payload.mime_type, &payload.content_hash, |d| {
                            sign(d)
                        })
                        .map_err(|e| PvfsError::BadInput {
                            field: "rename".into(),
                            reason: e.to_string(),
                        })?;
                    for uri in &locations {
                        client
                            .add_location(&new_id, uri, |d| sign(d))
                            .map_err(|e| PvfsError::BadInput {
                                field: "rename".into(),
                                reason: e.to_string(),
                            })?;
                    }
                    client
                        .unlink(&entry.link_id, |d| sign(d))
                        .map_err(|e| PvfsError::BadInput {
                            field: "rename".into(),
                            reason: e.to_string(),
                        })?;
                    pvfs_client::advertise::catch_up(&self.data_dir, client);
                    Ok(())
                }
                None => {
                    let new_id = self.engine.add_node(
                        to,
                        pvfs_core::NodeSpec {
                            node_type: pvfs_core::TYPE_FILE.into(),
                            label: newname.to_string(),
                            payload: entry.node.payload.clone(),
                            is_temp: false,
                            creation_nonce: None,
                        },
                    )?;
                    for uri in &locations {
                        self.engine.add_location(&new_id, uri)?;
                    }
                    self.engine.remove_link(&entry.link_id)
                }
            }
        })();
        res.map_err(|e| {
            pv_error!("pvfs.mount.rename_failed", error = content(&e); "pvfs mount: rename failed: {e}");
            libc::EIO
        })
    }

    /// D71 — renaming a FOLDER, which Chris needs to propagate too.
    ///
    /// Same successor shape as a file, one level deeper: a folder's label is in
    /// its id, so the rename mints a new folder node and **re-links every child
    /// under it**. Children keep their own ids and their own subtrees, so a
    /// season folder full of episodes — or a show folder full of seasons —
    /// moves by re-linking, not by touching a single byte.
    ///
    /// What follows is the expensive part, and why this needed the mover's
    /// same-filesystem move first: every descendant file's TREE PATH just
    /// changed, so under tree layout the mover relocates each of them. With a
    /// `rename` on the holder that is milliseconds per episode; streaming them
    /// through `cat` would make renaming a show unusable.
    fn rename_folder(
        &mut self,
        entry: &pvfs_core::ChildEntry,
        to: &NodeId,
        newname: &str,
    ) -> Result<(), i32> {
        let children = self
            .engine
            .children(&entry.node.id)
            .map_err(|_| libc::EIO)?;

        let res = (|| -> Result<(), PvfsError> {
            match &mut self.route {
                Some((client, sign)) => {
                    let new_id = client
                        .mkdir(to, newname, |d| sign(d))
                        .map_err(|e| PvfsError::BadInput {
                            field: "rename".into(),
                            reason: e.to_string(),
                        })?;
                    // MOVE, not link: a node has exactly ONE containing
                    // parent, so linking a child under a second one is refused
                    // (`AlreadyContained`). The lab said so — a folder rename
                    // half-completed, leaving an empty new folder beside an
                    // intact original.
                    for c in &children {
                        client
                            .mv(&c.node.id, &new_id, |d| sign(d))
                            .map_err(|e| PvfsError::BadInput {
                                field: "rename".into(),
                                reason: e.to_string(),
                            })?;
                    }
                    // Old folder last: a crash before this leaves the subtree
                    // reachable from BOTH names, which is untidy but complete.
                    // The other order can orphan every child.
                    client
                        .unlink(&entry.link_id, |d| sign(d))
                        .map_err(|e| PvfsError::BadInput {
                            field: "rename".into(),
                            reason: e.to_string(),
                        })?;
                    pvfs_client::advertise::catch_up(&self.data_dir, client);
                    Ok(())
                }
                None => {
                    let new_id = self.engine.add_node(
                        to,
                        pvfs_core::NodeSpec {
                            node_type: pvfs_core::TYPE_FOLDER.into(),
                            label: newname.to_string(),
                            payload: entry.node.payload.clone(),
                            is_temp: false,
                            creation_nonce: None,
                        },
                    )?;
                    // Locally there is no single move primitive, and a node
                    // may have only ONE containing parent — so it must be
                    // unlink-then-link, not the safer link-first order. The
                    // window between them leaves the child an orphan rather
                    // than duplicated; orphans are recoverable (`pvfs orphans`)
                    // and duplication is refused outright, so this is the only
                    // order available.
                    for c in &children {
                        self.engine.remove_link(&c.link_id)?;
                        self.engine.link(
                            &new_id,
                            &c.node.id,
                            pvfs_core::LINK_CONTAINS,
                            None,
                            0,
                        )?;
                    }
                    self.engine.remove_link(&entry.link_id)
                }
            }
        })();
        // Say WHY. A mount that answers EIO with no explanation is exactly
        // what turned a one-line bug into a lab round.
        res.map_err(|e| {
            pv_error!("pvfs.mount.rename_failed", error = content(&e); "pvfs mount: folder rename failed: {e}");
            libc::EIO
        })
    }

    /// D71 W2 — retire a link, routing on a replica.
    ///
    /// This is the gap that made the design a REGRESSION against the rclone
    /// mounts it replaces: those are read-write, so Sonarr deleting a drained
    /// file works today, and against a read-only PVFS branch it got EROFS.
    /// Upgrades hit this constantly.
    ///
    /// The catalog op happens here; the BYTES are not touched from this box.
    /// A holder reclaims its own files (`pvfs reclaim`), which is what keeps
    /// the owner from reaching across NFS to delete, and what routes every
    /// automated deletion through the trash.
    fn retire(&mut self, parent: u64, name: &OsStr, want_dir: bool) -> Result<(), i32> {
        if self.view {
            // The view's handlers never reach here: `view_unlink` (D169),
            // `view_rmdir` and `view_rename` (D170).
            return Err(libc::EROFS);
        }
        let parent_node = self
            .ino_to_node
            .get(&parent)
            .cloned()
            .ok_or(libc::ENOENT)?;
        let name = name.to_str().ok_or(libc::ENOENT)?;
        let children = self.engine.children(&parent_node).map_err(|_| libc::EIO)?;
        let entry = children
            .into_iter()
            .find(|c| c.label == name)
            .ok_or(libc::ENOENT)?;
        let is_dir = entry.node.node_type == pvfs_core::TYPE_FOLDER;
        if want_dir && !is_dir {
            return Err(libc::ENOTDIR);
        }
        if !want_dir && is_dir {
            return Err(libc::EISDIR);
        }
        if is_dir
            && !self
                .engine
                .children(&entry.node.id)
                .map_err(|_| libc::EIO)?
                .is_empty()
        {
            return Err(libc::ENOTEMPTY);
        }
        match &mut self.route {
            Some((client, sign)) => {
                client
                    .unlink(&entry.link_id, |d| sign(d))
                    .map_err(|_| libc::EIO)?;
                pvfs_client::advertise::catch_up(&self.data_dir, client);
            }
            None => self
                .engine
                .remove_link(&entry.link_id)
                .map_err(|_| libc::EIO)?,
        }
        Ok(())
    }
}


impl PvfsFs {
    /// D217 tier 1 — allow edits of files whose bytes this box already holds.
    /// Off by default: turning it on is a mount decision (`pvfs mount
    /// --writable`), because it changes what the arrs and Plex can do to the
    /// library through this path.
    pub fn set_writable(&mut self, yes: bool) {
        self.writable = yes;
    }

    /// D217 tier 1 — shorten a file this box holds. PVOS D233 — through the
    /// write handle when the call carries one (`ftruncate`), else the file an
    /// edit of the path would write to ([`Self::write_target`]).
    fn truncate_local(&mut self, ino: u64, new_len: u64, fh: Option<u64>) -> Result<(), i32> {
        if !self.writable || !self.view {
            return Err(libc::EROFS);
        }
        let errno = |e: std::io::Error| e.raw_os_error().unwrap_or(libc::EIO);
        if let Some(h) = fh.and_then(|fh| self.write_handles.get(&fh)) {
            return h.file.set_len(new_len).map_err(errno);
        }
        self.sync_overlay();
        let rel = self.ino_to_path.get(&ino).cloned().ok_or(libc::ENOENT)?;
        let w = self.write_target(&rel)?;
        let f = std::fs::OpenOptions::new().write(true).open(&w.path).map_err(errno)?;
        f.set_len(new_len).map_err(errno)?;
        self.overlay.lock().unwrap().remember_edit(&rel, w.path, w.root, &w.region, false);
        Ok(())
    }

    /// D217 tier 1 — open a file for writing, if this box holds its bytes.
    ///
    /// `EROFS` when the mount was not told to allow edits, and `EROFS` with
    /// nothing attempted when the bytes live on another box: copying a whole
    /// film across the network to change a header is a decision for a person,
    /// not a side effect of `open`.
    fn open_for_write(&mut self, ino: u64) -> Result<u64, i32> {
        if !self.writable || !self.view {
            return Err(libc::EROFS);
        }
        self.sync_overlay();
        let rel = self.ino_to_path.get(&ino).cloned().ok_or(libc::ENOENT)?;
        let w = self.write_target(&rel)?;
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&w.path)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        self.overlay.lock().unwrap().remember_edit(&rel, w.path, w.root, &w.region, true);
        let fh = self.next_fh;
        self.next_fh += 1;
        self.write_handles.insert(fh, WriteHandle { file: f, rel });
        Ok(fh)
    }

    /// PVOS D233 — the file an edit of view path `rel` writes to: the file
    /// THIS mount wrote there (made, or already being edited), else this
    /// box's own copy AT THAT PATH ([`Engine::local_copy_at`]).
    ///
    /// D217 asked for any local file with the served hash, and with two
    /// byte-identical files (every empty file is one) an edit of one changed
    /// the other (D218 §2.1 item 1). Refused with `EROFS`, and said why:
    /// - the bytes are on another box (D217 tier 1: no copy-up);
    /// - the view has more than one copy of the path — an edit of one would
    ///   set the copies against each other, and the ladder may then serve the
    ///   old bytes, so the edit looks lost;
    /// - the copy's region is draining (staging): the drain compares it with
    ///   the library's copy, and a `create` never lands there either.
    fn write_target(&mut self, rel: &str) -> Result<overlay::Written, i32> {
        let written = self.overlay.lock().unwrap().written(rel);
        if let Some(w) = written {
            if std::fs::symlink_metadata(&w.path).is_ok_and(|m| m.is_file()) {
                return Ok(w);
            }
        }
        let entry = self.view_entry_of(rel).ok_or(libc::ENOENT)?;
        if entry.kind == "dir" {
            return Err(libc::EISDIR);
        }
        let refuse = |why: &str| {
            pv_info!("pvfs.mount.edit_refused", path = content(rel), reason = why;
                "mount: edit of {rel} refused — {why}");
            libc::EROFS
        };
        let copies = entry.sources.iter().filter(|c| c.kind == "file").count();
        if copies > 1 {
            return Err(refuse(&format!(
                "the view has {copies} copies of it, and an edit of one would set them against each other"
            )));
        }
        let (hash, _size, _) = Self::view_served(&entry).ok_or(libc::EIO)?;
        let Some(local) = self.engine.local_copy_at(rel, &hash).ok().flatten() else {
            return Err(refuse("its bytes are on another box (an edit changes only a file this box holds)"));
        };
        if self.engine.region_drains(&local.region).unwrap_or(true) {
            return Err(refuse("its region is draining"));
        }
        // `<root>/<rel>`: the root is as many levels up as `rel` has parts.
        let root = local.path.ancestors().nth(rel.split('/').count()).ok_or(libc::EIO)?.to_path_buf();
        Ok(overlay::Written { path: local.path, root, region: local.region, made: false })
    }
}

fn opts(auto_unmount: bool, allow_other: bool) -> Vec<MountOption> {
    view_opts(auto_unmount, allow_other, false)
}

/// PVOS D233 — [`opts`], and for a VIEW mount `DefaultPermissions`: the
/// kernel checks each caller against the attributes the view reports (owner
/// the mounting user, files 0644, folders 0755), as on a disk. Without it any
/// user could create, overwrite, truncate, delete and rename library files
/// through an `--allow-other` mount with the mounting user's rights (D218
/// §2.1 item 6). Root — mergerfs, `sudo` — passes as on a disk. The node
/// mount reports 0444/0555 and would lose its own user's namespace writes
/// (D71 W2), so it is left as it was.
fn view_opts(auto_unmount: bool, allow_other: bool, view: bool) -> Vec<MountOption> {
    // D71 W2: NOT `MountOption::RO`. The kernel enforces that flag before any
    // handler runs, so `unlink`/`rmdir`/`rename` never saw the call — the lab
    // proved it, with `rm` returning EROFS against a mount whose handlers were
    // already implemented.
    //
    // The data path is the handlers' to refuse: a node mount, and a view
    // mount without `--writable`, answer EROFS to `create` and a write-open
    // (D217), so mergerfs keeps routing creates to /mnt/local. What W2 added
    // is the NAMESPACE — the one place this design was behind the read-write
    // rclone mounts it replaces.
    let mut o = vec![MountOption::FSName("pvfs".into())];
    if allow_other {
        o.push(MountOption::AllowOther);
    }
    if view {
        o.push(MountOption::DefaultPermissions);
    }
    if auto_unmount {
        o.push(MountOption::AutoUnmount);
    }
    o
}

/// Mount on a background thread (tests, and the CLI's future --daemon):
/// dropping the returned session unmounts.
pub fn spawn_mount(
    data_dir: &Path,
    target: &NodeId,
    mountpoint: &Path,
) -> Result<fuser::BackgroundSession, PvfsError> {
    let fs = PvfsFs::new(data_dir, target)?;
    match fuser::spawn_mount2(fs, mountpoint, &opts(true, false)) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let fs = PvfsFs::new(data_dir, target)?;
            fuser::spawn_mount2(fs, mountpoint, &opts(false, false))
                .map_err(|e| PvfsError::io("fuse mount", e))
        }
        Err(e) => Err(PvfsError::io("fuse mount", e)),
    }
}

/// D130 — mount the merged view of the forest at `data_dir` read-only at
/// `mountpoint` (doc 26 phase 6), blocking until unmounted.
pub fn mount_view(data_dir: &Path, mountpoint: &Path, allow_other: bool) -> Result<(), PvfsError> {
    mount_view_with(data_dir, mountpoint, allow_other, CacheOpts::default())
}

/// [`mount_view`] with the read-through cache's knobs (D165).
pub fn mount_view_with(
    data_dir: &Path,
    mountpoint: &Path,
    allow_other: bool,
    cache: CacheOpts,
) -> Result<(), PvfsError> {
    mount_view_writable(data_dir, mountpoint, allow_other, cache, false)
}

/// D217 — [`mount_view_with`], saying whether edits and new files are allowed
/// (tier 1: only for files whose bytes this box already holds).
pub fn mount_view_writable(
    data_dir: &Path,
    mountpoint: &Path,
    allow_other: bool,
    cache: CacheOpts,
    writable: bool,
) -> Result<(), PvfsError> {
    let mut fs = PvfsFs::new_view_with(data_dir, cache.clone(), None)?;
    fs.set_writable(writable);
    match fuser::mount2(fs, mountpoint, &view_opts(true, allow_other, true)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let mut fs = PvfsFs::new_view_with(data_dir, cache, None)?;
            fs.set_writable(writable);
            if allow_other {
                return fuser::mount2(fs, mountpoint, &view_opts(false, true, true)).map_err(allow_other_denied);
            }
            fuser::mount2(fs, mountpoint, &view_opts(false, false, true))
                .map_err(|e| PvfsError::io("fuse mount", e))
        }
        Err(e) => Err(PvfsError::io("fuse mount", e)),
    }
}

/// D130 — [`mount_view`] in the background (tests, embedders).
pub fn spawn_view_mount(
    data_dir: &Path,
    mountpoint: &Path,
) -> Result<fuser::BackgroundSession, PvfsError> {
    spawn_view_mount_with(data_dir, mountpoint, CacheOpts::default(), None)
}

/// [`spawn_view_mount`] with the cache's knobs and the boxes to ask (D165).
pub fn spawn_view_mount_with(
    data_dir: &Path,
    mountpoint: &Path,
    cache: CacheOpts,
    sources: Option<Vec<ReplicaSource>>,
) -> Result<fuser::BackgroundSession, PvfsError> {
    spawn_view_mount_writable(data_dir, mountpoint, cache, sources, false)
}

/// D217 tier 1 — [`spawn_view_mount_with`], saying whether edits of locally
/// held files are allowed.
pub fn spawn_view_mount_writable(
    data_dir: &Path,
    mountpoint: &Path,
    cache: CacheOpts,
    sources: Option<Vec<ReplicaSource>>,
    writable: bool,
) -> Result<fuser::BackgroundSession, PvfsError> {
    let mut fs = PvfsFs::new_view_with(data_dir, cache.clone(), sources.clone())?;
    fs.set_writable(writable);
    match fuser::spawn_mount2(fs, mountpoint, &view_opts(true, false, true)) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let mut fs = PvfsFs::new_view_with(data_dir, cache, sources)?;
            fs.set_writable(writable);
            fuser::spawn_mount2(fs, mountpoint, &view_opts(false, false, true))
                .map_err(|e| PvfsError::io("fuse mount", e))
        }
        Err(e) => Err(PvfsError::io("fuse mount", e)),
    }
}

/// PVOS D211 — is something mounted at `at` (by `/proc/mounts`)?
pub fn is_mounted(at: &Path) -> bool {
    // /proc/mounts writes a space, tab, newline and backslash as octal.
    let unescape = |p: &str| p.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\");
    let want = at.to_string_lossy();
    std::fs::read_to_string("/proc/mounts")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split(' ').nth(1))
        .any(|m| unescape(m) == want)
}

/// PVOS D211 — a background mount that is gone before its mountpoint is.
///
/// Dropping a fuser 0.14 `BackgroundSession` mounted with `AutoUnmount`
/// does not unmount: it closes the socket of the `fusermount3` helper,
/// which unmounts LATER. A test that then removes the mountpoint's
/// `TempDir` deletes THROUGH the still-mounted view (D210's hang), and a
/// test killed meanwhile leaves the mount for good — presubuntu had ~249 of
/// them by 2026-10-01. Dropping this (also while a failed test unwinds)
/// drops the session, waits up to a second, then `fusermount3 -u`, then
/// `-uz`, until `/proc/mounts` no longer lists it. Declare it AFTER the
/// mountpoint's `TempDir`, so it is dropped first.
pub struct MountGuard {
    session: Option<fuser::BackgroundSession>,
    at: PathBuf,
}

impl MountGuard {
    pub fn new(session: fuser::BackgroundSession, at: &Path) -> MountGuard {
        MountGuard { session: Some(session), at: at.to_path_buf() }
    }

    /// Where it is mounted.
    pub fn path(&self) -> &Path {
        &self.at
    }

    /// Unmount now and wait; `true` once the kernel has let go.
    pub fn unmount(mut self) -> bool {
        self.release()
    }

    fn release(&mut self) -> bool {
        let Some(session) = self.session.take() else { return !is_mounted(&self.at) };
        drop(session);
        let wait = |limit: Duration| {
            let deadline = std::time::Instant::now() + limit;
            while is_mounted(&self.at) && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
        };
        wait(Duration::from_secs(1));
        for flags in ["-u", "-uz"] {
            if is_mounted(&self.at) {
                for tool in ["fusermount3", "fusermount"] {
                    let ran = std::process::Command::new(tool)
                        .arg(flags)
                        .arg(&self.at)
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                    if ran.is_ok() {
                        break;
                    }
                }
                wait(Duration::from_secs(5));
            }
        }
        let gone = !is_mounted(&self.at);
        if !gone {
            pv_error!("pvfs.mount.unmount_failed", path = content(self.at.display()), error_kind = "external:unmount";
                "pvfs-fuse: {} is still mounted after fusermount -uz", self.at.display());
        }
        gone
    }
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D82: `allow_other` used to arrive only as a side effect of AutoUnmount,
    /// so the moment fusermount3 refused that pair the mount came up private —
    /// readable by the mounting user, invisible to root, and therefore empty as
    /// far as mergerfs was concerned. It is an option in its own right now.
    #[test]
    fn allow_other_is_requested_by_name_not_inherited() {
        assert!(opts(false, true).contains(&MountOption::AllowOther));
        assert!(opts(true, true).contains(&MountOption::AllowOther));
    }

    /// And it is opt-in: a mount stays private unless someone asks otherwise.
    #[test]
    fn a_mount_is_private_by_default() {
        assert!(!opts(true, false).contains(&MountOption::AllowOther));
        assert!(!opts(false, false).contains(&MountOption::AllowOther));
    }

    /// PVOS D233: a view mount has the kernel check each caller against the
    /// attributes it reports; the node mount (0444/0555, namespace writes by
    /// its own user) does not.
    #[test]
    fn a_view_mount_checks_permissions_and_a_node_mount_does_not() {
        for (auto, other) in [(true, true), (false, true), (true, false), (false, false)] {
            assert!(view_opts(auto, other, true).contains(&MountOption::DefaultPermissions));
            assert!(!opts(auto, other).contains(&MountOption::DefaultPermissions));
        }
    }
}
