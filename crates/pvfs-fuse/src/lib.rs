//! P7.3 (doc 20 §3) — the read-only streaming mount: browse a forest (or a
//! replica) as a real filesystem. Directories come from the projection;
//! opening a file resolves its bytes live — a local location, the sync
//! store, else a verified read-through fetch (F5.2) — and reads are served
//! straight from the resolved file with kernel-native offsets.
//!
//! Deliberately read-only: the catalog's write model belongs to the CLI and
//! daemon. Writes/xattrs/mtimes: refused/synthetic (doc 20 §3).

use std::collections::HashMap;
use std::sync::Arc;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyEntry, ReplyOpen, Request,
};
use pvfs_client::fetch::{Fetcher, SwarmProgress};
use pvfs_core::{Engine, FilePayload, NodeId, PvfsError, TYPE_FILE};

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
    /// P10.1 (doc 23 §11): handles proxying an IN-FLIGHT ingest file — each
    /// read forwards as a ranged `Cat` to the serving daemon, which waits
    /// for chunk coverage and registers our demand as a hot range.
    proxy: HashMap<u64, ProxyRead>,
    data_dir: std::path::PathBuf,
    next_fh: u64,
}

/// One in-flight proxy handle: the connection is reused across reads.
struct ProxyRead {
    node: NodeId,
    declared: u64,
    client: pvfs_client::Client,
}

impl PvfsFs {
    pub fn new(data_dir: &Path, target: &NodeId) -> Result<PvfsFs, PvfsError> {
        let engine = Engine::open(data_dir)?;
        let fetcher = Fetcher::new(data_dir);
        let mut fs = PvfsFs {
            engine,
            fetcher,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            ino_to_node: HashMap::new(),
            node_to_ino: HashMap::new(),
            next_ino: 2,
            handles: HashMap::new(),
            streaming: HashMap::new(),
            active: HashMap::new(),
            proxy: HashMap::new(),
            data_dir: data_dir.to_path_buf(),
            next_fh: 1,
        };
        fs.ino_to_node.insert(1, target.clone());
        fs.node_to_ino.insert(target.clone(), 1);
        Ok(fs)
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

fn enoent<E>(_e: E) -> i32 {
    libc::ENOENT
}

impl Filesystem for PvfsFs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
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
        match children.into_iter().find(|c| c.node.label == name) {
            Some(c) => match self.attr_for(&c.node.id.clone()) {
                Ok(attr) => reply.entry(&TTL, &attr, 0),
                Err(e) => reply.error(enoent(e)),
            },
            None => reply.error(libc::ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
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
            entries.push((child_ino, kind, c.node.label));
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
            return reply.error(libc::EROFS);
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
            let progress = match self.active.get(&node) {
                Some(p) => Arc::clone(p),
                None => {
                    eprintln!("mount: streaming {node} while its fetch verifies (doc 22 §2)");
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
        if local.is_none() {
            if let Some((declared, client)) = self.ingest_proxy(&node) {
                eprintln!("mount: ingest-stream {node} — reads proxy ranged Cat (doc 23 §11)");
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
        self.handles.remove(&fh);
        self.streaming.remove(&fh);
        self.proxy.remove(&fh);
        reply.ok();
    }
}

/// Mount `target` (a node in the forest at `data_dir`) read-only at
/// `mountpoint`, blocking until unmounted (`fusermount3 -u`, or the process
/// ends with auto-unmount).
pub fn mount(data_dir: &Path, target: &NodeId, mountpoint: &Path) -> Result<(), PvfsError> {
    // AutoUnmount implies allow_other on fusermount, which stock
    // /etc/fuse.conf forbids for users — try the convenient shape first,
    // fall back to the universally-permitted one.
    let fs = PvfsFs::new(data_dir, target)?;
    match fuser::mount2(fs, mountpoint, &opts(true)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let fs = PvfsFs::new(data_dir, target)?;
            fuser::mount2(fs, mountpoint, &opts(false)).map_err(|e| PvfsError::io("fuse mount", e))
        }
        Err(e) => Err(PvfsError::io("fuse mount", e)),
    }
}

fn opts(auto_unmount: bool) -> Vec<MountOption> {
    let mut o = vec![MountOption::RO, MountOption::FSName("pvfs".into())];
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
    match fuser::spawn_mount2(fs, mountpoint, &opts(true)) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let fs = PvfsFs::new(data_dir, target)?;
            fuser::spawn_mount2(fs, mountpoint, &opts(false))
                .map_err(|e| PvfsError::io("fuse mount", e))
        }
        Err(e) => Err(PvfsError::io("fuse mount", e)),
    }
}
