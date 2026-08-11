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

/// Where a file's synced bytes live under `data_dir`.
pub fn sync_store_path(data_dir: &Path, id: &str) -> PathBuf {
    let shard = if id.len() >= 2 { &id[..2] } else { "xx" };
    data_dir.join(SYNC_DIR).join(shard).join(id)
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
    pub central: Vec<(NodeId, PathBuf)>,
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
        if let Some(id) = line.strip_prefix("sync ") {
            out.sync.push(id.to_string());
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

/// Node ids of subtrees placed `sync` (order preserved, no duplicates).
pub fn load_placement(data_dir: &Path) -> Result<Vec<NodeId>> {
    Ok(load_placement_full(data_dir)?.sync)
}

/// Subtrees placed `central` with their store directories (owner-side).
pub fn load_central(data_dir: &Path) -> Result<Vec<(NodeId, PathBuf)>> {
    Ok(load_placement_full(data_dir)?.central)
}

fn save_placement(data_dir: &Path, p: &Placement) -> Result<()> {
    let mut text = String::from(PLACEMENT_HEADER);
    text.push('\n');
    for r in &p.sync {
        text.push_str(&format!("sync {r}\n"));
    }
    for (r, d) in &p.central {
        text.push_str(&format!("central {r} {}\n", d.display()));
    }
    crate::storage::atomic_overwrite(&placement_path(data_dir), text.as_bytes())
}

/// Place `id` as `sync` (true) or back to `pointer` (false). Either way any
/// `central` entry for the subtree is cleared — one mode per subtree.
pub fn set_placement(data_dir: &Path, id: &NodeId, sync: bool) -> Result<()> {
    let mut p = load_placement_full(data_dir)?;
    p.sync.retain(|r| r != id);
    p.central.retain(|(r, _)| r != id);
    if sync {
        p.sync.push(id.clone());
    }
    save_placement(data_dir, &p)
}

/// Place `id` as `central` with its store directory (owner-side, F5.3).
pub fn set_central(data_dir: &Path, id: &NodeId, dest: &Path) -> Result<()> {
    let mut p = load_placement_full(data_dir)?;
    p.sync.retain(|r| r != id);
    p.central.retain(|(r, _)| r != id);
    p.central.push((id.clone(), dest.to_path_buf()));
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
    for (id, uri, path) in engine.retired_own_host_locations()? {
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
        let dest = sync_store_path(&self.data_dir, id);
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
        })
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
