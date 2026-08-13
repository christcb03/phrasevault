//! P10.0 — external-ingest sessions (doc 23 §3/§9): catalog-at-add, sparse
//! partials with app-verified progress, commit through the existing
//! hash-fill + attest + publish gates.
//!
//! Session state is **deployment state** (the serve.rs/placement rule):
//! which box is mid-download needs no owner signature and two boxes
//! legitimately differ. The log carries only the typed records
//! (`pvos.download` / `pvos.download.closed`) and ordinary catalog events.
//! The per-file progress sidecar is **authoritative, not a cache** — which
//! bytes the app's piece verification blessed is knowledge only the app
//! had, persisted here at `IngestVerified` time (doc 23 §9.3).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use rand::RngCore;

use crate::engine::{
    active_home, bad, fetch_link, fetch_node, max_order_key, now_ms, Engine, PreparedEvent,
    PreparedWrite,
};
use crate::error::{PvfsError, Result};
use crate::event::{self, Event};
use crate::link::{Link, LINK_CONTAINS};
use crate::node::{FilePayload, Node, NodeId, TYPE_FILE, TYPE_FOLDER, VISIBILITY_PUBLIC};
use crate::orderkey::OrderKey;
use crate::sync::{manifest_root, swarm_part_path, sync_store_path, SWARM_CHUNK};

/// The `pvos.download` origin record's node type (doc 23 §9.1).
pub const TYPE_DOWNLOAD: &str = "pvos.download";
/// The closing record's node type — every origin record gets one (§8.4).
pub const TYPE_DOWNLOAD_CLOSED: &str = "pvos.download.closed";
/// Free-space margin the `IngestBegin` preflight keeps beyond the declared
/// total (doc 23 §8.3).
pub const INGEST_SPACE_MARGIN: u64 = 256 * 1024 * 1024;

// ---- free space (doc 23 §8.3) ---------------------------------------------------

/// Bytes available to unprivileged writes on the filesystem holding `dir`
/// (created if absent, so a fresh store answers for its real mount).
pub fn free_space_at(dir: &Path) -> Result<u64> {
    std::fs::create_dir_all(dir).map_err(|e| PvfsError::io("create store dir", e))?;
    let st = nix::sys::statvfs::statvfs(dir)
        .map_err(|e| PvfsError::io("statvfs store dir", std::io::Error::other(e)))?;
    Ok(st.blocks_available() as u64 * st.fragment_size() as u64)
}

// ---- the sessions file (deployment state, doc 23 §9.3) --------------------------

const SESSIONS_FILE: &str = "ingest.sessions";
const SESSIONS_HEADER: &str = "pvfs-ingest-sessions 1";

/// One declared file in a session: the catalog pointer node, its path inside
/// the torrent, the metainfo size, and — once committed — the hash-fill
/// successor's id (commits re-identify nodes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestFileRec {
    pub node: NodeId,
    pub rel_path: String,
    pub size: u64,
    pub committed: Option<NodeId>,
}

/// One ingest session, as persisted in `ingest.sessions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestSessionRec {
    pub id: String,
    /// The member that began the session — the only principal that may
    /// write/verify/commit/abort it.
    pub owner_pub: Vec<u8>,
    pub parent: NodeId,
    pub root: NodeId,
    pub origin: NodeId,
    pub files: Vec<IngestFileRec>,
}

pub fn sessions_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SESSIONS_FILE)
}

/// Sessions on disk. Missing file = none; a malformed file is a hard error
/// (the serve.jobs rule: silently dropping sessions is the failure we refuse).
pub fn load_sessions(data_dir: &Path) -> Result<Vec<IngestSessionRec>> {
    let text = match std::fs::read_to_string(sessions_path(data_dir)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(PvfsError::io("read ingest.sessions", e)),
    };
    let mut lines = text.lines();
    if lines.next() != Some(SESSIONS_HEADER) {
        return Err(bad("ingest", "unrecognized ingest.sessions file"));
    }
    let mut out: Vec<IngestSessionRec> = Vec::new();
    for line in lines.filter(|l| !l.trim().is_empty()) {
        if let Some(rest) = line.strip_prefix("session ") {
            let f: Vec<&str> = rest.split(' ').collect();
            if f.len() != 5 {
                return Err(bad("ingest", "malformed session line"));
            }
            out.push(IngestSessionRec {
                id: f[0].into(),
                owner_pub: hex::decode(f[1]).map_err(|_| bad("ingest", "owner not hex"))?,
                parent: f[2].into(),
                root: f[3].into(),
                origin: f[4].into(),
                files: Vec::new(),
            });
        } else if let Some(rest) = line.strip_prefix("file ") {
            // "<sid> <node> <size> <committed|-> <rel_path…>" — rel_path may hold spaces
            let mut f = rest.splitn(5, ' ');
            let (sid, node, size, committed, rel) = match (f.next(), f.next(), f.next(), f.next(), f.next()) {
                (Some(a), Some(b), Some(c), Some(d), Some(e)) => (a, b, c, d, e),
                _ => return Err(bad("ingest", "malformed file line")),
            };
            let sess = out
                .iter_mut()
                .find(|s| s.id == sid)
                .ok_or_else(|| bad("ingest", "file line before its session"))?;
            sess.files.push(IngestFileRec {
                node: node.into(),
                rel_path: rel.into(),
                size: size.parse().map_err(|_| bad("ingest", "bad size"))?,
                committed: if committed == "-" { None } else { Some(committed.into()) },
            });
        } else {
            return Err(bad("ingest", "unrecognized ingest.sessions line"));
        }
    }
    Ok(out)
}

pub fn save_sessions(data_dir: &Path, sessions: &[IngestSessionRec]) -> Result<()> {
    let mut text = String::from(SESSIONS_HEADER);
    text.push('\n');
    for s in sessions {
        text.push_str(&format!(
            "session {} {} {} {} {}\n",
            s.id,
            hex::encode(&s.owner_pub),
            s.parent,
            s.root,
            s.origin
        ));
        for f in &s.files {
            text.push_str(&format!(
                "file {} {} {} {} {}\n",
                s.id,
                f.node,
                f.size,
                f.committed.as_deref().unwrap_or("-"),
                f.rel_path
            ));
        }
    }
    crate::storage::atomic_overwrite(&sessions_path(data_dir), text.as_bytes())
}

// ---- the progress sidecar (doc 23 §9.3) -----------------------------------------

const PROGRESS_HEADER: &str = "pvfs-ingest-progress 1";

/// Per-file verification state: app-verified byte ranges (coalesced) and the
/// chunks fully covered by them, BLAKE3'd from the partial at mark time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngestProgressState {
    pub size: u64,
    pub chunk: u64,
    /// Half-open `[start, end)`, sorted, non-overlapping.
    pub ranges: Vec<(u64, u64)>,
    /// Fully covered chunk index → chunk hash.
    pub done: BTreeMap<u64, [u8; 32]>,
}

/// The sidecar beside the partial: `.{id}.progress` (not `.tmp`, so the
/// startup sweep leaves it — same reasoning as `.swarmpart`).
pub fn progress_path(data_dir: &Path, id: &str) -> Result<PathBuf> {
    let dest = sync_store_path(data_dir, id)?;
    Ok(dest.with_file_name(format!(".{id}.progress")))
}

impl IngestProgressState {
    pub fn fresh(size: u64) -> IngestProgressState {
        IngestProgressState {
            size,
            chunk: SWARM_CHUNK,
            ranges: Vec::new(),
            done: BTreeMap::new(),
        }
    }

    pub fn chunks_total(&self) -> u64 {
        if self.size == 0 {
            0
        } else {
            self.size.div_ceil(self.chunk)
        }
    }

    pub fn bytes_verified(&self) -> u64 {
        self.ranges.iter().map(|(s, e)| e - s).sum()
    }

    /// The chunk's byte span, clamped to the file.
    pub fn chunk_span(&self, idx: u64) -> (u64, u64) {
        let start = idx * self.chunk;
        (start, (start + self.chunk).min(self.size))
    }

    /// Merge validated ranges (half-open, within the file) into the set.
    pub fn add_ranges(&mut self, add: &[(u64, u64)]) -> Result<()> {
        for &(s, e) in add {
            if s >= e || e > self.size {
                return Err(bad("ranges", "range outside the declared size"));
            }
        }
        let mut all: Vec<(u64, u64)> = self.ranges.iter().copied().chain(add.iter().copied()).collect();
        all.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(all.len());
        for (s, e) in all {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        self.ranges = merged;
        Ok(())
    }

    fn covered(&self, start: u64, end: u64) -> bool {
        self.ranges.iter().any(|&(s, e)| s <= start && end <= e)
    }

    /// Chunks fully covered by verified ranges but not yet hashed/marked.
    pub fn newly_covered(&self) -> Vec<u64> {
        (0..self.chunks_total())
            .filter(|i| !self.done.contains_key(i))
            .filter(|&i| {
                let (s, e) = self.chunk_span(i);
                self.covered(s, e)
            })
            .collect()
    }
}

/// Load a file's progress; a missing sidecar is a fresh state (nothing
/// verified yet). A malformed one is a hard error — it is authoritative.
pub fn load_progress(path: &Path, size: u64) -> Result<IngestProgressState> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(IngestProgressState::fresh(size))
        }
        Err(e) => return Err(PvfsError::io("read ingest progress", e)),
    };
    let mut lines = text.lines();
    if lines.next() != Some(PROGRESS_HEADER) {
        return Err(bad("ingest", "unrecognized progress sidecar"));
    }
    let mut p = IngestProgressState::fresh(size);
    let mut ranges = Vec::new();
    for line in lines.filter(|l| !l.trim().is_empty()) {
        let f: Vec<&str> = line.split(' ').collect();
        match (f.first().copied(), f.len()) {
            (Some("chunk"), 2) => p.chunk = f[1].parse().map_err(|_| bad("ingest", "bad chunk"))?,
            (Some("size"), 2) => p.size = f[1].parse().map_err(|_| bad("ingest", "bad size"))?,
            (Some("range"), 3) => ranges.push((
                f[1].parse().map_err(|_| bad("ingest", "bad range"))?,
                f[2].parse().map_err(|_| bad("ingest", "bad range"))?,
            )),
            (Some("done"), 3) => {
                let idx: u64 = f[1].parse().map_err(|_| bad("ingest", "bad done index"))?;
                let h = hex::decode(f[2]).map_err(|_| bad("ingest", "bad done hash"))?;
                let h: [u8; 32] = h.try_into().map_err(|_| bad("ingest", "bad done hash"))?;
                p.done.insert(idx, h);
            }
            _ => return Err(bad("ingest", "unrecognized progress line")),
        }
    }
    p.add_ranges(&ranges)?;
    Ok(p)
}

pub fn save_progress(path: &Path, p: &IngestProgressState) -> Result<()> {
    let mut text = format!("{PROGRESS_HEADER}\nchunk {}\nsize {}\n", p.chunk, p.size);
    for (s, e) in &p.ranges {
        text.push_str(&format!("range {s} {e}\n"));
    }
    for (i, h) in &p.done {
        text.push_str(&format!("done {i} {}\n", hex::encode(h)));
    }
    crate::storage::atomic_overwrite(path, text.as_bytes())
}

// ---- the prepared batches (doc 23 §9.2/§9.4) ------------------------------------

/// One declared file in an `IngestBegin`.
#[derive(Debug, Clone)]
pub struct IngestFileSpec {
    pub rel_path: String,
    pub size: u64,
}

/// What `prepare_ingest_begin` lays out — mirrored into the session record
/// once the member's commit lands.
#[derive(Debug, Clone)]
pub struct IngestPlan {
    pub root: NodeId,
    pub origin: NodeId,
    pub files: Vec<IngestFileRec>,
}

/// The closing record batched into a last-file commit or an abort (§8.4).
#[derive(Debug, Clone)]
pub struct IngestClose {
    pub parent: NodeId,
    pub label: String,
    pub payload: Vec<u8>,
}

fn valid_kind(kind: &str) -> bool {
    !kind.is_empty()
        && kind
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' || c == '_')
}

fn check_rel_path(rel: &str) -> Result<()> {
    if rel.is_empty() || rel.starts_with('/') || rel.ends_with('/') {
        return Err(bad("rel_path", "must be a relative path"));
    }
    if rel.split('/').any(|seg| seg.is_empty() || seg == "." || seg == "..") {
        return Err(bad("rel_path", "path segments must be plain names"));
    }
    Ok(())
}

/// The origin record's JSON payload (doc 23 §9.1). Hand-formatted: every
/// interpolated field is a validated token or hex, so no escaping applies.
fn origin_payload(kind: &str, infohash: &str, piece_size: u64, root: &str, total: u64) -> Vec<u8> {
    format!(
        r#"{{"kind":"{kind}","infohash":"{infohash}","piece_size":{piece_size},"root":"{root}","total_bytes":{total}}}"#
    )
    .into_bytes()
}

/// The closing record's JSON payload (§8.4).
pub fn closed_payload(origin: &str, outcome: &str) -> Vec<u8> {
    format!(r#"{{"origin":"{origin}","outcome":"{outcome}"}}"#).into_bytes()
}

impl Engine {
    /// Phase 1 of `IngestBegin` (doc 23 §9.2): one member-signed batch that
    /// catalogs the whole torrent — the root folder (when needed),
    /// intermediate folders, one unhashed pointer node per file, and the
    /// `pvos.download` origin record, all under one timestamp. Requires
    /// write (`w`) on `parent`; intra-batch parentage is authorized at
    /// commit by the batch-aware check.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_ingest_begin(
        &self,
        author_pub: &[u8],
        parent: &NodeId,
        name: &str,
        kind: &str,
        infohash: &str,
        piece_size: u64,
        session_tag: &str,
        files: &[IngestFileSpec],
    ) -> Result<(PreparedWrite, IngestPlan)> {
        if files.is_empty() {
            return Err(bad("files", "an ingest session needs at least one file"));
        }
        if !valid_kind(kind) {
            return Err(bad("kind", "lowercase token (e.g. bittorrent)"));
        }
        if infohash.is_empty() || hex::decode(infohash).is_err() {
            return Err(bad("infohash", "must be hex"));
        }
        if piece_size == 0 {
            return Err(bad("piece_size", "must be positive"));
        }
        for f in files {
            check_rel_path(&f.rel_path)?;
        }
        let parent_node = fetch_node(&self.conn, parent)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: parent.clone(),
        })?;
        if parent_node.is_temp {
            return Err(bad("parent", "cannot ingest under a temp parent"));
        }
        let author = crate::acl::Principal::Key(author_pub.to_vec());
        if crate::projection::effective_rights(&self.conn, &author, parent)? & crate::acl::ACL_W
            == 0
        {
            return Err(PvfsError::Forbidden {
                action: "ingest begin".into(),
                reason: format!("you lack write (w) on {parent}"),
            });
        }
        let needs_folder =
            files.len() > 1 || files[0].rel_path.contains('/') || !name.is_empty();
        if needs_folder && name.is_empty() {
            return Err(bad("name", "a multi-file ingest needs a torrent name"));
        }
        if needs_folder {
            self.validate_label(name)?;
        }

        let t = now_ms();
        let mut events: Vec<PreparedEvent> = Vec::new();
        // Sibling order: existing parents continue after their current last
        // child; batch-born folders start fresh. Tracked per parent so the
        // batch lays out deterministic sibling order.
        let mut last_key: HashMap<NodeId, Option<OrderKey>> = HashMap::new();
        last_key.insert(parent.clone(), max_order_key(&self.conn, parent)?);

        let make_node = |events: &mut Vec<PreparedEvent>,
                             last_key: &mut HashMap<NodeId, Option<OrderKey>>,
                             node_type: &str,
                             label: &str,
                             payload: Vec<u8>,
                             under: &NodeId|
         -> Result<NodeId> {
            let creation_nonce = {
                let mut b = [0u8; 8];
                rand::thread_rng().fill_bytes(&mut b);
                u64::from_le_bytes(b)
            };
            let mut node = Node {
                id: String::new(),
                node_type: node_type.into(),
                label: label.into(),
                visibility: VISIBILITY_PUBLIC.into(),
                payload,
                is_temp: false,
                creation_nonce,
                created_at: t,
                author: author_pub.to_vec(),
                sig: Vec::new(),
            };
            let node_digest = node.id_digest();
            node.id = hex::encode(node_digest);
            let prev = last_key.entry(under.clone()).or_insert(None);
            let order = OrderKey::after(prev.as_ref())?;
            let order_str: String = order.as_str().into();
            *prev = Some(order);
            let mut link = Link {
                id: String::new(),
                parent_id: Some(under.clone()),
                child_id: node.id.clone(),
                link_type: LINK_CONTAINS.into(),
                link_nonce: 0,
                order_key: order_str,
                created_at: t,
                author: author_pub.to_vec(),
                sig: Vec::new(),
                removed_at: None,
                superseded_by: None,
                suspended_at: None,
            };
            let link_digest = link.id_digest();
            link.id = hex::encode(link_digest);
            let id = node.id.clone();
            events.push(PreparedEvent {
                digest: node_digest,
                event: Event::NodeCreated(node),
            });
            events.push(PreparedEvent {
                digest: link_digest,
                event: Event::LinkCreated(link),
            });
            Ok(id)
        };

        let root = if needs_folder {
            make_node(&mut events, &mut last_key, TYPE_FOLDER, name, Vec::new(), parent)?
        } else {
            parent.clone() // single bare file: the root IS the file, set below
        };

        // Intermediate folders, created once per distinct directory path.
        let mut dirs: HashMap<String, NodeId> = HashMap::new();
        let mut plan_files: Vec<IngestFileRec> = Vec::new();
        let mut single_root: Option<NodeId> = None;
        for f in files {
            let (dir_path, file_name) = match f.rel_path.rsplit_once('/') {
                Some((d, n)) => (Some(d), n),
                None => (None, f.rel_path.as_str()),
            };
            self.validate_label(file_name)?;
            let mut under = if needs_folder { root.clone() } else { parent.clone() };
            if let Some(dp) = dir_path {
                let mut sofar = String::new();
                for seg in dp.split('/') {
                    self.validate_label(seg)?;
                    if !sofar.is_empty() {
                        sofar.push('/');
                    }
                    sofar.push_str(seg);
                    under = match dirs.get(&sofar) {
                        Some(id) => id.clone(),
                        None => {
                            let id = make_node(
                                &mut events,
                                &mut last_key,
                                TYPE_FOLDER,
                                seg,
                                Vec::new(),
                                &under,
                            )?;
                            dirs.insert(sofar.clone(), id.clone());
                            id
                        }
                    };
                }
            }
            let payload = FilePayload {
                content_hash: String::new(),
                size_bytes: f.size,
                mime_type: String::new(),
                original_name: file_name.into(),
            }
            .encode();
            let id = make_node(&mut events, &mut last_key, TYPE_FILE, file_name, payload, &under)?;
            if !needs_folder {
                single_root = Some(id.clone());
            }
            plan_files.push(IngestFileRec {
                node: id,
                rel_path: f.rel_path.clone(),
                size: f.size,
                committed: None,
            });
        }
        let root = single_root.unwrap_or(root);

        // The origin record, last — its payload names the root (doc 23 §9.1).
        let total: u64 = files.iter().map(|f| f.size).sum();
        let tag8: String = session_tag.chars().take(8).collect();
        let origin = make_node(
            &mut events,
            &mut last_key,
            TYPE_DOWNLOAD,
            &format!(".pvos.download-{tag8}"),
            origin_payload(kind, infohash, piece_size, &root, total),
            parent,
        )?;

        Ok((
            PreparedWrite {
                result_id: root.clone(),
                events,
            },
            IngestPlan {
                root,
                origin,
                files: plan_files,
            },
        ))
    }

    /// Phase 1 of `IngestCommit` (doc 23 §9.4): the member-signed hash-fill
    /// successor + `ChunkManifestRecorded` attestation, with the
    /// `pvos.download.closed` record batched in when this is the session's
    /// last file. The caller hashed the partial outside any lock;
    /// `content_hash`/`size`/`chunks` are that read's answers. Returns the
    /// successor's id.
    pub fn prepare_ingest_commit(
        &self,
        author_pub: &[u8],
        file_id: &NodeId,
        content_hash: &str,
        size: u64,
        chunks: &[[u8; 32]],
        close: Option<&IngestClose>,
    ) -> Result<(PreparedWrite, NodeId)> {
        let old = fetch_node(&self.conn, file_id)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: file_id.clone(),
        })?;
        if old.node_type != TYPE_FILE {
            return Err(bad("file", "ingest commit works on file nodes"));
        }
        let old_payload = FilePayload::decode(&old.payload)?;
        if !old_payload.content_hash.is_empty() {
            return Err(bad("file", "already hashed (publish retry goes via swarm_commit)"));
        }
        if !self.locations(file_id)?.is_empty() {
            return Err(bad("file", "ingest commit expects a location-less pointer node"));
        }
        if content_hash.is_empty() {
            return Err(bad("content_hash", "must not be empty"));
        }
        let t = now_ms();
        let creation_nonce = {
            let mut b = [0u8; 8];
            rand::thread_rng().fill_bytes(&mut b);
            u64::from_le_bytes(b)
        };
        let mut new_node = Node {
            id: String::new(),
            node_type: old.node_type.clone(),
            label: old.label.clone(),
            visibility: VISIBILITY_PUBLIC.into(),
            payload: FilePayload {
                content_hash: content_hash.into(),
                size_bytes: size,
                mime_type: old_payload.mime_type,
                original_name: old_payload.original_name,
            }
            .encode(),
            is_temp: false,
            creation_nonce,
            created_at: t,
            author: author_pub.to_vec(),
            sig: Vec::new(),
        };
        let node_digest = new_node.id_digest();
        new_node.id = hex::encode(node_digest);
        let new_id = new_node.id.clone();

        let mut events = vec![PreparedEvent {
            digest: node_digest,
            event: Event::NodeCreated(new_node),
        }];

        // Home swap (mirrors fs.rs successor_node, member-authored).
        if let Some((old_link_id, parent)) = active_home(&self.conn, file_id)? {
            let order_key = fetch_link(&self.conn, &old_link_id)?
                .map(|l| l.order_key)
                .unwrap_or_else(|| OrderKey::middle().as_str().to_string());
            let mut new_link = Link {
                id: String::new(),
                parent_id: parent.clone(),
                child_id: new_id.clone(),
                link_type: LINK_CONTAINS.into(),
                link_nonce: 0,
                order_key,
                created_at: t,
                author: author_pub.to_vec(),
                sig: Vec::new(),
                removed_at: None,
                superseded_by: None,
                suspended_at: None,
            };
            let link_digest = new_link.id_digest();
            new_link.id = hex::encode(link_digest);
            let sup_digest = event::msg_link_superseded(&old_link_id, &new_link.id, author_pub);
            let rem_digest = event::msg_link_removed(&old_link_id, t, author_pub);
            let new_link_id = new_link.id.clone();
            events.push(PreparedEvent {
                digest: link_digest,
                event: Event::LinkCreated(new_link),
            });
            events.push(PreparedEvent {
                digest: sup_digest,
                event: Event::LinkSuperseded {
                    old_link_id: old_link_id.clone(),
                    new_link_id,
                    author: author_pub.to_vec(),
                    sig: Vec::new(),
                },
            });
            events.push(PreparedEvent {
                digest: rem_digest,
                event: Event::LinkRemoved {
                    link_id: old_link_id,
                    removed_at: t,
                    removed_by: author_pub.to_vec(),
                    removal_sig: Vec::new(),
                },
            });
        }

        // The attestation — the early-serve license (doc 22 §2, admin-gated).
        let root = manifest_root(chunks);
        let attest_digest = event::msg_chunk_manifest_recorded(
            &new_id,
            content_hash,
            SWARM_CHUNK,
            &root,
            t,
            author_pub,
        );
        events.push(PreparedEvent {
            digest: attest_digest,
            event: Event::ChunkManifestRecorded {
                file_id: new_id.clone(),
                content_hash: content_hash.into(),
                chunk_size: SWARM_CHUNK,
                manifest_root: root.to_vec(),
                at: t,
                author: author_pub.to_vec(),
                sig: Vec::new(),
            },
        });

        // The closing record, when this commit finishes the session (§8.4).
        if let Some(c) = close {
            let mut rec = Node {
                id: String::new(),
                node_type: TYPE_DOWNLOAD_CLOSED.into(),
                label: c.label.clone(),
                visibility: VISIBILITY_PUBLIC.into(),
                payload: c.payload.clone(),
                is_temp: false,
                creation_nonce: {
                    let mut b = [0u8; 8];
                    rand::thread_rng().fill_bytes(&mut b);
                    u64::from_le_bytes(b)
                },
                created_at: t,
                author: author_pub.to_vec(),
                sig: Vec::new(),
            };
            let rec_digest = rec.id_digest();
            rec.id = hex::encode(rec_digest);
            let order = OrderKey::after(max_order_key(&self.conn, &c.parent)?.as_ref())?;
            let mut rec_link = Link {
                id: String::new(),
                parent_id: Some(c.parent.clone()),
                child_id: rec.id.clone(),
                link_type: LINK_CONTAINS.into(),
                link_nonce: 0,
                order_key: order.as_str().into(),
                created_at: t,
                author: author_pub.to_vec(),
                sig: Vec::new(),
                removed_at: None,
                superseded_by: None,
                suspended_at: None,
            };
            let rec_link_digest = rec_link.id_digest();
            rec_link.id = hex::encode(rec_link_digest);
            events.push(PreparedEvent {
                digest: rec_digest,
                event: Event::NodeCreated(rec),
            });
            events.push(PreparedEvent {
                digest: rec_link_digest,
                event: Event::LinkCreated(rec_link),
            });
        }

        Ok((
            PreparedWrite {
                result_id: new_id.clone(),
                events,
            },
            new_id,
        ))
    }

    /// The hash-fill successor of an ingested pointer node, if one landed —
    /// the crash-window resolver (doc 23 §9.4): a commit that reached the
    /// log but not the sessions file is found by its superseded home link.
    pub fn ingest_successor(&self, old: &NodeId) -> Result<Option<NodeId>> {
        use rusqlite::OptionalExtension;
        self.conn
            .query_row(
                "SELECT l2.child_id FROM links l1 JOIN links l2 ON l1.superseded_by = l2.id
                  WHERE l1.child_id = ?1 AND l2.child_id != ?1 LIMIT 1",
                rusqlite::params![old],
                |r| r.get(0),
            )
            .optional()
            .map_err(crate::error::map_db("ingest successor lookup"))
    }

    /// Publish a just-committed ingest file: rename the partial into the
    /// store and cache the manifest sidecar. Skips `swarm_commit`'s
    /// whole-file re-read on purpose — this daemon hashed these very bytes
    /// moments ago (writes frozen since prepare), and the successor's
    /// catalog hash IS that hash, so the writer lock stays O(1). The
    /// crash-retry path (daemon restarted between commit and publish) goes
    /// through `swarm_commit`'s full verify instead (doc 23 §9.4).
    pub fn ingest_publish(
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
        if payload.content_hash.is_empty() {
            return Err(bad("file", "ingest publish requires a hashed file"));
        }
        let dest = sync_store_path(self.data_dir(), id)?;
        if let Some(dir) = dest.parent() {
            std::fs::create_dir_all(dir).map_err(|e| PvfsError::io("create store dir", e))?;
        }
        std::fs::rename(part, &dest).map_err(|e| PvfsError::io("publish ingest partial", e))?;
        // Sidecar is a cache — best-effort, like swarm_commit's.
        let _ = crate::sync::write_manifest_sidecar(&dest, manifest);
        self.conn
            .execute(
                "DELETE FROM location_quarantine WHERE file_id = ?1 AND uri = ?2",
                rusqlite::params![id, crate::sync::sync_uri(id)],
            )
            .map_err(crate::error::map_db("ingest publish quarantine"))?;
        Ok(dest)
    }
}

/// The partial's path for an ingest file — shared with the swarm (`.swarmpart`).
pub fn part_path(data_dir: &Path, id: &str) -> Result<PathBuf> {
    swarm_part_path(data_dir, id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_merge_and_cover_chunks() {
        let mut p = IngestProgressState::fresh(SWARM_CHUNK * 2 + 100);
        assert_eq!(p.chunks_total(), 3);
        p.add_ranges(&[(0, 100), (50, SWARM_CHUNK)]).unwrap();
        assert_eq!(p.ranges, vec![(0, SWARM_CHUNK)]);
        assert_eq!(p.newly_covered(), vec![0]);
        // the short tail chunk covers with a short range
        p.add_ranges(&[(SWARM_CHUNK * 2, SWARM_CHUNK * 2 + 100)]).unwrap();
        assert_eq!(p.newly_covered(), vec![0, 2]);
        p.done.insert(0, [0u8; 32]);
        assert_eq!(p.newly_covered(), vec![2]);
        assert_eq!(p.bytes_verified(), SWARM_CHUNK + 100);
        // out of bounds refused
        assert!(p.add_ranges(&[(0, SWARM_CHUNK * 9)]).is_err());
        assert!(p.add_ranges(&[(5, 5)]).is_err());
    }

    #[test]
    fn sessions_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = vec![IngestSessionRec {
            id: "abc123".into(),
            owner_pub: vec![1, 2, 3],
            parent: "p".repeat(64),
            root: "r".repeat(64),
            origin: "o".repeat(64),
            files: vec![
                IngestFileRec {
                    node: "f".repeat(64),
                    rel_path: "Season 1/ep 01.mkv".into(),
                    size: 42,
                    committed: None,
                },
                IngestFileRec {
                    node: "g".repeat(64),
                    rel_path: "b.txt".into(),
                    size: 7,
                    committed: Some("h".repeat(64)),
                },
            ],
        }];
        save_sessions(dir.path(), &sessions).unwrap();
        assert_eq!(load_sessions(dir.path()).unwrap(), sessions);
        // empty save + load
        save_sessions(dir.path(), &[]).unwrap();
        assert_eq!(load_sessions(dir.path()).unwrap(), Vec::new());
    }

    #[test]
    fn progress_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".x.progress");
        let mut p = IngestProgressState::fresh(SWARM_CHUNK + 5);
        p.add_ranges(&[(10, 900_000)]).unwrap();
        p.done.insert(1, [7u8; 32]);
        save_progress(&path, &p).unwrap();
        assert_eq!(load_progress(&path, SWARM_CHUNK + 5).unwrap(), p);
        // missing = fresh
        let fresh = load_progress(&dir.path().join("nope"), 9).unwrap();
        assert_eq!(fresh, IngestProgressState::fresh(9));
    }

    #[test]
    fn payloads_are_parseable_json() {
        let o = origin_payload("bittorrent", "aabb", 262144, &"r".repeat(64), 999);
        let s = String::from_utf8(o).unwrap();
        assert!(s.contains(r#""infohash":"aabb""#) && s.contains(r#""piece_size":262144"#));
        let c = closed_payload("orig", "aborted");
        assert_eq!(
            String::from_utf8(c).unwrap(),
            r#"{"origin":"orig","outcome":"aborted"}"#
        );
        assert!(valid_kind("bittorrent") && valid_kind("http-1.1"));
        assert!(!valid_kind("") && !valid_kind(r#"a"b"#) && !valid_kind("A"));
    }

    #[test]
    fn rel_paths_validated() {
        assert!(check_rel_path("a.mkv").is_ok());
        assert!(check_rel_path("Season 1/a.mkv").is_ok());
        for bad_path in ["", "/abs", "a/", "a//b", "../x", "a/../b", "."] {
            assert!(check_rel_path(bad_path).is_err(), "{bad_path:?} accepted");
        }
    }
}
