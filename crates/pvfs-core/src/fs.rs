//! P1 — bound folders, scan/reconcile, read path with integrity, lazy hash,
//! pending-change resolution, and the managed temp spool (doc 04).

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::PathBuf;

use rusqlite::{params, OptionalExtension};

use crate::engine::{active_home, bad, fetch_link, fetch_node, now_ms, Engine};
use crate::error::{map_db, IntegrityReason, PvfsError, Result};
use crate::event::{self, Event};
use crate::link::{Link, LINK_CONTAINS};
use crate::node::{self, FilePayload, Node, NodeId, VISIBILITY_PUBLIC};
use crate::orderkey::OrderKey;
use crate::storage::{
    guess_mime, path_to_uri, uri_to_path, ByteRange, LocalBackend, StorageBackend,
};

const SPOOL_DIR: &str = "tmp";
const TMP_URI_PREFIX: &str = "pvfs-tmp:///";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashPolicy {
    Lazy,
    OnAdd,
    Never,
}

impl HashPolicy {
    pub fn parse(s: &str) -> Result<HashPolicy> {
        match s {
            "lazy" => Ok(HashPolicy::Lazy),
            "on_add" => Ok(HashPolicy::OnAdd),
            "never" => Ok(HashPolicy::Never),
            other => Err(bad("hash_policy", &format!("unknown policy {other:?}"))),
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            HashPolicy::Lazy => "lazy",
            HashPolicy::OnAdd => "on_add",
            HashPolicy::Never => "never",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Binding {
    pub folder_id: NodeId,
    pub source_uri: String,
    pub recursive: bool,
    pub auto_index: bool,
    /// lowercased, empty = all
    pub extensions: Vec<String>,
    pub hash_policy: HashPolicy,
    pub bound_at: u64,
}

#[derive(Debug, Clone)]
pub struct BindSpec {
    pub source_uri: String,
    pub recursive: bool,
    pub auto_index: bool,
    pub extensions: String, // comma list, "" = all
    pub hash_policy: HashPolicy,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ScanStats {
    pub added: u64,
    pub unchanged: u64,
    pub changed: u64,
    pub removed: u64,
    /// Intentionally not indexed (dotfile, or filtered by the binding's extensions).
    pub skipped: u64,
    /// Present on disk but the operator can't read it, so it was not imported.
    pub unreadable: u64,
}

#[derive(Debug)]
pub struct ScanReport {
    pub folder_id: NodeId,
    pub stats: ScanStats,
}

#[derive(Debug, Clone)]
pub struct PendingChange {
    pub file_id: NodeId,
    pub label: String,
    pub uri: String,
    pub old_size: u64,
    pub new_size: u64,
    pub detected_at: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum ResolveAction {
    Replace,
    Delete { purge: bool },
}

#[derive(Debug, Clone)]
pub struct LocationStat {
    pub uri: String,
    pub exists: bool,
    pub size: u64,
    pub quarantined: Option<String>,
    pub pending_change: bool,
}

#[derive(Debug)]
pub struct NodeStat {
    pub node: Node,
    pub locations: Vec<LocationStat>,
    /// true when the node has no readable, trusted location
    pub unavailable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    Ok,
    Mismatch,
    Missing,
}

struct DiskFile {
    rel_dirs: Vec<String>,
    name: String,
    size: u64,
    mtime_ms: u64,
    path: PathBuf,
}

impl Engine {
    // ---- bindings (doc 04 §3) --------------------------------------------------

    pub fn bind_folder(&mut self, folder: &NodeId, spec: BindSpec) -> Result<()> {
        self.ensure_device_active()?;
        let n = fetch_node(&self.conn, folder)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: folder.clone(),
        })?;
        if n.node_type != node::TYPE_FOLDER {
            return Err(bad("folder", "bindings attach to folder nodes only"));
        }
        if n.is_temp {
            return Err(bad("folder", "cannot bind a temp folder"));
        }
        let st = LocalBackend.stat(&spec.source_uri)?;
        if !st.exists || !st.is_dir {
            return Err(bad(
                "source_uri",
                &format!("{} is not an existing directory", spec.source_uri),
            ));
        }
        if self.binding_for(folder)?.is_some() {
            return Err(bad("folder", "already bound; unbind first"));
        }
        let dup: Option<String> = self
            .conn
            .query_row(
                "SELECT folder_id FROM folder_bindings WHERE source_uri = ?1 AND unbound_at IS NULL",
                params![spec.source_uri],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_db("binding lookup"))?;
        if let Some(other) = dup {
            return Err(bad(
                "source_uri",
                &format!("already bound to folder {other}"),
            ));
        }
        // normalize extensions
        let exts = spec
            .extensions
            .split(',')
            .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(",");
        let t = now_ms();
        let me = self.device.pubkey();
        let sig = crate::crypto::sign_digest(
            &self.device.signing_key,
            &event::msg_folder_bound(
                folder,
                &spec.source_uri,
                spec.recursive,
                spec.auto_index,
                &exts,
                spec.hash_policy.as_str(),
                t,
                &me,
            ),
        )?;
        self.append_durable(vec![Event::FolderBound {
            folder_id: folder.clone(),
            source_uri: spec.source_uri,
            recursive: spec.recursive,
            auto_index: spec.auto_index,
            extensions: exts,
            hash_policy: spec.hash_policy.as_str().into(),
            bound_at: t,
            author: me,
            sig,
        }])
    }

    pub fn unbind_folder(&mut self, folder: &NodeId) -> Result<()> {
        self.ensure_device_active()?;
        if self.binding_for(folder)?.is_none() {
            return Err(PvfsError::NotFound {
                kind: "binding",
                id: folder.clone(),
            });
        }
        let t = now_ms();
        let me = self.device.pubkey();
        let sig = crate::crypto::sign_digest(
            &self.device.signing_key,
            &event::msg_folder_unbound(folder, t, &me),
        )?;
        self.append_durable(vec![Event::FolderUnbound {
            folder_id: folder.clone(),
            unbound_at: t,
            author: me,
            sig,
        }])
    }

    pub fn bindings(&self) -> Result<Vec<Binding>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT folder_id, source_uri, recursive, auto_index, extensions, hash_policy, bound_at
                 FROM folder_bindings WHERE unbound_at IS NULL ORDER BY folder_id",
            )
            .map_err(map_db("list bindings"))?;
        let rows = stmt
            .query_map([], row_to_binding)
            .map_err(map_db("list bindings"))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(map_db("list bindings"))??);
        }
        Ok(out)
    }

    pub fn binding_for(&self, folder: &NodeId) -> Result<Option<Binding>> {
        let got = self
            .conn
            .query_row(
                "SELECT folder_id, source_uri, recursive, auto_index, extensions, hash_policy, bound_at
                 FROM folder_bindings WHERE folder_id = ?1 AND unbound_at IS NULL",
                params![folder],
                row_to_binding,
            )
            .optional()
            .map_err(map_db("binding lookup"))?;
        match got {
            None => Ok(None),
            Some(r) => Ok(Some(r?)),
        }
    }

    // ---- scan & reconcile (doc 04 §4) --------------------------------------------

    /// Scan one bound folder (or all of them) against its directory.
    pub fn scan(&mut self, folder: Option<&NodeId>) -> Result<Vec<ScanReport>> {
        let bindings = match folder {
            Some(f) => {
                let b = self.binding_for(f)?.ok_or(PvfsError::NotFound {
                    kind: "binding",
                    id: f.clone(),
                })?;
                vec![b]
            }
            None => self.bindings()?,
        };
        let mut reports = Vec::new();
        for b in bindings {
            let stats = self.scan_binding(&b)?;
            reports.push(ScanReport {
                folder_id: b.folder_id.clone(),
                stats,
            });
        }
        Ok(reports)
    }

    fn scan_binding(&mut self, b: &Binding) -> Result<ScanStats> {
        let root = uri_to_path(&b.source_uri)?;
        let st = LocalBackend.stat(&b.source_uri)?;
        if !st.exists || !st.is_dir {
            // Source missing (unmounted NAS?) — do NOT mass-remove; surface it.
            return Err(PvfsError::NotFound {
                kind: "bound directory",
                id: b.source_uri.clone(),
            });
        }
        let mut stats = ScanStats::default();

        // 1. pure-FS walk
        let mut files = Vec::new();
        let mut visited = HashSet::new();
        walk_disk(&root, Vec::new(), b.recursive, &mut visited, &mut files, &mut stats, b)?;

        // 2. mirror folders + ingest files
        let mut folder_ids: HashMap<String, NodeId> = HashMap::new();
        folder_ids.insert(String::new(), b.folder_id.clone());
        let mut seen: HashSet<String> = HashSet::new();

        for f in &files {
            let uri = path_to_uri(&f.path)?;
            seen.insert(uri.clone());
            let parent = self.ensure_subfolders(&mut folder_ids, &b.folder_id, &f.rel_dirs)?;
            self.ingest_file(b, &parent, f, &uri, &mut stats)?;
        }

        // 3. deletions: tracked URIs under this binding that vanished from disk
        let prefix = format!("{}/", b.source_uri.trim_end_matches('/'));
        let tracked: Vec<(String, String)> = {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT uri, file_id FROM scan_state WHERE uri LIKE ?1 || '%'
                     UNION
                     SELECT uri, file_id FROM file_locations
                      WHERE uri LIKE ?1 || '%' AND removed_at IS NULL",
                )
                .map_err(map_db("scan removals"))?;
            let rows = stmt
                .query_map(params![prefix], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })
                .map_err(map_db("scan removals"))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(map_db("scan removals"))?
        };
        for (uri, file_id) in tracked {
            if seen.contains(&uri) {
                continue;
            }
            let still_there = LocalBackend.stat(&uri).map(|s| s.exists).unwrap_or(false);
            if still_there {
                continue; // filtered out, not deleted — leave it alone
            }
            // soft-remove the location if still active
            let active: Option<i64> = self
                .conn
                .query_row(
                    "SELECT 1 FROM file_locations WHERE file_id = ?1 AND uri = ?2 AND removed_at IS NULL",
                    params![file_id, uri],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_db("scan removals"))?;
            if active.is_some() {
                self.remove_location(&file_id, &uri)?;
            }
            self.conn
                .execute("DELETE FROM scan_state WHERE uri = ?1", params![uri])
                .map_err(map_db("scan removals"))?;
            self.conn
                .execute(
                    "DELETE FROM pending_changes WHERE file_id = ?1 AND uri = ?2",
                    params![file_id, uri],
                )
                .map_err(map_db("scan removals"))?;
            stats.removed += 1;
        }
        Ok(stats)
    }

    fn ensure_subfolders(
        &mut self,
        cache: &mut HashMap<String, NodeId>,
        root: &NodeId,
        rel_dirs: &[String],
    ) -> Result<NodeId> {
        let mut current = root.clone();
        let mut key = String::new();
        for d in rel_dirs {
            if !key.is_empty() {
                key.push('/');
            }
            key.push_str(d);
            if let Some(id) = cache.get(&key) {
                current = id.clone();
                continue;
            }
            // existing child folder with this label?
            let found = self
                .children(&current)?
                .into_iter()
                .find(|c| {
                    c.link_type == LINK_CONTAINS
                        && c.node.node_type == node::TYPE_FOLDER
                        && c.node.label == *d
                })
                .map(|c| c.node.id);
            let id = match found {
                Some(id) => id,
                None => self.add_node(
                    &current,
                    crate::engine::NodeSpec {
                        node_type: node::TYPE_FOLDER.into(),
                        label: d.clone(),
                        payload: node::folder_payload(),
                        is_temp: false,
                        creation_nonce: None,
                    },
                )?,
            };
            cache.insert(key.clone(), id.clone());
            current = id;
        }
        Ok(current)
    }

    fn ingest_file(
        &mut self,
        b: &Binding,
        parent: &NodeId,
        f: &DiskFile,
        uri: &str,
        stats: &mut ScanStats,
    ) -> Result<()> {
        // known via scan_state?
        let ss: Option<(u64, u64, String)> = self
            .conn
            .query_row(
                "SELECT size_bytes, mtime_ms, file_id FROM scan_state WHERE uri = ?1",
                params![uri],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)? as u64,
                        r.get::<_, i64>(1)? as u64,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(map_db("scan state"))?;
        if let Some((size, mtime, file_id)) = ss {
            if size == f.size && mtime == f.mtime_ms {
                stats.unchanged += 1;
            } else {
                self.flag_change(&file_id, uri, size, mtime, f)?;
                stats.changed += 1;
            }
            return Ok(());
        }
        // active location already recorded (e.g. post-rebuild)?
        let active: Option<String> = self
            .conn
            .query_row(
                "SELECT file_id FROM file_locations WHERE uri = ?1 AND removed_at IS NULL",
                params![uri],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_db("scan match"))?;
        if let Some(file_id) = active {
            let recorded = self.payload_size(&file_id)?;
            if recorded == Some(f.size) {
                self.set_scan_state(uri, f.size, f.mtime_ms, &file_id)?;
                stats.unchanged += 1;
            } else {
                self.flag_change(&file_id, uri, recorded.unwrap_or(0), 0, f)?;
                stats.changed += 1;
            }
            return Ok(());
        }
        // soft-removed location whose file came back, same size ⇒ reactivate
        let prior: Option<String> = self
            .conn
            .query_row(
                "SELECT file_id FROM file_locations WHERE uri = ?1 ORDER BY added_at DESC LIMIT 1",
                params![uri],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_db("scan match"))?;
        if let Some(file_id) = prior {
            if self.payload_size(&file_id)? == Some(f.size)
                && fetch_node(&self.conn, &file_id)?.is_some()
            {
                self.add_location(&file_id, uri)?;
                self.set_scan_state(uri, f.size, f.mtime_ms, &file_id)?;
                stats.added += 1;
                return Ok(());
            }
        }
        // brand-new file ⇒ pointer node + location
        let content_hash = match b.hash_policy {
            HashPolicy::OnAdd => LocalBackend.hash(uri)?,
            _ => String::new(),
        };
        let payload = FilePayload {
            content_hash,
            size_bytes: f.size,
            mime_type: guess_mime(&f.name),
            original_name: f.name.clone(),
        }
        .encode();
        let id = self.add_node(
            parent,
            crate::engine::NodeSpec {
                node_type: node::TYPE_FILE.into(),
                label: f.name.clone(),
                payload,
                is_temp: false,
                creation_nonce: None,
            },
        )?;
        self.add_location(&id, uri)?;
        self.set_scan_state(uri, f.size, f.mtime_ms, &id)?;
        stats.added += 1;
        Ok(())
    }

    fn flag_change(
        &mut self,
        file_id: &str,
        uri: &str,
        old_size: u64,
        old_mtime: u64,
        f: &DiskFile,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO pending_changes
                 (file_id, uri, old_size, old_mtime, new_size, new_mtime, detected_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(file_id, uri) DO UPDATE SET
                   new_size = excluded.new_size, new_mtime = excluded.new_mtime",
                params![
                    file_id,
                    uri,
                    old_size as i64,
                    old_mtime as i64,
                    f.size as i64,
                    f.mtime_ms as i64,
                    now_ms() as i64
                ],
            )
            .map_err(map_db("flag change"))?;
        Ok(())
    }

    fn payload_size(&self, file_id: &str) -> Result<Option<u64>> {
        match fetch_node(&self.conn, file_id)? {
            Some(n) if n.node_type == node::TYPE_FILE => {
                Ok(FilePayload::decode(&n.payload).ok().map(|p| p.size_bytes))
            }
            _ => Ok(None),
        }
    }

    fn set_scan_state(&self, uri: &str, size: u64, mtime: u64, file_id: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO scan_state (uri, size_bytes, mtime_ms, file_id)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(uri) DO UPDATE SET
                   size_bytes = excluded.size_bytes, mtime_ms = excluded.mtime_ms,
                   file_id = excluded.file_id",
                params![uri, size as i64, mtime as i64, file_id],
            )
            .map_err(map_db("scan state"))?;
        Ok(())
    }

    // ---- pending changes & resolve (doc 04 §4.4) -----------------------------------

    pub fn changes(&self) -> Result<Vec<PendingChange>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT p.file_id, p.uri, p.old_size, p.new_size, p.detected_at,
                        COALESCE(n.label, '?')
                 FROM pending_changes p LEFT JOIN nodes n ON n.id = p.file_id
                 ORDER BY p.detected_at",
            )
            .map_err(map_db("list changes"))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(PendingChange {
                    file_id: r.get(0)?,
                    uri: r.get(1)?,
                    old_size: r.get::<_, i64>(2)? as u64,
                    new_size: r.get::<_, i64>(3)? as u64,
                    detected_at: r.get::<_, i64>(4)? as u64,
                    label: r.get(5)?,
                })
            })
            .map_err(map_db("list changes"))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(map_db("list changes"))
    }

    /// Operator decision for a flagged node (doc 04 §4.4). Returns the
    /// replacement node id for `Replace`, the old id for `Delete`.
    pub fn resolve(&mut self, file_id: &NodeId, action: ResolveAction) -> Result<NodeId> {
        let rows: Vec<(String, u64)> = {
            let mut stmt = self
                .conn
                .prepare("SELECT uri, new_size FROM pending_changes WHERE file_id = ?1")
                .map_err(map_db("resolve"))?;
            let rows = stmt
                .query_map(params![file_id], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
                })
                .map_err(map_db("resolve"))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(map_db("resolve"))?
        };
        if rows.is_empty() {
            return Err(PvfsError::NotFound {
                kind: "pending change",
                id: file_id.clone(),
            });
        }
        match action {
            ResolveAction::Replace => {
                let (uri, _) = rows[0].clone();
                let hash_policy = self.policy_for_uri(&uri)?;
                let new_id = self.replace_file_node(file_id, &uri, hash_policy)?;
                self.clear_pending(file_id)?;
                Ok(new_id)
            }
            ResolveAction::Delete { purge } => {
                // orphan it: soft-remove inbound links + active locations
                let inbound: Vec<String> = {
                    let mut stmt = self
                        .conn
                        .prepare(
                            "SELECT id FROM links WHERE child_id = ?1 AND removed_at IS NULL",
                        )
                        .map_err(map_db("resolve delete"))?;
                    let rows = stmt
                        .query_map(params![file_id], |r| r.get::<_, String>(0))
                        .map_err(map_db("resolve delete"))?;
                    rows.collect::<std::result::Result<Vec<_>, _>>()
                        .map_err(map_db("resolve delete"))?
                };
                for l in inbound {
                    self.remove_link(&l)?;
                }
                for uri in self.locations(file_id)? {
                    self.remove_location(file_id, &uri)?;
                }
                self.clear_pending(file_id)?;
                if purge {
                    self.purge(std::slice::from_ref(file_id))?;
                }
                Ok(file_id.clone())
            }
        }
    }

    fn clear_pending(&self, file_id: &str) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM pending_changes WHERE file_id = ?1",
                params![file_id],
            )
            .map_err(map_db("clear pending"))?;
        Ok(())
    }

    fn policy_for_uri(&self, uri: &str) -> Result<HashPolicy> {
        let got: Option<String> = self
            .conn
            .query_row(
                "SELECT hash_policy FROM folder_bindings
                 WHERE unbound_at IS NULL AND ?1 LIKE source_uri || '/%'
                 ORDER BY LENGTH(source_uri) DESC LIMIT 1",
                params![uri],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_db("policy lookup"))?;
        match got {
            Some(s) => HashPolicy::parse(&s),
            None => Ok(HashPolicy::Lazy),
        }
    }

    /// Successor-node flow: new file node for the bytes now at `uri`, linked
    /// where the old node lived, with a LinkSuperseded trail. Moves only
    /// `move_uris`; other locations stay on the old node.
    fn replace_file_node(
        &mut self,
        old_id: &NodeId,
        uri: &str,
        hash_policy: HashPolicy,
    ) -> Result<NodeId> {
        let old = fetch_node(&self.conn, old_id)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: old_id.clone(),
        })?;
        let old_payload = FilePayload::decode(&old.payload)?;
        let st = LocalBackend.stat(uri)?;
        if !st.exists {
            return Err(PvfsError::NotFound {
                kind: "location",
                id: uri.to_string(),
            });
        }
        let content_hash = match hash_policy {
            HashPolicy::OnAdd => LocalBackend.hash(uri)?,
            _ => String::new(),
        };
        let new_payload = FilePayload {
            content_hash,
            size_bytes: st.size,
            mime_type: old_payload.mime_type.clone(),
            original_name: old_payload.original_name.clone(),
        };
        let new_id = self.successor_node(&old, new_payload.encode(), &[uri.to_string()])?;
        self.set_scan_state(uri, st.size, st.mtime_ms, &new_id)?;
        Ok(new_id)
    }

    /// Shared by resolve-replace and lazy-hash fill: create the successor
    /// node, swap the home link (Created + Superseded + Removed), move the
    /// given location URIs.
    fn successor_node(
        &mut self,
        old: &Node,
        new_payload: Vec<u8>,
        move_uris: &[String],
    ) -> Result<NodeId> {
        self.ensure_device_active()?;
        let t = now_ms();
        let me = self.device.pubkey();
        let creation_nonce = {
            use rand::RngCore;
            let mut b = [0u8; 8];
            rand::thread_rng().fill_bytes(&mut b);
            u64::from_le_bytes(b)
        };
        let new_node = self.sign_node(Node {
            id: String::new(),
            node_type: old.node_type.clone(),
            label: old.label.clone(),
            visibility: VISIBILITY_PUBLIC.into(),
            payload: new_payload,
            is_temp: false,
            creation_nonce,
            created_at: t,
            author: me.clone(),
            sig: Vec::new(),
        })?;

        let mut events = vec![Event::NodeCreated(new_node.clone())];

        // home swap (if the old node still has a home)
        if let Some((old_link_id, parent)) = active_home(&self.conn, &old.id)? {
            let old_link = fetch_link(&self.conn, &old_link_id)?;
            let order_key = old_link
                .as_ref()
                .map(|l| l.order_key.clone())
                .unwrap_or_else(|| OrderKey::middle().as_str().to_string());
            let new_link = self.sign_link(Link {
                id: String::new(),
                parent_id: parent.clone(),
                child_id: new_node.id.clone(),
                link_type: LINK_CONTAINS.into(),
                link_nonce: 0,
                order_key,
                created_at: t,
                author: me.clone(),
                sig: Vec::new(),
                removed_at: None,
                superseded_by: None,
                suspended_at: None,
            })?;
            let sup_sig = crate::crypto::sign_digest(
                &self.device.signing_key,
                &event::msg_link_superseded(&old_link_id, &new_link.id, &me),
            )?;
            let rem_sig = crate::crypto::sign_digest(
                &self.device.signing_key,
                &event::msg_link_removed(&old_link_id, t, &me),
            )?;
            events.push(Event::LinkCreated(new_link.clone()));
            events.push(Event::LinkSuperseded {
                old_link_id: old_link_id.clone(),
                new_link_id: new_link.id.clone(),
                author: me.clone(),
                sig: sup_sig,
            });
            events.push(Event::LinkRemoved {
                link_id: old_link_id,
                removed_at: t,
                removed_by: me.clone(),
                removal_sig: rem_sig,
            });
        }

        // move locations
        for uri in move_uris {
            let rm_sig = crate::crypto::sign_digest(
                &self.device.signing_key,
                &event::msg_file_location_removed(&old.id, uri, t, &me),
            )?;
            let add_sig = crate::crypto::sign_digest(
                &self.device.signing_key,
                &event::msg_file_location_added(&new_node.id, uri, t, &me),
            )?;
            events.push(Event::FileLocationRemoved {
                file_id: old.id.clone(),
                uri: uri.clone(),
                removed_at: t,
                removed_by: me.clone(),
                removal_sig: rm_sig,
            });
            events.push(Event::FileLocationAdded {
                file_id: new_node.id.clone(),
                uri: uri.clone(),
                added_at: t,
                author: me.clone(),
                sig: add_sig,
            });
        }
        let new_id = new_node.id.clone();
        self.append_durable(events)?;
        // local notes follow the node
        self.conn
            .execute(
                "UPDATE scan_state SET file_id = ?1 WHERE file_id = ?2",
                params![new_id, old.id],
            )
            .map_err(map_db("successor scan_state"))?;
        self.conn
            .execute(
                "DELETE FROM location_quarantine WHERE file_id = ?1",
                params![old.id],
            )
            .map_err(map_db("successor quarantine"))?;
        Ok(new_id)
    }

    // ---- read path (doc 04 §5) ------------------------------------------------------

    /// Stream a file node's bytes to `out`. Full reads verify the recorded
    /// content hash; a mismatch quarantines the location and errors.
    pub fn cat(
        &mut self,
        id: &NodeId,
        range: Option<ByteRange>,
        out: &mut dyn Write,
    ) -> Result<u64> {
        let n = fetch_node(&self.conn, id)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: id.clone(),
        })?;
        if n.node_type != node::TYPE_FILE {
            return Err(bad("node", "cat works on file nodes"));
        }
        let payload = FilePayload::decode(&n.payload)?;
        let uri = self
            .first_readable_location(id)?
            .ok_or(PvfsError::NotFound {
                kind: "available location",
                id: id.clone(),
            })?;
        let path_uri = self.resolve_uri(&uri)?;
        let mut reader = LocalBackend.read_range(&path_uri, range)?;

        if range.is_none() && !payload.content_hash.is_empty() {
            // verify while streaming
            let mut hasher = blake3::Hasher::new();
            let mut buf = vec![0u8; 1024 * 1024];
            let mut written = 0u64;
            loop {
                let got = reader.read(&mut buf).map_err(|e| PvfsError::io("cat read", e))?;
                if got == 0 {
                    break;
                }
                hasher.update(&buf[..got]);
                out.write_all(&buf[..got])
                    .map_err(|e| PvfsError::io("cat write", e))?;
                written += got as u64;
            }
            let actual = hasher.finalize().to_hex().to_string();
            if actual != payload.content_hash {
                self.quarantine(id, &uri, "hash mismatch on read")?;
                return Err(PvfsError::Integrity {
                    kind: "location",
                    id: uri,
                    reason: IntegrityReason::IdMismatch {
                        expected: payload.content_hash,
                        actual,
                    },
                });
            }
            Ok(written)
        } else {
            let mut limited_out = CountingWriter { inner: out, count: 0 };
            std::io::copy(&mut reader, &mut limited_out)
                .map_err(|e| PvfsError::io("cat copy", e))?;
            Ok(limited_out.count)
        }
    }

    fn first_readable_location(&self, id: &NodeId) -> Result<Option<String>> {
        let mut candidates = self.locations(id)?;
        candidates.sort(); // file:// before pvfs-tmp:// lexically — both local
        for uri in candidates {
            let flagged: Option<i64> = self
                .conn
                .query_row(
                    "SELECT 1 FROM pending_changes WHERE file_id = ?1 AND uri = ?2
                     UNION ALL
                     SELECT 1 FROM location_quarantine WHERE file_id = ?1 AND uri = ?2",
                    params![id, uri],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_db("read resolution"))?;
            if flagged.is_some() {
                continue;
            }
            let resolved = match self.resolve_uri(&uri) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if LocalBackend.stat(&resolved).map(|s| s.exists).unwrap_or(false) {
                return Ok(Some(uri));
            }
        }
        Ok(None)
    }

    /// Map pvfs-tmp:///<id> into the spool dir; pass file:// through.
    fn resolve_uri(&self, uri: &str) -> Result<String> {
        if let Some(name) = uri.strip_prefix(TMP_URI_PREFIX) {
            if name.contains('/') || name.contains("..") {
                return Err(bad("uri", "invalid pvfs-tmp URI"));
            }
            return path_to_uri(&self.data_dir.join(SPOOL_DIR).join(name));
        }
        if uri.starts_with("file://") {
            return Ok(uri.to_string());
        }
        Err(bad("uri", &format!("no backend for scheme: {uri}")))
    }

    fn quarantine(&self, id: &str, uri: &str, reason: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO location_quarantine (file_id, uri, reason, detected_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(file_id, uri) DO UPDATE SET
                   reason = excluded.reason, detected_at = excluded.detected_at",
                params![id, uri, reason, now_ms() as i64],
            )
            .map_err(map_db("quarantine"))?;
        Ok(())
    }

    /// Re-check a file's locations; lift quarantine where bytes match again.
    pub fn loc_verify(&mut self, id: &NodeId) -> Result<Vec<(String, VerifyOutcome)>> {
        let n = fetch_node(&self.conn, id)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: id.clone(),
        })?;
        let payload = FilePayload::decode(&n.payload)?;
        if payload.content_hash.is_empty() {
            return Err(bad("node", "no content_hash recorded — run `pvfs hash` first"));
        }
        let mut out = Vec::new();
        for uri in self.locations(id)? {
            let resolved = match self.resolve_uri(&uri) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if !LocalBackend.stat(&resolved)?.exists {
                out.push((uri, VerifyOutcome::Missing));
                continue;
            }
            let actual = LocalBackend.hash(&resolved)?;
            if actual == payload.content_hash {
                self.conn
                    .execute(
                        "DELETE FROM location_quarantine WHERE file_id = ?1 AND uri = ?2",
                        params![id, uri],
                    )
                    .map_err(map_db("verify"))?;
                out.push((uri, VerifyOutcome::Ok));
            } else {
                self.quarantine(id, &uri, "hash mismatch (verify)")?;
                out.push((uri, VerifyOutcome::Mismatch));
            }
        }
        Ok(out)
    }

    /// Fill a lazy content hash. NOTE: because the hash lives in the immutable
    /// payload, this creates a successor node (same flow as resolve-replace)
    /// and returns the NEW node id. Use `hash_policy = on_add` where stable
    /// ids matter from the start.
    pub fn hash_node(&mut self, id: &NodeId) -> Result<NodeId> {
        let n = fetch_node(&self.conn, id)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: id.clone(),
        })?;
        if n.node_type != node::TYPE_FILE {
            return Err(bad("node", "hash works on file nodes"));
        }
        let payload = FilePayload::decode(&n.payload)?;
        if !payload.content_hash.is_empty() {
            return Ok(id.clone()); // already hashed
        }
        let uri = self
            .first_readable_location(id)?
            .ok_or(PvfsError::NotFound {
                kind: "available location",
                id: id.clone(),
            })?;
        let resolved = self.resolve_uri(&uri)?;
        let content_hash = LocalBackend.hash(&resolved)?;
        let st = LocalBackend.stat(&resolved)?;
        let new_payload = FilePayload {
            content_hash,
            size_bytes: st.size,
            mime_type: payload.mime_type,
            original_name: payload.original_name,
        };
        let all_locations = self.locations(id)?;
        self.successor_node(&n, new_payload.encode(), &all_locations)
    }

    /// Node + per-location availability (doc 04 §9 `stat`).
    pub fn stat_node(&mut self, id: &NodeId) -> Result<NodeStat> {
        let n = fetch_node(&self.conn, id)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: id.clone(),
        })?;
        let mut locations = Vec::new();
        let mut any_good = false;
        for uri in self.locations(id)? {
            let quarantined: Option<String> = self
                .conn
                .query_row(
                    "SELECT reason FROM location_quarantine WHERE file_id = ?1 AND uri = ?2",
                    params![id, uri],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_db("stat"))?;
            let pending: Option<i64> = self
                .conn
                .query_row(
                    "SELECT 1 FROM pending_changes WHERE file_id = ?1 AND uri = ?2",
                    params![id, uri],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_db("stat"))?;
            let st = self
                .resolve_uri(&uri)
                .and_then(|r| LocalBackend.stat(&r))
                .unwrap_or(crate::storage::StatInfo {
                    exists: false,
                    is_dir: false,
                    size: 0,
                    mtime_ms: 0,
                });
            let good = st.exists && quarantined.is_none() && pending.is_none();
            any_good = any_good || good;
            locations.push(LocationStat {
                uri,
                exists: st.exists,
                size: st.size,
                quarantined,
                pending_change: pending.is_some(),
            });
        }
        Ok(NodeStat {
            unavailable: n.node_type == node::TYPE_FILE && !any_good,
            node: n,
            locations,
        })
    }

    // ---- managed temp spool (doc 04 §7) ---------------------------------------------

    pub(crate) fn spool_dir(&self) -> PathBuf {
        self.data_dir.join(SPOOL_DIR)
    }

    /// Write PVFS-managed bytes for a temp node into the spool; records a
    /// pvfs-tmp location. Only valid for temp nodes.
    pub fn write_managed_temp(&mut self, id: &NodeId, data: &mut dyn Read) -> Result<String> {
        let n = fetch_node(&self.conn, id)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: id.clone(),
        })?;
        if !n.is_temp {
            return Err(bad("node", "managed temp bytes attach to temp nodes only"));
        }
        let uri = format!("{TMP_URI_PREFIX}{id}");
        let disk_uri = self.resolve_uri(&uri)?;
        LocalBackend.write(&disk_uri, data)?;
        let t = now_ms() as i64;
        self.conn
            .execute(
                "INSERT INTO temp_file_locations (file_id, uri, added_at, removed_at)
                 VALUES (?1, ?2, ?3, NULL)
                 ON CONFLICT(file_id, uri) DO UPDATE SET
                   added_at = excluded.added_at, removed_at = NULL",
                params![id, uri, t],
            )
            .map_err(map_db("temp location"))?;
        Ok(uri)
    }

    /// Startup reconciliation sweep (doc 04 §7): delete spool files no temp
    /// node references; drop temp nodes whose spool file is missing. Only
    /// ever touches the spool dir.
    pub(crate) fn sweep_temp_spool(&mut self) -> Result<()> {
        let spool = self.spool_dir();
        std::fs::create_dir_all(&spool).map_err(|e| PvfsError::io("create spool", e))?;

        let live: Vec<String> = {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT file_id FROM temp_file_locations
                     WHERE uri LIKE 'pvfs-tmp:///%' AND removed_at IS NULL",
                )
                .map_err(map_db("spool sweep"))?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(map_db("spool sweep"))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(map_db("spool sweep"))?
        };
        let live_set: HashSet<&str> = live.iter().map(|s| s.as_str()).collect();

        // stale spool files → delete
        let rd = std::fs::read_dir(&spool).map_err(|e| PvfsError::io("read spool", e))?;
        let mut on_disk = HashSet::new();
        for entry in rd {
            let entry = entry.map_err(|e| PvfsError::io("read spool", e))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if live_set.contains(name.as_str()) {
                on_disk.insert(name);
            } else {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        // temp nodes whose backing bytes are gone → drop (force-purge)
        for id in live {
            if !on_disk.contains(&id) {
                self.temp_write(|tx| {
                    tx.execute(
                        "DELETE FROM temp_links WHERE parent_id = ?1 OR child_id = ?1",
                        params![id],
                    )
                    .map_err(map_db("spool sweep"))?;
                    tx.execute("DELETE FROM temp_nodes WHERE id = ?1", params![id])
                        .map_err(map_db("spool sweep"))?;
                    tx.execute(
                        "DELETE FROM temp_file_locations WHERE file_id = ?1",
                        params![id],
                    )
                    .map_err(map_db("spool sweep"))?;
                    Ok(())
                })?;
            }
        }
        Ok(())
    }
}

struct CountingWriter<'a> {
    inner: &'a mut dyn Write,
    count: u64,
}

impl Write for CountingWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn row_to_binding(r: &rusqlite::Row<'_>) -> std::result::Result<Result<Binding>, rusqlite::Error> {
    let policy: String = r.get(5)?;
    let exts: String = r.get(4)?;
    Ok(HashPolicy::parse(&policy).map(|hash_policy| Binding {
        folder_id: r.get(0).unwrap_or_default(),
        source_uri: r.get(1).unwrap_or_default(),
        recursive: r.get::<_, i64>(2).unwrap_or(1) != 0,
        auto_index: r.get::<_, i64>(3).unwrap_or(1) != 0,
        extensions: if exts.is_empty() {
            Vec::new()
        } else {
            exts.split(',').map(|s| s.to_string()).collect()
        },
        hash_policy,
        bound_at: r.get::<_, i64>(6).unwrap_or(0) as u64,
    }))
}

fn walk_disk(
    dir: &std::path::Path,
    rel: Vec<String>,
    recursive: bool,
    visited: &mut HashSet<PathBuf>,
    files: &mut Vec<DiskFile>,
    stats: &mut ScanStats,
    b: &Binding,
) -> Result<()> {
    let canon = std::fs::canonicalize(dir).map_err(|e| PvfsError::io("canonicalize", e))?;
    if !visited.insert(canon) {
        return Ok(()); // symlinked dir cycle
    }
    let uri = path_to_uri(dir)?;
    for entry in LocalBackend.list(&uri)? {
        if entry.name.starts_with('.') {
            stats.skipped += 1;
            continue;
        }
        let child = dir.join(&entry.name);
        if entry.is_dir {
            if recursive {
                // Skip directories the operator can't traverse/read rather than
                // aborting the whole import — never index what you can't read.
                if !is_accessible(&child, true) {
                    stats.unreadable += 1;
                    continue;
                }
                let mut sub = rel.clone();
                sub.push(entry.name.clone());
                walk_disk(&child, sub, recursive, visited, files, stats, b)?;
            }
            continue;
        }
        if !b.extensions.is_empty() {
            let ext = entry
                .name
                .rsplit('.')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            if !b.extensions.iter().any(|e| e == &ext) {
                stats.skipped += 1;
                continue;
            }
        }
        // Never import a file the operator cannot read.
        if !is_accessible(&child, false) {
            stats.unreadable += 1;
            continue;
        }
        files.push(DiskFile {
            rel_dirs: rel.clone(),
            name: entry.name.clone(),
            size: entry.size,
            mtime_ms: entry.mtime_ms,
            path: child,
        });
    }
    Ok(())
}

/// Whether the running user can read (and, for dirs, also traverse) `path`.
///
/// Uses `access(2)`, which checks the process's **real** uid/gid — matching the
/// intended model where the forest owner runs `init`/scans (and later their own
/// daemon) as themselves. Files that fail this are left out of the forest so it
/// never references content the owner can't actually read. Off Unix there is no
/// such check, so assume accessible.
#[cfg(unix)]
fn is_accessible(path: &std::path::Path, need_exec: bool) -> bool {
    use nix::unistd::{access, AccessFlags};
    let mut flags = AccessFlags::R_OK;
    if need_exec {
        flags |= AccessFlags::X_OK;
    }
    access(path, flags).is_ok()
}

#[cfg(not(unix))]
fn is_accessible(_path: &std::path::Path, _need_exec: bool) -> bool {
    true
}
