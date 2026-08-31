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
/// How long a file must have been untouched before the WATCHER will catalogue
/// it (D71 W6). Sonarr copies rather than renames, so a file appears under its
/// final name while still growing.
///
/// Deliberately **not** the default for `scan`: a one-shot scan, and
/// `forest init --import`, are asked to index what is on disk NOW, and a file
/// copied a minute ago is complete, not mid-write. Making this unconditional
/// changed the meaning of every scan in the codebase and broke 18 tests, which
/// was the correct signal. Only the continuous watcher — the one thing that
/// genuinely races an import — passes a non-zero window.
pub const WATCH_SETTLE_MS: u64 = 15_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashPolicy {
    OnAdd,
    Never,
}

impl HashPolicy {
    pub fn parse(s: &str) -> Result<HashPolicy> {
        match s {
            // D94 — `lazy` is GONE and is REFUSED, not quietly reinterpreted.
            //
            // Chris: it is not a real mode, so accepting the word would leave
            // something configured for a behaviour that no longer exists and
            // silently doing something else. A binding still asking for it is
            // exactly what we want to be told about, loudly, rather than have
            // work in a way it cannot.
            //
            // It did not defer the hashing, it skipped it: 91.5% of the media
            // forest was unhashed, and an unhashed file has no chunk manifest,
            // so a mount cannot stream it and blocks on a whole-file fetch —
            // 115.8s to read 1MB against 0.10s for a hashed one.
            //
            // Worse, it was the ORPHAN FACTORY. `on_add` gives a node its hash
            // at birth; `lazy` creates it bare and lets the fill mint a
            // SUCCESSOR, orphaning the original. That is 1298 orphaned unhashed
            // nodes on the ingest box and one more for every file still to be
            // filled — and an orphan could not even be retired until D90.
            "on_add" => Ok(HashPolicy::OnAdd),
            "never" => Ok(HashPolicy::Never),
            "lazy" => Err(bad(
                "hash_policy",
                "`lazy` was removed (D94): it did not defer hashing, it skipped \
                 it, and it orphaned a node per file by filling through a \
                 successor. Use `on_add` to hash on bind (the default), or \
                 `never` to deliberately leave a library unhashed.",
            )),
            other => Err(bad("hash_policy", &format!("unknown policy {other:?}"))),
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
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
    /// The device that ran the bind (D71 W1) — folded from the `FolderBound`
    /// event's author. `source_uri` is a path on THAT machine and nowhere
    /// else, so anything that touches the directory (scan, watch) must filter
    /// on this. See [`Engine::local_bindings`].
    pub bound_by: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BindSpec {
    pub source_uri: String,
    pub recursive: bool,
    pub auto_index: bool,
    pub extensions: String, // comma list, "" = all
    pub hash_policy: HashPolicy,
}

/// How a space is enrolled (P8, doc 21). Derived at read time from
/// placement state — see [`Engine::binding_listing`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindKind {
    InPlace,
    Migrate,
    Mirror,
}

impl BindKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            BindKind::InPlace => "in-place",
            BindKind::Migrate => "migrate",
            BindKind::Mirror => "mirror",
        }
    }
}

/// One row of the enrollment listing: the binding, its tree path from the
/// root (when attached), and the placement-derived kind + store.
#[derive(Debug, Clone)]
pub struct BindingRow {
    pub binding: Binding,
    pub folder_path: Option<String>,
    pub kind: BindKind,
    pub store: Option<PathBuf>,
    /// This machine bound it, so its directory exists here and this box
    /// scans/watches it (D71 W1). The listing deliberately shows the whole
    /// forest's enrollments — an operator wants to see the fleet — and marks
    /// which ones are local rather than hiding the rest.
    pub is_local: bool,
}

/// What `backfill_sidecars` did (D93).
#[derive(Debug, Default, Clone)]
pub struct BackfillReport {
    /// Hashes rescued out of the catalog and written beside the bytes.
    pub written: u64,
    /// Of those, ones with no chunk hashes to carry — the whole hash only.
    pub whole_hash_only: u64,
    /// Pre-D91 sidecars removed after their content was rewritten at the
    /// dotfile name.
    pub legacy_retired: u64,
    /// Already had a usable v2 sidecar; nothing to do.
    pub already_durable: u64,
    /// The catalog has no hash for these yet — the fill has not reached them.
    pub unhashed: u64,
    /// No readable copy on this box, so nowhere to leave the note.
    pub no_local_copy: u64,
    /// On-disk size disagrees with the catalog: a replacement at the same path,
    /// not the file that was hashed. Never stamped with the old hash.
    pub size_mismatch: u64,
    /// Nodes the catalog adopted that are actually PVFS's own sidecars. Skipped
    /// outright: a hash-rescue pass has no business touching our bookkeeping.
    pub own_bookkeeping: u64,
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
    /// D71 W6: recognised as a file the catalog already knows, found somewhere
    /// else in the tree. No new node was made — only a location added.
    pub relocated: u64,
    /// D71 W6: still being written when we looked, so deliberately NOT
    /// catalogued yet. Deferred, never dropped — the next pass takes it.
    pub settling: u64,
    /// The pass stopped early because a stop was asked for (D86). Everything
    /// counted here really happened; what is missing was never attempted.
    pub cancelled: bool,
    /// Directories mirrored that hold no indexed file DIRECTLY (they may still
    /// hold subdirectories). A folder is part of the shape of a tree, not merely
    /// a place files happen to be, so an empty one is content in its own right.
    pub empty_dirs: u64,
    /// D71 W4: the catalog refused this file for a reason retrying cannot fix
    /// (authorization, bad input). The pass skipped it and carried on — one bad
    /// file must never stop the line — but it needs a human. `quarantined`
    /// carries the first few, with reasons, so the report can say WHICH.
    pub needs_attention: u64,
    pub quarantined: Vec<(String, String)>,
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
        if !self.replica {
            self.ensure_device_active()?;
        }
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
        // D81 4d — mark it now, while we can see it. From here on, its absence
        // means the volume is not mounted, and the scan stops rather than
        // retiring everything under it.
        if let Ok(dir) = uri_to_path(&spec.source_uri) {
            crate::sync::write_root_marker(&dir, &self.identity.forest_id)?;
        }
        // D81 — a folder may have MANY roots. What is refused is a duplicate
        // (folder, directory) pair, and a directory already claimed by a
        // DIFFERENT folder; binding the same tree to a second directory is the
        // whole point. Before this, the second bind was refused outright — and
        // on a replica it did something worse, silently REPLACING the first.
        if self
            .bindings_for(folder)?
            .iter()
            .any(|b| b.source_uri == spec.source_uri)
        {
            return Err(bad(
                "source_uri",
                &format!("{} is already a root of this folder", spec.source_uri),
            ));
        }
        let dup: Option<String> = self
            .conn
            .query_row(
                "SELECT folder_id FROM folder_bindings
                  WHERE source_uri = ?1 AND folder_id != ?2 AND unbound_at IS NULL",
                params![spec.source_uri, folder],
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

        // A replica has no local writer and `bind` has no write-through wire
        // op, so this machine records its own enrollment locally (see the
        // local-bindings note above). Everything the scan then writes — nodes,
        // locations — DOES route write-through, so the catalog still gets the
        // content; only the enrollment itself stays here.
        if self.replica {
            let mut rows = load_local_bindings(&self.data_dir)?;
            // D81 — drop only THIS root's row, not every root of the folder.
            rows.retain(|b| !(b.folder_id == *folder && b.source_uri == spec.source_uri));
            rows.push(Binding {
                folder_id: folder.clone(),
                source_uri: spec.source_uri,
                recursive: spec.recursive,
                auto_index: spec.auto_index,
                extensions: if exts.is_empty() {
                    Vec::new()
                } else {
                    exts.split(',').map(|s| s.to_string()).collect()
                },
                hash_policy: spec.hash_policy,
                bound_at: t,
                bound_by: self.device.pubkey(),
            });
            return save_local_bindings(&self.data_dir, &rows);
        }

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

    /// Remove one root, or the only root.
    ///
    /// D81 — with many roots per folder, "unbind this folder" is ambiguous and
    /// the ambiguous answer is destructive: unbinding every root of a
    /// two-volume library because the caller named no root would be a very
    /// quiet way to lose half a catalog's reach. So it is refused, and the
    /// roots are listed.
    pub fn unbind_folder(&mut self, folder: &NodeId, root: Option<&str>) -> Result<()> {
        if !self.replica {
            self.ensure_device_active()?;
        }
        let roots = self.bindings_for(folder)?;
        if roots.is_empty() {
            return Err(PvfsError::NotFound {
                kind: "binding",
                id: folder.clone(),
            });
        }
        let target: String = match root {
            Some(r) => {
                if !roots.iter().any(|b| b.source_uri == r) {
                    return Err(bad(
                        "root",
                        &format!(
                            "{r} is not a root of this folder; it has: {}",
                            roots
                                .iter()
                                .map(|b| b.source_uri.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    ));
                }
                r.to_string()
            }
            None if roots.len() == 1 => roots[0].source_uri.clone(),
            None => {
                return Err(bad(
                    "root",
                    &format!(
                        "this folder has {} roots — name the one to remove: {}",
                        roots.len(),
                        roots
                            .iter()
                            .map(|b| b.source_uri.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ))
            }
        };
        if self.replica {
            let mut rows = load_local_bindings(&self.data_dir)?;
            rows.retain(|b| !(b.folder_id == *folder && b.source_uri == target));
            return save_local_bindings(&self.data_dir, &rows);
        }
        let t = now_ms();
        let me = self.device.pubkey();
        let sig = crate::crypto::sign_digest(
            &self.device.signing_key,
            &event::msg_folder_unbound_root(folder, &target, t, &me),
        )?;
        self.append_durable(vec![Event::FolderUnboundRoot {
            folder_id: folder.clone(),
            source_uri: target,
            unbound_at: t,
            author: me,
            sig,
        }])
    }

    pub fn bindings(&self) -> Result<Vec<Binding>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT folder_id, source_uri, recursive, auto_index, extensions, hash_policy, bound_at, bound_by
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
        // This machine's own enrollments (D71 W4) sit beside the logged ones.
        // A logged binding for the same ROOT wins — the log is the shared
        // truth, and a local row for it would be this box shadowing the fleet.
        //
        // D81 — the comparison is on (folder, ROOT), not folder alone. Matching
        // on the folder meant that once the first local root was pushed, every
        // later root of that folder matched it and was dropped: a replica with
        // two roots listed one, and `local_bindings` — which the SCAN uses —
        // returned one, so the watcher only ever scanned half the library.
        //
        // Exactly Chris's NAS with `Data` and `Data_ext`. Invisible to
        // single-box testing, because an owner's bindings are LOGGED and come
        // from the query above; only a replica's are local, and only a replica
        // can have several.
        let me = self.device.pubkey();
        for mut b in load_local_bindings(&self.data_dir)? {
            if out
                .iter()
                .any(|l| l.folder_id == b.folder_id && l.source_uri == b.source_uri)
            {
                continue;
            }
            b.bound_by = me.clone();
            out.push(b);
        }
        out.sort_by(|a, b| a.folder_id.cmp(&b.folder_id));
        Ok(out)
    }

    /// The bindings THIS machine owns — the only ones whose `source_uri`
    /// names a directory that exists here (D71 W1).
    ///
    /// A binding is a forest-wide catalog record describing a machine-local
    /// fact, so every caller that touches the directory behind it must filter
    /// on the device. Before this existed, `scan(None)` and the watcher walked
    /// every binding in the forest and died on the first one belonging to
    /// another box — which made the `watch` job unusable on any replica
    /// (proven on the D69 lab: an ingest box aborted on the owner's four
    /// binds).
    ///
    /// Note this is deliberately NOT "skip bindings whose directory is
    /// missing". A binding that IS this machine's and whose directory has
    /// vanished must still raise — that is the unmounted-NAS guard in
    /// [`Engine::scan_binding`], and quietly skipping it would let a scan
    /// soft-remove every location under it.
    pub fn local_bindings(&self) -> Result<Vec<Binding>> {
        let me = self.device.pubkey();
        Ok(self
            .bindings()?
            .into_iter()
            .filter(|b| b.bound_by == me)
            .collect())
    }

    /// Whether `binding` was bound by this machine.
    pub fn is_local_binding(&self, binding: &Binding) -> bool {
        binding.bound_by == self.device.pubkey()
    }

    /// EVERY root of this folder — logged and this machine's own (D81).
    ///
    /// `binding_for` returns at most one, which was the only possible answer
    /// while `folder_id` was a primary key. It still exists for callers that
    /// genuinely want a single root, but any caller deciding what to SCAN must
    /// use this: a folder with two roots scanned through the singular form
    /// silently ignores one of them.
    pub fn bindings_for(&self, folder: &NodeId) -> Result<Vec<Binding>> {
        let mut out: Vec<Binding> = Vec::new();
        let mut stmt = self
            .conn
            .prepare(
                "SELECT folder_id, source_uri, recursive, auto_index, extensions, hash_policy, bound_at, bound_by
                 FROM folder_bindings WHERE folder_id = ?1 AND unbound_at IS NULL",
            )
            .map_err(map_db("binding lookup"))?;
        let rows = stmt
            .query_map(params![folder], row_to_binding)
            .map_err(map_db("binding lookup"))?;
        for r in rows {
            out.push(r.map_err(map_db("binding lookup"))??);
        }
        for b in load_local_bindings(&self.data_dir)? {
            if b.folder_id == *folder && !out.iter().any(|x| x.source_uri == b.source_uri) {
                out.push(b);
            }
        }
        Ok(out)
    }

    pub fn binding_for(&self, folder: &NodeId) -> Result<Option<Binding>> {
        let got = self
            .conn
            .query_row(
                "SELECT folder_id, source_uri, recursive, auto_index, extensions, hash_policy, bound_at, bound_by
                 FROM folder_bindings WHERE folder_id = ?1 AND unbound_at IS NULL",
                params![folder],
                row_to_binding,
            )
            .optional()
            .map_err(map_db("binding lookup"))?;
        match got {
            Some(r) => Ok(Some(r?)),
            // Fall through to this machine's own enrollments (D71 W4).
            None => {
                let me = self.device.pubkey();
                Ok(load_local_bindings(&self.data_dir)?
                    .into_iter()
                    .find(|b| b.folder_id == *folder)
                    .map(|mut b| {
                        b.bound_by = me;
                        b
                    }))
            }
        }
    }

    /// The enrollment listing (doc 21, D64): every live binding joined
    /// against placement state to recover its kind — `central` → migrate,
    /// `central-keep` → mirror, neither → in-place. The kind is a derived
    /// fact: placement is per-instance deployment state, never catalog
    /// truth (doc 17 §6), so the log stores no kind and the join happens
    /// at read time. Read-only; works on a read view.
    pub fn binding_listing(&self) -> Result<Vec<BindingRow>> {
        let centrals = crate::sync::load_central_all(&self.data_dir)?;
        let mut out = Vec::new();
        for binding in self.bindings()? {
            // D81 — which roots DRAIN is per root, so the kind must be too.
            // The listing used to read the folder's placement and label every
            // root of it `migrate`, which in a three-root library said that all
            // three drained when only one did. An operator reading that before
            // deciding where to put a title would be reading a lie.
            let staging = crate::sync::staging_roots_of(&self.data_dir, &binding.folder_id)?;
            let declared = crate::sync::library_roots_of(&self.data_dir, &binding.folder_id)?;
            // D81 — a folder is opted into the per-root model by EITHER kind of
            // declaration. Checking only staging meant a root declared LIBRARY
            // still listed as `migrate`, telling the operator it drains when it
            // keeps — the exact reverse of the truth, on the one screen they
            // would check before trusting it.
            let opted_in = !staging.is_empty() || !declared.is_empty();
            let drains = staging.iter().any(|u| u == &binding.source_uri);
            let (kind, store) = match centrals.iter().find(|(id, _, _)| id == &binding.folder_id)
            {
                Some((_, dir, true)) => (BindKind::Mirror, Some(dir.clone())),
                Some((_, dir, false)) if !opted_in || drains => {
                    (BindKind::Migrate, Some(dir.clone()))
                }
                // Marked roots exist and this is not one of them: it KEEPS what
                // it holds, and the store is still where new content goes.
                Some((_, dir, false)) => (BindKind::InPlace, Some(dir.clone())),
                None => (BindKind::InPlace, None),
            };
            let folder_path = self.folder_tree_path(&binding.folder_id)?;
            let is_local = self.is_local_binding(&binding);
            out.push(BindingRow {
                binding,
                folder_path,
                kind,
                store,
                is_local,
            });
        }
        Ok(out)
    }

    /// Tree path of a node from the forest root ("/media/import"), walking
    /// contains-links upward. `None` when the node is detached from the
    /// root (or the walk exceeds any sane depth) — an absent path is
    /// honest; an invented one is not.
    /// Which live node claims this location URI, if any (D71 W5).
    ///
    /// The mover asks before writing over anything: the answer decides whether
    /// an occupied destination is this file's own older copy (an upgrade —
    /// replace it), another live file's bytes (refuse), or something the
    /// catalog has never seen (refuse, because on a 130T NAS silently
    /// clobbering an unrecognised file is the worst thing this can do).
    pub fn location_owner(&self, uri: &str) -> Result<Option<NodeId>> {
        self.conn
            .query_row(
                "SELECT file_id FROM file_locations
                  WHERE uri = ?1 AND removed_at IS NULL LIMIT 1",
                params![uri],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_db("location owner"))
    }

    /// The path of `node` relative to `ancestor`, as tree segments (D71 W5).
    ///
    /// This is what lets a migrated file land at
    /// `…/Media/TV/Show/Season 03/ep.mkv` on the NAS instead of a hex blob in
    /// a node-addressed store — so the NAS stays a normal media library that
    /// Plex reads directly, and PVFS stops being *required* to read it.
    ///
    /// `None` when `node` is not under `ancestor` at all, which the caller must
    /// treat as "do not place this here" rather than guessing a path.
    pub fn tree_path_under(
        &self,
        node: &NodeId,
        ancestor: &NodeId,
    ) -> Result<Option<Vec<String>>> {
        let mut segments: Vec<String> = Vec::new();
        let mut current = node.clone();
        for _ in 0..256 {
            if current == *ancestor {
                segments.reverse();
                return Ok(Some(segments));
            }
            let Some(n) = fetch_node(&self.conn, &current)? else {
                return Ok(None);
            };
            // D72: the segment is the name the CONTAINING LINK gives this
            // child, not the node's own. Reading `n.label` here would make the
            // tree path — and therefore the file's path on the NAS — keep the
            // name a file was renamed AWAY from, so a rename would never reach
            // the disk that matters.
            let parent: Option<(String, String)> = self
                .conn
                .query_row(
                    "SELECT parent_id, label FROM links
                     WHERE child_id = ?1 AND link_type = ?2 AND removed_at IS NULL
                       AND parent_id IS NOT NULL
                     ORDER BY id LIMIT 1",
                    params![current, LINK_CONTAINS],
                    |r| Ok((r.get(0)?, r.get::<_, String>(1).unwrap_or_default())),
                )
                .optional()
                .map_err(map_db("tree path"))?;
            match parent {
                Some((p, link_label)) => {
                    segments.push(if link_label.is_empty() {
                        n.label
                    } else {
                        link_label
                    });
                    current = p;
                }
                None => return Ok(None),
            }
        }
        Ok(None)
    }

    fn folder_tree_path(&self, folder: &NodeId) -> Result<Option<String>> {
        let root = &self.identity.root_node_id;
        if folder == root {
            return Ok(Some("/".into()));
        }
        let mut segments: Vec<String> = Vec::new();
        let mut current = folder.clone();
        for _ in 0..256 {
            let Some(node) = fetch_node(&self.conn, &current)? else {
                return Ok(None);
            };
            // D72: same rule as `tree_path_under` — the containing link names
            // the child. A folder rename must move the binding path with it.
            let parent: Option<(String, String)> = self
                .conn
                .query_row(
                    "SELECT parent_id, label FROM links
                     WHERE child_id = ?1 AND link_type = ?2 AND removed_at IS NULL
                       AND parent_id IS NOT NULL
                     ORDER BY id LIMIT 1",
                    params![current, LINK_CONTAINS],
                    |r| Ok((r.get(0)?, r.get::<_, String>(1).unwrap_or_default())),
                )
                .optional()
                .map_err(map_db("binding path walk"))?;
            match parent {
                None => return Ok(None),
                Some((p, link_label)) => {
                    segments.push(if link_label.is_empty() {
                        node.label
                    } else {
                        link_label
                    });
                    if &p == root {
                        segments.reverse();
                        return Ok(Some(format!("/{}", segments.join("/"))));
                    }
                    current = p;
                }
            }
        }
        Ok(None)
    }

    // ---- scan & reconcile (doc 04 §4) --------------------------------------------

    /// Scan one bound folder (or all of them) against its directory.
    ///
    /// "All of them" means **this machine's** (D71 W1) — a binding made on
    /// another box names a directory that does not exist here, and walking it
    /// is at best an error and at worst a mass soft-removal. Naming a foreign
    /// binding explicitly is a clear error rather than a silent skip: the
    /// caller asked for something this machine cannot do.
    pub fn scan(&mut self, folder: Option<&NodeId>) -> Result<Vec<ScanReport>> {
        self.scan_routed(folder, None, 0)
    }

    /// `scan`, with the catalog writes sent somewhere other than this engine
    /// (D71 W4). `None` = write locally, which is what an owner does.
    pub fn scan_routed(
        &mut self,
        folder: Option<&NodeId>,
        mut writer: Option<&mut dyn ScanWriter>,
        settle_ms: u64,
    ) -> Result<Vec<ScanReport>> {
        // A replica with no route cannot write a single thing it finds, so say
        // so ONCE, up front, naming the fix — rather than walking the whole
        // library and quarantining every file with the same reason. The cause
        // is the configuration, not the files.
        if self.replica && writer.is_none() {
            return Err(PvfsError::Forbidden {
                action: "scan".into(),
                reason: "a replica has no local writer, so its scan must be routed to the \
                         owner — run it from the `watch` serve job, which opens that route, \
                         rather than as a bare local scan"
                    .into(),
            });
        }
        let bindings = match folder {
            Some(f) => {
                // D81 — every root of this folder, not just the first. Scanning
                // one root of a two-root folder is how "the library is on two
                // volumes" turns into "half the library vanished".
                let all = self.bindings_for(f)?;
                if all.is_empty() {
                    return Err(PvfsError::NotFound {
                        kind: "binding",
                        id: f.clone(),
                    });
                }
                let mine: Vec<Binding> = all
                    .iter()
                    .filter(|b| self.is_local_binding(b))
                    .cloned()
                    .collect();
                if mine.is_empty() {
                    let b = all[0].clone();
                    return Err(bad(
                        "folder",
                        &format!(
                            "{} is bound on another machine ({}) — scan it there; \
                             this box only scans directories it bound itself",
                            b.source_uri,
                            short_key(&b.bound_by),
                        ),
                    ));
                }
                mine
            }
            None => self.local_bindings()?,
        };
        let mut reports = Vec::new();
        for b in bindings {
            let stats = self.scan_binding(&b, &mut writer, settle_ms)?;
            let stopped = stats.cancelled;
            reports.push(ScanReport {
                folder_id: b.folder_id.clone(),
                stats,
            });
            // A folder with several roots (D81) must not carry on to the next
            // one after being told to stop.
            if stopped {
                break;
            }
        }
        Ok(reports)
    }

    /// Index a directory into `folder` WITHOUT taking the folder's binding.
    ///
    /// D74/D78 — the bug this exists to avoid: bindings are keyed
    /// `folder_id PRIMARY KEY`, fleet-wide, and a LOGGED binding beats a
    /// machine's local one ("a local row for it would be this box shadowing
    /// the fleet"). So adopting a central store by binding it on the owner
    /// silently shadowed the ingest box's binding, and its watcher — still
    /// reporting `running`, with no error — scanned nothing at all.
    ///
    /// Adoption is a ONE-SHOT index, not an ongoing enrollment. It has no
    /// business claiming the folder's binding, and now does not: the spec is
    /// built in memory, used for one pass, and never persisted.
    pub fn scan_unbound(
        &mut self,
        folder: &NodeId,
        source_uri: &str,
        spec: &BindSpec,
        writer: &mut Option<&mut dyn ScanWriter>,
        settle_ms: u64,
    ) -> Result<ScanStats> {
        let transient = Binding {
            folder_id: folder.clone(),
            source_uri: source_uri.to_string(),
            recursive: spec.recursive,
            auto_index: spec.auto_index,
            extensions: spec
                .extensions
                .split(',')
                .filter(|e| !e.is_empty())
                .map(|e| e.trim().to_lowercase())
                .collect(),
            hash_policy: spec.hash_policy,
            bound_at: now_ms(),
            // This machine's — the directory is a path here and nowhere else.
            bound_by: self.device.pubkey(),
        };
        self.scan_binding(&transient, writer, settle_ms)
    }

    fn scan_binding(
        &mut self,
        b: &Binding,
        writer: &mut Option<&mut dyn ScanWriter>,
        settle_ms: u64,
    ) -> Result<ScanStats> {
        let root = uri_to_path(&b.source_uri)?;
        let st = LocalBackend.stat(&b.source_uri)?;
        if !st.exists || !st.is_dir {
            // Source missing (unmounted NAS?) — do NOT mass-remove; surface it.
            return Err(PvfsError::NotFound {
                kind: "bound directory",
                id: b.source_uri.clone(),
            });
        }
        // D81 4d — the path existing is not the volume being THERE. A volume
        // that mounts empty, or whose mountpoint survives an unmount, passes
        // the check above and then every tracked location under it stats as
        // gone. The marker is what tells the difference (Chris's suggestion,
        // and the same discriminator D74 gave central stores after the mover
        // wrote 16MB to a VM's root filesystem believing it was the NAS).
        crate::sync::verify_root_marker(&root)?;
        let mut stats = ScanStats::default();

        // 1. pure-FS walk
        let mut files = Vec::new();
        let mut dirs = Vec::new();
        let mut visited = HashSet::new();
        walk_disk(
            &root,
            Vec::new(),
            &mut visited,
            &mut files,
            &mut dirs,
            &mut stats,
            &WalkCtx { binding: b, settle_ms },
        )?;

        // 2. mirror folders + ingest files
        let mut folder_ids: HashMap<String, NodeId> = HashMap::new();
        folder_ids.insert(String::new(), b.folder_id.clone());
        let mut seen: HashSet<String> = HashSet::new();

        // Directories FIRST, so the shape of the tree does not depend on which
        // directories happened to contain a file. `ensure_subfolders` is
        // idempotent and shares `folder_ids` with the ingest below, so a
        // directory that does hold files costs a cache hit here, not a lookup.
        for d in &dirs {
            if self.cancelled() {
                stats.cancelled = true;
                return Ok(stats);
            }
            self.ensure_subfolders(&mut folder_ids, &b.folder_id, d, writer)?;
        }
        // Report only the ones holding no file of their own; the rest are about
        // to be counted as the files they hold.
        let dirs_with_files: HashSet<&[String]> =
            files.iter().map(|f| f.rel_dirs.as_slice()).collect();
        stats.empty_dirs = dirs
            .iter()
            .filter(|d| !dirs_with_files.contains(d.as_slice()))
            .count() as u64;

        for f in &files {
            // Between files, as well as inside the hash. A pass abandoned here
            // has recorded every file before this one; the next pass resumes.
            if self.cancelled() {
                stats.cancelled = true;
                return Ok(stats);
            }
            let uri = path_to_uri(&f.path)?;
            seen.insert(uri.clone());
            let parent = self.ensure_subfolders(&mut folder_ids, &b.folder_id, &f.rel_dirs, writer)?;
            // One file the catalog will never accept must not stop the line —
            // the hook this replaced quarantined a bad event and carried on.
            if let Err(e) = self.ingest_file(b, &parent, f, &uri, &mut stats, writer) {
                if is_transient(&e) {
                    return Err(e);
                }
                stats.needs_attention += 1;
                if stats.quarantined.len() < 8 {
                    stats.quarantined.push((uri.clone(), e.to_string()));
                }
            }
        }

        // 3. deletions: tracked URIs under this binding that vanished from disk
        //
        // D81 — TWO prefixes, not one. This box's own locations are recorded
        // host-implicit (`file:///path`) when it owns the log, and
        // PIN-QUALIFIED (`pvfs-host://<pin>/path`) when it is a REPLICA writing
        // through to the owner (D75). Matching only the bare `file://` prefix
        // meant a replica's `file_locations` half matched NOTHING: the removal
        // was skipped by the `active.is_some()` guard below, the `scan_state`
        // row was deleted anyway so the next pass could not see it either, and
        // the stale location survived forever while the scan reported it gone.
        //
        // Production is not exposed today only because the NAS library is
        // catalogued by the OWNER over NFS in bare `file://` form. D80's
        // migration converts all 27,565 to pin-qualified on a replica, which is
        // the moment this would have started losing every move and delete.
        let prefix = format!("{}/", b.source_uri.trim_end_matches('/'));
        let own_pin = self.own_pin().map(str::to_string);
        let host_prefix = own_pin.as_deref().and_then(|pin| {
            crate::storage::host_uri(pin, &root)
                .ok()
                .map(|u| format!("{}/", u.trim_end_matches('/')))
        });
        let tracked: Vec<(String, String)> = {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT uri, file_id FROM scan_state
                      WHERE uri LIKE ?1 || '%' OR (?2 IS NOT NULL AND uri LIKE ?2 || '%')
                     UNION
                     SELECT uri, file_id FROM file_locations
                      WHERE (uri LIKE ?1 || '%' OR (?2 IS NOT NULL AND uri LIKE ?2 || '%'))
                        AND removed_at IS NULL",
                )
                .map_err(map_db("scan removals"))?;
            let rows = stmt
                .query_map(params![prefix, host_prefix], |r| {
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
            // D81 — resolve BEFORE statting. `LocalBackend.stat` takes a
            // `file://` URI; handed a pin-qualified one it errors, which
            // `unwrap_or(false)` turned into "the bytes are gone" — the most
            // dangerous possible default for a function that decides what to
            // retire. A location whose path cannot be resolved on this host is
            // not ours to judge, so it is left alone.
            let Some(path) = crate::storage::local_path_of(&uri, own_pin.as_deref()) else {
                continue;
            };
            if path.exists() {
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
            // D81 — count what actually happened. `stats.removed` used to be
            // incremented unconditionally, below, outside this guard: when the
            // location did not match (the pin-qualified case) the scan reported
            // a removal it had just skipped. A counter that lies about the one
            // operation that destroys information is worse than no counter.
            let mut removed_here = false;
            if active.is_some() {
                let attempt = match writer {
                    Some(w) => w.remove_location(&file_id, &uri),
                    None => self.remove_location(&file_id, &uri),
                };
                // D89 — the same rule the ingest arm above already follows: one
                // file the catalog will never accept must not stop the line.
                // Retiring is where it was missing, and the cost was total: a
                // single refusal propagated and abandoned the WHOLE pass, so
                // every later file went unreconciled and the next pass met the
                // same node and died in the same place. Seen in the field as
                // `watch` stuck in backoff for hours while the tree drifted.
                //
                // The refusal is real and not ours to override: an ORPHANED node
                // has no live `contains` parent, `effective_rights` resolves
                // authority by walking exactly that chain, and the grants live
                // at the root — so a node you authored, holding your own bytes,
                // becomes unwritable the moment it is unlinked. Quarantine says
                // so out loud instead of hiding it in a dead pass.
                //
                // scan_state is deliberately NOT cleared here: the location is
                // still live, so a later pass (or a repaired grant) must be able
                // to try again. Deleting it would forget the only record that
                // this needs fixing.
                match attempt {
                    Ok(()) => removed_here = true,
                    Err(e) if is_transient(&e) => return Err(e),
                    Err(e) => {
                        stats.needs_attention += 1;
                        if stats.quarantined.len() < 8 {
                            stats.quarantined.push((uri.clone(), e.to_string()));
                        }
                        continue;
                    }
                }
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
            if removed_here {
                stats.removed += 1;
            }
        }
        Ok(stats)
    }

    fn ensure_subfolders(
        &mut self,
        cache: &mut HashMap<String, NodeId>,
        root: &NodeId,
        rel_dirs: &[String],
        writer: &mut Option<&mut dyn ScanWriter>,
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
                        && c.label == *d
                })
                .map(|c| c.node.id);
            let id = match found {
                Some(id) => id,
                None => match writer {
                    Some(w) => w.add_folder(&current, d)?,
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
                },
            };
            cache.insert(key.clone(), id.clone());
            current = id;
        }
        Ok(current)
    }

    /// D71 W6 — identity by content, not by path.
    ///
    /// Chris's rule: *files with the same name and exact size are really the
    /// same file even living in different folders, so it doesn't have to
    /// re-catalogue, just change the pointer location.* Without this a file
    /// that moves is a NEW file, which is why a migrated copy would be
    /// catalogued twice and why reorganising folders would duplicate a library.
    ///
    /// **Ambiguity refuses.** Two candidates (two `poster.jpg` of equal size in
    /// different shows) is not a match — sidecars are exactly where a
    /// name+size rule would otherwise invent nonsense. One candidate, or none.
    ///
    /// Honest about what this is: a heuristic, not a proof. Two files can share
    /// a name and an exact size and differ in bytes. It never overrides a hash
    /// that disagrees, and the first hash computed for either side settles it.
    /// Is this node still IN the tree? "Live" is having an active containing
    /// link — the same rule `match_by_identity` joins on.
    ///
    /// D84 — the collision pass unlinks a losing duplicate but leaves its
    /// locations active, so a file on disk kept resolving to a node that was no
    /// longer anywhere. Nothing can be written about such a node (rights are
    /// inherited from the parent it no longer has), which is why the hash fill
    /// refused it. Treating it as a MISS instead sends the file down the
    /// identity path, which matches only linked nodes and therefore re-homes
    /// the location onto the duplicate that won.
    fn is_homed(&self, id: &NodeId) -> Result<bool> {
        Ok(crate::engine::active_home(&self.conn, id)?
            .and_then(|(_, parent)| parent)
            .is_some())
    }

    fn match_by_identity(&self, label: &str, size: u64) -> Result<Option<NodeId>> {
        let mut stmt = self
            .conn
            .prepare(
                // "Live" is not a column on `nodes` — it is having an active
                // containing link. Joining on that also means a file Sonarr
                // DELETED is never matched and silently resurrected: a deletion
                // is a decision, and the same bytes arriving later are new.
                // D72: match the EFFECTIVE name, resolved exactly as
                // `Engine::children` resolves it — the link's label when it has
                // one, the node's otherwise.
                //
                // Matching `n.label` alone was a real bug once labels moved onto
                // links: renaming a file in place leaves the NODE label stale,
                // so the file on disk would stop matching its own catalogue
                // entry and the next watch pass would enrol it as a NEW file.
                // A duplicate node for a file that was merely renamed is exactly
                // the re-cataloguing this milestone exists to remove.
                //
                // Written as two indexed branches rather than a COALESCE so
                // both sides can still use an index (`idx_links_label`,
                // `idx_nodes_label`); COALESCE would force a scan.
                "SELECT DISTINCT n.id, n.payload FROM nodes n
                   JOIN links l ON l.child_id = n.id AND l.removed_at IS NULL
                  WHERE n.node_type = ?2
                    AND ( (l.label <> '' AND l.label = ?1)
                       OR (l.label =  '' AND n.label = ?1) )",
            )
            .map_err(map_db("identity match"))?;
        let rows = stmt
            .query_map(params![label, node::TYPE_FILE], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(map_db("identity match"))?;
        let mut hit: Option<NodeId> = None;
        for row in rows {
            let (id, payload) = row.map_err(map_db("identity match"))?;
            let same = FilePayload::decode(&payload)
                .map(|p| p.size_bytes == size)
                .unwrap_or(false);
            if !same {
                continue;
            }
            if hit.is_some() {
                return Ok(None); // ambiguous — refuse rather than guess
            }
            hit = Some(id);
        }
        Ok(hit)
    }

    fn ingest_file(
        &mut self,
        b: &Binding,
        parent: &NodeId,
        f: &DiskFile,
        uri: &str,
        stats: &mut ScanStats,
        writer: &mut Option<&mut dyn ScanWriter>,
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
        // An unlinked node is not an identity (see `is_homed`). Falling through
        // costs one resolution; trusting it cost a 606 MB re-read per pass, on
        // every pass, for a write that could never land.
        let ss = match ss {
            Some((_, _, ref id)) if !self.is_homed(id)? => None,
            other => other,
        };
        if let Some((size, mtime, file_id)) = ss {
            if size == f.size && mtime == f.mtime_ms {
                // D74 — unchanged ON DISK is not the same as recorded IN THE
                // CATALOG, and this short-circuit used to conflate them.
                //
                // `scan_state` remembers that this uri was scanned, so a
                // matching size+mtime returned "unchanged" without ever asking
                // whether the location is still live. When a pass had retired
                // those locations, a re-scan of 27,562 files reported every one
                // of them unchanged and repaired nothing — the catalog could
                // not find bytes that were sitting right there, and rescanning
                // (the obvious remedy) was a no-op.
                //
                // The reactivation path below already knew how to fix this; it
                // was simply unreachable. So: confirm the location before
                // believing our own memory of it.
                // D81 — the SAME equivalence the deletion pass needed, on the
                // add side. A replica records this location pin-qualified
                // (D75); comparing only the bare `file://` form meant the check
                // never matched, so every pass "discovered" every file again
                // and re-added a location that was already there. Measured on
                // the lab holder: 1,998 pointless routed writes per pass, each
                // one a round trip to the owner — which is why a pass over
                // 2,000 files could not finish inside the stall threshold.
                let qualified = self.own_pin().and_then(|pin| {
                    crate::storage::uri_to_path(uri)
                        .ok()
                        .and_then(|p| crate::storage::host_uri(pin, &p).ok())
                });
                let live: Option<i64> = self
                    .conn
                    .query_row(
                        "SELECT 1 FROM file_locations
                          WHERE file_id = ?2 AND removed_at IS NULL
                            AND (uri = ?1 OR (?3 IS NOT NULL AND uri = ?3))",
                        params![uri, file_id, qualified],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(map_db("scan location check"))?;
                if live.is_none() && fetch_node(&self.conn, &file_id)?.is_some() {
                    match writer {
                        Some(w) => w.add_location(&file_id, uri)?,
                        None => {
                            self.add_location(&file_id, uri)?;
                        }
                    }
                    stats.added += 1;
                    return Ok(());
                }
                // D85 — an unchanged file may still be UNHASHED. This is the
                // path the backlog actually arrives on.
                let filled = self.fill_hash_if_needed(
                    &file_id,
                    uri,
                    f.size,
                    b.hash_policy,
                    writer,
                );
                if filled != file_id {
                    self.set_scan_state(uri, f.size, f.mtime_ms, &filled)?;
                }
                stats.unchanged += 1;
            } else {
                // D81 — count a change ONCE, when it is first detected.
                //
                // `scan_state` is deliberately NOT advanced here: the change is
                // unresolved, and pending changes wait for an operator
                // (doc 04 §4.4). But that means the very same file is
                // re-detected on every later pass, and counting it again each
                // time made `stats.changed` permanently non-zero — which fires
                // the watcher's progress signal forever and SILENCES the stall
                // detector on any box with one unresolved change. A wedged job
                // reporting `running` is the exact failure D78 was built to
                // prevent, reintroduced through the detector's own input.
                let already: Option<i64> = self
                    .conn
                    .query_row(
                        "SELECT 1 FROM pending_changes WHERE file_id = ?1 AND uri = ?2",
                        params![file_id, uri],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(map_db("pending change"))?;
                self.flag_change(&file_id, uri, size, mtime, f)?;
                if already.is_none() {
                    stats.changed += 1;
                }
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
        let active = match active {
            Some(ref id) if !self.is_homed(id)? => None,
            other => other,
        };
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
                && self.is_homed(&file_id)?
            {
                match writer {
                    Some(w) => w.add_location(&file_id, uri)?,
                    None => {
                        self.add_location(&file_id, uri)?;
                    }
                }
                self.set_scan_state(uri, f.size, f.mtime_ms, &file_id)?;
                stats.added += 1;
                return Ok(());
            }
        }
        // D71 W6 — before deciding this is new, ask whether the catalog already
        // knows it under another path. A migrated copy, a moved folder, a
        // re-import: same file, new place. Record the location, not a new node.
        if let Some(known) = self.match_by_identity(&f.name, f.size)? {
            // D85 — SELF-HEALING HASH FILL.
            //
            // Chris: "It seems [lazy hashing] isn't very useful since it can't
            // serve the files properly in a swarm which is the whole point of
            // the file system... It should also hash any newly found or known
            // but unhashed files on each scan."
            //
            // A lazily-hashed file has no chunk manifest, so the swarm refuses
            // it and a mount cannot stream it — measured through FUSE, 115.8s
            // to read 1MB of an unhashed file against 0.10s for a hashed one.
            // The library's default state was its least useful one.
            //
            // So a scan fills what it finds empty. It converges: each file is
            // hashed once and skipped thereafter, and a scan interrupted
            // halfway simply resumes on the next pass. That is why this needs
            // no bulk backfill tool — the ordinary cycle drains the backlog.
            let known =
                self.fill_hash_if_needed(&known, uri, f.size, b.hash_policy, writer);
            match writer {
                Some(w) => w.add_location(&known, uri)?,
                None => {
                    self.add_location(&known, uri)?;
                }
            }
            self.set_scan_state(uri, f.size, f.mtime_ms, &known)?;
            stats.relocated += 1;
            return Ok(());
        }

        // brand-new file ⇒ pointer node + location. P9.1: hashing computes
        // the chunk manifest in the same read and attests it after the node
        // exists (doc 22 §2).
        let (content_hash, chunks) = match b.hash_policy {
            HashPolicy::OnAdd => {
                crate::sync::hash_with_manifest(&crate::storage::uri_to_path(uri)?)?
            }
            _ => (String::new(), Vec::new()),
        };
        let payload = FilePayload {
            content_hash: content_hash.clone(),
            size_bytes: f.size,
            mime_type: guess_mime(&f.name),
            original_name: f.name.clone(),
        }
        .encode();
        let id = match writer {
            // D84 — the hash computed just above now TRAVELS. It used to be
            // discarded here: a replica under `on_add` hashed the file and then
            // sent a plain pointer node, because the write-through op had no
            // field for it. The comment that stood here said `tier` would
            // attest on migration instead; measured 2026-08-25, it does not —
            // 0 of the 12 most recently migrated files were hashed. So the
            // hash has to survive this call, and now does.
            Some(w) => w.add_file(parent, &f.name, f.size, &guess_mime(&f.name), &content_hash)?,
            None => {
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
                self.attest_manifest(&id, &content_hash, &chunks)?;
                id
            }
        };
        match writer {
            Some(w) => w.add_location(&id, uri)?,
            None => {
                self.add_location(&id, uri)?;
            }
        }
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

    /// The size the catalog records for a file (D71). Public because `evict`
    /// must check that the bytes it is about to reclaim are still the ones its
    /// retired location row described — an upgrade writes its replacement at
    /// the very same path.
    pub fn payload_size_of(&self, file_id: &str) -> Result<Option<u64>> {
        self.payload_size(file_id)
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
            // D94 — binding a library now hashes it. The old default was
            // `lazy`, which is why so little of the fleet was ever hashed.
            None => Ok(HashPolicy::OnAdd),
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
        let (content_hash, chunks) = match hash_policy {
            HashPolicy::OnAdd => {
                crate::sync::hash_with_manifest(&crate::storage::uri_to_path(uri)?)?
            }
            _ => (String::new(), Vec::new()),
        };
        let new_payload = FilePayload {
            content_hash: content_hash.clone(),
            size_bytes: st.size,
            mime_type: old_payload.mime_type.clone(),
            original_name: old_payload.original_name.clone(),
        };
        let new_id = self.successor_node(&old, new_payload.encode(), &[uri.to_string()])?;
        self.attest_manifest(&new_id, &content_hash, &chunks)?;
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
        // D81 — a MEASUREMENT follows its file. Attestation mints a successor
        // node, and quality is keyed by node id, so without this every file the
        // mover attests silently loses what the probe or the arrs measured
        // about it — the whole backfill undone one migration at a time. Found
        // in the lab: the winner of a cross-root upgrade arrived at the store
        // with no quality at all, while its measurement sat stranded on the
        // superseded node.
        //
        // Re-signed as a fresh event for the NEW id rather than moved: the log
        // is append-only, and the successor is a different file node that
        // happens to describe the same bytes.
        let carried = self.media_quality(&old.id)?;
        let new_id = new_node.id.clone();
        self.append_durable(events)?;
        if let Some((quality, source)) = carried {
            self.set_media_quality(&new_id, &quality, &source)?;
        }
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

    /// Return the first readable local filesystem path for a file node (no ACL
    /// check — callers must check ACL before calling). `None` if no readable
    /// location exists. Used by the daemon data plane to resolve a path before
    /// releasing the engine lock for concurrent streaming (doc 07 §6).
    /// D85 — fill this node's hash if it is empty, returning the id to use.
    ///
    /// Called from BOTH scan paths — the file the scan re-discovers and the one
    /// it considers unchanged. The unchanged path is the one that matters for a
    /// grown library: 27,049 files whose size and mtime have not moved in
    /// months are exactly the backlog, and a fill that only ran on newly-seen
    /// files would never reach them.
    ///
    /// Never fails a scan. A file that cannot be hashed right now is recorded
    /// as it was and retried next pass.
    fn fill_hash_if_needed(
        &mut self,
        id: &NodeId,
        uri: &str,
        size: u64,
        policy: HashPolicy,
        writer: &mut Option<&mut dyn ScanWriter>,
    ) -> NodeId {
        if matches!(policy, HashPolicy::Never) {
            return id.clone();
        }
        if !self.needs_hash(id).unwrap_or(false) {
            return id.clone();
        }
        // Check BEFORE reading the file, not after. `set_content_hash` inherits
        // its rights from the node's parent, so an unlinked node is refused —
        // and the refusal used to arrive having already hashed the whole file.
        match self.is_homed(id) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!(
                    "scan: not hashing {uri} — its node is not linked into the tree \
                     (a duplicate that lost a collision); the location belongs on the \
                     node that won"
                );
                return id.clone();
            }
            Err(e) => {
                eprintln!("scan: cannot tell whether {uri} is linked: {e}");
                return id.clone();
            }
        }
        // D85 — every reason to skip is now SAYABLE. These branches returned
        // silently, so a fill that never ran and a fill that ran and failed
        // looked identical from outside: on the live holder the pass reported
        // success and 27,049 files stayed unhashed with nothing in the log.
        let path = match crate::storage::uri_to_path(uri) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("scan: cannot resolve {uri} to a path for hashing: {e}");
                return id.clone();
            }
        };
        // D91 — a sidecar beside the file may already hold this hash, written by
        // an earlier pass or by a PREVIOUS FOREST. Reading 20 GB to recompute
        // what is sitting next to it is exactly the cost the record exists to
        // avoid: it is what lets the library be re-imported into a fresh forest
        // without paying for the hashing again. The size check inside is the
        // honest limit of what a sidecar can promise.
        let (content_hash, chunks) = match crate::sync::sidecar_hashes(&path, size) {
            Some(known) => {
                eprintln!("scan: hash from sidecar {} ({size} bytes)", path.display());
                known
            }
            // A sidecar carrying only the whole hash still saves the whole read,
            // which is the entire cost here. `sidecar backfill` writes these when
            // it rescues a hash that existed only in a previous forest's catalog.
            // Chunks stay unrecorded rather than guessed — `manifest_for`
            // computes them the first time the file is actually served.
            None if crate::sync::sidecar_whole_hash(&path, size).is_some() => {
                let w = crate::sync::sidecar_whole_hash(&path, size).unwrap();
                eprintln!(
                    "scan: hash from sidecar (no chunks) {} ({size} bytes)",
                    path.display()
                );
                (w, Vec::new())
            }
            None => {
                eprintln!("scan: hashing {} ({size} bytes)", path.display());
                match crate::sync::hash_with_manifest_until(&path, self.cancel_flag()) {
                    Ok(Some(v)) => v,
                    // Asked to stop mid-file. Not a failure: nothing is recorded,
                    // and the next pass hashes it from the start.
                    Ok(None) => return id.clone(),
                    Err(e) => {
                        eprintln!("scan: could not hash {}: {e}", path.display());
                        return id.clone();
                    }
                }
            }
        };
        // Persist it beside the file. The fill used to record the hash ONLY in
        // the node payload, so tens of hours of holder time lived in one
        // forest's catalog and died with it — 2918 hashed nodes against 90
        // sidecars on disk. Best-effort: a read-only store still fills, it just
        // cannot leave the note.
        // Do not overwrite a good sidecar with a chunkless one: if we got here
        // FROM a chunkless sidecar there is nothing new to record.
        if !chunks.is_empty() {
            let _ = crate::sync::write_manifest_sidecar(&path, Some(&content_hash), &chunks);
        }
        // The bytes are read and hashed — that is the whole cost of this
        // function. A TRANSIENT failure to record it must not throw that away.
        //
        // Measured on the NAS holder: 230 of 551 fills came back `SQLite is
        // busy/locked during routed scan write (retried 0x)`. Every one had just
        // read a whole film, and every one would read it again on the next pass,
        // which is a large part of why that box ran hot for days. The write is
        // the cheap half; retry THAT.
        let mut attempt = 0u32;
        loop {
            let filled = match writer.as_deref_mut() {
                Some(w) => w.set_content_hash(id, &content_hash, size),
                None => self.fill_content_hash(id, &content_hash, size, &chunks),
            };
            match filled {
                Ok(new_id) => return new_id,
                Err(e) if is_transient(&e) && attempt < HASH_WRITE_RETRIES => {
                    attempt += 1;
                    // Backs off rather than adding to the contention it just
                    // met, and caps the single wait so a stop is still prompt.
                    let ms = (100u64 << attempt).min(HASH_WRITE_BACKOFF_MAX_MS);
                    std::thread::sleep(std::time::Duration::from_millis(ms));
                    // Asked to stop while waiting out a busy owner: drop it
                    // rather than spending another half minute on a write
                    // nobody is waiting for.
                    if self.cancelled() {
                        return id.clone();
                    }
                }
                Err(e) => {
                    eprintln!(
                        "scan: hash fill failed for {} after {attempt} retries: {e}",
                        path.display()
                    );
                    return id.clone();
                }
            }
        }
    }

    /// D85 — is this file node still carrying an empty content hash?
    pub fn needs_hash(&self, id: &NodeId) -> Result<bool> {
        let Some(n) = crate::engine::fetch_node(&self.conn, id)? else {
            return Ok(false);
        };
        if n.node_type != node::TYPE_FILE {
            return Ok(false);
        }
        Ok(FilePayload::decode(&n.payload)
            .map(|p| p.content_hash.is_empty())
            .unwrap_or(false))
    }

    /// D85 — owner-side hash fill: the successor node plus its attestation.
    /// The replica equivalent routes through `ScanWriter::set_content_hash`.
    pub fn fill_content_hash(
        &mut self,
        id: &NodeId,
        content_hash: &str,
        size_bytes: u64,
        chunks: &[[u8; 32]],
    ) -> Result<NodeId> {
        let n = crate::engine::fetch_node(&self.conn, id)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: id.clone(),
        })?;
        let old = FilePayload::decode(&n.payload)?;
        let payload = FilePayload {
            content_hash: content_hash.into(),
            size_bytes,
            mime_type: old.mime_type,
            original_name: old.original_name,
        };
        let all = self.locations(id)?;
        let new_id = self.successor_node(&n, payload.encode(), &all)?;
        // Attest ONLY what we actually computed. `manifest_root(&[])` is the
        // root of an empty manifest, so attesting with no chunks would sign a
        // statement that this file HAS no chunks — false for every non-empty
        // file, and signed. A hash recovered from a sidecar that carries no
        // chunk hashes is still worth recording; the manifest is simply built
        // the first time the file is served.
        if !chunks.is_empty() {
            self.attest_manifest(&new_id, content_hash, chunks)?;
        }
        Ok(new_id)
    }

    /// D93 — rescue hashes that exist ONLY in this forest's catalog, and retire
    /// the pre-D91 sidecar name while we are there.
    ///
    /// The fill recorded a content hash in the node payload and wrote nothing to
    /// disk, so tens of hours of holder time were pinned to one forest and would
    /// die with it: 3005 hashed nodes against 90 sidecars. This walks what the
    /// catalog knows and leaves it beside the bytes, where a re-import can find
    /// it. It reads no file content — only `stat` — so it costs nothing next to
    /// the hashing it preserves.
    ///
    /// Chunk hashes are carried forward when a v1 sidecar happens to hold them,
    /// and otherwise left unrecorded rather than invented. The whole hash is the
    /// half that cost a full read and the half that gives a node its identity.
    pub fn backfill_sidecars(&self, dry_run: bool) -> Result<BackfillReport> {
        let mut report = BackfillReport::default();
        let mut stmt = self
            .conn
            .prepare("SELECT id, payload FROM nodes WHERE node_type = 'file'")
            .map_err(map_db("backfill scan"))?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))
            .map_err(map_db("backfill scan"))?;
        for row in rows {
            let (id, payload) = row.map_err(map_db("backfill scan"))?;
            let Ok(p) = FilePayload::decode(&payload) else {
                continue;
            };
            if p.content_hash.is_empty() {
                report.unhashed += 1;
                continue;
            }
            let Some(path) = self.readable_path(&id)? else {
                report.no_local_copy += 1;
                continue;
            };
            // D95 — never treat our OWN bookkeeping as content, even when the
            // catalog has adopted it as a node (which it did, ~1667 times,
            // before D87). `write_manifest_sidecar` already refuses these, so
            // nothing was written — but they were still COUNTED as rescued,
            // and worse: for a node at `x.mkv.manifest` the "legacy" path
            // resolves to `x.mkv.manifest.manifest`, so the real run would have
            // deleted the next level of the chain as a side effect of a rule
            // written for something else entirely. Cleaning that junk is a
            // separate, deliberate act — not something a hash-rescue pass does
            // by accident.
            if crate::sync::is_sidecar_path(&path) {
                report.own_bookkeeping += 1;
                continue;
            }
            let Ok(md) = std::fs::metadata(&path) else {
                report.no_local_copy += 1;
                continue;
            };
            // The same exact-size rule the read path uses: a file whose size
            // disagrees with the catalog is a replacement written at the same
            // path, and stamping the OLD hash beside it would be a lie that
            // outlives this forest.
            if md.len() != p.size_bytes {
                report.size_mismatch += 1;
                continue;
            }
            if crate::sync::sidecar_whole_hash(&path, p.size_bytes).is_some() {
                report.already_durable += 1;
                continue;
            }
            // A v1 sidecar lying here still holds real chunk work — carry it.
            let chunks = crate::sync::sidecar_chunks(&path);
            let legacy = crate::sync::legacy_manifest_sidecar_path(&path);
            let had_legacy = legacy.exists();
            if !dry_run {
                crate::sync::write_manifest_sidecar(&path, Some(&p.content_hash), &chunks)?;
                if had_legacy {
                    let _ = std::fs::remove_file(&legacy);
                }
            }
            report.written += 1;
            if had_legacy {
                report.legacy_retired += 1;
            }
            if chunks.is_empty() {
                report.whole_hash_only += 1;
            }
        }
        Ok(report)
    }

    pub fn readable_path(&self, id: &NodeId) -> Result<Option<std::path::PathBuf>> {
        let uri = match self.first_readable_location(id)? {
            Some(u) => u,
            None => return Ok(None),
        };
        let resolved = self.resolve_uri(&uri)?;
        let path = uri_to_path(&resolved)?;
        Ok(Some(path))
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

    /// Map pvfs-tmp:///<id> into the spool dir and pvfs-sync:///<id> into the
    /// managed sync store (F3); pass file:// through.
    fn resolve_uri(&self, uri: &str) -> Result<String> {
        if let Some(name) = uri.strip_prefix(TMP_URI_PREFIX) {
            if name.contains('/') || name.contains("..") {
                return Err(bad("uri", "invalid pvfs-tmp URI"));
            }
            return path_to_uri(&self.data_dir.join(SPOOL_DIR).join(name));
        }
        if let Some(id) = crate::sync::parse_sync_uri(uri) {
            // read path: whichever root holds the file (configured, then
            // default — doc 19 §3); a not-yet-fetched file resolves to where
            // a new fetch would land
            let p = match crate::sync::sync_store_lookup(&self.data_dir, id)? {
                Some(p) => p,
                None => crate::sync::sync_store_path(&self.data_dir, id)?,
            };
            return path_to_uri(&p);
        }
        // Instance-qualified (F5.1): local only when the pin is our own;
        // a foreign pin is a remote candidate (fetch via sync, doc 17 §7.3).
        if let Some((pin, path)) = crate::storage::parse_host_uri(uri) {
            return match crate::storage::host_pin(&self.data_dir) {
                Some(own) if own == pin => Ok(format!("file://{path}")),
                _ => Err(bad(
                    "uri",
                    &format!("location is on another instance (pin {}…)", &pin[..8]),
                )),
            };
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
        let (content_hash, chunks) =
            crate::sync::hash_with_manifest(&crate::storage::uri_to_path(&resolved)?)?;
        let st = LocalBackend.stat(&resolved)?;
        let new_payload = FilePayload {
            content_hash: content_hash.clone(),
            size_bytes: st.size,
            mime_type: payload.mime_type,
            original_name: payload.original_name,
        };
        let all_locations = self.locations(id)?;
        let new_id = self.successor_node(&n, new_payload.encode(), &all_locations)?;
        self.attest_manifest(&new_id, &content_hash, &chunks)?;
        Ok(new_id)
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

/// Where a scan's catalog writes go (D71 W4).
///
/// On the forest owner that is the engine itself. On a **replica** it is the
/// owner's daemon over the wire — a replica has no local writer, so the box
/// that must scan its own library could otherwise enrol a directory and then
/// not write a word about what was in it.
///
/// The scan writes exactly these four things, and `pvfs-client`'s `Client`
/// already speaks all of them: no new wire op, no `PROTO_VERSION` bump.
pub trait ScanWriter {
    fn add_folder(&mut self, parent: &str, label: &str) -> Result<NodeId>;
    /// D84 — `content_hash` is computed by the caller from bytes it holds.
    /// Empty means an unhashed pointer node (the old behaviour).
    fn add_file(
        &mut self,
        parent: &str,
        label: &str,
        size: u64,
        mime: &str,
        content_hash: &str,
    ) -> Result<NodeId>;
    fn add_location(&mut self, file: &str, uri: &str) -> Result<()>;
    fn remove_location(&mut self, file: &str, uri: &str) -> Result<()>;
    /// D85 — fill a lazy hash on an EXISTING node, returning the successor id.
    /// The caller computed it from bytes it holds; the owner records it.
    fn set_content_hash(&mut self, file: &str, content_hash: &str, size: u64) -> Result<NodeId>;
}

/// Will retrying fix it? (D71 W4 — Chris: *fail loudly, but autocorrect, and
/// only ask for intervention when that isn't possible*.)
///
/// A lost owner, a busy database, an I/O blip: the next pass fixes it by
/// itself, because a scan is idempotent by URI. So the pass fails **loudly**
/// and the watcher's next tick puts it right with nobody involved.
///
/// A refusal (`Forbidden`) or a rejected argument (`BadInput`) will fail the
/// same way forever. Retrying is not repair, it is a loop — so that ONE file is
/// quarantined with its reason, the rest of the pass continues, and the report
/// says a human is needed.
/// How many times a hash WRITE is retried before the hash is discarded, and the
/// longest single wait between tries.
///
/// The budget is set by the ASYMMETRY, not by taste. Behind this write sits a
/// whole-file read — 7.7 GB for one of the films on the holder, minutes of disk
/// — and behind the failure sits doing it all again next pass. Waiting a minute
/// for a lock is nothing against that, so the retry is deliberately patient:
/// ~29s of sleeping across 8 tries, on top of each attempt's own 5s SQLite
/// busy_timeout.
///
/// It is still bounded. A lock held longer than that is a real fault and should
/// be reported rather than waited out forever.
const HASH_WRITE_RETRIES: u32 = 8;
const HASH_WRITE_BACKOFF_MAX_MS: u64 = 8_000;

pub(crate) fn is_transient(e: &PvfsError) -> bool {
    !matches!(
        e,
        PvfsError::Forbidden { .. } | PvfsError::BadInput { .. } | PvfsError::Identity { .. }
    )
}

// ---- local bindings (D71 W4, doc 04 §3) -------------------------------------
//
// A binding names a directory that exists on ONE machine. On the forest owner
// that fact is logged (`FolderBound`) and replicates. A **replica** cannot
// append to the log at all, and `bind` — unlike `add`/`loc add`/`unlink` — has
// no write-through wire op, so an ingest box could never enroll its own
// library: the box that must scan the directory was the one box that could not
// say it had one.
//
// It is recorded here instead, as per-machine deployment state beside
// `placement`. That is not a workaround but the rule this codebase already
// states for exactly this class of fact — "placement is per-instance
// deployment state, never catalog truth" (§`binding_listing`) — and `sync.rs`
// describes that file as being "like bindings and the replica marker".
//
// Consequence, deliberately accepted: the owner sees an ingest box's *effects*
// (the nodes and locations its scans write, which do route write-through) but
// not its enrollment. Making enrollment fleet-visible needs a wire op and a
// PROTO bump — a fleet-wide upgrade, which is the one thing the rolling
// upgrade play refuses to do.

const LOCAL_BINDINGS_FILE: &str = "bindings.local";
const LOCAL_BINDINGS_HEADER: &str = "pvfs-local-bindings 1";

fn local_bindings_path(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join(LOCAL_BINDINGS_FILE)
}

/// Read this machine's own bindings. Absent file = none, never an error.
pub(crate) fn load_local_bindings(data_dir: &std::path::Path) -> Result<Vec<Binding>> {
    let text = match std::fs::read_to_string(local_bindings_path(data_dir)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(PvfsError::io("read local bindings", e)),
    };
    let mut lines = text.lines();
    if lines.next() != Some(LOCAL_BINDINGS_HEADER) {
        return Err(bad("bindings.local", "unrecognized local bindings file"));
    }
    let mut out = Vec::new();
    for line in lines.filter(|l| !l.trim().is_empty()) {
        // bind <folder> <recursive> <auto_index> <hash_policy> <bound_at> <exts> <uri…>
        // `exts` is comma-joined (never contains a space); the URI is the REST,
        // so a directory with spaces in its name survives the round trip.
        let Some(rest) = line.strip_prefix("bind ") else {
            continue;
        };
        let mut f = rest.splitn(7, ' ');
        let (Some(folder), Some(rec), Some(auto), Some(policy), Some(at), Some(exts), Some(uri)) = (
            f.next(),
            f.next(),
            f.next(),
            f.next(),
            f.next(),
            f.next(),
            f.next(),
        ) else {
            return Err(bad("bindings.local", "malformed bind line"));
        };
        out.push(Binding {
            folder_id: folder.to_string(),
            source_uri: uri.to_string(),
            recursive: rec == "1",
            auto_index: auto == "1",
            extensions: if exts == "-" {
                Vec::new()
            } else {
                exts.split(',').map(|s| s.to_string()).collect()
            },
            hash_policy: HashPolicy::parse(policy)?,
            bound_at: at.parse().unwrap_or(0),
            // Filled by the caller, which knows this device's key.
            bound_by: Vec::new(),
        });
    }
    Ok(out)
}

fn save_local_bindings(data_dir: &std::path::Path, rows: &[Binding]) -> Result<()> {
    let mut text = String::from(LOCAL_BINDINGS_HEADER);
    text.push('\n');
    for b in rows {
        let exts = if b.extensions.is_empty() {
            "-".to_string()
        } else {
            b.extensions.join(",")
        };
        text.push_str(&format!(
            "bind {} {} {} {} {} {} {}\n",
            b.folder_id,
            if b.recursive { 1 } else { 0 },
            if b.auto_index { 1 } else { 0 },
            b.hash_policy.as_str(),
            b.bound_at,
            exts,
            b.source_uri,
        ));
    }
    std::fs::write(local_bindings_path(data_dir), text)
        .map_err(|e| PvfsError::io("write local bindings", e))
}

/// A device key, short enough to name a machine in an error message.
fn short_key(key: &[u8]) -> String {
    let full = hex::encode(key);
    if full.is_empty() {
        return "unattributed".into();
    }
    full.chars().take(12).collect::<String>() + "…"
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
        bound_by: r.get(7).unwrap_or_default(),
    }))
}

/// What a disk walk needs to know about the scan it belongs to. Bundled
/// because `recursive` and the settle window both come from the same place as
/// the binding, and passing them individually pushed the walk past clippy's
/// argument limit — a fair complaint about a growing parameter list.
struct WalkCtx<'a> {
    binding: &'a Binding,
    /// 0 = index whatever is on disk now (a one-shot scan, `--import`);
    /// non-zero = the watcher's "has it stopped being written" window.
    settle_ms: u64,
}

fn walk_disk(
    dir: &std::path::Path,
    rel: Vec<String>,
    visited: &mut HashSet<PathBuf>,
    files: &mut Vec<DiskFile>,
    dirs: &mut Vec<Vec<String>>,
    stats: &mut ScanStats,
    ctx: &WalkCtx<'_>,
) -> Result<()> {
    let canon = std::fs::canonicalize(dir).map_err(|e| PvfsError::io("canonicalize", e))?;
    if !visited.insert(canon) {
        return Ok(()); // symlinked dir cycle
    }
    let uri = path_to_uri(dir)?;
    for entry in LocalBackend.list(&uri)? {
        if entry.name.starts_with('.') {
            // D81 — our OWN bookkeeping is not something the operator chose not
            // to index, and counting it as `skipped` would put a permanent +1
            // on every scan report of every root. Dotfiles they put there are
            // still counted, because that is a fact about their directory.
            if entry.name != crate::sync::ROOT_MARKER {
                stats.skipped += 1;
            }
            continue;
        }
        // Our chunk-manifest sidecar, which is bookkeeping and not content.
        // Unconditional, and BEFORE the extension filter: an empty `extensions`
        // list means "every file the operator has", not "also the files we
        // ourselves write next to them". Not counted as `skipped`, for the same
        // reason the dotfile arm above does not count ours (D81).
        if !entry.is_dir && crate::sync::is_sidecar_name(&entry.name) {
            continue;
        }
        let child = dir.join(&entry.name);
        if entry.is_dir {
            if ctx.binding.recursive {
                // Skip directories the operator can't traverse/read rather than
                // aborting the whole import — never index what you can't read.
                if !is_accessible(&child, true) {
                    stats.unreadable += 1;
                    continue;
                }
                let mut sub = rel.clone();
                sub.push(entry.name.clone());
                // Every directory we descend into, not just the ones holding
                // files: a directory IS content. An empty one is a fact about
                // the tree — the place a season is filed before the episodes
                // land — and a filesystem that cannot show it is not mirroring
                // the disk, it is summarising it.
                dirs.push(sub.clone());
                walk_disk(&child, sub, visited, files, dirs, stats, ctx)?;
            }
            continue;
        }
        if !ctx.binding.extensions.is_empty() {
            let ext = entry
                .name
                .rsplit('.')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            if !ctx.binding.extensions.iter().any(|e| e == &ext) {
                stats.skipped += 1;
                continue;
            }
        }
        // Never import a file the operator cannot read.
        if !is_accessible(&child, false) {
            stats.unreadable += 1;
            continue;
        }
        // D71 W6 — do not catalogue a file that is still being written.
        //
        // Measured on feederbox: Sonarr COPIES into the library (every sampled
        // file has link count 1, because its source and destination are
        // different filesystems from its own view), so a 5.8 GB import grows
        // under its final name for minutes. Identity is by EXACT SIZE, so
        // cataloguing a half-copied file records a wrong size and then
        // confidently mis-identifies it later.
        //
        // mtime is the cheapest possible "has it stopped moving" test and
        // needs no stored state: a growing file's mtime keeps advancing.
        // Deferred, never dropped — counted, and the watcher comes back.
        if ctx.settle_ms > 0 && entry.mtime_ms.saturating_add(ctx.settle_ms) > now_ms() {
            stats.settling += 1;
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
