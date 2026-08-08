//! F0 — materialized native-view export (doc 17 §3): present a tree as a
//! plain directory any non-PVFS app can read. Symlinks by default; hardlinks
//! or hash-verified copies on request. A `.pvfs-export` manifest at the dest
//! root marks the directory as export-owned and makes re-runs idempotent
//! (refresh what changed, prune or report what left the tree).

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt};
use std::path::{Path, PathBuf};

use crate::engine::{bad, fetch_node, Engine};
use crate::error::{PvfsError, Result};
use crate::link::LINK_CONTAINS;
use crate::node::{FilePayload, NodeId, TYPE_FILE, TYPE_FOLDER, TYPE_SECURE};
use crate::storage::{atomic_overwrite, hash_stream};

pub const MANIFEST_NAME: &str = ".pvfs-export";
const MANIFEST_HEADER: &str = "pvfs-export 1";
/// Longest name emitted before disambiguation kicks in (labels soft-cap at
/// 4 KiB; most filesystems cap a name at 255 bytes).
const NAME_BYTE_CAP: usize = 240;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportMode {
    Symlink,
    Hardlink,
    Copy,
}

impl ExportMode {
    pub fn parse(s: &str) -> Result<ExportMode> {
        match s {
            "symlink" => Ok(ExportMode::Symlink),
            "hardlink" => Ok(ExportMode::Hardlink),
            "copy" => Ok(ExportMode::Copy),
            other => Err(bad("mode", &format!("unknown export mode {other:?}"))),
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            ExportMode::Symlink => "symlink",
            ExportMode::Hardlink => "hardlink",
            ExportMode::Copy => "copy",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExportSpec {
    pub mode: ExportMode,
    pub prune: bool,
}

/// A tree entry the export could not materialize. Skips are reported, never
/// fatal (doc 17 §3): a missing location is the pointer-without-bytes case
/// until F3, and a failed copy quarantines like any verified read.
#[derive(Debug, Clone)]
pub struct ExportSkip {
    pub path: String,
    pub node: NodeId,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct ExportReport {
    pub dirs_created: usize,
    pub exported: usize,
    pub unchanged: usize,
    pub pruned: usize,
    /// Manifest entries no longer in the tree, left in place (`prune` off or
    /// a directory that would not empty).
    pub stale: Vec<String>,
    pub skipped: Vec<ExportSkip>,
}

struct Manifest {
    root: NodeId,
    dirs: Vec<String>,
    files: Vec<String>,
}

impl Manifest {
    fn load(path: &Path) -> Result<Manifest> {
        let text =
            fs::read_to_string(path).map_err(|e| PvfsError::io("read export manifest", e))?;
        let mut lines = text.lines();
        if lines.next() != Some(MANIFEST_HEADER) {
            return Err(bad("dest", "unrecognized .pvfs-export manifest"));
        }
        let mut root = String::new();
        let mut dirs = Vec::new();
        let mut files = Vec::new();
        for line in lines {
            if let Some(r) = line.strip_prefix("root ") {
                root = r.to_string();
            } else if let Some(d) = line.strip_prefix("d ") {
                dirs.push(d.to_string());
            } else if let Some(f) = line.strip_prefix("f ") {
                files.push(f.to_string());
            } else if line.starts_with("mode ") || line.is_empty() {
                // informational
            } else {
                return Err(bad("dest", "corrupt .pvfs-export manifest"));
            }
        }
        if root.is_empty() {
            return Err(bad("dest", "corrupt .pvfs-export manifest (no root)"));
        }
        Ok(Manifest { root, dirs, files })
    }

    fn save(&self, path: &Path, mode: ExportMode) -> Result<()> {
        let mut out = String::new();
        out.push_str(MANIFEST_HEADER);
        out.push('\n');
        out.push_str(&format!("root {}\n", self.root));
        out.push_str(&format!("mode {}\n", mode.as_str()));
        for d in &self.dirs {
            out.push_str(&format!("d {d}\n"));
        }
        for f in &self.files {
            out.push_str(&format!("f {f}\n"));
        }
        atomic_overwrite(path, out.as_bytes())
    }
}

/// One directory level of the walk: its dest-relative path and the names
/// already claimed inside it (collision disambiguation, doc 17 §3 item 5).
struct Level {
    rel: PathBuf,
    used: HashSet<String>,
}

/// Filesystem-safe rendering of a label: `/` and control characters become
/// `_`; a name that vanishes (empty, `.`, `..`) falls back to the node id.
fn safe_name(label: &str, id: &NodeId) -> String {
    let cleaned: String = label
        .chars()
        .map(|c| if c == '/' || c.is_control() { '_' } else { c })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return format!("node-{}", &id[..8]);
    }
    trimmed.to_string()
}

/// Claim a unique name inside `used`: over-long or already-taken names get a
/// `~<id8>` suffix (then a counter — two refs to one node can share a parent).
fn claim_name(base: &str, id: &NodeId, used: &mut HashSet<String>) -> String {
    let mut name = base.to_string();
    if name.len() > NAME_BYTE_CAP {
        let mut cut = NAME_BYTE_CAP - 40;
        while !name.is_char_boundary(cut) {
            cut -= 1;
        }
        name.truncate(cut);
        name = format!("{name}~{}", &id[..8]);
    }
    if used.contains(&name) {
        name = format!("{name}~{}", &id[..8]);
        let mut n = 1;
        while used.contains(&name) {
            name = format!("{base}~{}-{n}", &id[..8]);
            n += 1;
        }
    }
    used.insert(name.clone());
    name
}

/// Remove whatever sits at `path` (file, symlink, or directory) so a fresh
/// entry can land there. The dest is export-owned (manifest-marked), so
/// replacing a leftover of a previous run or mode is ours to do.
fn clear_path(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_dir() => {
            fs::remove_dir_all(path).map_err(|e| PvfsError::io("replace export entry", e))
        }
        Ok(_) => fs::remove_file(path).map_err(|e| PvfsError::io("replace export entry", e)),
        Err(_) => Ok(()),
    }
}

impl Engine {
    /// Materialize the `contains` tree under `root` into `dest` (doc 17 §3).
    /// Folders become directories; files become symlinks, hardlinks, or
    /// verified copies per `spec.mode`. Owner-side, no ACL filtering — a
    /// member-scoped export composes with F2 (export from a replica).
    pub fn export_tree(
        &mut self,
        root: &NodeId,
        dest: &Path,
        spec: &ExportSpec,
    ) -> Result<ExportReport> {
        let root_node = fetch_node(&self.conn, root)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: root.clone(),
        })?;
        if root_node.node_type != TYPE_FOLDER {
            return Err(bad("export", "export target must be a folder node"));
        }

        let manifest_path = dest.join(MANIFEST_NAME);
        let prior = if dest.symlink_metadata().is_ok() {
            if !dest.is_dir() {
                return Err(bad("dest", "export destination exists and is not a directory"));
            }
            if manifest_path.exists() {
                let m = Manifest::load(&manifest_path)?;
                if m.root != *root {
                    return Err(bad(
                        "dest",
                        "directory holds an export of a different root — refusing",
                    ));
                }
                Some(m)
            } else {
                let mut entries =
                    fs::read_dir(dest).map_err(|e| PvfsError::io("read export dir", e))?;
                if entries.next().is_some() {
                    return Err(bad(
                        "dest",
                        "refusing to export into a non-empty directory without a .pvfs-export manifest",
                    ));
                }
                None
            }
        } else {
            fs::create_dir_all(dest).map_err(|e| PvfsError::io("create export dir", e))?;
            None
        };

        let entries = self.walk(root)?.entries;
        let mut report = ExportReport::default();
        let mut new_dirs: Vec<String> = Vec::new();
        let mut new_files: Vec<String> = Vec::new();
        let mut stack: Vec<Level> = vec![Level {
            rel: PathBuf::new(),
            used: HashSet::new(),
        }];

        for entry in entries.into_iter().skip(1) {
            stack.truncate(entry.depth);
            let parent = stack
                .last_mut()
                .expect("walk order keeps the parent level on the stack");
            let id = entry.node.id.clone();
            let name = claim_name(&safe_name(&entry.node.label, &id), &id, &mut parent.used);
            let rel = parent.rel.join(&name);
            let rel_str = rel.to_string_lossy().into_owned();
            let full = dest.join(&rel);

            match entry.node.node_type.as_str() {
                TYPE_FOLDER => {
                    if entry.link_type != LINK_CONTAINS {
                        report.skipped.push(ExportSkip {
                            path: rel_str,
                            node: id,
                            reason: "folder ref — not descended (one home elsewhere)".into(),
                        });
                        continue;
                    }
                    if !full.is_dir() {
                        clear_path(&full)?;
                        fs::create_dir(&full).map_err(|e| PvfsError::io("create export dir", e))?;
                        report.dirs_created += 1;
                    }
                    new_dirs.push(rel_str);
                    stack.push(Level {
                        rel,
                        used: HashSet::new(),
                    });
                }
                TYPE_FILE => {
                    let src = match self.readable_path(&id)? {
                        Some(p) => p,
                        None => {
                            report.skipped.push(ExportSkip {
                                path: rel_str,
                                node: id,
                                reason: "no readable local location (pointer without bytes — F3)"
                                    .into(),
                            });
                            continue;
                        }
                    };
                    match self.export_file(&id, &entry.node.payload, &src, &full, spec.mode) {
                        Ok(true) => {
                            report.exported += 1;
                            new_files.push(rel_str);
                        }
                        Ok(false) => {
                            report.unchanged += 1;
                            new_files.push(rel_str);
                        }
                        Err(e) => report.skipped.push(ExportSkip {
                            path: rel_str,
                            node: id,
                            reason: e.to_string(),
                        }),
                    }
                }
                TYPE_SECURE => report.skipped.push(ExportSkip {
                    path: rel_str,
                    node: id,
                    reason: "secure node (ciphertext-only; companion-gated reads)".into(),
                }),
                other => report.skipped.push(ExportSkip {
                    path: rel_str,
                    node: id,
                    reason: format!("unsupported node type {other:?}"),
                }),
            }
        }

        // Entries of the previous run that left the tree: prune, or report as
        // stale. A stale entry that survives (prune off, or a directory that
        // would not empty) stays in the manifest — the export still owns it,
        // so a later `--prune` can remove it.
        if let Some(old) = &prior {
            let files_now: HashSet<&String> = new_files.iter().collect();
            let dirs_now: HashSet<&String> = new_dirs.iter().collect();
            let stale_files: Vec<String> = old
                .files
                .iter()
                .filter(|f| !files_now.contains(f))
                .cloned()
                .collect();
            for f in stale_files {
                if spec.prune {
                    match fs::remove_file(dest.join(&f)) {
                        Ok(()) => report.pruned += 1,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(PvfsError::io("prune export entry", e)),
                    }
                } else {
                    report.stale.push(f.clone());
                    new_files.push(f);
                }
            }
            let mut stale_dirs: Vec<String> = old
                .dirs
                .iter()
                .filter(|d| !dirs_now.contains(d))
                .cloned()
                .collect();
            // deepest first, so emptied parents remove after their children
            stale_dirs.sort_by_key(|d| std::cmp::Reverse(d.matches('/').count()));
            for d in stale_dirs {
                if spec.prune {
                    match fs::remove_dir(dest.join(&d)) {
                        Ok(()) => report.pruned += 1,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(_) => {
                            // not empty — leave it, keep owning it
                            report.stale.push(d.clone());
                            new_dirs.push(d);
                        }
                    }
                } else {
                    report.stale.push(d.clone());
                    new_dirs.push(d);
                }
            }
        }

        Manifest {
            root: root.clone(),
            dirs: new_dirs,
            files: new_files,
        }
        .save(&manifest_path, spec.mode)?;
        Ok(report)
    }

    /// Materialize one file entry. `Ok(true)` = created/replaced, `Ok(false)`
    /// = already current; errors become per-entry skips in the caller.
    fn export_file(
        &mut self,
        id: &NodeId,
        payload: &[u8],
        src: &Path,
        full: &Path,
        mode: ExportMode,
    ) -> Result<bool> {
        match mode {
            ExportMode::Symlink => {
                if let Ok(md) = fs::symlink_metadata(full) {
                    if md.file_type().is_symlink()
                        && fs::read_link(full).map(|t| t == *src).unwrap_or(false)
                    {
                        return Ok(false);
                    }
                    clear_path(full)?;
                }
                symlink(src, full).map_err(|e| PvfsError::io("symlink export entry", e))?;
                Ok(true)
            }
            ExportMode::Hardlink => {
                if let (Ok(have), Ok(want)) = (fs::symlink_metadata(full), fs::metadata(src)) {
                    if have.file_type().is_file()
                        && have.dev() == want.dev()
                        && have.ino() == want.ino()
                    {
                        return Ok(false);
                    }
                    clear_path(full)?;
                }
                fs::hard_link(src, full).map_err(|e| PvfsError::io("hardlink export entry", e))?;
                Ok(true)
            }
            ExportMode::Copy => {
                let content_hash = FilePayload::decode(payload)?.content_hash;
                if !content_hash.is_empty() {
                    if let Ok(md) = fs::symlink_metadata(full) {
                        if md.file_type().is_file() {
                            let mut f = fs::File::open(full)
                                .map_err(|e| PvfsError::io("open export entry", e))?;
                            if hash_stream(&mut f)? == content_hash {
                                return Ok(false);
                            }
                        }
                    }
                }
                let tmp = PathBuf::from(format!("{}.pvfs-export-tmp", full.to_string_lossy()));
                let copied = (|| -> Result<()> {
                    let mut f = fs::File::create(&tmp)
                        .map_err(|e| PvfsError::io("create export copy", e))?;
                    self.cat(id, None, &mut f)?; // full read = hash-verified when known
                    Ok(())
                })();
                if let Err(e) = copied {
                    let _ = fs::remove_file(&tmp);
                    return Err(e);
                }
                if fs::symlink_metadata(full).map(|m| m.is_dir()).unwrap_or(false) {
                    clear_path(full)?;
                }
                fs::rename(&tmp, full).map_err(|e| PvfsError::io("place export copy", e))?;
                Ok(true)
            }
        }
    }
}
