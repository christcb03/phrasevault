//! D81 4e — move a file's BYTES between roots of its own library.
//!
//! Chris: "maybe we need a way to move files between swarm location with a
//! cli-type command (and later a gui file explorer in PVOS)".
//!
//! Distinct from `pvfs mv`, which moves a NODE to a different parent in the
//! tree. This moves bytes between physical roots — `Data` to `Data_ext` — and
//! is the supported form of what is otherwise done by hand behind the
//! catalog's back.
//!
//! Doing it THROUGH PVFS removes an ambiguity a scan can never resolve. A
//! filesystem diff cannot tell "moved" from "deleted" from "the volume is
//! unavailable"; all three are a tracked path that is no longer there. Told
//! directly, there is nothing to infer.
//!
//! The ordering is D80's migration in the small, and it is the only safe one:
//! **place at the target, verify it arrived, and only then retire the source.**
//! Reversed, it is the drain that left 26,729 files catalogued with no live
//! location while every byte sat untouched on disk.

use pvfs_core::{Engine, NodeId, PvfsError, TYPE_FILE};
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub struct MoveReport {
    pub moved: u64,
    /// Already at the destination — not work, and not a failure.
    pub skipped: u64,
    pub failed: Vec<(String, String)>,
    /// What a dry run WOULD do, in order, one line per action.
    pub planned: Vec<String>,
}

/// Move `node` — a file, or every file under a folder — to `dest_root`.
pub fn move_to_root(
    engine: &mut Engine,
    node: &NodeId,
    dest_root: &Path,
    dry_run: bool,
) -> Result<MoveReport, PvfsError> {
    let mut report = MoveReport::default();

    // The destination must be a root of this library, not an arbitrary
    // directory: moving bytes somewhere nothing is bound would put them where
    // no scan will ever look, which is indistinguishable from losing them.
    let dest_uri = pvfs_core::storage::path_to_uri(dest_root)?;
    let mut anchor = node.clone();
    let mut roots = engine.bindings_for(&anchor)?;
    while roots.is_empty() {
        match engine.parent_of(&anchor)? {
            Some(up) => {
                anchor = up;
                roots = engine.bindings_for(&anchor)?;
            }
            None => break,
        }
    }
    if !roots.iter().any(|b| b.source_uri == dest_uri) {
        return Err(PvfsError::BadInput {
            field: "to".into(),
            reason: format!(
                "{} is not a root of this library. Its roots are: {}",
                dest_root.display(),
                if roots.is_empty() {
                    "(none)".to_string()
                } else {
                    roots
                        .iter()
                        .map(|b| b.source_uri.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ),
        });
    }
    // The volume has to be THERE before anything is written to it (4d).
    pvfs_core::sync::verify_root_marker(dest_root)?;

    let files: Vec<NodeId> = engine
        .walk(node)?
        .into_iter()
        .filter(|e| e.node.node_type == TYPE_FILE)
        .map(|e| e.node.id)
        .collect();

    for id in files {
        let Some(segs) = engine.tree_path_under(&id, &anchor)? else {
            continue;
        };
        if segs.is_empty() {
            continue;
        }
        let want: PathBuf = segs.iter().fold(dest_root.to_path_buf(), |a, s| a.join(s));
        let label = segs.last().cloned().unwrap_or_default();

        let locs = engine.locations(&id)?;
        let want_uri = pvfs_core::storage::path_to_uri(&want)?;
        if locs.iter().any(|u| {
            u == &want_uri
                || pvfs_core::storage::any_path_of(u).is_some_and(|p| p == want)
        }) {
            report.skipped += 1;
            continue;
        }

        // A readable source, on this box. Bytes held only by another holder
        // are that holder's to move — say so rather than pretending.
        let Some(src) = engine.readable_path(&id)? else {
            report.failed.push((
                label,
                "no readable copy on this box — run it where the bytes are".into(),
            ));
            continue;
        };

        if dry_run {
            report
                .planned
                .push(format!("WOULD MOVE   {} -> {}", src.display(), want.display()));
            report.moved += 1;
            continue;
        }

        // 1. PLACE.
        if let Some(parent) = want.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| PvfsError::io("create destination dir", e))?;
        }
        if let Err(e) = std::fs::rename(&src, &want) {
            // A different filesystem — Data and Data_ext are exactly that — so
            // copy, then remove only after the copy is verified below.
            if let Err(e2) = std::fs::copy(&src, &want) {
                report
                    .failed
                    .push((label, format!("rename failed ({e}); copy failed ({e2})")));
                continue;
            }
        }

        // 2. VERIFY it actually arrived, at the right size, before anything is
        //    retired. This is the step whose absence turned D74's drain into
        //    26,729 stranded files.
        let ok = std::fs::metadata(&want)
            .ok()
            .zip(engine.payload_size_of(&id)?)
            .map(|(m, want_size)| m.len() == want_size)
            .unwrap_or(false);
        if !ok {
            report.failed.push((
                label,
                format!(
                    "{} did not arrive at the expected size — source left untouched",
                    want.display()
                ),
            ));
            continue;
        }

        // 3. Only now record the new location and retire the old one.
        engine.add_location(&id, &want_uri)?;
        let src_uri = pvfs_core::storage::path_to_uri(&src)?;
        for u in locs {
            if pvfs_core::storage::any_path_of(&u).is_some_and(|p| p == src) {
                let _ = engine.remove_location(&id, &u);
            }
        }
        if src.exists() && src != want {
            let _ = std::fs::remove_file(&src);
        }
        let _ = src_uri;
        report.moved += 1;
    }
    Ok(report)
}
