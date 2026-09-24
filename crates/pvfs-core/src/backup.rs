//! PVOS D182 — dated copies of a forest's log, and the way back from one.
//!
//! Followers protect a forest against losing a box; they faithfully copy
//! whatever the owner writes, a bad build's events included. A dated copy is
//! the only way back to a known-good log. Nothing copied, exported or verified
//! a log before this.
//!
//! A copy is a directory: the top log (`log.db`) and any region log
//! generations (`regions/<root>/g-*.db`), each taken with `VACUUM INTO` — a
//! consistent snapshot, safe beside a running daemon, plain SQL on the bundled
//! SQLite. It counts only once VERIFIED: opened as a throwaway replica in a
//! scratch directory, where the full replay checks every chain hash, signature
//! and authorization from seq 1. The manifest beside it (written by the CLI,
//! which speaks JSON) says what it holds. Catalogue manifests
//! (`regions/<id>/manifest.<seq>`) are not copied: they are snapshots each
//! box republishes, not history.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};

use crate::error::{map_db, PvfsError, Result};
use crate::replica::ReplicaSource;

/// What a verified copy holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCopy {
    pub instance_id: String,
    pub forest_id: String,
    pub seq: u64,
    pub hash: Vec<u8>,
    /// Log files, relative to the copy's directory.
    pub files: Vec<PathBuf>,
    pub bytes: u64,
}

/// The region log generations under a data dir, relative to it.
fn region_logs(data_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let regions = data_dir.join("regions");
    let Ok(entries) = std::fs::read_dir(&regions) else { return Ok(out) };
    for region in entries.flatten() {
        let Ok(files) = std::fs::read_dir(region.path()) else { continue };
        for f in files.flatten() {
            let name = f.file_name().to_string_lossy().into_owned();
            if name.starts_with("g-") && name.ends_with(".db") {
                out.push(PathBuf::from("regions").join(region.file_name()).join(name));
            }
        }
    }
    out.sort();
    Ok(out)
}

fn vacuum_into(from: &Path, to: &Path) -> Result<()> {
    if let Some(dir) = to.parent() {
        std::fs::create_dir_all(dir).map_err(|e| PvfsError::io("make copy dir", e))?;
    }
    let conn = Connection::open_with_flags(from, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(map_db("open log read-only"))?;
    conn.execute("VACUUM INTO ?1", [to.to_string_lossy().as_ref()])
        .map_err(map_db("copy log (VACUUM INTO)"))?;
    Ok(())
}

/// Copy a data dir's logs into `dest` (which must not exist yet). Returns the
/// files copied, relative to `dest`.
pub fn copy_logs(data_dir: &Path, dest: &Path) -> Result<Vec<PathBuf>> {
    if dest.exists() {
        return Err(PvfsError::AlreadyExists { kind: "copy", id: dest.display().to_string() });
    }
    std::fs::create_dir_all(dest).map_err(|e| PvfsError::io("make copy dir", e))?;
    let mut files = vec![PathBuf::from("log.db")];
    files.extend(region_logs(data_dir)?);
    for f in &files {
        vacuum_into(&data_dir.join(f), &dest.join(f))?;
    }
    Ok(files)
}

/// Verify a copy: open it as a throwaway replica in a scratch directory,
/// where the full replay checks every chain hash, signature and
/// authorization from seq 1. Nothing in `copy` is changed.
pub fn verify_copy(copy: &Path) -> Result<VerifiedCopy> {
    let scratch = scratch_dir(copy)?;
    let result = (|| {
        let data = scratch.join(".pvfs");
        let mut files = vec![PathBuf::from("log.db")];
        files.extend(region_logs(copy)?);
        let mut bytes = 0;
        for f in &files {
            let to = data.join(f);
            if let Some(dir) = to.parent() {
                std::fs::create_dir_all(dir).map_err(|e| PvfsError::io("make scratch dir", e))?;
            }
            bytes += std::fs::copy(copy.join(f), &to).map_err(|e| PvfsError::io("copy to scratch", e))?;
        }
        // A marker naming no source: this replica is opened, never followed.
        ReplicaSource {
            transport: "socket".into(),
            target: "/nonexistent/pvfs-copy-verification".into(),
            pin: String::new(),
            region: String::new(),
        }
        .save(&data)?;
        let engine = crate::engine::Engine::open(&data)?;
        let (seq, hash) = engine.log_tip_hash()?;
        let v = VerifiedCopy {
            instance_id: engine.identity.instance_id.clone(),
            forest_id: engine.identity.forest_id.clone(),
            seq,
            hash,
            files,
            bytes,
        };
        let _ = engine.close();
        Ok(v)
    })();
    let _ = std::fs::remove_dir_all(&scratch);
    result
}

fn scratch_dir(near: &Path) -> Result<PathBuf> {
    let base = near.parent().unwrap_or(near);
    let d = base.join(format!(".pvfs-verify-{}-{}", std::process::id(), crate::engine::now_ms()));
    std::fs::create_dir_all(&d).map_err(|e| PvfsError::io("make scratch dir", e))?;
    Ok(d)
}

/// `YYYYMMDD-HHMM` (UTC) for an ms-epoch stamp — a copy's name sorts by time.
pub fn stamp(ms: u64) -> String {
    let secs = ms / 1000;
    let days = (secs / 86_400) as i64;
    let (y, m, d) = civil_from_days(days);
    let hm = secs % 86_400;
    format!("{y:04}{m:02}{d:02}-{:02}{:02}", hm / 3600, (hm % 3600) / 60)
}

/// Days since 1970-01-01 → (year, month, day), proleptic Gregorian (Howard
/// Hinnant's `civil_from_days`). No date crate in this tree.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The directory name for a copy: `<forest-id-8>-<YYYYMMDD-HHMM>-seq<N>`.
pub fn copy_name(forest_id: &str, made_ms: u64, seq: u64) -> String {
    let short: String = forest_id.chars().filter(|c| c.is_ascii_alphanumeric()).take(8).collect();
    format!("{short}-{}-seq{seq}", stamp(made_ms))
}

/// Remove this forest's copies older than `keep_days` under `dir` — only
/// directories whose name is a copy's name for this forest AND that hold a
/// manifest (nothing else in `dir` is touched). Returns what was removed.
pub fn prune(dir: &Path, forest_id: &str, keep_days: u64, now_ms: u64) -> Result<Vec<PathBuf>> {
    let short: String = forest_id.chars().filter(|c| c.is_ascii_alphanumeric()).take(8).collect();
    let cutoff = stamp(now_ms.saturating_sub(keep_days * 86_400_000));
    let mut removed = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return Ok(removed) };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(rest) = name.strip_prefix(&format!("{short}-")) else { continue };
        // rest = YYYYMMDD-HHMM-seqN
        if rest.len() < 13 || !rest[13..].starts_with("-seq") {
            continue;
        }
        let when = &rest[..13];
        if when >= cutoff.as_str() || !e.path().join("manifest.json").is_file() {
            continue;
        }
        std::fs::remove_dir_all(e.path()).map_err(|er| PvfsError::io("prune copy", er))?;
        removed.push(e.path());
    }
    removed.sort();
    Ok(removed)
}

/// A new replica data dir at `<mount>/.pvfs` from a verified copy. Its marker
/// names `source` (what the copied box followed, from the copy's manifest)
/// when known — else an address that never answers, so `pvfs replica
/// repoint` (follow a live owner) or `pvfs forest promote` (the last resort)
/// is the next, deliberate step. Opened once here, which replays and
/// verifies the whole log into a fresh projection.
pub fn restore(copy: &Path, mount: &Path, source: Option<ReplicaSource>) -> Result<VerifiedCopy> {
    let data = mount.join(".pvfs");
    if data.exists() {
        return Err(PvfsError::AlreadyExists { kind: "forest", id: data.display().to_string() });
    }
    let verified = verify_copy(copy)?;
    for f in &verified.files {
        let to = data.join(f);
        if let Some(dir) = to.parent() {
            std::fs::create_dir_all(dir).map_err(|e| PvfsError::io("make restore dir", e))?;
        }
        std::fs::copy(copy.join(f), &to).map_err(|e| PvfsError::io("restore log", e))?;
    }
    source
        .unwrap_or(ReplicaSource {
            transport: "tcp".into(),
            target: "restored-from-a-copy.invalid:0".into(),
            pin: String::new(),
            region: String::new(),
        })
        .save(&data)?;
    let engine = crate::engine::Engine::open(&data)?;
    let _ = engine.close();
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_sort_and_read_as_utc() {
        assert_eq!(stamp(0), "19700101-0000");
        // 2026-09-23 23:59 UTC
        assert_eq!(stamp(1_790_207_940_000), "20260923-2359");
        assert!(stamp(1_790_207_940_000) < stamp(1_790_208_000_000));
        assert_eq!(copy_name("ae60b1db-72eb-434f", 0, 3472), "ae60b1db-19700101-0000-seq3472");
    }

    #[test]
    fn prune_touches_only_this_forests_old_copies_with_a_manifest() {
        let d = tempfile::tempdir().unwrap();
        let day = 86_400_000u64;
        let now = 100 * day;
        let mk = |name: &str, manifest: bool| {
            let p = d.path().join(name);
            std::fs::create_dir_all(&p).unwrap();
            if manifest {
                std::fs::write(p.join("manifest.json"), "{}").unwrap();
            }
            p
        };
        let old = mk(&copy_name("ae60b1db", now - 40 * day, 1), true);
        let recent = mk(&copy_name("ae60b1db", now - 2 * day, 2), true);
        let other_forest = mk(&copy_name("c3981e4e", now - 40 * day, 3), true);
        let no_manifest = mk(&copy_name("ae60b1db", now - 50 * day, 4), false);
        let stray = mk("ae60b1db-notes", true);
        let removed = prune(d.path(), "ae60b1db-72eb", 30, now).unwrap();
        assert_eq!(removed, vec![old.clone()]);
        assert!(!old.exists());
        for kept in [recent, other_forest, no_manifest, stray] {
            assert!(kept.exists(), "{} must be kept", kept.display());
        }
    }
}
