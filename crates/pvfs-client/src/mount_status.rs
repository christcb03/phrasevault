//! D181 — what a running view mount says about itself (PVOS D181 §8).
//!
//! A box whose mount feeds Plex keeps the mount running across a roll and
//! moves it to the new build when nothing is open through it. Two things then
//! need to know what the running mount IS: the roll, before it decides to
//! leave it up (`pvfs versions`), and the fleet's dashboard, which says when a
//! mount has been left behind. Neither can ask the mount process, so the mount
//! writes a small JSON file per mount point under `<data dir>/mounts/` at
//! start, rewrites it if it goes stale, and removes it at a clean exit.
//!
//! The file is advice, never authority: it can be missing (a mount older than
//! D181), or left behind by a killed process (hence the liveness check).

use std::path::{Path, PathBuf};

/// One mount point's file, as read back.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MountStatus {
    pub mountpoint: String,
    pub pid: u32,
    /// Its process is still there, and is still a `pvfs … mount` (pids are reused).
    pub alive: bool,
    pub build: String,
    pub version: String,
    pub mount_compat: u32,
    pub proto: u32,
    pub schema: u32,
    pub started_ms: u64,
    pub cache_mode: String,
    /// Set when the mount found the catalogue newer than it reads: why, in
    /// words, for the journal and the dashboard.
    pub stale: Option<String>,
}

/// `<data dir>/mounts/<mount point with / as ->.json`.
pub fn path(data_dir: &Path, mountpoint: &Path) -> PathBuf {
    let name = mountpoint.to_string_lossy().trim_matches('/').replace('/', "-");
    data_dir
        .join("mounts")
        .join(format!("{}.json", if name.is_empty() { "root" } else { name.as_str() }))
}

/// Write (or rewrite) one mount's file. Failing to is said, never fatal: a
/// status file is advice for the roll, not something a mount depends on.
#[allow(clippy::too_many_arguments)]
pub fn write(
    data_dir: &Path,
    mountpoint: &Path,
    build: &str,
    version: &str,
    mount_compat: u32,
    proto: u32,
    schema: u32,
    cache_mode: &str,
    started_ms: u64,
    stale: Option<&str>,
) {
    let file = path(data_dir, mountpoint);
    let v = serde_json::json!({
        "pid": std::process::id(),
        "build": build,
        "version": version,
        "mount_compat": mount_compat,
        "proto": proto,
        "schema": schema,
        "mountpoint": mountpoint.to_string_lossy(),
        "cache_mode": cache_mode,
        "started_ms": started_ms,
        "stale": stale,
    });
    let Some(dir) = file.parent() else { return };
    let tmp = file.with_extension("json.tmp");
    let wrote = std::fs::create_dir_all(dir)
        .and_then(|_| std::fs::write(&tmp, v.to_string()))
        .and_then(|_| std::fs::rename(&tmp, &file));
    if let Err(e) = wrote {
        eprintln!("mount: cannot write its status file {}: {e}", file.display());
    }
}

/// Remove one mount's file (a clean exit).
pub fn remove(data_dir: &Path, mountpoint: &Path) {
    let _ = std::fs::remove_file(path(data_dir, mountpoint));
}

/// Every mount the files under `<data dir>/mounts/` describe, sorted by mount
/// point, each with whether its process is still there.
pub fn running(data_dir: &Path) -> Vec<MountStatus> {
    let Ok(dir) = std::fs::read_dir(data_dir.join("mounts")) else { return Vec::new() };
    let mut out: Vec<MountStatus> = dir
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .filter_map(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .map(|v| {
            let n = |k: &str| v.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0);
            let s = |k: &str| v.get(k).and_then(serde_json::Value::as_str).unwrap_or("").to_string();
            let pid = n("pid") as u32;
            MountStatus {
                mountpoint: s("mountpoint"),
                pid,
                alive: is_a_mount(pid),
                build: v.get("build").and_then(serde_json::Value::as_str).unwrap_or("unknown").to_string(),
                version: s("version"),
                mount_compat: n("mount_compat") as u32,
                proto: n("proto") as u32,
                schema: n("schema") as u32,
                started_ms: n("started_ms"),
                cache_mode: s("cache_mode"),
                stale: v.get("stale").and_then(serde_json::Value::as_str).map(str::to_string),
            }
        })
        .collect();
    out.sort_by(|a, b| a.mountpoint.cmp(&b.mountpoint));
    out
}

/// Is that pid still a `pvfs … mount`? A file left behind by a killed mount
/// must not be read as a running one, and a pid is reused soon enough that
/// "the pid exists" is not an answer.
fn is_a_mount(pid: u32) -> bool {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|c| {
            let line = String::from_utf8_lossy(&c).replace('\0', " ");
            line.contains("pvfs") && line.contains("mount")
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mount_point_names_its_file() {
        let d = Path::new("/srv/pvfs/x/.pvfs");
        assert_eq!(path(d, Path::new("/mnt/pvfs/Media")), d.join("mounts/mnt-pvfs-Media.json"));
        assert_eq!(path(d, Path::new("/")), d.join("mounts/root.json"));
    }

    #[test]
    fn written_then_read_back_and_a_dead_one_is_not_alive() {
        let dir = tempfile::tempdir().unwrap();
        let mnt = Path::new("/mnt/pvfs/Media");
        write(dir.path(), mnt, "v1.4-417", "1.4.0", 1, 11, 19, "stream", 42, None);
        let got = running(dir.path());
        assert_eq!(got.len(), 1);
        let m = &got[0];
        assert_eq!((m.mountpoint.as_str(), m.build.as_str(), m.cache_mode.as_str()), ("/mnt/pvfs/Media", "v1.4-417", "stream"));
        assert_eq!((m.mount_compat, m.proto, m.schema, m.started_ms), (1, 11, 19, 42));
        assert!(m.stale.is_none());
        assert_eq!(m.pid, std::process::id());

        // A file left behind by a mount that is gone: its pid answers nothing.
        let f = path(dir.path(), mnt);
        let text = std::fs::read_to_string(&f).unwrap().replace(
            &format!("\"pid\":{}", std::process::id()),
            "\"pid\":4194305",
        );
        std::fs::write(&f, text).unwrap();
        assert!(!running(dir.path())[0].alive, "a status file whose process is gone is not a running mount");

        write(dir.path(), mnt, "v1.4-417", "1.4.0", 1, 11, 19, "stream", 42, Some("the catalogue is v20"));
        assert_eq!(running(dir.path())[0].stale.as_deref(), Some("the catalogue is v20"));
        remove(dir.path(), mnt);
        assert!(running(dir.path()).is_empty());
        // Rubbish in the directory is skipped, not fatal.
        std::fs::write(dir.path().join("mounts/nonsense.json"), "{oh dear").unwrap();
        assert!(running(dir.path()).is_empty());
    }
}
