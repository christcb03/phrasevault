//! PVOS D197 — the companion keeps its runtime files.
//!
//! `serve` writes two files beside its socket: `<socket>.pid` (its pid, for
//! the singleton takeover) and `<socket>.http` (the web agent's address and
//! token, which pvosd reads for "Sign in with PVFS" and `status` prints). They
//! stay where every reader looks — `/tmp`, beside the socket — and this keeps
//! them there: macOS's `tmp_cleaner` deletes a regular file in `/tmp` whose
//! access, modification and change times are all more than three days old
//! (sockets are left), and on 2026-09-26 both were gone while the app ran
//! (D189 §1.6). Every `KEEP_EVERY` a file that still holds what this companion
//! wrote is touched; one that has gone is written again; one another instance
//! has since rewritten is left to it.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// How often the files are looked at: well inside the cleaner's three days.
pub const KEEP_EVERY: Duration = Duration::from_secs(3600);

/// One file the companion keeps, and what it wrote there.
#[derive(Debug, Clone)]
pub struct RuntimeFile {
    pub path: PathBuf,
    pub contents: String,
}

/// Write `contents` to `path`, owner-only (0600) — as `serve` first did.
pub fn write_owner_only(path: &Path, contents: &str) -> std::io::Result<()> {
    let mut f = std::fs::File::create(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(contents.as_bytes())
}

/// One look at each file: one that still holds what this companion wrote is
/// touched (access and modification times set to now), one that has gone is
/// written again, and one holding anything else — another instance took over
/// — is left alone and dropped from `files`. Returns a line for each thing
/// worth saying (a file written again, or given up), for the log.
pub fn keep_once(files: &mut Vec<RuntimeFile>) -> Vec<String> {
    let mut said = Vec::new();
    files.retain(|f| match std::fs::read_to_string(&f.path) {
        Ok(now) if now == f.contents => {
            let t = SystemTime::now();
            let touched = std::fs::File::options()
                .write(true)
                .open(&f.path)
                .and_then(|h| h.set_times(std::fs::FileTimes::new().set_accessed(t).set_modified(t)));
            if let Err(e) = touched {
                said.push(format!("companion: could not touch {} ({e}) — the next look tries again", f.path.display()));
            }
            true
        }
        Ok(_) => {
            said.push(format!(
                "companion: {} now belongs to another instance — no longer kept by this one",
                f.path.display()
            ));
            false
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            match write_owner_only(&f.path, &f.contents) {
                Ok(()) => said.push(format!("companion: {} was gone — written again", f.path.display())),
                Err(e) => said.push(format!(
                    "companion: {} was gone and could not be written again ({e}) — the next look tries again",
                    f.path.display()
                )),
            }
            true
        }
        Err(e) => {
            said.push(format!("companion: could not read {} ({e}) — the next look tries again", f.path.display()));
            true
        }
    });
    said
}

/// Keep `files` for as long as the process runs, looking every `every`.
/// `PVFS_COMPANION_KEEP_SECS` shortens the interval for a rehearsal.
pub fn keep(mut files: Vec<RuntimeFile>, every: Duration) {
    let every = std::env::var("PVFS_COMPANION_KEEP_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&s| s > 0)
        .map(Duration::from_secs)
        .unwrap_or(every);
    std::thread::spawn(move || {
        while !files.is_empty() {
            std::thread::sleep(every);
            for line in keep_once(&mut files) {
                eprintln!("{line}");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn age(path: &Path, days: u64) {
        let t = SystemTime::now() - Duration::from_secs(days * 86_400);
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_accessed(t).set_modified(t))
            .unwrap();
    }

    fn modified_ago(path: &Path) -> Duration {
        let m = std::fs::metadata(path).unwrap().modified().unwrap();
        SystemTime::now().duration_since(m).unwrap_or_default()
    }

    #[test]
    fn a_kept_file_is_touched_and_a_gone_one_written_again() {
        let dir = tempfile::tempdir().unwrap();
        let pid = dir.path().join("c.pid");
        let http = dir.path().join("c.http");
        write_owner_only(&pid, "4242").unwrap();
        write_owner_only(&http, "{\"addr\":\"127.0.0.1:7421\",\"token\":\"ab\"}").unwrap();
        let mut files = vec![
            RuntimeFile { path: pid.clone(), contents: "4242".into() },
            RuntimeFile { path: http.clone(), contents: "{\"addr\":\"127.0.0.1:7421\",\"token\":\"ab\"}".into() },
        ];

        // Four days untouched: what the cleaner would take.
        age(&pid, 4);
        age(&http, 4);
        assert!(modified_ago(&pid) > Duration::from_secs(3 * 86_400));
        assert!(keep_once(&mut files).is_empty(), "touching is not news");
        assert!(modified_ago(&pid) < Duration::from_secs(60), "touched: {:?}", modified_ago(&pid));
        assert!(modified_ago(&http) < Duration::from_secs(60));
        assert_eq!(std::fs::read_to_string(&pid).unwrap(), "4242", "contents unchanged");

        // Deleted (the cleaner, or anyone): written again, owner-only.
        std::fs::remove_file(&pid).unwrap();
        std::fs::remove_file(&http).unwrap();
        let said = keep_once(&mut files);
        assert_eq!(said.len(), 2, "{said:?}");
        assert!(said[0].ends_with("was gone — written again"), "{said:?}");
        assert_eq!(std::fs::read_to_string(&pid).unwrap(), "4242");
        assert_eq!(std::fs::read_to_string(&http).unwrap(), "{\"addr\":\"127.0.0.1:7421\",\"token\":\"ab\"}");
        assert_eq!(std::fs::metadata(&http).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn a_file_another_instance_rewrote_is_left_to_it() {
        let dir = tempfile::tempdir().unwrap();
        let pid = dir.path().join("c.pid");
        write_owner_only(&pid, "4242").unwrap();
        let mut files = vec![RuntimeFile { path: pid.clone(), contents: "4242".into() }];
        // A new companion took over and wrote its own pid.
        write_owner_only(&pid, "5151").unwrap();
        let said = keep_once(&mut files);
        assert!(said[0].contains("now belongs to another instance"), "{said:?}");
        assert!(files.is_empty(), "no longer kept");
        assert_eq!(std::fs::read_to_string(&pid).unwrap(), "5151", "left alone");
        // Gone later: not this instance's to bring back.
        std::fs::remove_file(&pid).unwrap();
        assert!(keep_once(&mut files).is_empty());
        assert!(!pid.exists());
    }
}
