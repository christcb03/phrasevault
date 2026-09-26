//! PVOS D189 — which forests a phrase's keys are used for.
//!
//! One JSON file beside each vault (`<vault>.forests.json`), written by the
//! companion's router when a request that names its forest
//! ([`crate::proto::FOREST_FIELD`]) succeeds, and when a forest is linked
//! ([`crate::proto::AgentRequest::LinkForest`]). It holds what the requesting
//! tool said — a companion cannot check a forest id — so it is shown as that,
//! and it never routes or authorizes anything. Public data only.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::proto::ForestRef;

/// Entries kept per phrase; the oldest-used go first past it.
const MAX_ENTRIES: usize = 500;

/// One forest's use of one of the phrase's keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForestUse {
    pub forest_id: String,
    #[serde(default)]
    pub label: String,
    /// The key (hex), and which of the phrase's keys it is: `root`,
    /// `identity` or `encryption`.
    pub key: String,
    pub role: String,
    pub first_ms: u64,
    pub last_ms: u64,
    pub uses: u64,
    /// The last thing done for the forest with this key.
    #[serde(default)]
    pub last_action: String,
}

#[derive(Default, Serialize, Deserialize)]
struct LedgerFile {
    #[serde(default)]
    forests: Vec<ForestUse>,
}

/// A phrase's ledger file; writes from the router's connection threads
/// take turns.
pub struct Ledger {
    path: PathBuf,
    lock: Mutex<()>,
}

impl Ledger {
    pub fn at(path: &Path) -> Ledger {
        Ledger { path: path.to_path_buf(), lock: Mutex::new(()) }
    }

    /// Record one use: a new forest and key, or a newer label and action for
    /// a known pair.
    pub fn record(&self, forest: &ForestRef, key_hex: &str, role: &str, action: &str) -> std::io::Result<()> {
        check(forest)?;
        let _turn = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut file = read_file(&self.path);
        let now = now_ms();
        match file.forests.iter_mut().find(|u| u.forest_id == forest.id && u.key == key_hex) {
            Some(u) => {
                u.last_ms = now;
                u.uses += 1;
                u.role = role.to_string();
                if !forest.label.is_empty() {
                    u.label = forest.label.clone();
                }
                if !action.is_empty() {
                    u.last_action = action.to_string();
                }
            }
            None => file.forests.push(ForestUse {
                forest_id: forest.id.clone(),
                label: forest.label.clone(),
                key: key_hex.to_string(),
                role: role.to_string(),
                first_ms: now,
                last_ms: now,
                uses: 1,
                last_action: action.to_string(),
            }),
        }
        if file.forests.len() > MAX_ENTRIES {
            file.forests.sort_by(|a, b| b.last_ms.cmp(&a.last_ms));
            file.forests.truncate(MAX_ENTRIES);
        }
        write_file(&self.path, &file)
    }
}

/// A ledger's entries, most recently used first — read without a companion
/// (the `keys` command). A missing or unreadable file is an empty ledger.
pub fn read(path: &Path) -> Vec<ForestUse> {
    let mut forests = read_file(path).forests;
    forests.sort_by(|a, b| b.last_ms.cmp(&a.last_ms));
    forests
}

/// A forest reference fit to keep: an id and a label of sane size.
fn check(forest: &ForestRef) -> std::io::Result<()> {
    let ok = |s: &str, max: usize| s.len() <= max && !s.chars().any(char::is_control);
    if forest.id.trim().is_empty() || !ok(&forest.id, 128) || !ok(&forest.label, 256) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "forest: an id (≤128) and a label (≤256)"));
    }
    Ok(())
}

fn read_file(path: &Path) -> LedgerFile {
    std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

/// Write-then-rename, owner-only, so a reader never sees half a file.
fn write_file(path: &Path, file: &LedgerFile) -> std::io::Result<()> {
    let body = serde_json::to_vec_pretty(file).map_err(std::io::Error::other)?;
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "forests.json".into());
    let tmp = path.with_file_name(format!(".{name}.tmp"));
    {
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forest(id: &str, label: &str) -> ForestRef {
        ForestRef { id: id.into(), label: label.into() }
    }

    #[test]
    fn a_use_is_recorded_once_per_forest_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("media2.forests.json");
        let l = Ledger::at(&path);
        assert!(read(&path).is_empty(), "no file: an empty ledger");
        l.record(&forest("f-1", "media"), "03aa", "root", "public key (root)").unwrap();
        l.record(&forest("f-1", ""), "03aa", "root", "sign root_device_cert").unwrap();
        l.record(&forest("f-2", "lab4"), "03aa", "root", "linked").unwrap();
        let got = read(&path);
        assert_eq!(got.len(), 2);
        let media = got.iter().find(|u| u.forest_id == "f-1").unwrap();
        assert_eq!((media.uses, media.label.as_str()), (2, "media"), "an empty label keeps the known one");
        assert_eq!(media.last_action, "sign root_device_cert");
        assert!(media.first_ms <= media.last_ms);
        let mode = std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&path).unwrap().permissions());
        assert_eq!(mode & 0o777, 0o600, "owner-only");
    }

    #[test]
    fn a_bad_forest_reference_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let l = Ledger::at(&dir.path().join("x.forests.json"));
        assert!(l.record(&forest("", "x"), "03aa", "root", "").is_err());
        assert!(l.record(&forest("f\n1", "x"), "03aa", "root", "").is_err());
        assert!(l.record(&forest(&"f".repeat(200), "x"), "03aa", "root", "").is_err());
        assert!(read(&dir.path().join("x.forests.json")).is_empty());
    }
}
