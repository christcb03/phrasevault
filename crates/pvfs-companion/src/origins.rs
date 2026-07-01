//! Connected web origins (doc 14 §6): the wallet-style **connect** grants that
//! let an origin request identity assertions without a per-request prompt.
//!
//! A grant is `{origin, granted_at_ms, ttl_secs}`, persisted as `0600` JSON next
//! to the vault. The registry re-reads the file on every check, so a revocation
//! (CLI or UI) takes effect immediately even while an agent is serving. Grants
//! authorize **identity assertions only** — the web path can never reach a root
//! event (doc 14 §4).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Default connect TTL: 30 days.
pub const DEFAULT_CONNECT_TTL_SECS: u64 = 30 * 24 * 60 * 60;

#[derive(Clone, Serialize, Deserialize)]
pub struct OriginGrant {
    pub origin: String,
    pub granted_at_ms: u64,
    pub ttl_secs: u64,
}

impl OriginGrant {
    pub fn expires_at_ms(&self) -> u64 {
        self.granted_at_ms.saturating_add(self.ttl_secs.saturating_mul(1000))
    }
    fn live(&self, now_ms: u64) -> bool {
        now_ms < self.expires_at_ms()
    }
}

/// The grant store. Stateless in memory: every operation loads the file fresh.
pub struct OriginRegistry {
    path: PathBuf,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl OriginRegistry {
    /// The registry backed by `path` (created on the first grant).
    pub fn at(path: &Path) -> OriginRegistry {
        OriginRegistry {
            path: path.to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load(&self) -> Vec<OriginGrant> {
        let Ok(bytes) = std::fs::read(&self.path) else {
            return Vec::new();
        };
        serde_json::from_slice(&bytes).unwrap_or_default()
    }

    fn save(&self, grants: &[OriginGrant]) -> Result<(), String> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_vec_pretty(grants).map_err(|e| e.to_string())?;
        // Write-then-rename so a concurrent reader never sees a torn file.
        let tmp = self.path.with_extension("tmp");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| e.to_string())?;
            }
            f.write_all(&json).map_err(|e| e.to_string())?;
        }
        std::fs::rename(&tmp, &self.path).map_err(|e| e.to_string())
    }

    /// Is `origin` currently connected (granted and unexpired)?
    pub fn connected(&self, origin: &str) -> bool {
        let now = now_ms();
        self.load().iter().any(|g| g.origin == origin && g.live(now))
    }

    /// Record a connect grant (replacing any earlier grant for the origin) and
    /// drop expired rows while we're writing anyway.
    pub fn connect(&self, origin: &str, ttl_secs: u64) -> Result<(), String> {
        let now = now_ms();
        let mut grants: Vec<OriginGrant> = self
            .load()
            .into_iter()
            .filter(|g| g.origin != origin && g.live(now))
            .collect();
        grants.push(OriginGrant {
            origin: origin.to_string(),
            granted_at_ms: now,
            ttl_secs,
        });
        self.save(&grants)
    }

    /// Remove an origin's grant. Returns whether one was present.
    pub fn revoke(&self, origin: &str) -> Result<bool, String> {
        let grants = self.load();
        let kept: Vec<OriginGrant> = grants
            .iter()
            .filter(|g| g.origin != origin)
            .cloned()
            .collect();
        let removed = kept.len() != grants.len();
        if removed {
            self.save(&kept)?;
        }
        Ok(removed)
    }

    /// The live grants (expired rows filtered out).
    pub fn list(&self) -> Vec<OriginGrant> {
        let now = now_ms();
        self.load().into_iter().filter(|g| g.live(now)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> (tempfile::TempDir, OriginRegistry) {
        let dir = tempfile::tempdir().unwrap();
        let r = OriginRegistry::at(&dir.path().join("origins.json"));
        (dir, r)
    }

    #[test]
    fn connect_list_revoke_round_trip() {
        let (_d, r) = reg();
        assert!(!r.connected("https://app.example"));
        r.connect("https://app.example", 3600).unwrap();
        assert!(r.connected("https://app.example"));
        assert!(!r.connected("https://evil.example"));
        assert_eq!(r.list().len(), 1);
        assert!(r.revoke("https://app.example").unwrap());
        assert!(!r.connected("https://app.example"));
        assert!(!r.revoke("https://app.example").unwrap());
    }

    #[test]
    fn expired_grants_do_not_connect() {
        let (_d, r) = reg();
        r.connect("https://app.example", 0).unwrap(); // expires immediately
        assert!(!r.connected("https://app.example"));
        assert!(r.list().is_empty());
    }

    #[test]
    fn reconnect_replaces_the_grant() {
        let (_d, r) = reg();
        r.connect("https://app.example", 0).unwrap();
        r.connect("https://app.example", 3600).unwrap();
        assert!(r.connected("https://app.example"));
        assert_eq!(r.list().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn grants_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, r) = reg();
        r.connect("https://app.example", 3600).unwrap();
        let mode = std::fs::metadata(r.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
