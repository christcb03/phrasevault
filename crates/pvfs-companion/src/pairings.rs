//! Paired servers (doc 14 §6 extension; PVOS M3.1): a *pairing* lets a known
//! server — enrolled once over the 0600 agent socket with a human approval —
//! submit **relayed** signing requests through a browser page, verified two
//! ways: the payload must be signed by the paired server key, AND the relaying
//! request's browser-enforced `Origin` must be one the pairing registered.
//!
//! Persisted as `0600` JSON next to the vault (like the origin grants) and
//! re-read on every check so a revocation takes effect immediately.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Pairing {
    /// A human name, unique per registry ("PVOS on presubuntu").
    pub name: String,
    /// The server's secp256k1 public key (hex) — relay envelopes must verify
    /// against it.
    pub server_pubkey_hex: String,
    /// The web origins this server's pages are served from; a relay arriving
    /// from any other origin is refused before any prompt.
    pub origins: Vec<String>,
    pub created_ms: u64,
}

/// The pairing store. Stateless in memory: every operation loads the file
/// fresh (same posture as [`crate::origins::OriginRegistry`]).
pub struct PairingRegistry {
    path: PathBuf,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl PairingRegistry {
    pub fn at(path: &Path) -> PairingRegistry {
        PairingRegistry {
            path: path.to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load(&self) -> Vec<Pairing> {
        let Ok(bytes) = std::fs::read(&self.path) else {
            return Vec::new();
        };
        serde_json::from_slice(&bytes).unwrap_or_default()
    }

    fn store(&self, list: &[Pairing]) -> std::io::Result<()> {
        let json = serde_json::to_vec_pretty(list)?;
        let mut f = std::fs::File::create(&self.path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        use std::io::Write;
        f.write_all(&json)
    }

    pub fn list(&self) -> Vec<Pairing> {
        self.load()
    }

    /// Add or replace (same name = re-pair: key/origins updated).
    pub fn add(&self, name: &str, server_pubkey_hex: &str, origins: Vec<String>) -> std::io::Result<()> {
        let mut list = self.load();
        list.retain(|p| p.name != name);
        list.push(Pairing {
            name: name.to_string(),
            server_pubkey_hex: server_pubkey_hex.to_ascii_lowercase(),
            origins,
            created_ms: now_ms(),
        });
        self.store(&list)
    }

    /// Remove by name; `true` if something was removed.
    pub fn revoke(&self, name: &str) -> std::io::Result<bool> {
        let mut list = self.load();
        let before = list.len();
        list.retain(|p| p.name != name);
        let removed = list.len() != before;
        if removed {
            self.store(&list)?;
        }
        Ok(removed)
    }

    /// The pairing a relay envelope claims, verified by key lookup.
    pub fn find_by_pubkey(&self, pubkey_hex: &str) -> Option<Pairing> {
        let want = pubkey_hex.to_ascii_lowercase();
        self.load().into_iter().find(|p| p.server_pubkey_hex == want)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_list_revoke_and_repair() {
        let dir = tempfile::tempdir().unwrap();
        let reg = PairingRegistry::at(&dir.path().join("pairings.json"));
        assert!(reg.list().is_empty());

        reg.add("pvos", "AB", vec!["http://x:7420".into()]).unwrap();
        // Stored lowercased; findable by either case.
        assert_eq!(reg.find_by_pubkey("ab").unwrap().name, "pvos");
        assert_eq!(reg.find_by_pubkey("AB").unwrap().name, "pvos");

        // Re-pair replaces.
        reg.add("pvos", "CD", vec!["http://y:7420".into()]).unwrap();
        assert_eq!(reg.list().len(), 1);
        assert!(reg.find_by_pubkey("ab").is_none());
        assert_eq!(reg.find_by_pubkey("cd").unwrap().origins, vec!["http://y:7420"]);

        assert!(reg.revoke("pvos").unwrap());
        assert!(!reg.revoke("pvos").unwrap());
        assert!(reg.list().is_empty());
    }
}
