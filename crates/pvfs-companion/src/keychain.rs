//! OS secret-store backends for the vault data key (doc 14 §5, phase 4).
//!
//! A keychain-sealed vault (see [`crate::Vault`]) encrypts the seed under a random
//! 32-byte **data key**; that key lives in the platform secret store, named by the
//! vault's `key_id`. This module is the §5 abstraction over "where the data key
//! lives": [`SecretStore`] is the seam, [`OsKeychain`] (feature `os-keychain`) is
//! the real backend via the `keyring` crate — macOS Keychain, Linux Secret Service
//! (GNOME Keyring / KWallet), Windows Credential Manager — and [`MemoryStore`] is
//! the in-process test double, since CI and servers are headless.
//!
//! The passphrase fallback (doc 14 §5) is *not* a `SecretStore`: it stays the
//! Argon2id path inside the vault itself, so it works with no OS dependency.

use std::collections::HashMap;
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::vault::VaultError;

/// Where a vault's data key lives (doc 14 §5). Implementations must treat the
/// stored bytes as opaque and return exactly what was set.
pub trait SecretStore {
    /// Store (or replace) the data key for `key_id`.
    fn set(&self, key_id: &str, secret: &[u8]) -> Result<(), VaultError>;
    /// Fetch the data key for `key_id`.
    fn get(&self, key_id: &str) -> Result<Zeroizing<Vec<u8>>, VaultError>;
    /// Remove the data key for `key_id` (used when a vault is re-sealed/retired).
    fn delete(&self, key_id: &str) -> Result<(), VaultError>;
}

/// In-memory [`SecretStore`] for tests: behaves like a keychain that's present
/// and unlocked. Never use it to hold a real vault's key — it vanishes on drop,
/// which would orphan the vault (that's what the recovery phrase is for).
#[derive(Default)]
pub struct MemoryStore {
    map: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryStore {
    pub fn new() -> MemoryStore {
        MemoryStore::default()
    }
}

impl SecretStore for MemoryStore {
    fn set(&self, key_id: &str, secret: &[u8]) -> Result<(), VaultError> {
        self.map
            .lock()
            .expect("memory store poisoned")
            .insert(key_id.to_string(), secret.to_vec());
        Ok(())
    }
    fn get(&self, key_id: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        self.map
            .lock()
            .expect("memory store poisoned")
            .get(key_id)
            .map(|v| Zeroizing::new(v.clone()))
            .ok_or_else(|| VaultError::Keychain(format!("no secret for key id {key_id}")))
    }
    fn delete(&self, key_id: &str) -> Result<(), VaultError> {
        self.map
            .lock()
            .expect("memory store poisoned")
            .remove(key_id);
        Ok(())
    }
}

/// The platform secret store, via the `keyring` crate: macOS Keychain,
/// Linux Secret Service (GNOME Keyring / KWallet), Windows Credential Manager.
/// Entries are namespaced under one service name so they're recognizable in the
/// platform's keychain UI and can be cleaned up as a group.
#[cfg(feature = "os-keychain")]
pub struct OsKeychain {
    service: String,
}

#[cfg(feature = "os-keychain")]
impl Default for OsKeychain {
    fn default() -> Self {
        OsKeychain::new()
    }
}

#[cfg(feature = "os-keychain")]
impl OsKeychain {
    /// The default namespace: entries appear as service `pvfs-companion`.
    pub fn new() -> OsKeychain {
        OsKeychain {
            service: "pvfs-companion".into(),
        }
    }

    fn entry(&self, key_id: &str) -> Result<keyring::Entry, VaultError> {
        keyring::Entry::new(&self.service, key_id)
            .map_err(|e| VaultError::Keychain(e.to_string()))
    }
}

#[cfg(feature = "os-keychain")]
impl SecretStore for OsKeychain {
    fn set(&self, key_id: &str, secret: &[u8]) -> Result<(), VaultError> {
        self.entry(key_id)?
            .set_secret(secret)
            .map_err(|e| VaultError::Keychain(e.to_string()))
    }
    fn get(&self, key_id: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        self.entry(key_id)?
            .get_secret()
            .map(Zeroizing::new)
            .map_err(|e| VaultError::Keychain(e.to_string()))
    }
    fn delete(&self, key_id: &str) -> Result<(), VaultError> {
        self.entry(key_id)?
            .delete_credential()
            .map_err(|e| VaultError::Keychain(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_round_trip_and_delete() {
        let s = MemoryStore::new();
        s.set("k1", b"data-key-bytes").unwrap();
        assert_eq!(&s.get("k1").unwrap()[..], b"data-key-bytes");
        s.set("k1", b"replaced").unwrap();
        assert_eq!(&s.get("k1").unwrap()[..], b"replaced");
        s.delete("k1").unwrap();
        assert!(matches!(s.get("k1"), Err(VaultError::Keychain(_))));
    }

    /// Touches the REAL platform keychain — run by hand on a desktop:
    /// `cargo test -p pvfs-companion -- --ignored os_keychain`.
    #[cfg(feature = "os-keychain")]
    #[test]
    #[ignore]
    fn os_keychain_round_trip() {
        let s = OsKeychain::new();
        let key_id = format!("pvfs-test-{}", std::process::id());
        s.set(&key_id, b"test-data-key").unwrap();
        assert_eq!(&s.get(&key_id).unwrap()[..], b"test-data-key");
        s.delete(&key_id).unwrap();
        assert!(s.get(&key_id).is_err());
    }
}
