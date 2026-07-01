//! Per-user vault store (doc 14 §13) — the server-side, multi-tenant custody
//! layer. Each app-user has their own sealed [`Vault`] under `<dir>/<user>.vault`;
//! the store is a thin, safe directory wrapper. Unlock is on-demand: the app
//! supplies the user's secret, the store unseals *that* user's key, and the caller
//! (see `session`) decides whether to cache it.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::vault::{KdfParams, Vault, VaultError};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error("store io: {0}")]
    Io(String),
    #[error("invalid user id {0:?}")]
    BadUserId(String),
    #[error("no vault for user {0:?}")]
    NotFound(String),
    #[error("a vault already exists for user {0:?}")]
    Exists(String),
}

/// A directory of per-user vaults.
pub struct VaultStore {
    dir: PathBuf,
}

impl VaultStore {
    /// Open (creating if absent) a vault store directory, `0700` on Unix.
    pub fn open(dir: &Path) -> Result<VaultStore, StoreError> {
        std::fs::create_dir_all(dir).map_err(|e| StoreError::Io(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| StoreError::Io(e.to_string()))?;
        }
        Ok(VaultStore {
            dir: dir.to_path_buf(),
        })
    }

    /// Whether a vault exists for `user_id`.
    pub fn has(&self, user_id: &str) -> bool {
        self.path(user_id).map(|p| p.exists()).unwrap_or(false)
    }

    /// Seal `secret` for `user_id` under `passphrase` (default KDF). Refuses to
    /// overwrite an existing vault.
    pub fn create(&self, user_id: &str, secret: &[u8], passphrase: &[u8]) -> Result<(), StoreError> {
        self.create_with(user_id, secret, passphrase, KdfParams::default())
    }

    /// As [`create`](VaultStore::create) with explicit KDF params.
    pub fn create_with(
        &self,
        user_id: &str,
        secret: &[u8],
        passphrase: &[u8],
        params: KdfParams,
    ) -> Result<(), StoreError> {
        let path = self.path(user_id)?;
        if path.exists() {
            return Err(StoreError::Exists(user_id.to_string()));
        }
        Vault::create_with(&path, secret, passphrase, params)?;
        Ok(())
    }

    /// Unseal `user_id`'s vault with `passphrase`, returning the zeroizing secret.
    pub fn unseal(&self, user_id: &str, passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let path = self.path(user_id)?;
        if !path.exists() {
            return Err(StoreError::NotFound(user_id.to_string()));
        }
        Ok(Vault::open(&path)?.unseal(passphrase)?)
    }

    /// `<dir>/<user_id>.vault`, rejecting any id that isn't a safe filename slug
    /// (so a user id can never traverse out of the store directory).
    fn path(&self, user_id: &str) -> Result<PathBuf, StoreError> {
        if !valid_user_id(user_id) {
            return Err(StoreError::BadUserId(user_id.to_string()));
        }
        Ok(self.dir.join(format!("{user_id}.vault")))
    }
}

/// A safe per-user filename slug: non-empty, ≤128 ASCII alphanumerics plus
/// `. _ -`, and never `.`/`..` — no path separators, so no traversal.
fn valid_user_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s != "."
        && s != ".."
        && s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast() -> KdfParams {
        KdfParams {
            m_cost: 32,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn create_unseal_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::open(dir.path()).unwrap();
        assert!(!store.has("alice"));
        store.create_with("alice", b"alice-seed", b"pw", fast()).unwrap();
        assert!(store.has("alice"));
        let secret = store.unseal("alice", b"pw").unwrap();
        assert_eq!(&secret[..], b"alice-seed");
    }

    #[test]
    fn per_user_isolation() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::open(dir.path()).unwrap();
        store.create_with("alice", b"a", b"apw", fast()).unwrap();
        store.create_with("bob", b"b", b"bpw", fast()).unwrap();
        assert_eq!(&store.unseal("alice", b"apw").unwrap()[..], b"a");
        assert_eq!(&store.unseal("bob", b"bpw").unwrap()[..], b"b");
        // alice's passphrase cannot open bob's vault
        assert!(store.unseal("bob", b"apw").is_err());
    }

    #[test]
    fn refuses_duplicate_and_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::open(dir.path()).unwrap();
        store.create_with("u", b"s", b"pw", fast()).unwrap();
        assert!(matches!(
            store.create_with("u", b"s2", b"pw", fast()),
            Err(StoreError::Exists(_))
        ));
        assert!(matches!(
            store.unseal("nobody", b"pw"),
            Err(StoreError::NotFound(_))
        ));
    }

    #[test]
    fn rejects_unsafe_user_ids() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::open(dir.path()).unwrap();
        for bad in ["../evil", "a/b", "", ".", "..", "has space"] {
            assert!(
                matches!(store.create_with(bad, b"s", b"pw", fast()), Err(StoreError::BadUserId(_))),
                "user id {bad:?} should be rejected"
            );
        }
    }
}
