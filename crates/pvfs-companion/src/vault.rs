//! The companion key vault (doc 14 §5).
//!
//! A vault file seals a secret (the recovery seed) under a passphrase:
//! `passphrase --Argon2id--> key`, then `XChaCha20-Poly1305(key, nonce)` over the
//! secret. The file is a small versioned JSON envelope; salt and nonce are public,
//! the ciphertext is authenticated, so flipping any byte fails `unseal`. Derived
//! key material is held in `Zeroizing` buffers and wiped on drop.
//!
//! Two sealings share that one AEAD code path (doc 14 §5) — they differ only in
//! where the 32-byte key comes from:
//!
//! - **Passphrase** (version 1, the portable fallback): `passphrase --Argon2id-->
//!   key`. No OS dependency.
//! - **Keychain** (version 2, phase 4): a random **data key** held by the platform
//!   secret store (see [`crate::keychain`]); the vault file names it by `key_id`
//!   and holds no KDF material at all. Losing the keychain entry orphans the vault
//!   — recovery is the 24-word phrase, exactly as before.

use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// On-disk format version of a passphrase-sealed vault.
const VAULT_VERSION: u32 = 1;
/// On-disk format version of a keychain-sealed vault (doc 14 §5, phase 4).
const VAULT_VERSION_KEYCHAIN: u32 = 2;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24; // XChaCha20-Poly1305 nonce
const KEY_LEN: usize = 32;
const KEY_ID_LEN: usize = 16; // random key-id bytes (hex on the wire)

// Argon2id defaults for an interactive desktop unlock (~19 MiB, 2 passes, 1 lane).
const DEFAULT_M_COST: u32 = 19_456; // KiB
const DEFAULT_T_COST: u32 = 2;
const DEFAULT_P_COST: u32 = 1;

/// Argon2id cost parameters. [`Default`] is a desktop-interactive setting; tests
/// and constrained hosts can dial it down via [`Vault::create_with`].
#[derive(Clone, Copy, Debug)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams {
            m_cost: DEFAULT_M_COST,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("vault io: {0}")]
    Io(String),
    #[error("vault format: {0}")]
    Format(String),
    #[error("unsupported vault version {0}")]
    Version(u32),
    #[error("unlock failed: wrong passphrase or corrupt vault")]
    Unlock,
    #[error("kdf: {0}")]
    Kdf(String),
    #[error("keychain: {0}")]
    Keychain(String),
}

/// How a vault's data key is held (doc 14 §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sealing {
    /// Argon2id from a passphrase — the portable, no-OS-dependency fallback.
    Passphrase,
    /// A random data key in the platform secret store, named by the vault's key id.
    Keychain,
}

#[derive(Serialize, Deserialize)]
struct KdfWire {
    algo: String, // "argon2id"
    salt: String, // hex
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    /// v2 only: "keychain". Absent in v1 (implicitly passphrase-sealed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sealing: Option<String>,
    /// v1 only: the Argon2id parameters. Absent in v2 (no KDF — random data key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kdf: Option<KdfWire>,
    /// v2 only: names the data key in the OS secret store (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
    /// The current identity index (doc 15 §1 A1): `3'/<id>'`; absent ⇒ 0.
    /// Plaintext by design — public info; tampering yields a key that matches
    /// nothing (a visible DoS, not an escalation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity_index: Option<u64>,
    cipher: String,     // "xchacha20poly1305"
    nonce: String,      // hex
    ciphertext: String, // hex (sealed secret + AEAD tag)
}

/// A passphrase-sealed vault, loaded from disk and ready to [`unseal`](Vault::unseal).
pub struct Vault {
    file: VaultFile,
}

impl Vault {
    /// Seal `secret` under `passphrase` with default KDF params and write a new
    /// vault file at `path` (mode `0600` on Unix).
    pub fn create(path: &Path, secret: &[u8], passphrase: &[u8]) -> Result<(), VaultError> {
        Self::create_with(path, secret, passphrase, KdfParams::default())
    }

    /// As [`create`](Vault::create) but with explicit KDF cost parameters.
    pub fn create_with(
        path: &Path,
        secret: &[u8],
        passphrase: &[u8],
        params: KdfParams,
    ) -> Result<(), VaultError> {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let key = derive_key(passphrase, &salt, params)?;
        let (nonce, ciphertext) = seal(&key, secret)?;

        let file = VaultFile {
            version: VAULT_VERSION,
            sealing: None,
            kdf: Some(KdfWire {
                algo: "argon2id".into(),
                salt: hex::encode(salt),
                m_cost: params.m_cost,
                t_cost: params.t_cost,
                p_cost: params.p_cost,
            }),
            key_id: None,
            identity_index: None,
            cipher: "xchacha20poly1305".into(),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(&ciphertext),
        };
        let json =
            serde_json::to_vec_pretty(&file).map_err(|e| VaultError::Format(e.to_string()))?;
        write_private(path, &json)
    }

    /// Seal `secret` under a fresh random data key held by `store` (doc 14 §5,
    /// phase 4) and write a version-2 vault file at `path` (mode `0600` on Unix).
    /// The vault file gets a random `key_id` naming the store entry; no KDF, no
    /// passphrase. If the store write fails, no vault file is written.
    pub fn create_keychain(
        path: &Path,
        secret: &[u8],
        store: &dyn crate::keychain::SecretStore,
    ) -> Result<(), VaultError> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        rand::thread_rng().fill_bytes(&mut key[..]);
        let mut key_id_bytes = [0u8; KEY_ID_LEN];
        rand::thread_rng().fill_bytes(&mut key_id_bytes);
        let key_id = hex::encode(key_id_bytes);

        // Store the data key first: a vault file naming a missing key is an orphan.
        store.set(&key_id, &key[..])?;
        let (nonce, ciphertext) = seal(&key, secret)?;

        let file = VaultFile {
            version: VAULT_VERSION_KEYCHAIN,
            sealing: Some("keychain".into()),
            kdf: None,
            key_id: Some(key_id),
            identity_index: None,
            cipher: "xchacha20poly1305".into(),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(&ciphertext),
        };
        let json =
            serde_json::to_vec_pretty(&file).map_err(|e| VaultError::Format(e.to_string()))?;
        write_private(path, &json)
    }

    /// Load (but do not unlock) a vault file — either sealing.
    pub fn open(path: &Path) -> Result<Vault, VaultError> {
        let bytes = std::fs::read(path).map_err(|e| VaultError::Io(e.to_string()))?;
        let file: VaultFile =
            serde_json::from_slice(&bytes).map_err(|e| VaultError::Format(e.to_string()))?;
        match file.version {
            VAULT_VERSION => {
                let kdf = file
                    .kdf
                    .as_ref()
                    .ok_or_else(|| VaultError::Format("v1 vault missing kdf".into()))?;
                if kdf.algo != "argon2id" {
                    return Err(VaultError::Format(format!("unknown kdf {}", kdf.algo)));
                }
            }
            VAULT_VERSION_KEYCHAIN => {
                if file.sealing.as_deref() != Some("keychain") {
                    return Err(VaultError::Format("v2 vault missing keychain sealing".into()));
                }
                if file.key_id.is_none() {
                    return Err(VaultError::Format("keychain vault missing key_id".into()));
                }
            }
            v => return Err(VaultError::Version(v)),
        }
        if file.cipher != "xchacha20poly1305" {
            return Err(VaultError::Format(format!("unknown cipher {}", file.cipher)));
        }
        Ok(Vault { file })
    }

    /// How this vault's data key is held — lets a caller pick the unlock path.
    pub fn sealing(&self) -> Sealing {
        if self.file.version == VAULT_VERSION_KEYCHAIN {
            Sealing::Keychain
        } else {
            Sealing::Passphrase
        }
    }

    /// The OS-store entry name of a keychain-sealed vault's data key.
    pub fn key_id(&self) -> Option<&str> {
        self.file.key_id.as_deref()
    }

    /// The current identity index (doc 15 §1): which `3'/<id>'` key is *the*
    /// identity. Bumped by an identity replacement; absent means 0.
    pub fn identity_index(&self) -> u64 {
        self.file.identity_index.unwrap_or(0)
    }

    /// Persist a new identity index (doc 15 §1 A1) — rewrites the envelope in
    /// place, leaving the sealed secret and every other field untouched.
    pub fn set_identity_index(path: &Path, index: u64) -> Result<(), VaultError> {
        let bytes = std::fs::read(path).map_err(|e| VaultError::Io(e.to_string()))?;
        let mut file: VaultFile =
            serde_json::from_slice(&bytes).map_err(|e| VaultError::Format(e.to_string()))?;
        file.identity_index = Some(index);
        let json =
            serde_json::to_vec_pretty(&file).map_err(|e| VaultError::Format(e.to_string()))?;
        write_private(path, &json)
    }

    /// Unlock a **passphrase-sealed** vault: re-derive the key from `passphrase`
    /// and return the secret in a zeroizing buffer (wiped on drop — "locking" is
    /// dropping it). Returns [`VaultError::Unlock`] on a wrong passphrase or any
    /// tampering (AEAD failure); a keychain-sealed vault is a `Format` error —
    /// use [`unseal_keychain`](Vault::unseal_keychain).
    pub fn unseal(&self, passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let kdf = self.file.kdf.as_ref().ok_or_else(|| {
            VaultError::Format("keychain-sealed vault: unlock via the OS keychain".into())
        })?;
        let salt = hex::decode(&kdf.salt).map_err(|_| VaultError::Format("salt hex".into()))?;
        let params = KdfParams {
            m_cost: kdf.m_cost,
            t_cost: kdf.t_cost,
            p_cost: kdf.p_cost,
        };
        let key = derive_key(passphrase, &salt, params)?;
        self.unseal_with_key(&key)
    }

    /// Unlock a **keychain-sealed** vault: fetch the data key named by `key_id`
    /// from `store` and decrypt. A missing entry is a `Keychain` error (the vault
    /// is orphaned — recover from the phrase); tampering is `Unlock` as usual.
    pub fn unseal_keychain(
        &self,
        store: &dyn crate::keychain::SecretStore,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let key_id = self.file.key_id.as_deref().ok_or_else(|| {
            VaultError::Format("passphrase-sealed vault: unlock with the passphrase".into())
        })?;
        let key = store.get(key_id)?;
        if key.len() != KEY_LEN {
            return Err(VaultError::Keychain("stored data key has wrong length".into()));
        }
        let mut k = Zeroizing::new([0u8; KEY_LEN]);
        k.copy_from_slice(&key);
        self.unseal_with_key(&k)
    }

    /// Shared decrypt path (doc 14 §5 "one code path"): both sealings converge on
    /// XChaCha20-Poly1305 with a 32-byte key.
    fn unseal_with_key(
        &self,
        key: &Zeroizing<[u8; KEY_LEN]>,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let nonce =
            hex::decode(&self.file.nonce).map_err(|_| VaultError::Format("nonce hex".into()))?;
        let ct = hex::decode(&self.file.ciphertext)
            .map_err(|_| VaultError::Format("ciphertext hex".into()))?;
        if nonce.len() != NONCE_LEN {
            return Err(VaultError::Format("bad nonce length".into()));
        }
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|_| VaultError::Kdf("bad key length".into()))?;
        let plaintext = cipher
            .decrypt(XNonce::from_slice(&nonce), ct.as_ref())
            .map_err(|_| VaultError::Unlock)?;
        Ok(Zeroizing::new(plaintext))
    }
}

/// Shared encrypt path: fresh random nonce, XChaCha20-Poly1305 under `key`.
fn seal(
    key: &Zeroizing<[u8; KEY_LEN]>,
    secret: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), VaultError> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| VaultError::Kdf("bad key length".into()))?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), secret)
        .map_err(|_| VaultError::Format("encrypt failed".into()))?;
    Ok((nonce, ciphertext))
}

/// `passphrase` + `salt` -> a 32-byte key via Argon2id, in a zeroizing buffer.
fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let p = Params::new(params.m_cost, params.t_cost, params.p_cost, None)
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(passphrase, salt, &mut key[..])
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    Ok(key)
}

/// Write `bytes` to `path`, truncating, with mode `0600` on Unix.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    use std::io::Write;
    let mut f = std::fs::File::create(path).map_err(|e| VaultError::Io(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| VaultError::Io(e.to_string()))?;
    }
    f.write_all(bytes).map_err(|e| VaultError::Io(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fast KDF for tests — the desktop default (~19 MiB) is needlessly slow here.
    fn fast() -> KdfParams {
        KdfParams { m_cost: 32, t_cost: 1, p_cost: 1 }
    }

    fn vault_path() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        (dir, path)
    }

    #[test]
    fn seal_unseal_round_trip() {
        let (_d, path) = vault_path();
        let secret = b"24-word seed phrase goes here";
        Vault::create_with(&path, secret, b"correct horse", fast()).unwrap();
        let v = Vault::open(&path).unwrap();
        let out = v.unseal(b"correct horse").unwrap();
        assert_eq!(&out[..], secret);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let (_d, path) = vault_path();
        Vault::create_with(&path, b"seed", b"right", fast()).unwrap();
        let v = Vault::open(&path).unwrap();
        assert!(matches!(v.unseal(b"wrong"), Err(VaultError::Unlock)));
    }

    #[test]
    fn ciphertext_tamper_fails() {
        let (_d, path) = vault_path();
        Vault::create_with(&path, b"seed-secret", b"pw", fast()).unwrap();
        // Flip one nibble of the stored ciphertext.
        let mut file: VaultFile =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let mut ct: Vec<u8> = hex::decode(&file.ciphertext).unwrap();
        ct[0] ^= 0x01;
        file.ciphertext = hex::encode(&ct);
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        let v = Vault::open(&path).unwrap();
        assert!(matches!(v.unseal(b"pw"), Err(VaultError::Unlock)));
    }

    #[test]
    fn nonce_tamper_fails() {
        let (_d, path) = vault_path();
        Vault::create_with(&path, b"seed-secret", b"pw", fast()).unwrap();
        let mut file: VaultFile =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let mut nonce: Vec<u8> = hex::decode(&file.nonce).unwrap();
        nonce[0] ^= 0x01;
        file.nonce = hex::encode(&nonce);
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        let v = Vault::open(&path).unwrap();
        assert!(matches!(v.unseal(b"pw"), Err(VaultError::Unlock)));
    }

    #[test]
    fn unsupported_version_rejected() {
        let (_d, path) = vault_path();
        Vault::create_with(&path, b"seed", b"pw", fast()).unwrap();
        let mut file: VaultFile =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        file.version = 99;
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert!(matches!(Vault::open(&path), Err(VaultError::Version(99))));
    }

    #[test]
    fn distinct_salts_and_nonces_across_vaults() {
        let (_d1, p1) = vault_path();
        let (_d2, p2) = vault_path();
        Vault::create_with(&p1, b"seed", b"pw", fast()).unwrap();
        Vault::create_with(&p2, b"seed", b"pw", fast()).unwrap();
        let a: VaultFile = serde_json::from_slice(&std::fs::read(&p1).unwrap()).unwrap();
        let b: VaultFile = serde_json::from_slice(&std::fs::read(&p2).unwrap()).unwrap();
        // Same secret + passphrase must still seal to different bytes (random salt+nonce).
        assert_ne!(a.kdf.as_ref().unwrap().salt, b.kdf.as_ref().unwrap().salt);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    // ---- keychain sealing (doc 14 §5, phase 4) --------------------------------

    use crate::keychain::{MemoryStore, SecretStore};

    #[test]
    fn keychain_seal_unseal_round_trip() {
        let (_d, path) = vault_path();
        let store = MemoryStore::new();
        let secret = b"24-word seed phrase goes here";
        Vault::create_keychain(&path, secret, &store).unwrap();
        let v = Vault::open(&path).unwrap();
        assert_eq!(v.sealing(), Sealing::Keychain);
        let out = v.unseal_keychain(&store).unwrap();
        assert_eq!(&out[..], secret);
    }

    #[test]
    fn keychain_vault_holds_no_kdf_material() {
        let (_d, path) = vault_path();
        let store = MemoryStore::new();
        Vault::create_keychain(&path, b"seed", &store).unwrap();
        let file: VaultFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(file.version, VAULT_VERSION_KEYCHAIN);
        assert!(file.kdf.is_none());
        assert_eq!(file.sealing.as_deref(), Some("keychain"));
        assert!(file.key_id.is_some());
    }

    #[test]
    fn keychain_missing_entry_is_orphaned_not_unlock() {
        let (_d, path) = vault_path();
        let store = MemoryStore::new();
        Vault::create_keychain(&path, b"seed", &store).unwrap();
        let v = Vault::open(&path).unwrap();
        store.delete(v.key_id().unwrap()).unwrap();
        // A lost data key is a Keychain error (recover from the phrase), not Unlock.
        assert!(matches!(v.unseal_keychain(&store), Err(VaultError::Keychain(_))));
    }

    #[test]
    fn keychain_ciphertext_tamper_fails() {
        let (_d, path) = vault_path();
        let store = MemoryStore::new();
        Vault::create_keychain(&path, b"seed-secret", &store).unwrap();
        let mut file: VaultFile =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let mut ct: Vec<u8> = hex::decode(&file.ciphertext).unwrap();
        ct[0] ^= 0x01;
        file.ciphertext = hex::encode(&ct);
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        let v = Vault::open(&path).unwrap();
        assert!(matches!(v.unseal_keychain(&store), Err(VaultError::Unlock)));
    }

    #[test]
    fn wrong_unlock_path_is_a_clear_error() {
        let (_d, p1) = vault_path();
        let (_d2, p2) = vault_path();
        let store = MemoryStore::new();
        Vault::create_keychain(&p1, b"seed", &store).unwrap();
        Vault::create_with(&p2, b"seed", b"pw", fast()).unwrap();
        // Passphrase on a keychain vault, and store on a passphrase vault: both
        // are Format errors telling the caller which unlock path to use.
        let kc = Vault::open(&p1).unwrap();
        assert!(matches!(kc.unseal(b"pw"), Err(VaultError::Format(_))));
        let pp = Vault::open(&p2).unwrap();
        assert_eq!(pp.sealing(), Sealing::Passphrase);
        assert!(matches!(pp.unseal_keychain(&store), Err(VaultError::Format(_))));
    }

    #[test]
    fn distinct_key_ids_across_keychain_vaults() {
        let (_d1, p1) = vault_path();
        let (_d2, p2) = vault_path();
        let store = MemoryStore::new();
        Vault::create_keychain(&p1, b"seed", &store).unwrap();
        Vault::create_keychain(&p2, b"seed", &store).unwrap();
        let a = Vault::open(&p1).unwrap();
        let b = Vault::open(&p2).unwrap();
        assert_ne!(a.key_id().unwrap(), b.key_id().unwrap());
    }

    #[test]
    fn identity_index_persists_without_touching_the_seal() {
        let (_d, path) = vault_path();
        Vault::create_with(&path, b"seed-secret", b"pw", fast()).unwrap();
        assert_eq!(Vault::open(&path).unwrap().identity_index(), 0);
        Vault::set_identity_index(&path, 3).unwrap();
        let v = Vault::open(&path).unwrap();
        assert_eq!(v.identity_index(), 3);
        // The sealed secret is untouched by the envelope rewrite.
        assert_eq!(&v.unseal(b"pw").unwrap()[..], b"seed-secret");
    }

    #[test]
    fn v2_without_sealing_field_rejected() {
        let (_d, path) = vault_path();
        let store = MemoryStore::new();
        Vault::create_keychain(&path, b"seed", &store).unwrap();
        let mut file: VaultFile =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        file.sealing = None;
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert!(matches!(Vault::open(&path), Err(VaultError::Format(_))));
    }

    #[cfg(unix)]
    #[test]
    fn vault_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, path) = vault_path();
        Vault::create_with(&path, b"seed", b"pw", fast()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
