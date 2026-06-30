//! The companion key vault (doc 14 §5).
//!
//! A vault file seals a secret (the recovery seed) under a passphrase:
//! `passphrase --Argon2id--> key`, then `XChaCha20-Poly1305(key, nonce)` over the
//! secret. The file is a small versioned JSON envelope; salt and nonce are public,
//! the ciphertext is authenticated, so flipping any byte fails `unseal`. Derived
//! key material is held in `Zeroizing` buffers and wiped on drop.
//!
//! Phase 1 covers only the passphrase-sealed file (doc 14 §9 phase 1). The OS
//! keychain backend (phase 4) will seal the same vault key behind the platform
//! secret store; the file format carries a `version` for that evolution.

use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Current on-disk vault format version.
const VAULT_VERSION: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24; // XChaCha20-Poly1305 nonce
const KEY_LEN: usize = 32;

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
    kdf: KdfWire,
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

        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|_| VaultError::Kdf("bad key length".into()))?;
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), secret)
            .map_err(|_| VaultError::Format("encrypt failed".into()))?;

        let file = VaultFile {
            version: VAULT_VERSION,
            kdf: KdfWire {
                algo: "argon2id".into(),
                salt: hex::encode(salt),
                m_cost: params.m_cost,
                t_cost: params.t_cost,
                p_cost: params.p_cost,
            },
            cipher: "xchacha20poly1305".into(),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(&ciphertext),
        };
        let json =
            serde_json::to_vec_pretty(&file).map_err(|e| VaultError::Format(e.to_string()))?;
        write_private(path, &json)
    }

    /// Load (but do not unlock) a vault file.
    pub fn open(path: &Path) -> Result<Vault, VaultError> {
        let bytes = std::fs::read(path).map_err(|e| VaultError::Io(e.to_string()))?;
        let file: VaultFile =
            serde_json::from_slice(&bytes).map_err(|e| VaultError::Format(e.to_string()))?;
        if file.version != VAULT_VERSION {
            return Err(VaultError::Version(file.version));
        }
        if file.kdf.algo != "argon2id" {
            return Err(VaultError::Format(format!("unknown kdf {}", file.kdf.algo)));
        }
        if file.cipher != "xchacha20poly1305" {
            return Err(VaultError::Format(format!("unknown cipher {}", file.cipher)));
        }
        Ok(Vault { file })
    }

    /// Unlock the vault: re-derive the key from `passphrase` and return the secret
    /// in a zeroizing buffer (wiped on drop — "locking" is dropping it). Returns
    /// [`VaultError::Unlock`] on a wrong passphrase or any tampering (AEAD failure).
    pub fn unseal(&self, passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let salt = hex::decode(&self.file.kdf.salt).map_err(|_| VaultError::Format("salt hex".into()))?;
        let nonce =
            hex::decode(&self.file.nonce).map_err(|_| VaultError::Format("nonce hex".into()))?;
        let ct = hex::decode(&self.file.ciphertext)
            .map_err(|_| VaultError::Format("ciphertext hex".into()))?;
        if nonce.len() != NONCE_LEN {
            return Err(VaultError::Format("bad nonce length".into()));
        }
        let params = KdfParams {
            m_cost: self.file.kdf.m_cost,
            t_cost: self.file.kdf.t_cost,
            p_cost: self.file.kdf.p_cost,
        };
        let key = derive_key(passphrase, &salt, params)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|_| VaultError::Kdf("bad key length".into()))?;
        let plaintext = cipher
            .decrypt(XNonce::from_slice(&nonce), ct.as_ref())
            .map_err(|_| VaultError::Unlock)?;
        Ok(Zeroizing::new(plaintext))
    }
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
        assert_ne!(a.kdf.salt, b.kdf.salt);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
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
