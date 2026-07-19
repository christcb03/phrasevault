//! Identity — spec §10. Generated BIP39 mnemonic → BIP32 hardened HD keys.
//!
//! Paths (all hardened; purpose-field style, see spec §10):
//!   identity root : m/43'/20566'/0'
//!   device keys   : m/43'/20566'/1'/n'
//!   encryption    : m/43'/20566'/2'/...   (RESERVED — secure module, P3)
//!   identity auth : m/43'/20566'/3'/<id>' (the human's stable tag authority, doc 14)
//!
//! 20566 = 0x5056 = ASCII "PV". The PVFS-specific path guarantees no key
//! collision with coin wallets even if a user reuses a phrase (they should
//! not — PVFS generates its own).

use std::io::Write;
use std::path::Path;

use bip39::Language;
pub use bip39::Mnemonic;
pub use k256::ecdsa::SigningKey;

use crate::crypto;
use crate::error::{PvfsError, Result};

pub const PVFS_PURPOSE: u32 = 43;
pub const PVFS_PATH_INDEX: u32 = 20566; // "PV"
const DEVICE_KEY_FILE: &str = "device.key";

fn identity_err<E: std::fmt::Display>(what: &str) -> impl Fn(E) -> PvfsError + '_ {
    move |e| PvfsError::Identity {
        detail: format!("{what}: {e}"),
    }
}

/// Generate a fresh 24-word mnemonic (256-bit entropy, OS CSPRNG).
pub fn generate_mnemonic() -> Result<Mnemonic> {
    Mnemonic::generate_in(Language::English, 24).map_err(identity_err("mnemonic generation"))
}

/// Parse a user-supplied mnemonic phrase.
pub fn parse_mnemonic(phrase: &str) -> Result<Mnemonic> {
    Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(identity_err("mnemonic parse"))
}

fn derive(mnemonic: &Mnemonic, bip39_passphrase: &str, path: &str) -> Result<SigningKey> {
    let seed = mnemonic.to_seed(bip39_passphrase);
    let parsed: bip32::DerivationPath = path.parse().map_err(identity_err("derivation path"))?;
    let xprv =
        bip32::XPrv::derive_from_path(seed, &parsed).map_err(identity_err("key derivation"))?;
    Ok(xprv.private_key().clone())
}

/// Identity root key — signs `ForestCreated` and device certificates only.
pub fn root_key(mnemonic: &Mnemonic, bip39_passphrase: &str) -> Result<SigningKey> {
    derive(
        mnemonic,
        bip39_passphrase,
        &format!("m/{PVFS_PURPOSE}'/{PVFS_PATH_INDEX}'/0'"),
    )
}

/// Fresh random device signing key (not seed-derived). Used when genesis is
/// root-signed by an external companion: the machine gets its own key and a
/// root-signed `DeviceAuthorized` cert, without exposing the recovery phrase.
pub fn generate_device_key() -> SigningKey {
    use rand::rngs::OsRng;
    SigningKey::random(&mut OsRng)
}

/// Device signing key `n` — the everyday author on one machine.
pub fn device_key(mnemonic: &Mnemonic, bip39_passphrase: &str, index: u64) -> Result<SigningKey> {
    if index >= 0x8000_0000 {
        return Err(PvfsError::BadInput {
            field: "device_index".into(),
            reason: "must be < 2^31 (hardened BIP32 child index)".into(),
        });
    }
    derive(
        mnemonic,
        bip39_passphrase,
        &format!("m/{PVFS_PURPOSE}'/{PVFS_PATH_INDEX}'/1'/{index}'"),
    )
}

/// Identity-authority key `id` (doc 10 §9.1, doc 14 §1) — the human's **stable,
/// cross-device** key behind their own tag grants/memberships and identity
/// assertions. A distinct hardened branch (`3'`) from per-machine device keys, so
/// the same phrase reproduces the same authority on every machine. `id` selects
/// among a person's identities (default `0`).
pub fn identity_key(mnemonic: &Mnemonic, bip39_passphrase: &str, id: u64) -> Result<SigningKey> {
    if id >= 0x8000_0000 {
        return Err(PvfsError::BadInput {
            field: "identity_id".into(),
            reason: "must be < 2^31 (hardened BIP32 child index)".into(),
        });
    }
    derive(
        mnemonic,
        bip39_passphrase,
        &format!("m/{PVFS_PURPOSE}'/{PVFS_PATH_INDEX}'/3'/{id}'"),
    )
}

/// Encryption key `id` (doc 12 §8.5) — the owner's decryption credential on the
/// reserved `2'` branch, custodied by the companion (used for ECDH unwrapping,
/// never for signing). `id` defaults to 0, mirroring the identity branch.
pub fn encryption_key(mnemonic: &Mnemonic, bip39_passphrase: &str, id: u64) -> Result<SigningKey> {
    if id >= 0x8000_0000 {
        return Err(PvfsError::BadInput {
            field: "encryption_id".into(),
            reason: "must be < 2^31 (hardened BIP32 child index)".into(),
        });
    }
    derive(
        mnemonic,
        bip39_passphrase,
        &format!("m/{PVFS_PURPOSE}'/{PVFS_PATH_INDEX}'/2'/{id}'"),
    )
}

/// The digest both keys sign in an identity **handoff assertion** (doc 15 §1
/// A4): "the human behind `old_pub` is now `new_pub`". Length-prefixed fields
/// under a domain tag, so the encoding is unambiguous.
pub fn handoff_digest(old_pub: &[u8], new_pub: &[u8], replaced_at_ms: u64) -> [u8; 32] {
    let mut buf = Vec::with_capacity(old_pub.len() + new_pub.len() + 16);
    buf.extend_from_slice(&(old_pub.len() as u32).to_le_bytes());
    buf.extend_from_slice(old_pub);
    buf.extend_from_slice(&(new_pub.len() as u32).to_le_bytes());
    buf.extend_from_slice(new_pub);
    buf.extend_from_slice(&replaced_at_ms.to_le_bytes());
    crypto::domain_digest("pvfs:identity-handoff:v1:", &buf)
}

/// Verify both signatures of a handoff assertion (doc 15 §1 A4). The assertion
/// is a *convenience, not an authority*: the receiving forest owner's own
/// root/admin signature is what actually changes their forest.
pub fn verify_handoff(
    old_pub: &[u8],
    new_pub: &[u8],
    replaced_at_ms: u64,
    sig_old: &[u8],
    sig_new: &[u8],
) -> crate::error::Result<()> {
    let digest = handoff_digest(old_pub, new_pub, replaced_at_ms);
    crypto::verify_digest(old_pub, &digest, sig_old)?;
    crypto::verify_digest(new_pub, &digest, sig_new)
}

/// The on-disk device-key cache (mode 0600). Cache, not source of truth —
/// the mnemonic regenerates it (spec §10).
pub struct DeviceKeyCache {
    pub signing_key: SigningKey,
    pub device_index: u64,
}

impl DeviceKeyCache {
    pub fn pubkey(&self) -> Vec<u8> {
        crypto::pubkey_bytes(&self.signing_key)
    }

    pub fn save(&self, data_dir: &Path) -> Result<()> {
        let path = data_dir.join(DEVICE_KEY_FILE);
        let body = format!(
            "{}\n{}\n",
            hex::encode(self.signing_key.to_bytes()),
            self.device_index
        );
        let mut f = std::fs::File::create(&path)
            .map_err(|e| PvfsError::io("create device.key", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| PvfsError::io("chmod device.key", e))?;
        }
        f.write_all(body.as_bytes())
            .map_err(|e| PvfsError::io("write device.key", e))?;
        Ok(())
    }

    pub fn load(data_dir: &Path) -> Result<DeviceKeyCache> {
        let path = data_dir.join(DEVICE_KEY_FILE);
        let body = std::fs::read_to_string(&path).map_err(|e| PvfsError::io("read device.key", e))?;
        let mut lines = body.lines();
        let key_hex = lines.next().ok_or_else(|| PvfsError::BadInput {
            field: "device.key".into(),
            reason: "missing key line".into(),
        })?;
        let index: u64 = lines
            .next()
            .unwrap_or("0")
            .trim()
            .parse()
            .map_err(|_| PvfsError::BadInput {
                field: "device.key".into(),
                reason: "bad device index".into(),
            })?;
        let raw = hex::decode(key_hex.trim()).map_err(|_| PvfsError::BadInput {
            field: "device.key".into(),
            reason: "bad key hex".into(),
        })?;
        let signing_key = SigningKey::from_slice(&raw).map_err(|_| PvfsError::Identity {
            detail: "cached device key invalid".into(),
        })?;
        Ok(DeviceKeyCache {
            signing_key,
            device_index: index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_mnemonic() -> Mnemonic {
        // deterministic test mnemonic from fixed entropy
        Mnemonic::from_entropy_in(Language::English, &[7u8; 32]).unwrap()
    }

    #[test]
    fn determinism_and_separation() {
        let m = fixed_mnemonic();
        let r1 = crypto::pubkey_bytes(&root_key(&m, "").unwrap());
        let r2 = crypto::pubkey_bytes(&root_key(&m, "").unwrap());
        assert_eq!(r1, r2, "same mnemonic must reproduce the same root");

        let d0 = crypto::pubkey_bytes(&device_key(&m, "", 0).unwrap());
        let d1 = crypto::pubkey_bytes(&device_key(&m, "", 1).unwrap());
        assert_ne!(d0, d1, "device keys must differ by index");
        assert_ne!(r1, d0, "root and device keys must differ");

        let other = Mnemonic::from_entropy_in(Language::English, &[9u8; 32]).unwrap();
        assert_ne!(
            r1,
            crypto::pubkey_bytes(&root_key(&other, "").unwrap()),
            "different mnemonic ⇒ different identity"
        );
        // 25th word changes everything
        assert_ne!(
            r1,
            crypto::pubkey_bytes(&root_key(&m, "extra").unwrap())
        );
    }

    #[test]
    fn cache_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let m = fixed_mnemonic();
        let cache = DeviceKeyCache {
            signing_key: device_key(&m, "", 0).unwrap(),
            device_index: 0,
        };
        cache.save(dir.path()).unwrap();
        let loaded = DeviceKeyCache::load(dir.path()).unwrap();
        assert_eq!(loaded.pubkey(), cache.pubkey());
        assert_eq!(loaded.device_index, 0);
    }
}
