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

/// PVOS D245 — the config dir, made if missing (`0700`), and narrowed to its
/// owner if something opened it to group or others ([`tighten`]). It holds
/// the client identity and the instance pins, which only this user may read
/// or replace.
pub fn ensure_config_dir() -> Result<std::path::PathBuf> {
    let dir = config_dir()?;
    ensure_private_dir(&dir)?;
    Ok(dir)
}

fn ensure_private_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent).map_err(|e| PvfsError::io("create config dir", e))?;
        }
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        match b.create(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(PvfsError::io("create config dir", e)),
        }
    }
    tighten(dir, 0o700);
    Ok(())
}

/// PVOS D245 — if `path` is open to group or others, set it to `mode` (the
/// owner's bits only). Logged once a minute per path at warning, as a
/// security event: something widened a secret (on mediabox and feederbox a
/// recursive chmod had made every file under `~/.config` 0775). A chmod that
/// fails is logged and the caller goes on — refusing would stop the box.
pub fn tighten(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let Ok(meta) = std::fs::metadata(path) else { return };
        let old = meta.permissions().mode() & 0o7777;
        if old & 0o077 == 0 {
            return;
        }
        let key = path.display().to_string();
        match std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
            Ok(()) => {
                if let Some(n) = pvfs_log::limit("pvfs.config.mode_tightened", &key) {
                    pvfs_log::pv_warn!(security "pvfs.config.mode_tightened",
                        path = pvfs_log::content(&key), old_mode = format!("{old:o}"),
                        mode = format!("{mode:o}"), suppressed = n, error_kind = "auth:secret_mode";
                        "{key} was open to other users (mode {old:o}) — set to {mode:o}");
                }
            }
            Err(e) => {
                if let Some(n) = pvfs_log::limit("pvfs.config.mode_open", &key) {
                    pvfs_log::pv_warn!(security "pvfs.config.mode_open",
                        path = pvfs_log::content(&key), old_mode = format!("{old:o}"),
                        error = pvfs_log::content(&e), suppressed = n, error_kind = "auth:secret_mode";
                        "{key} is open to other users (mode {old:o}) and could not be narrowed: {e}");
                }
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

/// The per-user pvfs config dir: `$XDG_CONFIG_HOME/pvfs`, else `~/.config/pvfs`.
pub fn config_dir() -> Result<std::path::PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config")))
        .ok_or_else(|| PvfsError::Identity {
            detail: "set XDG_CONFIG_HOME or HOME".into(),
        })?;
    Ok(base.join("pvfs"))
}

/// Load (or create on first use, mode 0600) this machine's **client identity**
/// phrase (`<config>/identity.phrase`, doc 07 §2) — the principal every
/// network connection authenticates as. Forest device keys never dial
/// (doc 18 §4); this is the key that does. Moved here from the CLI so the
/// daemon's background jobs (P5) share one identity with the CLI.
///
/// D163: creation is first-writer-wins. Two callers that find no file (the
/// CLI beside a daemon job on a box's first start; two tests of one binary)
/// each write a whole phrase to a private file and link it into place. The
/// link fails for whoever came second, who then reads the first's. Nobody
/// reads a phrase mid-write, and nobody keeps a phrase the file does not
/// hold. Before D163 `File::create` truncated whichever phrase was there and
/// the loser's write could land on top of the winner's — a 25-word file, and
/// a dial as a stranger (GitHub CI, `serve_jobs`, 2026-09-16).
pub fn client_identity_mnemonic() -> Result<Mnemonic> {
    client_identity_mnemonic_in(&config_dir()?)
}

/// [`client_identity_mnemonic`] in `dir` (tests name their own). PVOS D245:
/// the dir is kept `0700` and the phrase `0600` on every read.
pub fn client_identity_mnemonic_in(dir: &Path) -> Result<Mnemonic> {
    let path = dir.join("identity.phrase");
    // The loop runs again only when another writer landed first, and then
    // the read succeeds; the bound is for a file that keeps disappearing.
    for _ in 0..8 {
        match std::fs::read_to_string(&path) {
            Ok(phrase) => {
                tighten(dir, 0o700);
                tighten(&path, 0o600);
                return parse_mnemonic(phrase.trim());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(PvfsError::io("read identity", e)),
        }
        ensure_private_dir(dir)?;
        let mn = generate_mnemonic()?;
        // pid + a process-wide counter: unique across processes and across
        // threads of one. A timestamp was not — sixteen callers released
        // together on GitHub's runner drew the same nanosecond, and the
        // second `create_new` failed "File exists" (2026-09-16, 10:11 PM EDT).
        static NTH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let mine = dir.join(format!(
            ".identity.phrase.{}.{}",
            std::process::id(),
            NTH.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&mine).map_err(|e| PvfsError::io("create identity", e))?;
        let written = f
            .write_all(format!("{mn}\n").as_bytes())
            .and_then(|()| f.sync_all());
        drop(f);
        let placed = written.and_then(|()| std::fs::hard_link(&mine, &path));
        let _ = std::fs::remove_file(&mine);
        match placed {
            Ok(()) => return Ok(mn),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(PvfsError::io("write identity", e)),
        }
    }
    Err(PvfsError::Identity {
        detail: format!("{} keeps disappearing while it is made", path.display()),
    })
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

    /// A throwaway key for engines that never author events — a replica has
    /// no device identity in the forest it mirrors (F2). Never saved.
    pub fn ephemeral() -> Result<DeviceKeyCache> {
        let mn = generate_mnemonic()?;
        Ok(DeviceKeyCache {
            signing_key: device_key(&mn, "", 0)?,
            device_index: 0,
        })
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

    /// PVOS D245 — a widened config dir and identity are narrowed on the
    /// next read, said once each; a second read says nothing; a fresh
    /// identity is made in a 0700 dir.
    #[cfg(unix)]
    #[test]
    fn the_identity_and_its_dir_are_kept_for_the_owner() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let tmp = tempfile::tempdir().unwrap();

        // fresh: made 0700 / 0600, nothing logged
        let fresh = tmp.path().join("fresh").join("pvfs");
        let recs = pvfs_log::capture(|| {
            client_identity_mnemonic_in(&fresh).unwrap();
        });
        assert_eq!(mode(&fresh), 0o700);
        assert_eq!(mode(&fresh.join("identity.phrase")), 0o600);
        assert!(recs.is_empty(), "{recs:?}");

        // widened (the mediabox shape): narrowed, one record per path
        let dir = tmp.path().join("wide").join("pvfs");
        let first = client_identity_mnemonic_in(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o775)).unwrap();
        let phrase = dir.join("identity.phrase");
        std::fs::set_permissions(&phrase, std::fs::Permissions::from_mode(0o775)).unwrap();
        let recs = pvfs_log::capture(|| {
            assert_eq!(client_identity_mnemonic_in(&dir).unwrap(), first, "the same identity, read");
        });
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&phrase), 0o600);
        let tightened: Vec<_> = recs.iter().filter(|r| r.event == "pvfs.config.mode_tightened").collect();
        assert_eq!(tightened.len(), 2, "{recs:?}");
        assert!(tightened.iter().all(|r| r.severity == pvfs_log::Severity::Warning));
        assert!(tightened.iter().any(|r| r.line().contains("775")), "the old mode is named");

        // a second read: already private, nothing said
        let recs = pvfs_log::capture(|| {
            client_identity_mnemonic_in(&dir).unwrap();
        });
        assert!(recs.is_empty(), "{recs:?}");
    }

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
