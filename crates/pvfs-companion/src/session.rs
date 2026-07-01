//! On-demand unlock + session manager (doc 14 §13.3) — the server-side custody
//! runtime over a [`VaultStore`].
//!
//! Two paths, matching the per-device "trusted vs public" choice the app makes at
//! login:
//! - **Public device** → [`Sessions::sign_once`]: unlock from the user's secret,
//!   sign, drop the key. Nothing is cached; each action re-supplies the secret.
//! - **Trusted device** → [`Sessions::open_session`] then [`Sessions::sign_with_session`]:
//!   unlock once and cache the key for a TTL, so everyday signing is friction-free.
//!
//! **Root operations always re-authenticate** (doc 14 §13.3 composition with §4):
//! a `RootDeviceCert` (admit/revoke a device) can never ride a remembered session —
//! it must go through `sign_once` with a fresh secret, mirroring the local
//! companion's per-action approval prompt.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::RngCore;

use crate::signer::{KeyRole, RequestType, SignerError, UnlockedSigner};
use crate::store::{StoreError, VaultStore};

/// The per-device trust the app selected at login (doc 14 §13.3). It governs which
/// signing path the app uses, not anything inside a single request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceTrust {
    /// Cache the unlocked key for a session TTL (no re-prompt per action).
    Trusted,
    /// Never cache — re-supply the secret for each action.
    Public,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Signer(#[from] SignerError),
    #[error("no such session (expired or unknown)")]
    NoSession,
    #[error("re-authentication required (root operations cannot use a remembered session)")]
    NeedsReauth,
}

struct Live {
    signer: UnlockedSigner,
    expires_at: Instant,
}

/// Server-side custody: per-user vaults plus cached unlocked sessions.
pub struct Sessions {
    store: VaultStore,
    live: Mutex<HashMap<String, Live>>,
}

impl Sessions {
    pub fn new(store: VaultStore) -> Sessions {
        Sessions {
            store,
            live: Mutex::new(HashMap::new()),
        }
    }

    pub fn store(&self) -> &VaultStore {
        &self.store
    }

    /// Public-device path: unlock `user_id`, sign, and drop the key — no caching.
    pub fn sign_once(
        &self,
        user_id: &str,
        passphrase: &[u8],
        request: RequestType,
        digest: &[u8; 32],
    ) -> Result<Vec<u8>, SessionError> {
        let signer = self.unlock(user_id, passphrase)?;
        Ok(signer.sign(request, digest)?)
    }

    /// Trusted-device path: unlock and cache for `ttl`; returns a session token.
    pub fn open_session(
        &self,
        user_id: &str,
        passphrase: &[u8],
        ttl: Duration,
    ) -> Result<String, SessionError> {
        let signer = self.unlock(user_id, passphrase)?;
        let token = random_token();
        self.live.lock().unwrap().insert(
            token.clone(),
            Live {
                signer,
                expires_at: Instant::now() + ttl,
            },
        );
        Ok(token)
    }

    /// Sign with a cached session. **Root request types always fail with
    /// [`SessionError::NeedsReauth`]** — they must use [`sign_once`](Sessions::sign_once)
    /// with a fresh secret (doc 14 §13.3).
    pub fn sign_with_session(
        &self,
        token: &str,
        request: RequestType,
        digest: &[u8; 32],
    ) -> Result<Vec<u8>, SessionError> {
        if request.key_role() == KeyRole::Root {
            return Err(SessionError::NeedsReauth);
        }
        let mut live = self.live.lock().unwrap();
        let session = live.get(token).ok_or(SessionError::NoSession)?;
        if Instant::now() >= session.expires_at {
            live.remove(token);
            return Err(SessionError::NoSession);
        }
        Ok(session.signer.sign(request, digest)?)
    }

    /// Explicitly end a session (e.g. logout), wiping the cached key.
    pub fn close_session(&self, token: &str) {
        self.live.lock().unwrap().remove(token);
    }

    /// Drop expired sessions (call periodically). Returns how many were removed.
    pub fn sweep_expired(&self) -> usize {
        let now = Instant::now();
        let mut live = self.live.lock().unwrap();
        let before = live.len();
        live.retain(|_, s| s.expires_at > now);
        before - live.len()
    }

    fn unlock(&self, user_id: &str, passphrase: &[u8]) -> Result<UnlockedSigner, SessionError> {
        let secret = self.store.unseal(user_id, passphrase)?;
        let phrase = std::str::from_utf8(&secret)
            .map_err(|_| SignerError::Identity("vault secret is not a valid phrase".into()))?;
        Ok(UnlockedSigner::from_phrase(phrase)?)
    }
}

fn random_token() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::KdfParams;
    use pvfs_core::{crypto, identity};

    fn fast() -> KdfParams {
        KdfParams {
            m_cost: 32,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn store_with_user(user: &str) -> (tempfile::TempDir, Sessions, Vec<u8>) {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::open(dir.path()).unwrap();
        let mn = identity::generate_mnemonic().unwrap();
        let id_pub = crypto::pubkey_bytes(&identity::identity_key(&mn, "", 0).unwrap());
        store
            .create_with(user, mn.to_string().as_bytes(), b"pw", fast())
            .unwrap();
        (dir, Sessions::new(store), id_pub)
    }

    #[test]
    fn public_sign_once_identity_verifies() {
        let (_d, s, id_pub) = store_with_user("u");
        let digest = [3u8; 32];
        let sig = s
            .sign_once("u", b"pw", RequestType::IdentityTag, &digest)
            .unwrap();
        crypto::verify_digest(&id_pub, &digest, &sig).unwrap();
        // wrong passphrase fails to unlock
        assert!(s.sign_once("u", b"nope", RequestType::IdentityTag, &digest).is_err());
    }

    #[test]
    fn trusted_session_signs_until_expiry() {
        let (_d, s, _id) = store_with_user("u");
        let digest = [4u8; 32];
        let token = s
            .open_session("u", b"pw", Duration::from_secs(30))
            .unwrap();
        assert!(s.sign_with_session(&token, RequestType::IdentityTag, &digest).is_ok());

        // an expired session is rejected
        let short = s.open_session("u", b"pw", Duration::from_millis(1)).unwrap();
        std::thread::sleep(Duration::from_millis(15));
        assert!(matches!(
            s.sign_with_session(&short, RequestType::IdentityTag, &digest),
            Err(SessionError::NoSession)
        ));

        // closing a session wipes it
        s.close_session(&token);
        assert!(matches!(
            s.sign_with_session(&token, RequestType::IdentityTag, &digest),
            Err(SessionError::NoSession)
        ));
    }

    #[test]
    fn root_ops_always_reauthenticate() {
        let (_d, s, _id) = store_with_user("u");
        let digest = [5u8; 32];
        let token = s.open_session("u", b"pw", Duration::from_secs(30)).unwrap();
        // a remembered session may NOT sign a root device cert
        assert!(matches!(
            s.sign_with_session(&token, RequestType::RootDeviceCert, &digest),
            Err(SessionError::NeedsReauth)
        ));
        // but a fresh unlock (per-action) can
        assert!(s
            .sign_once("u", b"pw", RequestType::RootDeviceCert, &digest)
            .is_ok());
    }
}
