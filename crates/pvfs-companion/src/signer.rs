//! The signing core (doc 14 §1, §3).
//!
//! An [`UnlockedSigner`] holds the seed (reconstructed from the unsealed vault)
//! and signs a 32-byte digest with the **key the request type calls for**: the
//! **root** key for device certificates / genesis, the **identity** key for the
//! human's own tag grants/memberships and identity assertions. Per-machine device
//! keys are never held here — they sign everyday writes locally (doc 14 §1).
//!
//! The signer makes no policy decision; the caller consults [`crate::policy`]
//! first. It returns signatures only, never key material.

use pvfs_core::{crypto, identity, identity::Mnemonic};

#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("identity: {0}")]
    Identity(String),
    #[error("sign: {0}")]
    Sign(String),
}

/// The kind of thing being signed — selects the key and (via [`crate::policy`])
/// the approval tier (doc 14 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestType {
    /// `DeviceAuthorized` / `DeviceRevoked` / genesis — signed by the **root** key.
    RootDeviceCert,
    /// The human's own tag grant or membership — signed by the **identity** key.
    IdentityTag,
    /// An identity assertion / daemon auth challenge for auto-login — **identity** key.
    IdentityAssertion,
}

/// Which custodied key a request resolves to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRole {
    Root,
    Identity,
}

impl RequestType {
    pub fn key_role(self) -> KeyRole {
        match self {
            RequestType::RootDeviceCert => KeyRole::Root,
            RequestType::IdentityTag | RequestType::IdentityAssertion => KeyRole::Identity,
        }
    }

    /// Parse the wire string used in the socket protocols.
    pub fn parse(s: &str) -> Option<RequestType> {
        match s {
            "root_device_cert" => Some(RequestType::RootDeviceCert),
            "identity_tag" => Some(RequestType::IdentityTag),
            "identity_assertion" => Some(RequestType::IdentityAssertion),
            _ => None,
        }
    }
}

impl KeyRole {
    /// Parse the wire string (`"root"` / `"identity"`).
    pub fn parse(s: &str) -> Option<KeyRole> {
        match s {
            "root" => Some(KeyRole::Root),
            "identity" => Some(KeyRole::Identity),
            _ => None,
        }
    }
}

/// An unlocked signer: the seed is in memory (use only while the companion is
/// unlocked; dropping it locks). `identity_id` selects which identity (doc 14 §10).
pub struct UnlockedSigner {
    mnemonic: Mnemonic,
    identity_id: u64,
}

impl UnlockedSigner {
    /// Build from a recovery phrase (the unsealed vault secret), default identity 0.
    pub fn from_phrase(phrase: &str) -> Result<Self, SignerError> {
        let mnemonic =
            identity::parse_mnemonic(phrase).map_err(|e| SignerError::Identity(e.to_string()))?;
        Ok(UnlockedSigner {
            mnemonic,
            identity_id: 0,
        })
    }

    /// Select the identity index (doc 14 §10 multi-identity).
    pub fn with_identity(mut self, id: u64) -> Self {
        self.identity_id = id;
        self
    }

    /// The current identity index.
    pub fn identity_id(&self) -> u64 {
        self.identity_id
    }

    /// Derive the **next** identity (doc 15 §1 A1): same seed, index `id+1`.
    /// Returns `(next_signer, old_identity_pub, new_identity_pub)` — the caller
    /// decides when to swap (after dual-signing the handoff with both).
    pub fn rotate_identity(&self) -> Result<(UnlockedSigner, Vec<u8>, Vec<u8>), SignerError> {
        let old = self.pubkey(KeyRole::Identity)?;
        let next = UnlockedSigner {
            mnemonic: self.mnemonic.clone(),
            identity_id: self.identity_id + 1,
        };
        let new = next.pubkey(KeyRole::Identity)?;
        Ok((next, old, new))
    }

    /// The compressed public key for a role — what a forest authorizes / verifies.
    pub fn pubkey(&self, role: KeyRole) -> Result<Vec<u8>, SignerError> {
        let key = match role {
            KeyRole::Root => identity::root_key(&self.mnemonic, ""),
            KeyRole::Identity => identity::identity_key(&self.mnemonic, "", self.identity_id),
        }
        .map_err(|e| SignerError::Identity(e.to_string()))?;
        Ok(crypto::pubkey_bytes(&key))
    }

    /// Sign `digest` with the key the request type calls for. The caller must have
    /// already approved via [`crate::policy`].
    pub fn sign(&self, request: RequestType, digest: &[u8; 32]) -> Result<Vec<u8>, SignerError> {
        let key = match request.key_role() {
            KeyRole::Root => identity::root_key(&self.mnemonic, ""),
            KeyRole::Identity => identity::identity_key(&self.mnemonic, "", self.identity_id),
        }
        .map_err(|e| SignerError::Identity(e.to_string()))?;
        crypto::sign_digest(&key, digest).map_err(|e| SignerError::Sign(e.to_string()))
    }
}
