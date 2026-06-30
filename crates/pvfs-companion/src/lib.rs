//! PVFS companion (doc 14): the local key vault and signing agent.
//!
//! **Phase 1 — the vault.** The recovery seed is sealed at rest under a key
//! derived from a passphrase (Argon2id) with an AEAD (XChaCha20-Poly1305), and
//! only decrypted into **zeroizing** memory while the companion is unlocked.
//! Tampering with any field fails the AEAD on unseal. Later phases (doc 14 §9)
//! add the OS-keychain sealing backend, the Unix-socket signer + approval policy,
//! and the loopback identity agent.

mod vault;

pub use vault::{KdfParams, Vault, VaultError};
