//! PVFS companion (doc 14): the local key vault and signing agent.
//!
//! **Phase 1 — the vault.** The recovery seed is sealed at rest under a key
//! derived from a passphrase (Argon2id) with an AEAD (XChaCha20-Poly1305), and
//! only decrypted into **zeroizing** memory while the companion is unlocked.
//! Tampering with any field fails the AEAD on unseal. Later phases (doc 14 §9)
//! add the OS-keychain sealing backend, the Unix-socket signer + approval policy,
//! and the loopback identity agent.

mod agent;
mod client;
mod policy;
mod proto;
mod signer;
mod vault;

pub use agent::{serve, Agent};
pub use client::request;
pub use policy::{ApprovalPolicy, Decision, Origin};
pub use proto::{AgentRequest, AgentResponse};
pub use signer::{KeyRole, RequestType, SignerError, UnlockedSigner};
pub use vault::{KdfParams, Vault, VaultError};
