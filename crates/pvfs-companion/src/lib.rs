//! PVFS companion (doc 14): the local key vault and signing agent.
//!
//! **The vault.** The recovery seed is sealed at rest with an AEAD
//! (XChaCha20-Poly1305) and only decrypted into **zeroizing** memory while the
//! companion is unlocked. The data key comes from either a passphrase (Argon2id,
//! the portable fallback) or the **OS keychain** (doc 14 §5, phase 4 — macOS
//! Keychain / Secret Service / Credential Manager, behind the `os-keychain`
//! feature). Tampering with any field fails the AEAD on unseal. Later phases
//! (doc 14 §9) add the approval UI and the loopback identity agent.

mod agent;
mod client;
pub mod keychain;
mod policy;
mod proto;
mod session;
mod signer;
mod store;
mod tenant;
mod vault;

pub use agent::{serve, Agent};
pub use client::request;
#[cfg(feature = "os-keychain")]
pub use keychain::OsKeychain;
pub use keychain::{MemoryStore, SecretStore};
pub use policy::{ApprovalPolicy, Decision, Origin};
pub use proto::{AgentRequest, AgentResponse};
pub use session::{DeviceTrust, SessionError, Sessions};
pub use signer::{KeyRole, RequestType, SignerError, UnlockedSigner};
pub use store::{StoreError, VaultStore};
pub use tenant::{serve_tenant, tenant_request, TenantAgent, TenantRequest, TenantResponse};
pub use vault::{KdfParams, Sealing, Vault, VaultError};
