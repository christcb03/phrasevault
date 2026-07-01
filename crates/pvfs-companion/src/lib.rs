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
pub mod approve;
mod audit;
mod client;
pub mod keychain;
mod origins;
mod paths;
mod policy;
mod webagent;
mod proto;
mod session;
mod signer;
mod store;
mod tenant;
mod vault;

pub use agent::{serve, Agent, Unlocker};
pub use approve::{auto_prompter, auto_prompter_labeled, DenyPrompter, Prompter};
pub use audit::{AuditEntry, AuditLog};
pub use client::request;
#[cfg(feature = "os-keychain")]
pub use keychain::OsKeychain;
pub use origins::{OriginGrant, OriginRegistry, DEFAULT_CONNECT_TTL_SECS};
pub use webagent::WebAgent;
pub use keychain::{MemoryStore, SecretStore};
pub use paths::{default_socket_path, default_vault_path};
pub use policy::{ApprovalPolicy, Decision, Origin};
pub use proto::{AgentRequest, AgentResponse};
pub use session::{DeviceTrust, SessionError, Sessions};
pub use signer::{KeyRole, RequestType, SignerError, UnlockedSigner};
pub use store::{StoreError, VaultStore};
pub use tenant::{serve_tenant, tenant_request, TenantAgent, TenantRequest, TenantResponse};
pub use vault::{KdfParams, Sealing, Vault, VaultError};
