//! Companion signer-socket protocol (doc 14 §3, §7).
//!
//! Length-prefixed JSON frames (reusing the daemon's `pvfs_proto::{read_msg,
//! write_msg}`) over an owner-only `AF_UNIX` socket. The socket's `0600` mode is
//! the authentication — only the owner's processes can reach it — so there is no
//! challenge handshake here (unlike the daemon, which serves other users). The
//! surface is a subset of the eventual PVFS+PVOS superset API (doc 14 §7).

use serde::{Deserialize, Serialize};

/// A request to the companion agent.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum AgentRequest {
    /// Return the public key for a role: `"root"` or `"identity"`.
    GetPubkey { role: String },
    /// Sign a 32-byte digest (hex). `request_type` selects the key and approval
    /// tier (`"root_device_cert"`, `"identity_tag"`, `"identity_assertion"`);
    /// `origin` is `"local"` (default) or `"web"`.
    Sign {
        request_type: String,
        digest: String,
        #[serde(default)]
        origin: Option<String>,
    },
    /// Drop the seed from memory (doc 14 §4 lock). The agent keeps serving; a
    /// later request re-unlocks through the configured unlocker, or is refused.
    Lock,
    /// Replace the identity key (doc 15 §1): derive `3'/<id+1>'`, dual-sign the
    /// handoff assertion, swap the in-memory signer, persist the new index.
    /// Root-tier approval (prompt, or `--allow-root` for automation).
    RotateIdentity,
}

/// The agent's reply.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AgentResponse {
    Pubkey { pubkey: String },
    Signature { sig: String },
    /// The result of a [`AgentRequest::RotateIdentity`]: the swap pair plus the
    /// dual-signed handoff assertion (doc 15 §1 A4), all hex.
    IdentityRotated {
        old_pubkey: String,
        new_pubkey: String,
        replaced_at_ms: u64,
        sig_old: String,
        sig_new: String,
    },
    Ok,
    Error { code: String, message: String },
}

impl AgentResponse {
    pub(crate) fn error(code: &str, message: impl Into<String>) -> AgentResponse {
        AgentResponse::Error {
            code: code.into(),
            message: message.into(),
        }
    }
}
