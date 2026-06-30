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
}

/// The agent's reply.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AgentResponse {
    Pubkey { pubkey: String },
    Signature { sig: String },
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
