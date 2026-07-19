//! Companion signer-socket protocol (doc 14 §3, §7).
//!
//! Length-prefixed JSON frames (reusing the daemon's `pvfs_proto::{read_msg,
//! write_msg}`) over an owner-only `AF_UNIX` socket. The socket's `0600` mode is
//! the authentication — only the owner's processes can reach it — so there is no
//! challenge handshake here (unlike the daemon, which serves other users). The
//! surface is a subset of the eventual PVFS+PVOS superset API (doc 14 §7).

use serde::{Deserialize, Serialize};

/// The agent protocol version (doc 16 §7 item 4). Bump on any breaking change
/// to the request/response surface; clients negotiate via
/// [`AgentRequest::ApiVersion`] before relying on newer ops.
///
/// v2: pairing (`Pair`/`ListPairings`/`RevokePairing`) + the browser-relay
/// envelope (PVOS M3.1).
pub const API_VERSION: u32 = 2;

/// Domain prefix for the relay envelope signature: the paired server signs
/// `domain_digest(RELAY_DOMAIN, payload_json_bytes)`.
pub const RELAY_DOMAIN: &str = "pvfs:relay:v1:";

/// The 6-digit verification code both screens display (M3.1 §4.3): derived
/// from the operation digest so the approving human can match the prompt to
/// the page that caused it.
pub fn verify_code(digest: &[u8; 32]) -> String {
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{n:06}")
}

/// The relayed request a paired server signs (transmitted as the exact JSON
/// string the signature covers — no canonicalization games).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayPayload {
    /// `"sign_in"` or `"user_action"`.
    pub kind: String,
    /// The paired server's pubkey (hex) — selects the pairing to verify with.
    pub server_pubkey: String,
    /// The 32-byte digest (hex) to sign.
    pub digest: String,
    /// Required for `user_action` (doc 16 §3); optional context for sign-in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<ApprovalContext>,
}

/// A pairing as reported over the socket (no secrets — it's all public data).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairingInfo {
    pub name: String,
    pub server_pubkey_hex: String,
    pub origins: Vec<String>,
    pub created_ms: u64,
}

/// The human-approval context a trusted broker binds to a digest (doc 16 §3.1).
/// `pvosd` composes it from the *same operation* it computed the digest from, so
/// the prompt cannot lie about what is being signed. The companion renders it
/// and records it in the audit log; it never re-derives the digest (§3.2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalContext {
    /// The authenticated app's id (the broker fills this — the app can't forge it).
    pub app_id: String,
    /// A verb from the controlled vocabulary (`share`, `delete`, `grant`, …).
    pub action: String,
    /// One human-readable line composed by the broker from the operation.
    pub summary: String,
    /// The affected node/scope, shown in the prompt when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// What will be signed, computed by the broker. When present it must equal
    /// the request's `digest` — a mismatch is refused as `bad_input`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_hex: Option<String>,
}

/// A request to the companion agent.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum AgentRequest {
    /// Return the agent protocol version ([`API_VERSION`]). Answered even while
    /// locked — negotiation must never require an unlock.
    ApiVersion,
    /// Return the public key for a role: `"root"` or `"identity"`.
    GetPubkey { role: String },
    /// Sign a 32-byte digest (hex). `request_type` selects the key and approval
    /// tier (`"root_device_cert"`, `"identity_tag"`, `"identity_assertion"`,
    /// `"user_action"`); `origin` is `"local"` (default) or `"web"`; `context`
    /// is the doc 16 §3 approval context (required rendering for `user_action`
    /// prompts, optional elsewhere).
    Sign {
        request_type: String,
        digest: String,
        #[serde(default)]
        origin: Option<String>,
        #[serde(default)]
        context: Option<ApprovalContext>,
    },
    /// Drop the seed from memory (doc 14 §4 lock). The agent keeps serving; a
    /// later request re-unlocks through the configured unlocker, or is refused.
    Lock,
    /// Replace the identity key (doc 15 §1): derive `3'/<id+1>'`, dual-sign the
    /// handoff assertion, swap the in-memory signer, persist the new index.
    /// Root-tier approval (prompt, or `--allow-root` for automation).
    RotateIdentity,
    /// Unwrap a secure-blob content key (doc 12 §8.5): the wrap's fields (hex);
    /// returns the recovered content key. Local, auto-while-unlocked tier — the
    /// encryption key never leaves the companion.
    SecureUnwrap {
        ephemeral_pubkey: String,
        nonce: String,
        wrapped_key: String,
    },
    /// Enroll a paired server (PVOS M3.1): human-prompted (name + key +
    /// origins rendered); replaces an existing pairing of the same name.
    /// Answers `Paired{identity_pubkey}` so the server can store the identity
    /// it will verify relayed answers against.
    Pair {
        name: String,
        server_pubkey: String,
        origins: Vec<String>,
    },
    ListPairings,
    RevokePairing { name: String },
}

/// The agent's reply.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AgentResponse {
    /// The reply to [`AgentRequest::ApiVersion`].
    ApiVersion { api_version: u32 },
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
    /// A recovered secure-blob content key (hex), from `SecureUnwrap`.
    ContentKey { content_key: String },
    /// Pairing accepted: the identity pubkey (hex) the server stores and will
    /// verify relayed answers against.
    Paired { identity_pubkey: String },
    Pairings { pairings: Vec<PairingInfo> },
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
