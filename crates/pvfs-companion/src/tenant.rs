//! Multi-tenant signer socket (doc 14 §13) — the app-facing surface over
//! [`Sessions`]. Each request names a user and carries either their unlock secret
//! (public-device / per-action) or a session token (trusted-device). Root request
//! types can only be signed with a fresh secret, never a token (§13.3).
//!
//! Transport is the same length-prefixed JSON as the local agent
//! (`pvfs_proto::{read_msg, write_msg}`) over an owner-only `AF_UNIX` socket — here
//! the "owner" is the app's service account, and the app authenticates end users
//! before it ever calls the companion.

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use pvfs_proto::{read_msg, write_msg};
use serde::{Deserialize, Serialize};

use crate::proto::{ApprovalContext, API_VERSION};
use crate::session::{SessionError, Sessions};
use crate::signer::{KeyRole, RequestType};

/// A request to the multi-tenant custody agent.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum TenantRequest {
    /// The agent protocol version (doc 16 §7 item 4); needs no secret.
    ApiVersion,
    /// Public key for a user's `role` (`"root"`/`"identity"`); needs the secret.
    GetPubkey {
        user_id: String,
        passphrase: String,
        role: String,
    },
    /// Trusted-device: unlock and cache the key for `ttl_secs` (capped); returns a token.
    OpenSession {
        user_id: String,
        passphrase: String,
        ttl_secs: u64,
    },
    /// Public-device / per-action: unlock, sign, drop. `context` is the doc 16
    /// §3 approval context — checked against `digest` and carried so the
    /// per-user prompt (PVOS D18) has something meaningful to render.
    SignOnce {
        user_id: String,
        passphrase: String,
        request_type: String,
        digest: String,
        #[serde(default)]
        context: Option<ApprovalContext>,
    },
    /// Trusted-device: sign with a cached session (never a root request type).
    SignWithSession {
        token: String,
        request_type: String,
        digest: String,
        #[serde(default)]
        context: Option<ApprovalContext>,
    },
    /// End a session (logout), wiping the cached key.
    CloseSession { token: String },
}

/// The agent's reply.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TenantResponse {
    ApiVersion { api_version: u32 },
    Session { token: String, ttl_secs: u64 },
    Signature { sig: String },
    Pubkey { pubkey: String },
    Ok,
    Error { code: String, message: String },
}

impl TenantResponse {
    fn bad(message: &str) -> TenantResponse {
        TenantResponse::Error {
            code: "bad_input".into(),
            message: message.into(),
        }
    }
    fn from_err(e: SessionError) -> TenantResponse {
        let code = match &e {
            SessionError::NeedsReauth => "reauth_required",
            SessionError::NoSession => "no_session",
            _ => "error",
        };
        TenantResponse::Error {
            code: code.into(),
            message: e.to_string(),
        }
    }
}

/// Per-user custody served to an app. `max_ttl` caps how long a trusted session
/// may cache an unlocked key.
pub struct TenantAgent {
    sessions: Sessions,
    max_ttl: Duration,
}

impl TenantAgent {
    pub fn new(sessions: Sessions, max_ttl: Duration) -> TenantAgent {
        TenantAgent { sessions, max_ttl }
    }

    pub fn handle(&self, req: TenantRequest) -> TenantResponse {
        match req {
            TenantRequest::ApiVersion => TenantResponse::ApiVersion {
                api_version: API_VERSION,
            },
            TenantRequest::GetPubkey {
                user_id,
                passphrase,
                role,
            } => {
                let Some(role) = KeyRole::parse(&role) else {
                    return TenantResponse::bad("unknown role");
                };
                match self.sessions.pubkey_once(&user_id, passphrase.as_bytes(), role) {
                    Ok(pk) => TenantResponse::Pubkey {
                        pubkey: hex::encode(pk),
                    },
                    Err(e) => TenantResponse::from_err(e),
                }
            }
            TenantRequest::OpenSession {
                user_id,
                passphrase,
                ttl_secs,
            } => {
                let ttl = Duration::from_secs(ttl_secs).min(self.max_ttl);
                match self
                    .sessions
                    .open_session(&user_id, passphrase.as_bytes(), ttl)
                {
                    Ok(token) => TenantResponse::Session {
                        token,
                        ttl_secs: ttl.as_secs(),
                    },
                    Err(e) => TenantResponse::from_err(e),
                }
            }
            TenantRequest::SignOnce {
                user_id,
                passphrase,
                request_type,
                digest,
                context,
            } => {
                let (Some(rt), Some(d)) = (RequestType::parse(&request_type), parse_digest(&digest))
                else {
                    return TenantResponse::bad("unknown request_type or bad digest");
                };
                if context_digest_mismatch(context.as_ref(), &digest) {
                    return TenantResponse::bad("context digest_hex does not match the digest");
                }
                match self
                    .sessions
                    .sign_once(&user_id, passphrase.as_bytes(), rt, &d)
                {
                    Ok(sig) => TenantResponse::Signature {
                        sig: hex::encode(sig),
                    },
                    Err(e) => TenantResponse::from_err(e),
                }
            }
            TenantRequest::SignWithSession {
                token,
                request_type,
                digest,
                context,
            } => {
                let (Some(rt), Some(d)) = (RequestType::parse(&request_type), parse_digest(&digest))
                else {
                    return TenantResponse::bad("unknown request_type or bad digest");
                };
                if context_digest_mismatch(context.as_ref(), &digest) {
                    return TenantResponse::bad("context digest_hex does not match the digest");
                }
                match self.sessions.sign_with_session(&token, rt, &d) {
                    Ok(sig) => TenantResponse::Signature {
                        sig: hex::encode(sig),
                    },
                    Err(e) => TenantResponse::from_err(e),
                }
            }
            TenantRequest::CloseSession { token } => {
                self.sessions.close_session(&token);
                TenantResponse::Ok
            }
        }
    }
}

/// Serve the multi-tenant custody protocol until the listener closes.
pub fn serve_tenant(listener: UnixListener, agent: Arc<TenantAgent>) -> io::Result<()> {
    for stream in listener.incoming() {
        let stream = stream?;
        let a = Arc::clone(&agent);
        std::thread::spawn(move || {
            let _ = serve_connection(&a, stream);
        });
    }
    Ok(())
}

fn serve_connection(agent: &TenantAgent, mut stream: UnixStream) -> io::Result<()> {
    while let Some(req) = read_msg::<_, TenantRequest>(&mut stream)? {
        let resp = agent.handle(req);
        write_msg(&mut stream, &resp)?;
    }
    Ok(())
}

fn parse_digest(hexs: &str) -> Option<[u8; 32]> {
    hex::decode(hexs).ok()?.try_into().ok()
}

/// True when a context names a digest that is NOT the one being signed —
/// refused as `bad_input` (same rule as the local agent, doc 16 §3.1).
fn context_digest_mismatch(context: Option<&ApprovalContext>, digest: &str) -> bool {
    context
        .and_then(|c| c.digest_hex.as_deref())
        .is_some_and(|d| !d.eq_ignore_ascii_case(digest))
}

/// Client: send one request to a multi-tenant custody agent and read its reply.
pub fn tenant_request(socket: &Path, req: &TenantRequest) -> io::Result<TenantResponse> {
    let mut stream = UnixStream::connect(socket)?;
    write_msg(&mut stream, req)?;
    read_msg::<_, TenantResponse>(&mut stream)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "companion closed the connection"))
}
