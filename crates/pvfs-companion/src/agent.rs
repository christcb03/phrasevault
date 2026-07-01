//! The companion agent: an unlocked signer + approval policy served over a local
//! Unix socket (doc 14 §3). Phase 2b is **headless** — a `Prompt` decision becomes
//! a denial (no UI yet; the approval UI is doc 14 §9 phase 5).

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;

use pvfs_proto::{read_msg, write_msg};

use crate::policy::{ApprovalPolicy, Decision, Origin};
use crate::proto::{AgentRequest, AgentResponse};
use crate::signer::{KeyRole, RequestType, UnlockedSigner};

/// An unlocked signer plus the approval policy that gates it.
pub struct Agent {
    signer: UnlockedSigner,
    policy: ApprovalPolicy,
}

impl Agent {
    pub fn new(signer: UnlockedSigner, policy: ApprovalPolicy) -> Agent {
        Agent { signer, policy }
    }

    /// Handle one request (pure — no I/O), applying the headless approval policy.
    pub fn handle(&self, req: AgentRequest) -> AgentResponse {
        match req {
            AgentRequest::GetPubkey { role } => {
                let Some(role) = KeyRole::parse(&role) else {
                    return AgentResponse::error("bad_input", "unknown role");
                };
                match self.signer.pubkey(role) {
                    Ok(pk) => AgentResponse::Pubkey {
                        pubkey: hex::encode(pk),
                    },
                    Err(e) => AgentResponse::error("sign", e.to_string()),
                }
            }
            AgentRequest::Sign {
                request_type,
                digest,
                origin,
            } => {
                let Some(rt) = RequestType::parse(&request_type) else {
                    return AgentResponse::error("bad_input", "unknown request_type");
                };
                let origin = parse_origin(origin.as_deref());
                // Headless: a Prompt means "needs a human" — deny without a UI.
                if self.policy.decide_headless(rt, origin) != Decision::Approve {
                    return AgentResponse::error("denied", "approval required or denied by policy");
                }
                let bytes = match hex::decode(&digest) {
                    Ok(b) => b,
                    Err(_) => return AgentResponse::error("bad_input", "digest not hex"),
                };
                let digest: [u8; 32] = match bytes.try_into() {
                    Ok(a) => a,
                    Err(_) => return AgentResponse::error("bad_input", "digest must be 32 bytes"),
                };
                match self.signer.sign(rt, &digest) {
                    Ok(sig) => AgentResponse::Signature {
                        sig: hex::encode(sig),
                    },
                    Err(e) => AgentResponse::error("sign", e.to_string()),
                }
            }
        }
    }
}

/// Serve requests on `listener` until it closes — one thread per connection.
pub fn serve(listener: UnixListener, agent: Arc<Agent>) -> io::Result<()> {
    for stream in listener.incoming() {
        let stream = stream?;
        let a = Arc::clone(&agent);
        std::thread::spawn(move || {
            let _ = serve_connection(&a, stream);
        });
    }
    Ok(())
}

fn serve_connection(agent: &Agent, mut stream: UnixStream) -> io::Result<()> {
    while let Some(req) = read_msg::<_, AgentRequest>(&mut stream)? {
        let resp = agent.handle(req);
        write_msg(&mut stream, &resp)?;
    }
    Ok(())
}

fn parse_origin(s: Option<&str>) -> Origin {
    match s {
        Some("web") => Origin::Web,
        _ => Origin::Local,
    }
}
