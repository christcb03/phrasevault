//! The companion agent: an unlocked signer + approval policy served over a local
//! Unix socket (doc 14 §3), with the phase 5 controls (doc 14 §4, §9): a
//! [`Prompter`] for decisions the policy won't auto-approve, a signature
//! [`AuditLog`], a rate limit, and **lock** — explicit (protocol op) or
//! idle-timeout — that drops the seed from memory. A locked agent re-unlocks on
//! demand through an optional `Unlocker` (keychain refetch, env passphrase, or a
//! terminal prompt), so locking is safe to do aggressively.

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pvfs_proto::{read_msg, write_msg};

use crate::approve::{DenyPrompter, Prompter};
use crate::audit::AuditLog;
use crate::policy::{ApprovalPolicy, Decision, Origin};
use crate::proto::{AgentRequest, AgentResponse};
use crate::signer::{KeyRole, RequestType, UnlockedSigner};

/// Re-creates an [`UnlockedSigner`] after a lock (doc 14 §5): fetch the data key
/// from the OS keychain, re-read the env passphrase, or prompt on the terminal.
/// Must not retain secret material of its own.
pub type Unlocker = Box<dyn Fn() -> Result<UnlockedSigner, String> + Send + Sync>;

/// Persists a new identity index after a rotation (doc 15 §1 A1) — typically
/// `Vault::set_identity_index` on the served vault, so the bump survives
/// restarts and the lock/re-unlock cycle.
pub type IdentityRotator = Box<dyn Fn(u64) -> Result<(), String> + Send + Sync>;

/// Default sliding-window rate limit: signatures per minute (doc 14 §4).
const DEFAULT_RATE_PER_MIN: u32 = 60;

/// An unlocked signer plus the controls that gate it.
pub struct Agent {
    signer: Mutex<Option<UnlockedSigner>>,
    policy: ApprovalPolicy,
    prompter: Box<dyn Prompter>,
    audit: Option<AuditLog>,
    unlocker: Option<Unlocker>,
    rotator: Option<IdentityRotator>,
    idle_timeout: Option<Duration>,
    last_used: Mutex<Instant>,
    rate: Mutex<Vec<Instant>>,
    rate_per_min: u32,
}

impl Agent {
    /// A headless agent: prompts deny, no audit, no re-unlock, no idle lock —
    /// exactly the phase 2b posture. Layer the phase 5 controls with `with_*`.
    pub fn new(signer: UnlockedSigner, policy: ApprovalPolicy) -> Agent {
        Agent {
            signer: Mutex::new(Some(signer)),
            policy,
            prompter: Box::new(DenyPrompter),
            audit: None,
            unlocker: None,
            rotator: None,
            idle_timeout: None,
            last_used: Mutex::new(Instant::now()),
            rate: Mutex::new(Vec::new()),
            rate_per_min: DEFAULT_RATE_PER_MIN,
        }
    }

    /// How a [`Decision::Prompt`] reaches a human (doc 14 §9 phase 5).
    pub fn with_prompter(mut self, prompter: Box<dyn Prompter>) -> Agent {
        self.prompter = prompter;
        self
    }

    /// Record every signing decision and lock event.
    pub fn with_audit(mut self, audit: AuditLog) -> Agent {
        audit.event("serve_start");
        self.audit = Some(audit);
        self
    }

    /// Allow a locked agent to re-unlock on demand.
    pub fn with_unlocker(mut self, unlocker: Unlocker) -> Agent {
        self.unlocker = Some(unlocker);
        self
    }

    /// Persist identity-index bumps (doc 15 §1). Without one, rotation is refused.
    pub fn with_identity_rotator(mut self, rotator: IdentityRotator) -> Agent {
        self.rotator = Some(rotator);
        self
    }

    /// Drop the seed after this long without a request (`None` = never).
    pub fn with_idle_timeout(mut self, timeout: Option<Duration>) -> Agent {
        self.idle_timeout = timeout;
        self
    }

    /// Signatures allowed per minute (0 = unlimited).
    pub fn with_rate_limit(mut self, per_min: u32) -> Agent {
        self.rate_per_min = per_min;
        self
    }

    fn audit_sign(&self, rt: &str, origin: Origin, decision: &str, digest: &str) {
        let o = match origin {
            Origin::Local => "local",
            Origin::Web => "web",
        };
        self.audit_sign_str(rt, o, decision, digest);
    }

    fn audit_sign_str(&self, rt: &str, origin: &str, decision: &str, digest: &str) {
        if let Some(a) = &self.audit {
            a.sign(rt, origin, decision, digest);
        }
    }

    fn audit_event(&self, event: &str) {
        if let Some(a) = &self.audit {
            a.event(event);
        }
    }

    /// Drop the seed (explicit lock or idle timeout). Idempotent.
    pub fn lock(&self, reason: &str) {
        let had = self.signer.lock().expect("signer poisoned").take().is_some();
        if had {
            self.audit_event(reason);
        }
    }

    /// Enforce the idle timeout, then run `f` with the signer — re-unlocking
    /// through the `Unlocker` if the agent is locked.
    fn with_signer<T>(&self, f: impl FnOnce(&UnlockedSigner) -> T) -> Result<T, AgentResponse> {
        if let Some(idle) = self.idle_timeout {
            let last = *self.last_used.lock().expect("last_used poisoned");
            if last.elapsed() >= idle {
                self.lock("idle_lock");
            }
        }
        let mut guard = self.signer.lock().expect("signer poisoned");
        if guard.is_none() {
            let Some(unlocker) = &self.unlocker else {
                return Err(AgentResponse::error(
                    "locked",
                    "agent is locked — restart `pvfs-companion serve`",
                ));
            };
            match unlocker() {
                Ok(s) => {
                    *guard = Some(s);
                    self.audit_event("unlock");
                }
                Err(e) => {
                    return Err(AgentResponse::error("locked", format!("unlock failed: {e}")));
                }
            }
        }
        *self.last_used.lock().expect("last_used poisoned") = Instant::now();
        Ok(f(guard.as_ref().expect("signer present")))
    }

    /// Sliding-window rate check; true = over the limit.
    fn rate_limited(&self) -> bool {
        if self.rate_per_min == 0 {
            return false;
        }
        let mut window = self.rate.lock().expect("rate poisoned");
        if let Some(cutoff) = Instant::now().checked_sub(Duration::from_secs(60)) {
            window.retain(|t| *t > cutoff);
        }
        if window.len() as u32 >= self.rate_per_min {
            return true;
        }
        window.push(Instant::now());
        false
    }

    /// The wallet-style connect approval (doc 14 §6): ask the human whether
    /// `origin` may sign in as them. Audited either way.
    pub fn approve_connect(&self, origin: &str) -> bool {
        let ok = self.prompter.approve_connect(origin);
        if let Some(a) = &self.audit {
            a.record(&crate::audit::AuditEntry {
                ts_ms: 0,
                event: "connect",
                request_type: None,
                origin: Some(origin),
                decision: Some(if ok { "approved" } else { "denied" }),
                digest: None,
            });
        }
        ok
    }

    /// Sign an identity assertion for a **connected** web origin (doc 14 §6):
    /// the standing connect grant is the approval, so there is no per-request
    /// prompt — and no other request type exists on this path, so the web can
    /// never reach a root event (doc 14 §4). Rate limit and lock still apply.
    pub fn sign_connected_assertion(&self, origin: &str, digest: &[u8; 32]) -> AgentResponse {
        let hexd = hex::encode(digest);
        if self.rate_limited() {
            self.audit_sign_str("identity_assertion", origin, "rate_limited", &hexd);
            return AgentResponse::error("rate_limited", "too many signature requests");
        }
        match self.with_signer(|s| s.sign(RequestType::IdentityAssertion, digest)) {
            Ok(Ok(sig)) => {
                self.audit_sign_str("identity_assertion", origin, "approved", &hexd);
                AgentResponse::Signature {
                    sig: hex::encode(sig),
                }
            }
            Ok(Err(e)) => {
                self.audit_sign_str("identity_assertion", origin, "error", &hexd);
                AgentResponse::error("sign", e.to_string())
            }
            Err(resp) => {
                self.audit_sign_str("identity_assertion", origin, "locked", &hexd);
                resp
            }
        }
    }

    /// The identity public key (for a connected origin's `/identity`).
    pub fn identity_pubkey(&self) -> AgentResponse {
        match self.with_signer(|s| s.pubkey(KeyRole::Identity)) {
            Ok(Ok(pk)) => AgentResponse::Pubkey {
                pubkey: hex::encode(pk),
            },
            Ok(Err(e)) => AgentResponse::error("sign", e.to_string()),
            Err(resp) => resp,
        }
    }

    /// Handle one request, applying the policy, prompter, rate limit, and lock.
    pub fn handle(&self, req: AgentRequest) -> AgentResponse {
        match req {
            AgentRequest::GetPubkey { role } => {
                let Some(role) = KeyRole::parse(&role) else {
                    return AgentResponse::error("bad_input", "unknown role");
                };
                match self.with_signer(|s| s.pubkey(role)) {
                    Ok(Ok(pk)) => AgentResponse::Pubkey {
                        pubkey: hex::encode(pk),
                    },
                    Ok(Err(e)) => AgentResponse::error("sign", e.to_string()),
                    Err(resp) => resp,
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
                let bytes = match hex::decode(&digest) {
                    Ok(b) => b,
                    Err(_) => return AgentResponse::error("bad_input", "digest not hex"),
                };
                let arr: [u8; 32] = match bytes.try_into() {
                    Ok(a) => a,
                    Err(_) => return AgentResponse::error("bad_input", "digest must be 32 bytes"),
                };
                if self.rate_limited() {
                    self.audit_sign(&request_type, origin, "rate_limited", &digest);
                    return AgentResponse::error("rate_limited", "too many signature requests");
                }
                let approved = match self.policy.decide(rt, origin) {
                    Decision::Approve => true,
                    Decision::Deny => false,
                    Decision::Prompt => self.prompter.approve(rt, origin),
                };
                if !approved {
                    self.audit_sign(&request_type, origin, "denied", &digest);
                    return AgentResponse::error("denied", "approval required or denied by policy");
                }
                match self.with_signer(|s| s.sign(rt, &arr)) {
                    Ok(Ok(sig)) => {
                        self.audit_sign(&request_type, origin, "approved", &digest);
                        AgentResponse::Signature {
                            sig: hex::encode(sig),
                        }
                    }
                    Ok(Err(e)) => {
                        self.audit_sign(&request_type, origin, "error", &digest);
                        AgentResponse::error("sign", e.to_string())
                    }
                    Err(resp) => {
                        self.audit_sign(&request_type, origin, "locked", &digest);
                        resp
                    }
                }
            }
            AgentRequest::Lock => {
                self.lock("lock");
                AgentResponse::Ok
            }
            AgentRequest::RotateIdentity => self.rotate_identity(),
        }
    }

    /// Doc 15 §1: derive the next identity, dual-sign the handoff with both
    /// keys, swap the in-memory signer, persist the index. Root-tier approval:
    /// `auto_root` (explicit automation opt-in) or the rotation prompt.
    fn rotate_identity(&self) -> AgentResponse {
        if self.rotator.is_none() {
            return AgentResponse::error(
                "unsupported",
                "this agent cannot persist an identity rotation (no vault hook)",
            );
        }
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        // Derive + dual-sign under the signer lock; swap only after approval.
        let prepared = self.with_signer(|s| {
            let (next, old, new) = s.rotate_identity().map_err(|e| e.to_string())?;
            let digest = pvfs_core::identity::handoff_digest(&old, &new, ts);
            let sig_old = s
                .sign(RequestType::IdentityAssertion, &digest)
                .map_err(|e| e.to_string())?;
            let sig_new = next
                .sign(RequestType::IdentityAssertion, &digest)
                .map_err(|e| e.to_string())?;
            Ok((next, old, new, sig_old, sig_new))
        });
        let (next, old, new, sig_old, sig_new) = match prepared {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return AgentResponse::error("sign", e),
            Err(resp) => return resp,
        };
        let (old_hex, new_hex) = (hex::encode(&old), hex::encode(&new));
        if !(self.policy.auto_root || self.prompter.approve_rotation(&old_hex, &new_hex)) {
            self.audit_event("identity_rotate_denied");
            return AgentResponse::error("denied", "approval required or denied by policy");
        }
        // Persist first, then swap — a failed persist must not leave a running
        // agent on an index that a restart would silently roll back.
        let next_id = next.identity_id();
        if let Err(e) = (self.rotator.as_ref().expect("checked above"))(next_id) {
            return AgentResponse::error("rotate", format!("could not persist the new index: {e}"));
        }
        *self.signer.lock().expect("signer poisoned") = Some(next);
        self.audit_event("identity_rotate");
        AgentResponse::IdentityRotated {
            old_pubkey: old_hex,
            new_pubkey: new_hex,
            replaced_at_ms: ts,
            sig_old: hex::encode(sig_old),
            sig_new: hex::encode(sig_new),
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

#[cfg(test)]
mod tests {
    use super::*;
    use pvfs_core::identity;

    struct ApproveAll;
    impl Prompter for ApproveAll {
        fn approve(&self, _r: RequestType, _o: Origin) -> bool {
            true
        }
    }

    fn signer() -> (UnlockedSigner, String) {
        let mn = identity::generate_mnemonic().unwrap().to_string();
        (UnlockedSigner::from_phrase(&mn).unwrap(), mn)
    }

    fn sign_req(rt: &str) -> AgentRequest {
        AgentRequest::Sign {
            request_type: rt.into(),
            digest: "ab".repeat(32),
            origin: None,
        }
    }

    #[test]
    fn prompter_approval_signs_a_root_event() {
        let (s, _) = signer();
        // auto_root stays FALSE — the prompt (not the policy) approves.
        let agent = Agent::new(s, ApprovalPolicy::default()).with_prompter(Box::new(ApproveAll));
        assert!(matches!(
            agent.handle(sign_req("root_device_cert")),
            AgentResponse::Signature { .. }
        ));
        // The headless default still denies the same request.
        let (s2, _) = signer();
        let headless = Agent::new(s2, ApprovalPolicy::default());
        assert!(matches!(
            headless.handle(sign_req("root_device_cert")),
            AgentResponse::Error { code, .. } if code == "denied"
        ));
    }

    #[test]
    fn rate_limit_kicks_in_and_is_audited() {
        let dir = tempfile::tempdir().unwrap();
        let audit = AuditLog::open(&dir.path().join("a.jsonl")).unwrap();
        let (s, _) = signer();
        let agent = Agent::new(s, ApprovalPolicy::default())
            .with_rate_limit(2)
            .with_audit(audit);
        assert!(matches!(
            agent.handle(sign_req("identity_tag")),
            AgentResponse::Signature { .. }
        ));
        assert!(matches!(
            agent.handle(sign_req("identity_tag")),
            AgentResponse::Signature { .. }
        ));
        assert!(matches!(
            agent.handle(sign_req("identity_tag")),
            AgentResponse::Error { code, .. } if code == "rate_limited"
        ));
        let text = std::fs::read_to_string(dir.path().join("a.jsonl")).unwrap();
        assert_eq!(text.matches("\"decision\":\"approved\"").count(), 2);
        assert_eq!(text.matches("\"decision\":\"rate_limited\"").count(), 1);
        assert!(text.contains("\"event\":\"serve_start\""));
    }

    #[test]
    fn lock_without_unlocker_denies_until_restart() {
        let (s, _) = signer();
        let agent = Agent::new(s, ApprovalPolicy::default());
        assert!(matches!(agent.handle(AgentRequest::Lock), AgentResponse::Ok));
        assert!(matches!(
            agent.handle(AgentRequest::GetPubkey { role: "identity".into() }),
            AgentResponse::Error { code, .. } if code == "locked"
        ));
    }

    #[test]
    fn lock_with_unlocker_reunlocks_on_demand() {
        let (s, mn) = signer();
        let agent = Agent::new(s, ApprovalPolicy::default()).with_unlocker(Box::new(move || {
            UnlockedSigner::from_phrase(&mn).map_err(|e| e.to_string())
        }));
        let before = agent.handle(AgentRequest::GetPubkey {
            role: "identity".into(),
        });
        assert!(matches!(agent.handle(AgentRequest::Lock), AgentResponse::Ok));
        let after = agent.handle(AgentRequest::GetPubkey {
            role: "identity".into(),
        });
        // Same key on both sides of the lock — the unlocker rebuilt the signer.
        match (before, after) {
            (AgentResponse::Pubkey { pubkey: a }, AgentResponse::Pubkey { pubkey: b }) => {
                assert_eq!(a, b)
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn idle_timeout_locks_and_unlocker_restores() {
        let (s, mn) = signer();
        let dir = tempfile::tempdir().unwrap();
        let audit = AuditLog::open(&dir.path().join("a.jsonl")).unwrap();
        let agent = Agent::new(s, ApprovalPolicy::default())
            .with_idle_timeout(Some(Duration::from_millis(10)))
            .with_audit(audit)
            .with_unlocker(Box::new(move || {
                UnlockedSigner::from_phrase(&mn).map_err(|e| e.to_string())
            }));
        assert!(matches!(
            agent.handle(sign_req("identity_tag")),
            AgentResponse::Signature { .. }
        ));
        std::thread::sleep(Duration::from_millis(30));
        // Idle expired: the agent locks, then transparently re-unlocks and signs.
        assert!(matches!(
            agent.handle(sign_req("identity_tag")),
            AgentResponse::Signature { .. }
        ));
        let text = std::fs::read_to_string(dir.path().join("a.jsonl")).unwrap();
        assert!(text.contains("\"event\":\"idle_lock\""));
        assert!(text.contains("\"event\":\"unlock\""));
    }
}
