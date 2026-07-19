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
use crate::proto::{AgentRequest, AgentResponse, ApprovalContext, API_VERSION};
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
    /// Paired servers (PVOS M3.1). `None` = pairing ops refused.
    pairings: Option<crate::pairings::PairingRegistry>,
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
            pairings: None,
        }
    }

    /// Enable server pairing (PVOS M3.1): where enrolled pairings persist.
    pub fn with_pairings(mut self, registry: crate::pairings::PairingRegistry) -> Agent {
        self.pairings = Some(registry);
        self
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

    fn audit_sign(
        &self,
        rt: &str,
        origin: Origin,
        decision: &str,
        digest: &str,
        context: Option<&ApprovalContext>,
    ) {
        let o = match origin {
            Origin::Local => "local",
            Origin::Web => "web",
        };
        if let Some(a) = &self.audit {
            a.sign_ctx(rt, o, decision, digest, context);
        }
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
                context: None,
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
    /// Enroll a paired server (PVOS M3.1). Socket-only (0600-trusted caller);
    /// human-prompted with name + key + origins; answers with the identity
    /// pubkey the server stores for verifying relayed answers.
    fn pair(&self, name: &str, server_pubkey: &str, origins: Vec<String>) -> AgentResponse {
        let Some(reg) = &self.pairings else {
            return AgentResponse::error("unsupported", "pairing not enabled");
        };
        if name.is_empty() || origins.is_empty() {
            return AgentResponse::error("bad_input", "pairing needs a name and origins");
        }
        let Ok(pk) = hex::decode(server_pubkey) else {
            return AgentResponse::error("bad_input", "server_pubkey not hex");
        };
        if pvfs_core::crypto::validate_pubkey(&pk).is_err() {
            return AgentResponse::error("bad_input", "server_pubkey invalid");
        }
        if !self.prompter.approve_pair(name, server_pubkey, &origins) {
            if let Some(a) = &self.audit {
                a.event("pair_denied");
            }
            return AgentResponse::error("denied", "pairing not approved");
        }
        if let Err(e) = reg.add(name, server_pubkey, origins) {
            return AgentResponse::error("io", e.to_string());
        }
        if let Some(a) = &self.audit {
            a.event("paired");
        }
        match self.identity_pubkey() {
            AgentResponse::Pubkey { pubkey } => AgentResponse::Paired {
                identity_pubkey: pubkey,
            },
            other => other,
        }
    }

    /// A browser-relayed signing request from a paired server (M3.1 §3.2/3.3).
    /// `request_origin` is the relaying page's browser-enforced Origin header.
    /// Verification order: pairing exists (by claimed key) → Origin bound to
    /// that pairing → envelope signature over `domain_digest(RELAY_DOMAIN,
    /// payload_json)` → inner digest/context agreement → rate limit → prompt
    /// (server name + origin + 6-digit code + context) → sign.
    pub fn relay(
        &self,
        request_origin: &str,
        payload_json: &str,
        server_sig_hex: &str,
    ) -> AgentResponse {
        use crate::proto::{verify_code, RelayPayload, RELAY_DOMAIN};

        let Some(reg) = &self.pairings else {
            return AgentResponse::error("unsupported", "pairing not enabled");
        };
        let Ok(payload) = serde_json::from_str::<RelayPayload>(payload_json) else {
            return AgentResponse::error("bad_input", "malformed relay payload");
        };
        let Some(pairing) = reg.find_by_pubkey(&payload.server_pubkey) else {
            return AgentResponse::error("unpaired", "no pairing for that server key");
        };
        if !pairing.origins.iter().any(|o| o == request_origin) {
            return AgentResponse::error("bad_origin", "origin not bound to this pairing");
        }
        let (Ok(pk), Ok(sig)) = (hex::decode(&payload.server_pubkey), hex::decode(server_sig_hex))
        else {
            return AgentResponse::error("bad_input", "sig not hex");
        };
        let relay_digest = pvfs_core::crypto::domain_digest(RELAY_DOMAIN, payload_json.as_bytes());
        if pvfs_core::crypto::verify_digest(&pk, &relay_digest, &sig).is_err() {
            return AgentResponse::error("bad_sig", "envelope signature does not verify");
        }
        let Ok(bytes) = hex::decode(&payload.digest) else {
            return AgentResponse::error("bad_input", "digest not hex");
        };
        let Ok(digest32) = <[u8; 32]>::try_from(bytes.as_slice()) else {
            return AgentResponse::error("bad_input", "digest must be 32 bytes");
        };
        let code = verify_code(&digest32);

        let (rt, rt_name, context) = match payload.kind.as_str() {
            "sign_in" => {
                let ctx = crate::proto::ApprovalContext {
                    app_id: pairing.name.clone(),
                    action: "sign_in".into(),
                    summary: format!(
                        "Sign in to \"{}\" from {request_origin} — code {code}",
                        pairing.name
                    ),
                    resource: None,
                    digest_hex: Some(payload.digest.clone()),
                };
                (RequestType::IdentityAssertion, "identity_assertion", ctx)
            }
            "user_action" => {
                let Some(mut ctx) = payload.context.clone() else {
                    return AgentResponse::error("bad_input", "user_action needs a context");
                };
                // doc 16 §3.2 unchanged: context digest must equal the digest.
                if ctx.digest_hex.as_deref() != Some(payload.digest.as_str()) {
                    return AgentResponse::error(
                        "bad_input",
                        "context digest_hex does not match the digest being signed",
                    );
                }
                ctx.summary = format!(
                    "{} — via \"{}\" from {request_origin}, code {code}",
                    ctx.summary, pairing.name
                );
                (RequestType::UserAction, "user_action", ctx)
            }
            _ => return AgentResponse::error("bad_input", "unknown relay kind"),
        };

        if self.rate_limited() {
            self.audit_sign(rt_name, Origin::Web, "rate_limited", &payload.digest, Some(&context));
            return AgentResponse::error("rate_limited", "too many signature requests");
        }
        let approved = match self.policy.decide(rt, Origin::Web) {
            Decision::Approve => true,
            Decision::Deny => false,
            Decision::Prompt => self
                .prompter
                .approve_with_context(rt, Origin::Web, Some(&context)),
        };
        if !approved {
            self.audit_sign(rt_name, Origin::Web, "denied", &payload.digest, Some(&context));
            return AgentResponse::error("denied", "approval required or denied");
        }
        match self.with_signer(|s| s.sign(rt, &digest32)) {
            Ok(Ok(sig)) => {
                self.audit_sign(rt_name, Origin::Web, "approved", &payload.digest, Some(&context));
                AgentResponse::Signature {
                    sig: hex::encode(sig),
                }
            }
            Ok(Err(e)) => AgentResponse::error("sign", e.to_string()),
            Err(resp) => {
                self.audit_sign(rt_name, Origin::Web, "locked", &payload.digest, Some(&context));
                resp
            }
        }
    }

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
            // Version negotiation must work even while locked (doc 16 §7 item 4).
            AgentRequest::ApiVersion => AgentResponse::ApiVersion {
                api_version: API_VERSION,
            },
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
                context,
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
                // A context that names a digest must name THIS one — the broker
                // built both from one operation (doc 16 §3.1), so a mismatch
                // means a confused (or lying) caller. Refuse before any prompt.
                if let Some(ctx_digest) = context.as_ref().and_then(|c| c.digest_hex.as_deref()) {
                    if !ctx_digest.eq_ignore_ascii_case(&digest) {
                        return AgentResponse::error(
                            "bad_input",
                            "context digest_hex does not match the digest being signed",
                        );
                    }
                }
                let ctx = context.as_ref();
                if self.rate_limited() {
                    self.audit_sign(&request_type, origin, "rate_limited", &digest, ctx);
                    return AgentResponse::error("rate_limited", "too many signature requests");
                }
                let approved = match self.policy.decide(rt, origin) {
                    Decision::Approve => true,
                    Decision::Deny => false,
                    Decision::Prompt => self.prompter.approve_with_context(rt, origin, ctx),
                };
                if !approved {
                    self.audit_sign(&request_type, origin, "denied", &digest, ctx);
                    return AgentResponse::error("denied", "approval required or denied by policy");
                }
                match self.with_signer(|s| s.sign(rt, &arr)) {
                    Ok(Ok(sig)) => {
                        self.audit_sign(&request_type, origin, "approved", &digest, ctx);
                        AgentResponse::Signature {
                            sig: hex::encode(sig),
                        }
                    }
                    Ok(Err(e)) => {
                        self.audit_sign(&request_type, origin, "error", &digest, ctx);
                        AgentResponse::error("sign", e.to_string())
                    }
                    Err(resp) => {
                        self.audit_sign(&request_type, origin, "locked", &digest, ctx);
                        resp
                    }
                }
            }
            AgentRequest::Lock => {
                self.lock("lock");
                AgentResponse::Ok
            }
            // ── pairing (PVOS M3.1; socket-only ops, 0600-trusted caller) ──
            AgentRequest::Pair {
                name,
                server_pubkey,
                origins,
            } => self.pair(&name, &server_pubkey, origins),
            AgentRequest::ListPairings => match &self.pairings {
                None => AgentResponse::error("unsupported", "pairing not enabled"),
                Some(reg) => AgentResponse::Pairings {
                    pairings: reg
                        .list()
                        .into_iter()
                        .map(|p| crate::proto::PairingInfo {
                            name: p.name,
                            server_pubkey_hex: p.server_pubkey_hex,
                            origins: p.origins,
                            created_ms: p.created_ms,
                        })
                        .collect(),
                },
            },
            AgentRequest::RevokePairing { name } => match &self.pairings {
                None => AgentResponse::error("unsupported", "pairing not enabled"),
                Some(reg) => match reg.revoke(&name) {
                    Ok(true) => {
                        if let Some(a) = &self.audit {
                            a.event("pairing_revoked");
                        }
                        AgentResponse::Ok
                    }
                    Ok(false) => AgentResponse::error("not_found", "no pairing by that name"),
                    Err(e) => AgentResponse::error("io", e.to_string()),
                },
            },
            AgentRequest::RotateIdentity => self.rotate_identity(),
            AgentRequest::SecureUnwrap {
                ephemeral_pubkey,
                nonce,
                wrapped_key,
            } => {
                // Local, auto-while-unlocked (doc 12 §8.5): same tier as the
                // owner's own identity ops — no per-request prompt, and the
                // encryption key never leaves the companion. Only the unwrapped
                // content key is returned. Rate limit + lock still apply.
                let (Ok(eph), Ok(non), Ok(wk)) = (
                    hex::decode(&ephemeral_pubkey),
                    hex::decode(&nonce),
                    hex::decode(&wrapped_key),
                ) else {
                    return AgentResponse::error("bad_input", "wrap fields must be hex");
                };
                if self.rate_limited() {
                    return AgentResponse::error("rate_limited", "too many requests");
                }
                let wrap = pvfs_core::envelope::Wrap {
                    recipient_pubkey: Vec::new(), // not needed to unwrap
                    ephemeral_pubkey: eph,
                    nonce: non,
                    wrapped_key: wk,
                };
                match self.with_signer(|s| s.unwrap_content_key(&wrap)) {
                    Ok(Ok(ck)) => AgentResponse::ContentKey {
                        content_key: hex::encode(ck),
                    },
                    Ok(Err(e)) => AgentResponse::error("unwrap", e.to_string()),
                    Err(resp) => resp,
                }
            }
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
            Ok::<_, String>((next, old, new, sig_old, sig_new))
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
            context: None,
        }
    }

    fn ctx(digest_hex: Option<&str>) -> ApprovalContext {
        ApprovalContext {
            app_id: "app:mediaforest".into(),
            action: "share".into(),
            summary: "Share 3 photos with your Friends".into(),
            resource: None,
            digest_hex: digest_hex.map(String::from),
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
    fn api_version_answers_even_locked() {
        let (s, _) = signer();
        let agent = Agent::new(s, ApprovalPolicy::default());
        assert!(matches!(agent.handle(AgentRequest::Lock), AgentResponse::Ok));
        assert!(matches!(
            agent.handle(AgentRequest::ApiVersion),
            AgentResponse::ApiVersion { api_version } if api_version == API_VERSION
        ));
    }

    /// Doc 16 §2–3: a `user_action` prompts by default, the prompter sees the
    /// broker's context, the signature is the identity key's, and the audit
    /// line carries the full context.
    #[test]
    fn user_action_prompts_with_context_and_audits_it() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static SAW_CONTEXT: AtomicBool = AtomicBool::new(false);
        struct CtxProbe;
        impl Prompter for CtxProbe {
            fn approve(&self, _r: RequestType, _o: Origin) -> bool {
                true
            }
            fn approve_with_context(
                &self,
                r: RequestType,
                _o: Origin,
                context: Option<&ApprovalContext>,
            ) -> bool {
                assert_eq!(r, RequestType::UserAction);
                let c = context.expect("the broker context reaches the prompt");
                assert_eq!(c.summary, "Share 3 photos with your Friends");
                SAW_CONTEXT.store(true, Ordering::SeqCst);
                true
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let audit = AuditLog::open(&dir.path().join("a.jsonl")).unwrap();
        let (s, _) = signer();
        let id_pub = s.pubkey(KeyRole::Identity).unwrap();
        let agent = Agent::new(s, ApprovalPolicy::default())
            .with_prompter(Box::new(CtxProbe))
            .with_audit(audit);

        let digest_hex = "ab".repeat(32);
        let resp = agent.handle(AgentRequest::Sign {
            request_type: "user_action".into(),
            digest: digest_hex.clone(),
            origin: None,
            context: Some(ctx(Some(&digest_hex))),
        });
        let AgentResponse::Signature { sig } = resp else {
            panic!("expected a signature, got {resp:?}");
        };
        assert!(SAW_CONTEXT.load(Ordering::SeqCst));

        // Signed by the IDENTITY key (doc 16 §5), verifiable by anyone.
        let digest: [u8; 32] = hex::decode(&digest_hex).unwrap().try_into().unwrap();
        pvfs_core::crypto::verify_digest(&id_pub, &digest, &hex::decode(sig).unwrap()).unwrap();

        // The audit line records the whole context.
        let text = std::fs::read_to_string(dir.path().join("a.jsonl")).unwrap();
        assert!(text.contains("\"request_type\":\"user_action\""));
        assert!(text.contains("\"app_id\":\"app:mediaforest\""));
        assert!(text.contains("Share 3 photos with your Friends"));

        // Headless (no prompter): the same request is denied — prompt-by-default.
        let (s2, _) = signer();
        let headless = Agent::new(s2, ApprovalPolicy::default());
        assert!(matches!(
            headless.handle(AgentRequest::Sign {
                request_type: "user_action".into(),
                digest: digest_hex.clone(),
                origin: None,
                context: Some(ctx(None)),
            }),
            AgentResponse::Error { code, .. } if code == "denied"
        ));
    }

    /// A context that names a different digest than the one being signed is a
    /// lying (or confused) caller — refused before any prompt.
    #[test]
    fn context_digest_mismatch_is_refused() {
        let (s, _) = signer();
        let agent = Agent::new(s, ApprovalPolicy::default()).with_prompter(Box::new(ApproveAll));
        let resp = agent.handle(AgentRequest::Sign {
            request_type: "user_action".into(),
            digest: "ab".repeat(32),
            origin: None,
            context: Some(ctx(Some(&"cd".repeat(32)))),
        });
        assert!(matches!(
            resp,
            AgentResponse::Error { code, message } if code == "bad_input" && message.contains("digest_hex")
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
