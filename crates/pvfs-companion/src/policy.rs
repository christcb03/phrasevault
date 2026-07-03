//! Approval policy (doc 14 §4) — tiered by request type, not one global mode.
//!
//! The signer never decides on its own; a caller asks the policy first. The point
//! is to keep **high-authority** (root) and **remotely-originated** (web) requests
//! from being driven silently — everyday, owner-initiated identity signing stays
//! friction-free while the vault is unlocked.

use crate::signer::RequestType;

/// Where a request came from. Local = the owner's CLI/daemon on this host; Web = a
/// browser/app via the loopback identity agent (doc 14 §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Local,
    Web,
}

/// What the policy decided. `Prompt` means "ask the human" — with no UI (headless)
/// a `Prompt` resolves to `Deny` (see [`ApprovalPolicy::decide_headless`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Approve,
    Deny,
    Prompt,
}

/// Which request classes auto-approve without a prompt. [`Default`] is the
/// **headless-safe** posture (doc 14 §10): everyday identity signing the owner
/// initiated locally is automatic; root events and new web origins are not.
#[derive(Clone, Copy, Debug)]
pub struct ApprovalPolicy {
    /// Auto-sign the human's own tag/identity ops initiated locally.
    pub auto_identity_local: bool,
    /// Auto-sign root device-cert events (admit/revoke). Off by default — these
    /// always want a human (interactive desktop) or an explicit opt-in (server).
    pub auto_root: bool,
    /// Auto-sign requests from a web origin without a per-origin connect.
    pub auto_web_origin: bool,
}

impl Default for ApprovalPolicy {
    fn default() -> Self {
        ApprovalPolicy {
            auto_identity_local: true,
            auto_root: false,
            auto_web_origin: false,
        }
    }
}

impl ApprovalPolicy {
    /// Decide for an interactive companion (a `Prompt` will be shown to the user).
    pub fn decide(&self, request: RequestType, origin: Origin) -> Decision {
        match (request, origin) {
            // Root events: rare and high-authority — prompt unless explicitly auto.
            (RequestType::RootDeviceCert, _) => yes_or_prompt(self.auto_root),
            // Anything from a web origin: bind to a per-origin connect (prompt) unless auto.
            (_, Origin::Web) => yes_or_prompt(self.auto_web_origin),
            // A brokered app action signed as the human (doc 16 §2–3): the
            // context drives the prompt, and the companion's floor is
            // prompt-by-default (doc 16 §8) — any auto-approve allow-list
            // lives broker-side (`pvos.sso`), never here.
            (RequestType::UserAction, Origin::Local) => Decision::Prompt,
            // The human's own identity ops + secure-blob decryption, initiated
            // locally: friction-free while unlocked (doc 12 §8.5). A web origin
            // never reaches here — it hit the Origin::Web arm above.
            (
                RequestType::IdentityTag
                | RequestType::IdentityAssertion
                | RequestType::SecureUnwrap,
                Origin::Local,
            ) => yes_or_prompt(self.auto_identity_local),
        }
    }

    /// Decide for a headless companion (no UI): a `Prompt` becomes `Deny`.
    pub fn decide_headless(&self, request: RequestType, origin: Origin) -> Decision {
        match self.decide(request, origin) {
            Decision::Prompt => Decision::Deny,
            other => other,
        }
    }
}

fn yes_or_prompt(auto: bool) -> Decision {
    if auto {
        Decision::Approve
    } else {
        Decision::Prompt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_headless_safe() {
        let p = ApprovalPolicy::default();
        // identity-local auto-approves
        assert_eq!(
            p.decide(RequestType::IdentityTag, Origin::Local),
            Decision::Approve
        );
        // root events prompt (interactive) / deny (headless)
        assert_eq!(
            p.decide(RequestType::RootDeviceCert, Origin::Local),
            Decision::Prompt
        );
        assert_eq!(
            p.decide_headless(RequestType::RootDeviceCert, Origin::Local),
            Decision::Deny
        );
        // a connected origin can never reach a root event silently
        assert_eq!(
            p.decide(RequestType::RootDeviceCert, Origin::Web),
            Decision::Prompt
        );
        // web identity assertion prompts (connect) by default
        assert_eq!(
            p.decide_headless(RequestType::IdentityAssertion, Origin::Web),
            Decision::Deny
        );
        // a brokered user_action always prompts (deny headless) — the
        // companion floor has no auto-approve for app actions (doc 16 §8)
        assert_eq!(
            p.decide(RequestType::UserAction, Origin::Local),
            Decision::Prompt
        );
        assert_eq!(
            p.decide_headless(RequestType::UserAction, Origin::Local),
            Decision::Deny
        );
    }

    #[test]
    fn explicit_auto_root_approves() {
        let p = ApprovalPolicy {
            auto_root: true,
            ..Default::default()
        };
        assert_eq!(
            p.decide(RequestType::RootDeviceCert, Origin::Local),
            Decision::Approve
        );
    }
}
