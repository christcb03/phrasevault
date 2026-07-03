//! The approval UI (doc 14 §9 phase 5): how a [`Decision::Prompt`] reaches a
//! human. The policy (doc 14 §4) decides *whether* to ask; a [`Prompter`]
//! decides *how* — a desktop dialog where a GUI session exists, the controlling
//! terminal otherwise, and a headless agent denies (the phase 2b posture,
//! unchanged: a prompt nobody can see must never approve).
//!
//! Prompts are serialized (one at a time) and default to **deny**: closing the
//! dialog, EOF on the terminal, or any error counts as "no".

use std::io::{BufRead, Write};
use std::sync::Mutex;

use crate::policy::Origin;
use crate::proto::ApprovalContext;
use crate::signer::RequestType;

/// Ask the human to approve a signature the policy wouldn't auto-approve.
pub trait Prompter: Send + Sync {
    fn approve(&self, request: RequestType, origin: Origin) -> bool;

    /// As [`approve`](Prompter::approve), rendering the broker-built
    /// [`ApprovalContext`] (doc 16 §3.2) so the human reads *"MediaForest wants
    /// to share 3 photos"*, never an opaque hash. Default: ignore the context
    /// and fall back to the plain prompt — backends that can show text override.
    fn approve_with_context(
        &self,
        request: RequestType,
        origin: Origin,
        context: Option<&ApprovalContext>,
    ) -> bool {
        let _ = context;
        self.approve(request, origin)
    }

    /// The wallet-style connect (doc 14 §6): "allow `origin` to sign in as
    /// you?". Default deny — a backend must opt in explicitly.
    fn approve_connect(&self, _origin: &str) -> bool {
        false
    }

    /// An identity **replacement** (doc 15 §1) — root-tier consequence, its own
    /// wording. Default deny.
    fn approve_rotation(&self, old_hex: &str, new_hex: &str) -> bool {
        let _ = (old_hex, new_hex);
        false
    }
}

/// Headless: every prompt is a denial (never approve what nobody saw).
pub struct DenyPrompter;

impl Prompter for DenyPrompter {
    fn approve(&self, _request: RequestType, _origin: Origin) -> bool {
        false
    }
}

fn describe_connect(origin: &str) -> String {
    format!(
        "pvfs-companion: allow \"{origin}\" to SIGN IN as you (identity assertions \
         only, revocable with `pvfs-companion origins revoke`)?"
    )
}

fn describe_rotation(old_hex: &str, new_hex: &str) -> String {
    format!(
        "pvfs-companion: REPLACE your identity key? {old_hex} -> {new_hex}. Grants \
         under the old key go inert until re-issued; do this only for a compromise."
    )
}

fn describe(request: RequestType, origin: Origin) -> String {
    let what = match request {
        RequestType::RootDeviceCert => {
            "ROOT signature: admit or revoke a device/member (changes who can act in your forest)"
        }
        RequestType::IdentityTag => "identity signature: a tag grant or membership under your authority",
        RequestType::IdentityAssertion => "identity assertion: prove who you are (sign-in)",
        RequestType::SecureUnwrap => "decrypt a secure blob (unwrap its content key)",
        RequestType::UserAction => "an app action signed AS YOU (brokered by pvos.sso)",
    };
    let from = match origin {
        Origin::Local => "this machine",
        Origin::Web => "a WEB ORIGIN",
    };
    format!("pvfs-companion: approve {what}, requested from {from}?")
}

/// The doc 16 §3.2 rendering: lead with the broker's human line, then the
/// attributed app, action verb, and resource — the digest is never shown.
fn describe_with_context(
    request: RequestType,
    origin: Origin,
    context: Option<&ApprovalContext>,
) -> String {
    let Some(ctx) = context else {
        return describe(request, origin);
    };
    let mut s = format!(
        "pvfs-companion: \"{}\" wants to sign as you: {} (action: {}",
        ctx.app_id, ctx.summary, ctx.action
    );
    if let Some(r) = &ctx.resource {
        s.push_str(&format!(", resource: {r}"));
    }
    let from = match origin {
        Origin::Local => "this machine",
        Origin::Web => "a WEB ORIGIN",
    };
    s.push_str(&format!("), requested from {from}. Approve?"));
    s
}

/// Ask on the controlling terminal (`/dev/tty`), independent of stdin/stdout —
/// works even while `serve` runs in the foreground of that terminal.
pub struct TerminalPrompter {
    tty: Mutex<()>,
}

impl TerminalPrompter {
    /// `None` when there is no controlling terminal.
    pub fn open() -> Option<TerminalPrompter> {
        // Probe once so a headless agent falls through to the next backend.
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()?;
        Some(TerminalPrompter {
            tty: Mutex::new(()),
        })
    }
}

impl TerminalPrompter {
    fn ask(&self, question: &str) -> bool {
        let _one_at_a_time = self.tty.lock().expect("tty prompt poisoned");
        let Ok(mut tty) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
        else {
            return false;
        };
        if write!(tty, "\n{question}\nType yes to approve, anything else denies: ")
            .and_then(|_| tty.flush())
            .is_err()
        {
            return false;
        }
        let mut line = String::new();
        let mut reader = std::io::BufReader::new(tty);
        if reader.read_line(&mut line).is_err() {
            return false;
        }
        line.trim().eq_ignore_ascii_case("yes")
    }
}

impl Prompter for TerminalPrompter {
    fn approve(&self, request: RequestType, origin: Origin) -> bool {
        self.ask(&describe(request, origin))
    }
    fn approve_with_context(
        &self,
        request: RequestType,
        origin: Origin,
        context: Option<&ApprovalContext>,
    ) -> bool {
        self.ask(&describe_with_context(request, origin, context))
    }
    fn approve_connect(&self, origin: &str) -> bool {
        self.ask(&describe_connect(origin))
    }
    fn approve_rotation(&self, old_hex: &str, new_hex: &str) -> bool {
        self.ask(&describe_rotation(old_hex, new_hex))
    }
}

/// Ask with a native desktop dialog: `osascript` on macOS, `zenity` on Linux.
/// Only constructed when the session looks graphical; any failure denies.
pub struct DesktopPrompter;

impl DesktopPrompter {
    /// `None` when there's no GUI session to show a dialog in.
    pub fn detect() -> Option<DesktopPrompter> {
        if cfg!(target_os = "macos") {
            return Some(DesktopPrompter);
        }
        let gui = std::env::var_os("DISPLAY").is_some()
            || std::env::var_os("WAYLAND_DISPLAY").is_some();
        if gui && which("zenity") {
            return Some(DesktopPrompter);
        }
        None
    }
}

impl Prompter for DesktopPrompter {
    fn approve(&self, request: RequestType, origin: Origin) -> bool {
        self.dialog(&describe(request, origin))
    }
    fn approve_with_context(
        &self,
        request: RequestType,
        origin: Origin,
        context: Option<&ApprovalContext>,
    ) -> bool {
        self.dialog(&describe_with_context(request, origin, context))
    }
    fn approve_connect(&self, origin: &str) -> bool {
        self.dialog(&describe_connect(origin))
    }
    fn approve_rotation(&self, old_hex: &str, new_hex: &str) -> bool {
        self.dialog(&describe_rotation(old_hex, new_hex))
    }
}

impl DesktopPrompter {
    fn dialog(&self, text: &str) -> bool {
        let status = if cfg!(target_os = "macos") {
            std::process::Command::new("osascript")
                .arg("-e")
                .arg(format!(
                    "display dialog {} buttons {{\"Deny\", \"Approve\"}} \
                     default button \"Deny\" with icon caution",
                    applescript_quote(text)
                ))
                .output()
                .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("Approve"))
        } else {
            std::process::Command::new("zenity")
                .args(["--question", "--title", "PVFS companion", "--text", text])
                .status()
                .map(|s| s.success())
        };
        status.unwrap_or(false)
    }
}

/// The doc 14 §9 phase 5 default: desktop dialog where a GUI exists, the
/// terminal where one is attached, deny otherwise (headless).
pub fn auto_prompter() -> Box<dyn Prompter> {
    auto_prompter_labeled().0
}

/// As [`auto_prompter`], with a human-readable label for the serve banner.
pub fn auto_prompter_labeled() -> (Box<dyn Prompter>, &'static str) {
    if let Some(p) = DesktopPrompter::detect() {
        return (Box::new(p), "desktop dialog");
    }
    if let Some(p) = TerminalPrompter::open() {
        return (Box::new(p), "terminal");
    }
    (Box::new(DenyPrompter), "deny (headless)")
}

fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|d| d.join(bin).is_file())
        })
        .unwrap_or(false)
}

fn applescript_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_prompter_always_denies() {
        assert!(!DenyPrompter.approve(RequestType::RootDeviceCert, Origin::Local));
        assert!(!DenyPrompter.approve(RequestType::IdentityAssertion, Origin::Web));
    }

    #[test]
    fn descriptions_name_the_authority_and_origin() {
        let s = describe(RequestType::RootDeviceCert, Origin::Web);
        assert!(s.contains("ROOT") && s.contains("WEB ORIGIN"));
    }

    #[test]
    fn context_rendering_leads_with_the_brokers_line() {
        let ctx = ApprovalContext {
            app_id: "app:mediaforest".into(),
            action: "share".into(),
            summary: "Share 3 photos with your Friends".into(),
            resource: Some("pvfs://f/media/albums/trip".into()),
            digest_hex: None,
        };
        let s = describe_with_context(RequestType::UserAction, Origin::Local, Some(&ctx));
        assert!(s.contains("app:mediaforest"));
        assert!(s.contains("Share 3 photos with your Friends"));
        assert!(s.contains("albums/trip"));
        // No context falls back to the generic wording.
        let s = describe_with_context(RequestType::UserAction, Origin::Local, None);
        assert!(s.contains("signed AS YOU"));
    }
}
