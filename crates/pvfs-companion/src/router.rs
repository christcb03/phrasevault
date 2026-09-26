//! PVOS D189 — several recovery phrases in one companion.
//!
//! One [`Agent`] per vault (its own signer, lock, prompter, audit log and
//! pairings — exactly what a single-vault companion runs), and a router in
//! front: each request goes to the phrase that holds the public key its
//! top-level [`KEY_FIELD`] names — any of that phrase's root, identity or
//! encryption keys; `role`/`request_type` still choose the key inside it. A
//! request that names no key goes to the default phrase (the first vault),
//! so every client older than protocol v4 works unchanged. A key no phrase
//! holds is refused (`no_such_key`), never answered with another phrase.
//!
//! Routing is by public key, not forest id: a forest id is a random UUID no
//! phrase can derive, and a forest's root can rotate — a client names the
//! forest's CURRENT root, which it already reads before asking a signature.
//!
//! A request may also name its forest ([`FOREST_FIELD`]): once it succeeds,
//! the answering phrase's ledger records which of its keys that forest used
//! and for what ([`crate::ledger`]) — shown in the companion's settings, never
//! used to route or authorize. [`AgentRequest::LinkForest`] records a forest
//! made before the companion kept ledgers.

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;

use pvfs_proto::{read_msg, write_msg};

use crate::agent::Agent;
use crate::ledger::Ledger;
use crate::proto::{AgentRequest, AgentResponse, ForestRef, KeyInfo, API_VERSION, FOREST_FIELD, KEY_FIELD};

/// One phrase: its vault's name, its public keys (derived from the phrase
/// when the companion started, so routing never needs an unlock), its agent.
pub struct Slot {
    pub vault: String,
    root: Vec<u8>,
    identity: Vec<u8>,
    encryption: Vec<u8>,
    agent: Arc<Agent>,
    /// The vault file, and the ledger beside it (none: nothing is recorded).
    path: String,
    ledger: Option<Ledger>,
}

impl Slot {
    /// Reads the phrase's public keys now (the agent unlocks if it must).
    pub fn new(vault: impl Into<String>, agent: Arc<Agent>) -> Result<Slot, String> {
        let keys = agent.public_keys()?;
        Ok(Slot {
            vault: vault.into(),
            root: keys.root,
            identity: keys.identity,
            encryption: keys.encryption,
            agent,
            path: String::new(),
            ledger: None,
        })
    }

    /// The vault file this phrase came from; its forest ledger is kept beside
    /// it (`<vault>.forests.json`).
    pub fn with_vault_path(mut self, vault: &Path) -> Slot {
        self.path = vault.display().to_string();
        self.ledger = Some(Ledger::at(&vault.with_extension("forests.json")));
        self
    }

    /// Which of this phrase's keys `key` is.
    fn role_of(&self, key: &[u8]) -> Option<&'static str> {
        if key == self.root.as_slice() {
            Some("root")
        } else if key == self.identity.as_slice() {
            Some("identity")
        } else if key == self.encryption.as_slice() {
            Some("encryption")
        } else {
            None
        }
    }

    fn key_of(&self, role: &str) -> &[u8] {
        match role {
            "root" => &self.root,
            "encryption" => &self.encryption,
            _ => &self.identity,
        }
    }

    /// Note a forest's use of one of this phrase's keys; a ledger that cannot
    /// be written is said, never fatal to the request it records.
    fn note(&self, forest: &ForestRef, role: &str, action: &str) {
        if let Some(l) = &self.ledger {
            if let Err(e) = l.record(forest, &hex::encode(self.key_of(role)), role, action) {
                eprintln!("pvfs-companion: ledger for {}: {e}", self.vault);
            }
        }
    }
}

/// The key a request uses inside its phrase, and a line for the ledger.
fn use_of(req: &AgentRequest) -> (&'static str, String) {
    match req {
        AgentRequest::Sign { request_type, context, .. } => {
            let role = if request_type == "root_device_cert" { "root" } else { "identity" };
            let what = context.as_ref().map(|c| format!(" — {}", c.summary)).unwrap_or_default();
            (role, format!("sign {request_type}{what}"))
        }
        AgentRequest::GetPubkey { role } => match role.as_str() {
            "root" => ("root", "public key (root)".into()),
            "encryption" => ("encryption", "public key (encryption)".into()),
            _ => ("identity", format!("public key ({role})")),
        },
        AgentRequest::SecureUnwrap { .. } => ("encryption", "unwrap a secure node's key".into()),
        AgentRequest::RotateIdentity => ("identity", "rotate the identity".into()),
        AgentRequest::Pair { name, .. } => ("identity", format!("pair {name}")),
        _ => ("identity", String::new()),
    }
}

/// The companion's phrases; the first is the default.
pub struct Router {
    slots: Vec<Slot>,
}

impl Router {
    /// Refuses no phrases, or two with the same root (the same phrase twice,
    /// or one forest's root in two vaults — a request could not say which).
    pub fn new(slots: Vec<Slot>) -> Result<Router, String> {
        if slots.is_empty() {
            return Err("no phrase to serve".into());
        }
        for (i, a) in slots.iter().enumerate() {
            if let Some(b) = slots[..i].iter().find(|b| b.root == a.root) {
                return Err(format!(
                    "vaults {} and {} hold the same phrase (root {}) — serve one of them",
                    b.vault,
                    a.vault,
                    short(&a.root)
                ));
            }
        }
        Ok(Router { slots })
    }

    /// The default phrase's agent (the web agent serves it).
    pub fn default_agent(&self) -> Arc<Agent> {
        Arc::clone(&self.slots[0].agent)
    }

    /// The phrases, public keys only.
    pub fn keys(&self) -> Vec<KeyInfo> {
        self.slots
            .iter()
            .enumerate()
            .map(|(i, s)| KeyInfo {
                vault: s.vault.clone(),
                default: i == 0,
                root: hex::encode(&s.root),
                identity: hex::encode(&s.identity),
                encryption: hex::encode(&s.encryption),
                locked: s.agent.is_locked(),
                path: s.path.clone(),
            })
            .collect()
    }

    /// Handle one request frame as it came off the socket: the selector is
    /// read from the frame, the rest is the request the chosen phrase's agent
    /// handles exactly as a single-vault companion would.
    pub fn handle_frame(&self, mut frame: serde_json::Value) -> AgentResponse {
        let key = match frame.as_object_mut().and_then(|o| o.remove(KEY_FIELD)) {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(k)) => match hex::decode(k.trim()) {
                Ok(k) => Some(k),
                Err(_) => return AgentResponse::error("bad_input", "key must be a hex public key"),
            },
            Some(_) => return AgentResponse::error("bad_input", "key must be a hex public key"),
        };
        let forest: Option<ForestRef> = match frame.as_object_mut().and_then(|o| o.remove(FOREST_FIELD)) {
            None | Some(serde_json::Value::Null) => None,
            Some(v) => match serde_json::from_value(v) {
                Ok(f) => Some(f),
                Err(_) => return AgentResponse::error("bad_input", "forest must be {\"id\": …, \"label\": …}"),
            },
        };
        let req: AgentRequest = match serde_json::from_value(frame) {
            Ok(r) => r,
            Err(e) => return AgentResponse::error("bad_input", format!("unreadable request: {e}")),
        };
        match req {
            AgentRequest::ApiVersion => return AgentResponse::ApiVersion { api_version: API_VERSION },
            AgentRequest::ListKeys => return AgentResponse::Keys { keys: self.keys() },
            AgentRequest::LinkForest => return self.link(key.as_deref(), forest.as_ref()),
            _ => {}
        }
        let slot = match &key {
            None => &self.slots[0],
            Some(k) => match self.slots.iter().find(|s| s.role_of(k).is_some()) {
                Some(s) => s,
                None => {
                    return AgentResponse::error(
                        "no_such_key",
                        format!("no phrase in this companion holds key {}", short(k)),
                    )
                }
            },
        };
        let (role, action) = use_of(&req);
        let resp = slot.agent.handle(req);
        if let Some(f) = &forest {
            if !matches!(resp, AgentResponse::Error { .. }) {
                slot.note(f, role, &action);
            }
        }
        resp
    }

    /// [`AgentRequest::LinkForest`]: record that `forest` uses `key`, when a
    /// phrase here holds it — public keys only, no unlock, no prompt.
    fn link(&self, key: Option<&[u8]>, forest: Option<&ForestRef>) -> AgentResponse {
        let (Some(key), Some(forest)) = (key, forest) else {
            return AgentResponse::error("bad_input", "link_forest needs a key and a forest");
        };
        let Some((slot, role)) = self.slots.iter().find_map(|s| s.role_of(key).map(|r| (s, r))) else {
            return AgentResponse::error("no_such_key", format!("no phrase in this companion holds key {}", short(key)));
        };
        let Some(ledger) = &slot.ledger else {
            return AgentResponse::error("unsupported", "this companion keeps no forest ledger");
        };
        match ledger.record(forest, &hex::encode(key), role, "linked") {
            Ok(()) => AgentResponse::Ok,
            Err(e) => AgentResponse::error("bad_input", e.to_string()),
        }
    }
}

fn short(key: &[u8]) -> String {
    let h = hex::encode(key);
    h[..h.len().min(12)].to_string()
}

/// Serve requests on `listener` through the router — one thread per
/// connection (the single-vault [`crate::serve`] for many phrases).
pub fn serve_router(listener: UnixListener, router: Arc<Router>) -> io::Result<()> {
    for stream in listener.incoming() {
        let stream = stream?;
        let r = Arc::clone(&router);
        std::thread::spawn(move || {
            let _ = serve_connection(&r, stream);
        });
    }
    Ok(())
}

fn serve_connection(router: &Router, mut stream: UnixStream) -> io::Result<()> {
    while let Some(frame) = read_msg::<_, serde_json::Value>(&mut stream)? {
        let resp = router.handle_frame(frame);
        write_msg(&mut stream, &resp)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ApprovalPolicy;
    use crate::signer::UnlockedSigner;
    use pvfs_core::{crypto, identity};

    fn agent_for(phrase: &str) -> Arc<Agent> {
        let signer = UnlockedSigner::from_phrase(phrase).unwrap();
        let policy = ApprovalPolicy { auto_root: true, ..Default::default() };
        Arc::new(Agent::new(signer, policy))
    }

    fn phrase() -> String {
        identity::generate_mnemonic().unwrap().to_string()
    }

    fn root_of(phrase: &str) -> Vec<u8> {
        let mn = identity::parse_mnemonic(phrase).unwrap();
        crypto::pubkey_bytes(&identity::root_key(&mn, "").unwrap())
    }

    fn frame(v: serde_json::Value) -> serde_json::Value {
        v
    }

    fn pubkey(r: AgentResponse) -> String {
        match r {
            AgentResponse::Pubkey { pubkey } => pubkey,
            other => panic!("expected a pubkey, got {other:?}"),
        }
    }

    #[test]
    fn a_request_goes_to_the_phrase_that_holds_its_key() {
        let (a, b) = (phrase(), phrase());
        let router = Router::new(vec![
            Slot::new("companion", agent_for(&a)).unwrap(),
            Slot::new("media2", agent_for(&b)).unwrap(),
        ])
        .unwrap();
        let (ra, rb) = (hex::encode(root_of(&a)), hex::encode(root_of(&b)));

        // No key: the default phrase — a v3 client's request, unchanged.
        let got = pubkey(router.handle_frame(frame(serde_json::json!({"op": "get_pubkey", "role": "root"}))));
        assert_eq!(got, ra);
        // The second phrase's root selects it.
        let got = pubkey(router.handle_frame(frame(
            serde_json::json!({"op": "get_pubkey", "role": "root", "key": rb}),
        )));
        assert_eq!(got, rb);
        // Any key of a phrase selects it; the role picks the key inside it.
        let keys = router.keys();
        assert_eq!(keys.len(), 2);
        assert!(keys[0].default && !keys[1].default);
        assert_eq!((keys[0].vault.as_str(), keys[1].vault.as_str()), ("companion", "media2"));
        let got = pubkey(router.handle_frame(frame(
            serde_json::json!({"op": "get_pubkey", "role": "root", "key": keys[1].identity}),
        )));
        assert_eq!(got, rb, "the identity key names the phrase; the role picks its root");
        let got = pubkey(router.handle_frame(frame(
            serde_json::json!({"op": "get_pubkey", "role": "encryption", "key": rb}),
        )));
        assert_eq!(got, keys[1].encryption);

        // A signature routed to the second phrase verifies against ITS root.
        let digest = [7u8; 32];
        let r = router.handle_frame(frame(serde_json::json!({
            "op": "sign", "request_type": "root_device_cert", "digest": hex::encode(digest), "key": rb,
        })));
        let AgentResponse::Signature { sig } = r else { panic!("expected a signature, got {r:?}") };
        crypto::verify_digest(&root_of(&b), &digest, &hex::decode(sig).unwrap()).expect("signed by media2's root");
    }

    #[test]
    fn a_key_no_phrase_holds_is_refused_never_substituted() {
        let (a, b, stranger) = (phrase(), phrase(), phrase());
        let router =
            Router::new(vec![Slot::new("companion", agent_for(&a)).unwrap(), Slot::new("media2", agent_for(&b)).unwrap()])
                .unwrap();
        let r = router.handle_frame(frame(serde_json::json!({
            "op": "sign", "request_type": "root_device_cert", "digest": hex::encode([1u8; 32]),
            "key": hex::encode(root_of(&stranger)),
        })));
        match r {
            AgentResponse::Error { code, .. } => assert_eq!(code, "no_such_key"),
            other => panic!("a key no phrase holds must be refused, got {other:?}"),
        }
        match router.handle_frame(frame(serde_json::json!({"op": "get_pubkey", "role": "root", "key": "not-hex"}))) {
            AgentResponse::Error { code, .. } => assert_eq!(code, "bad_input"),
            other => panic!("expected bad_input, got {other:?}"),
        }
        // Version negotiation and the listing need no key and no unlock.
        match router.handle_frame(frame(serde_json::json!({"op": "api_version"}))) {
            AgentResponse::ApiVersion { api_version } => assert_eq!(api_version, API_VERSION),
            other => panic!("{other:?}"),
        }
        match router.handle_frame(frame(serde_json::json!({"op": "list_keys"}))) {
            AgentResponse::Keys { keys } => assert_eq!(keys.len(), 2),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_request_that_names_its_forest_is_recorded_by_the_phrase_that_answered() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (phrase(), phrase());
        let router = Router::new(vec![
            Slot::new("companion", agent_for(&a)).unwrap().with_vault_path(&dir.path().join("companion.vault")),
            Slot::new("media2", agent_for(&b)).unwrap().with_vault_path(&dir.path().join("media2.vault")),
        ])
        .unwrap();
        let rb = hex::encode(root_of(&b));
        let media = serde_json::json!({"id": "f-media", "label": "media"});

        // A root signature for the media forest, routed to media2 by its root.
        let r = router.handle_frame(frame(serde_json::json!({
            "op": "sign", "request_type": "root_device_cert", "digest": hex::encode([3u8; 32]),
            "key": rb, "forest": media,
            "context": {"app_id": "pvfs", "action": "admit", "summary": "Admit 02cd… as owner"},
        })));
        assert!(matches!(r, AgentResponse::Signature { .. }), "{r:?}");
        let got = crate::ledger::read(&dir.path().join("media2.forests.json"));
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].forest_id.as_str(), got[0].label.as_str(), got[0].role.as_str()), ("f-media", "media", "root"));
        assert_eq!(got[0].key, rb);
        assert_eq!(got[0].last_action, "sign root_device_cert — Admit 02cd… as owner");
        assert!(crate::ledger::read(&dir.path().join("companion.forests.json")).is_empty(), "the other phrase records nothing");

        // A refused request records nothing; one without a forest records nothing.
        let r = router.handle_frame(frame(serde_json::json!({
            "op": "get_pubkey", "role": "root", "key": hex::encode(root_of(&phrase())), "forest": {"id": "f-x"},
        })));
        assert!(matches!(r, AgentResponse::Error { .. }));
        let _ = router.handle_frame(frame(serde_json::json!({"op": "get_pubkey", "role": "root", "key": rb})));
        let got = crate::ledger::read(&dir.path().join("media2.forests.json"));
        assert_eq!((got.len(), got[0].uses), (1, 1));

        // A malformed forest is refused before anything is asked.
        match router.handle_frame(frame(serde_json::json!({"op": "get_pubkey", "role": "root", "forest": "media"}))) {
            AgentResponse::Error { code, .. } => assert_eq!(code, "bad_input"),
            other => panic!("{other:?}"),
        }
        // list_keys says where each phrase's files are.
        let keys = router.keys();
        assert!(keys[1].path.ends_with("media2.vault"), "{}", keys[1].path);
    }

    #[test]
    fn a_forest_is_linked_only_to_a_key_this_companion_holds() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (phrase(), phrase());
        let router = Router::new(vec![
            Slot::new("companion", agent_for(&a)).unwrap().with_vault_path(&dir.path().join("companion.vault")),
            Slot::new("media2", agent_for(&b)).unwrap().with_vault_path(&dir.path().join("media2.vault")),
        ])
        .unwrap();
        let keys = router.keys();
        let r = router.handle_frame(frame(serde_json::json!({
            "op": "link_forest", "key": keys[1].root, "forest": {"id": "f-media", "label": "Media forest"},
        })));
        assert!(matches!(r, AgentResponse::Ok), "{r:?}");
        let got = crate::ledger::read(&dir.path().join("media2.forests.json"));
        assert_eq!((got[0].role.as_str(), got[0].last_action.as_str()), ("root", "linked"));
        // By its identity key too: the role follows the key.
        let r = router.handle_frame(frame(serde_json::json!({
            "op": "link_forest", "key": keys[0].identity, "forest": {"id": "f-pvos", "label": "PVOS"},
        })));
        assert!(matches!(r, AgentResponse::Ok), "{r:?}");
        assert_eq!(crate::ledger::read(&dir.path().join("companion.forests.json"))[0].role, "identity");
        // A key no phrase holds, or no forest: refused, nothing written.
        for (req, want) in [
            (serde_json::json!({"op": "link_forest", "key": hex::encode(root_of(&phrase())), "forest": {"id": "f"}}), "no_such_key"),
            (serde_json::json!({"op": "link_forest", "key": keys[1].root}), "bad_input"),
            (serde_json::json!({"op": "link_forest", "forest": {"id": "f"}}), "bad_input"),
        ] {
            match router.handle_frame(frame(req)) {
                AgentResponse::Error { code, .. } => assert_eq!(code, want),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(crate::ledger::read(&dir.path().join("media2.forests.json")).len(), 1);
    }

    #[test]
    fn the_same_phrase_twice_is_refused() {
        let a = phrase();
        let err = Router::new(vec![
            Slot::new("companion", agent_for(&a)).unwrap(),
            Slot::new("copy", agent_for(&a)).unwrap(),
        ])
        .err()
        .unwrap();
        assert!(err.contains("same phrase"), "{err}");
        assert!(Router::new(Vec::new()).is_err());
    }
}
