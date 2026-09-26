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

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;

use pvfs_proto::{read_msg, write_msg};

use crate::agent::Agent;
use crate::proto::{AgentRequest, AgentResponse, KeyInfo, API_VERSION, KEY_FIELD};

/// One phrase: its vault's name, its public keys (derived from the phrase
/// when the companion started, so routing never needs an unlock), its agent.
pub struct Slot {
    pub vault: String,
    root: Vec<u8>,
    identity: Vec<u8>,
    encryption: Vec<u8>,
    agent: Arc<Agent>,
}

impl Slot {
    /// Reads the phrase's public keys now (the agent unlocks if it must).
    pub fn new(vault: impl Into<String>, agent: Arc<Agent>) -> Result<Slot, String> {
        let (root, identity, encryption) = agent.public_keys()?;
        Ok(Slot { vault: vault.into(), root, identity, encryption, agent })
    }

    fn holds(&self, key: &[u8]) -> bool {
        key == self.root.as_slice() || key == self.identity.as_slice() || key == self.encryption.as_slice()
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
        let req: AgentRequest = match serde_json::from_value(frame) {
            Ok(r) => r,
            Err(e) => return AgentResponse::error("bad_input", format!("unreadable request: {e}")),
        };
        match req {
            AgentRequest::ApiVersion => return AgentResponse::ApiVersion { api_version: API_VERSION },
            AgentRequest::ListKeys => return AgentResponse::Keys { keys: self.keys() },
            _ => {}
        }
        let slot = match &key {
            None => &self.slots[0],
            Some(k) => match self.slots.iter().find(|s| s.holds(k)) {
                Some(s) => s,
                None => {
                    return AgentResponse::error(
                        "no_such_key",
                        format!("no phrase in this companion holds key {}", short(k)),
                    )
                }
            },
        };
        slot.agent.handle(req)
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
