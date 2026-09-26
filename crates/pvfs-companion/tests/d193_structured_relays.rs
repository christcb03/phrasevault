//! PVOS D193 — the statements a companion builds itself, over the relay.
//!
//! A paired server asks for a personal forest (prompted; the companion picks
//! the forest's id and signs the genesis and the binding with the phrase's
//! root and device keys), a session certificate (silent like a sign-in, but
//! only for a forest this phrase bound as its own on the very site asking),
//! and a confirmation of a delete or a grant (prompted, in words the
//! companion writes; an operation it does not know is refused).

use std::sync::{Arc, Mutex};

use pvfs_companion::{
    AgentRequest, AgentResponse, ApprovalContext, ApprovalPolicy, ConfirmFields, GenesisFields, PairingRegistry,
    Prompter, RelayPayload, SessionCertFields, RELAY_DOMAIN,
};
use pvfs_core::acl::{Principal, ACL_A, ACL_R, ACL_W};
use pvfs_core::personal::{attach_sigs, init_signed_genesis, prepare_personal_genesis_with, session_cert_events};
use pvfs_core::personal::{GenesisParams, PersonalGenesis, SessionCert};
use pvfs_core::{crypto, identity};

const ORIGIN: &str = "https://pvos.example";

/// Approves pairing and every companion-written statement (when `yes`),
/// recording each statement's words.
struct Recorder {
    yes: bool,
    said: Arc<Mutex<Vec<String>>>,
}

impl Prompter for Recorder {
    fn approve(&self, _r: pvfs_companion::RequestType, _o: pvfs_companion::Origin) -> bool {
        panic!("no raw prompt in these flows");
    }
    fn approve_with_context(
        &self,
        _r: pvfs_companion::RequestType,
        _o: pvfs_companion::Origin,
        _c: Option<&ApprovalContext>,
    ) -> bool {
        panic!("no context prompt in these flows");
    }
    fn approve_pair(&self, _n: &str, _k: &str, _o: &[String]) -> bool {
        true
    }
    fn approve_statement(&self, text: &str) -> bool {
        self.said.lock().unwrap().push(text.to_string());
        self.yes
    }
}

struct World {
    agent: pvfs_companion::Agent,
    mn: identity::Mnemonic,
    server_key: identity::SigningKey,
    server_pub: String,
    said: Arc<Mutex<Vec<String>>>,
    _dir: tempfile::TempDir,
}

fn world(yes: bool) -> World {
    let mn = identity::generate_mnemonic().unwrap();
    let signer = pvfs_companion::UnlockedSigner::from_phrase(&mn.to_string()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let said = Arc::new(Mutex::new(Vec::new()));
    let agent = pvfs_companion::Agent::new(signer, ApprovalPolicy::default())
        .with_prompter(Box::new(Recorder { yes, said: said.clone() }))
        .with_pairings(PairingRegistry::at(&dir.path().join("pairings.json")));
    let server_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let server_pub = hex::encode(crypto::pubkey_bytes(&server_key));
    let resp = agent.handle(AgentRequest::Pair { name: "pvos".into(), server_pubkey: server_pub.clone(), origins: vec![ORIGIN.into()] });
    assert!(matches!(resp, AgentResponse::Paired { .. }), "{resp:?}");
    World { agent, mn, server_key, server_pub, said, _dir: dir }
}

impl World {
    fn relay(&self, origin: &str, payload: &RelayPayload) -> AgentResponse {
        let json = serde_json::to_string(payload).unwrap();
        let sig = crypto::sign_digest(&self.server_key, &crypto::domain_digest(RELAY_DOMAIN, json.as_bytes())).unwrap();
        self.agent.relay(origin, &json, &hex::encode(sig))
    }

    fn device(&self) -> identity::SigningKey {
        identity::device_key(&self.mn, "", 0).unwrap()
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

#[test]
fn a_personal_forest_and_its_sessions_through_the_companion() {
    let w = world(true);
    let host = identity::generate_device_key();

    // ── the genesis: prompted once, in the companion's words ────────────
    let resp = w.relay(
        ORIGIN,
        &RelayPayload {
            kind: "personal_genesis".into(),
            server_pubkey: w.server_pub.clone(),
            genesis: Some(GenesisFields { member: "chris".into(), host_pub: hex::encode(crypto::pubkey_bytes(&host)) }),
            ..Default::default()
        },
    );
    let AgentResponse::Genesis(g) = resp else {
        panic!("expected Genesis, got {resp:?}");
    };
    let pvfs_companion::GenesisOut { root, owner, identity: ident, forest_id, instance_id, created_at, root_nonce, sigs, binding_sig } = *g;
    {
        let said = w.said.lock().unwrap();
        assert_eq!(said.len(), 1, "one prompt: {said:?}");
        assert!(said[0].contains("CREATE your personal forest") && said[0].contains("\"chris\""), "{}", said[0]);
    }
    assert_eq!(owner, hex::encode(crypto::pubkey_bytes(&w.device())), "the owner is the phrase's device key");
    assert_eq!(root, hex::encode(crypto::pubkey_bytes(&identity::root_key(&w.mn, "").unwrap())));
    assert_eq!(ident, hex::encode(crypto::pubkey_bytes(&identity::identity_key(&w.mn, "", 0).unwrap())));

    // The box rebuilds the same events from the parameters and keeps them.
    let params = GenesisParams { forest_id: forest_id.clone(), instance_id, created_at, root_nonce: root_nonce.parse().unwrap() };
    let g = PersonalGenesis { root_pub: hex::decode(&root).unwrap(), owner_pub: hex::decode(&owner).unwrap(), host_pub: crypto::pubkey_bytes(&host) };
    let events = prepare_personal_genesis_with(&g, params)
        .unwrap()
        .attach(sigs.iter().map(|s| hex::decode(s).unwrap()).collect())
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut engine = init_signed_genesis(&dir.path().join("personal"), events, host).expect("the companion's genesis replays");
    let root_node = engine.identity.root_node_id.clone();
    assert_eq!(
        engine.effective_rights(&Principal::Key(hex::decode(&owner).unwrap()), &root_node).unwrap(),
        ACL_R | ACL_W | ACL_A
    );
    let binding = pvfs_companion::pvos::personal_binding_digest("pvos.example", "chris", &forest_id, &root_node);
    crypto::verify_digest(&hex::decode(&owner).unwrap(), &binding, &hex::decode(&binding_sig).unwrap())
        .expect("bound to the asking site, by the owner key");

    // ── a session certificate: silent, and only for the bound forest ─────
    let session = identity::generate_device_key();
    let cert = |origin: &str, rp_id: &str, forest: &str, binding: &str| {
        w.relay(
            origin,
            &RelayPayload {
                kind: "session_cert".into(),
                server_pubkey: w.server_pub.clone(),
                session_cert: Some(SessionCertFields {
                    member: "chris".into(),
                    rp_id: rp_id.into(),
                    forest_id: forest.into(),
                    root_node_id: root_node.clone(),
                    binding_sig: binding.into(),
                    session_pubkey: hex::encode(crypto::pubkey_bytes(&session)),
                }),
                ..Default::default()
            },
        )
    };
    let resp = cert(ORIGIN, "pvos.example", &forest_id, &binding_sig);
    let AgentResponse::Certified { pubkey, at, expires_at, sigs } = resp else {
        panic!("expected Certified, got {resp:?}");
    };
    assert_eq!(pubkey, owner);
    assert_eq!(w.said.lock().unwrap().len(), 1, "a session certificate asks nothing");
    let prepared = session_cert_events(&SessionCert {
        forest_id: forest_id.clone(),
        root_node_id: root_node.clone(),
        owner_pub: hex::decode(&owner).unwrap(),
        session_pub: crypto::pubkey_bytes(&session),
        at,
        expires_at,
    })
    .unwrap();
    let events = attach_sigs(prepared, sigs.iter().map(|s| hex::decode(s).unwrap()).collect()).unwrap();
    engine.commit_member_write(events).expect("the certificate verifies in the forest");
    assert_eq!(
        engine.effective_rights(&Principal::Key(crypto::pubkey_bytes(&session)), &root_node).unwrap(),
        ACL_R | ACL_W,
        "rw, never admin"
    );
    engine.close().unwrap();

    // Another site than the page asking; a forest this phrase never bound.
    assert!(matches!(cert("https://evil.example", "pvos.example", &forest_id, &binding_sig), AgentResponse::Error { .. }));
    let other = "00000000-0000-4000-8000-00000000abcd";
    let resp = cert(ORIGIN, "pvos.example", other, &binding_sig);
    assert!(matches!(&resp, AgentResponse::Error { code, .. } if code == "bad_binding"), "{resp:?}");

    // ── a confirmation: the companion's words, the owner key's signature ─
    let action = |op: &str, expiry_ms: u64| ConfirmFields {
        op: op.into(),
        subject: "kim".into(),
        detail: String::new(),
        instance_id: "inst-1".into(),
        nonce: "00112233".into(),
        expiry_ms,
    };
    let confirm = |a: ConfirmFields| {
        w.relay(ORIGIN, &RelayPayload { kind: "confirm".into(), server_pubkey: w.server_pub.clone(), action: Some(a), ..Default::default() })
    };
    let expiry = now_ms() + 60_000;
    let resp = confirm(action("member_remove", expiry));
    let AgentResponse::Confirmed { pubkey, sig } = resp else {
        panic!("expected Confirmed, got {resp:?}");
    };
    assert_eq!(pubkey, owner);
    let digest = pvfs_companion::pvos::confirm_digest(&w.server_pub, "inst-1", "member_remove", "kim", "", "00112233", expiry);
    crypto::verify_digest(&hex::decode(&owner).unwrap(), &digest, &hex::decode(&sig).unwrap()).expect("the confirmation verifies");
    assert!(w.said.lock().unwrap()[1].contains("REMOVE member \"kim\""), "the companion wrote the words");
    assert!(matches!(confirm(action("format_disk", expiry)), AgentResponse::Error { .. }), "an unknown operation is refused");
    assert!(matches!(confirm(action("member_remove", now_ms() - 1)), AgentResponse::Error { .. }), "an expired request");
    assert_eq!(w.said.lock().unwrap().len(), 2, "refused requests never reach the human");
}

#[test]
fn denied_statements_sign_nothing() {
    let w = world(false);
    let host = hex::encode(crypto::pubkey_bytes(&identity::generate_device_key()));
    let resp = w.relay(
        ORIGIN,
        &RelayPayload {
            kind: "personal_genesis".into(),
            server_pubkey: w.server_pub.clone(),
            genesis: Some(GenesisFields { member: "chris".into(), host_pub: host }),
            ..Default::default()
        },
    );
    assert!(matches!(&resp, AgentResponse::Error { code, .. } if code == "denied"), "{resp:?}");
    let resp = w.relay(
        ORIGIN,
        &RelayPayload {
            kind: "confirm".into(),
            server_pubkey: w.server_pub.clone(),
            action: Some(ConfirmFields {
                op: "share".into(),
                subject: "media".into(),
                detail: "member".into(),
                instance_id: "i".into(),
                nonce: "00".into(),
                expiry_ms: now_ms() + 60_000,
            }),
            ..Default::default()
        },
    );
    assert!(matches!(&resp, AgentResponse::Error { code, .. } if code == "denied"), "{resp:?}");
}
