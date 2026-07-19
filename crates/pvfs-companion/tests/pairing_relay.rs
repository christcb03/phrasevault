//! M3.1 pairing + browser relay, end to end against a real WebAgent HTTP
//! listener: pair a server (prompted), then relayed sign_in/user_action with
//! the full verification order — pairing key, Origin↔pairing binding,
//! envelope signature, context/digest agreement, prompt (code rendered),
//! sign. Probes: unpaired key, wrong origin, forged envelope, context
//! mismatch. The /relay route is token-exempt by design (the pairing
//! signature + origin binding are its authentication).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use pvfs_companion::{
    verify_code, AgentRequest, AgentResponse, ApprovalContext, ApprovalPolicy, Prompter,
    PairingRegistry, RelayPayload, WebAgent, RELAY_DOMAIN,
};
use pvfs_core::{crypto, identity};

/// Approves everything and records the last rendered context summary into a
/// shared cell, so the test can assert the prompt carried the code + origin.
struct Recorder(Arc<Mutex<String>>);
impl Prompter for Recorder {
    fn approve(&self, _r: pvfs_companion::RequestType, _o: pvfs_companion::Origin) -> bool {
        true
    }
    fn approve_with_context(
        &self,
        _r: pvfs_companion::RequestType,
        _o: pvfs_companion::Origin,
        context: Option<&ApprovalContext>,
    ) -> bool {
        if let Some(c) = context {
            *self.0.lock().unwrap() = c.summary.clone();
        }
        true
    }
    fn approve_pair(&self, _n: &str, _k: &str, _o: &[String]) -> bool {
        true
    }
}

fn http_post(addr: &str, path: &str, origin: Option<&str>, body: &str) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    let origin_hdr = origin
        .map(|o| format!("Origin: {o}\r\n"))
        .unwrap_or_default();
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\
         {origin_hdr}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn envelope(sign_key: &impl SignKey, payload: &RelayPayload) -> String {
    let payload_json = serde_json::to_string(payload).unwrap();
    let d = crypto::domain_digest(RELAY_DOMAIN, payload_json.as_bytes());
    let sig = sign_key.sign(&d);
    serde_json::json!({ "payload": payload_json, "server_sig": hex::encode(sig) }).to_string()
}

/// The concrete key type isn't re-exported; hide it behind a trait.
trait SignKey {
    fn sign(&self, d: &[u8; 32]) -> Vec<u8>;
}
impl<F: Fn(&[u8; 32]) -> Vec<u8>> SignKey for F {
    fn sign(&self, d: &[u8; 32]) -> Vec<u8> {
        self(d)
    }
}

#[test]
fn verify_code_is_pinned() {
    let mut d = [0u8; 32];
    d[0] = 0x00;
    d[1] = 0x01;
    d[2] = 0x02;
    d[3] = 0x03;
    // 0x00010203 = 66051 → zero-padded six digits.
    assert_eq!(verify_code(&d), "066051");
}

#[test]
fn pairing_and_relay_end_to_end() {
    let origin_ok = "http://127.0.0.1:7420";

    // The human's companion (real seed) + recording prompter + pairings.
    let mn = identity::generate_mnemonic().unwrap();
    let signer = pvfs_companion::UnlockedSigner::from_phrase(&mn.to_string()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let summaries = Arc::new(Mutex::new(String::new()));
    let agent = Arc::new(
        pvfs_companion::Agent::new(signer, ApprovalPolicy::default())
            .with_prompter(Box::new(Recorder(summaries.clone())))
            .with_pairings(PairingRegistry::at(&dir.path().join("pairings.json"))),
    );

    // The paired server's key (pvosd's machine key in real life).
    let server_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let server_pub = hex::encode(crypto::pubkey_bytes(&server_key));
    let server_sign = |d: &[u8; 32]| crypto::sign_digest(&server_key, d).unwrap();

    // ── pair (socket-side op; prompted) ─────────────────────────────────
    let resp = agent.handle(AgentRequest::Pair {
        name: "pvos".into(),
        server_pubkey: server_pub.clone(),
        origins: vec![origin_ok.into()],
    });
    let AgentResponse::Paired { identity_pubkey } = resp else {
        panic!("expected Paired, got {resp:?}");
    };
    let identity_bytes = hex::decode(&identity_pubkey).unwrap();

    // ── the web agent over real HTTP ────────────────────────────────────
    let origins =
        pvfs_companion::OriginRegistry::at(&dir.path().join("origins.json"));
    let web = Arc::new(WebAgent::new(Arc::clone(&agent), origins));
    let http = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = format!("127.0.0.1:{}", http.local_addr().unwrap().port());
    {
        let w = Arc::clone(&web);
        std::thread::spawn(move || w.serve(http));
    }

    // sign_in happy path (note: NO x-pvfs-token header anywhere).
    let digest = [7u8; 32];
    let payload = RelayPayload {
        kind: "sign_in".into(),
        server_pubkey: server_pub.clone(),
        digest: hex::encode(digest),
        context: None,
    };
    let resp = http_post(&addr, "/relay", Some(origin_ok), &envelope(&server_sign, &payload));
    assert!(resp.contains("200 OK"), "sign_in relay: {resp}");
    let body = resp.split("\r\n\r\n").nth(1).unwrap();
    let v: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(v["pubkey"], identity_pubkey);
    let sig = hex::decode(v["sig"].as_str().unwrap()).unwrap();
    crypto::verify_digest(&identity_bytes, &digest, &sig).expect("relayed sig verifies");
    // The prompt rendered the code and the requesting origin.
    let seen = summaries.lock().unwrap().clone();
    assert!(seen.contains(&verify_code(&digest)), "code in prompt: {seen}");
    assert!(seen.contains(origin_ok), "origin in prompt: {seen}");

    // Wrong origin → bad_origin, before any prompt.
    let resp = http_post(&addr, "/relay", Some("http://evil.example"), &envelope(&server_sign, &payload));
    assert!(resp.contains("bad_origin"), "{resp}");

    // Forged envelope (payload tampered after signing) → bad_sig.
    let good = envelope(&server_sign, &payload);
    let forged = good.replace("sign_in", "sign_iN");
    let resp = http_post(&addr, "/relay", Some(origin_ok), &forged);
    assert!(resp.contains("bad_sig") || resp.contains("bad_input"), "{resp}");

    // Unpaired server key → unpaired.
    let other_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let other_sign = |d: &[u8; 32]| crypto::sign_digest(&other_key, d).unwrap();
    let unpaired = RelayPayload {
        server_pubkey: hex::encode(crypto::pubkey_bytes(&other_key)),
        ..payload.clone()
    };
    let resp = http_post(&addr, "/relay", Some(origin_ok), &envelope(&other_sign, &unpaired));
    assert!(resp.contains("unpaired"), "{resp}");

    // user_action: context digest must agree; then the attestation signs.
    let action_digest = [9u8; 32];
    let ctx = ApprovalContext {
        app_id: "greeter".into(),
        action: "grant".into(),
        summary: "greeter wants storage".into(),
        resource: None,
        digest_hex: Some(hex::encode(action_digest)),
    };
    let mismatch = RelayPayload {
        kind: "user_action".into(),
        server_pubkey: server_pub.clone(),
        digest: hex::encode([1u8; 32]),
        context: Some(ctx.clone()),
    };
    let resp = http_post(&addr, "/relay", Some(origin_ok), &envelope(&server_sign, &mismatch));
    assert!(resp.contains("bad_input"), "context mismatch refused: {resp}");

    let action = RelayPayload {
        kind: "user_action".into(),
        server_pubkey: server_pub.clone(),
        digest: hex::encode(action_digest),
        context: Some(ctx),
    };
    let resp = http_post(&addr, "/relay", Some(origin_ok), &envelope(&server_sign, &action));
    assert!(resp.contains("200 OK"), "user_action relay: {resp}");
    let seen = summaries.lock().unwrap().clone();
    assert!(seen.contains(&verify_code(&action_digest)), "code: {seen}");
    assert!(seen.contains("greeter wants storage"), "summary kept: {seen}");

    // Revoke → the same relay is refused.
    assert!(matches!(
        agent.handle(AgentRequest::RevokePairing { name: "pvos".into() }),
        AgentResponse::Ok
    ));
    let resp = http_post(&addr, "/relay", Some(origin_ok), &envelope(&server_sign, &payload));
    assert!(resp.contains("unpaired"), "revoked: {resp}");
}
