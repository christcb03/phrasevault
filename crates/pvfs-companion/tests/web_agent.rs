//! Integration (doc 14 §9 phase 6): the loopback identity agent end to end —
//! token gate, wallet-style connect, sign-in whose signature verifies against
//! the identity key, origin isolation, and revocation.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use pvfs_companion::approve::Prompter;
use pvfs_companion::{
    Agent, ApprovalPolicy, Origin, OriginRegistry, RequestType, UnlockedSigner, WebAgent,
};
use pvfs_core::{crypto, identity};

struct ApproveAll;
impl Prompter for ApproveAll {
    fn approve(&self, _r: RequestType, _o: Origin) -> bool {
        true
    }
    fn approve_connect(&self, _origin: &str) -> bool {
        true
    }
}

/// Raw HTTP/1.1 client: returns (status_code, body).
fn http(
    addr: &str,
    method: &str,
    path: &str,
    origin: &str,
    token: &str,
    body: &str,
) -> (u16, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nOrigin: {origin}\r\n\
         X-PVFS-Token: {token}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    let status: u16 = resp
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = resp
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or_default()
        .to_string();
    (status, body)
}

fn jfield(body: &str, key: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(body).unwrap();
    v[key].as_str().unwrap_or_default().to_string()
}

fn start(prompter: Box<dyn Prompter>) -> (String, String, Vec<u8>, tempfile::TempDir) {
    let mn = identity::generate_mnemonic().unwrap();
    let id_pub = crypto::pubkey_bytes(&identity::identity_key(&mn, "", 0).unwrap());
    let signer = UnlockedSigner::from_phrase(&mn.to_string()).unwrap();
    let agent = Arc::new(Agent::new(signer, ApprovalPolicy::default()).with_prompter(prompter));

    let dir = tempfile::tempdir().unwrap();
    let reg = OriginRegistry::at(&dir.path().join("origins.json"));
    let web = Arc::new(WebAgent::new(agent, reg));
    let token = web.token().to_string();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    // Dual-mode (M3.6 §4a): every test serves WITH TLS material, so the
    // plain-http requests below double as the peek-fallback coverage.
    let tls = pvfs_companion::webtls::load_or_generate(&dir.path().join("companion.vault"))
        .unwrap();
    {
        let w = Arc::clone(&web);
        let cfg = tls.config.clone();
        std::thread::spawn(move || w.serve(listener, Some(cfg)));
    }
    (addr, token, id_pub, dir)
}

/// The same raw request, but through a rustls client that trusts the
/// generated web-agent cert — the https side of the dual-mode port.
fn https_get_identity(addr: &str, dir: &tempfile::TempDir, token: &str, origin: &str) -> String {
    use std::io::{Read as _, Write as _};
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(
            pvfs_companion::webtls::webtls_dir(&dir.path().join("companion.vault"))
                .join("cert.pem"),
        )
        .unwrap(),
    )) {
        roots.add(c.unwrap()).unwrap();
    }
    let cfg = std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let tcp = std::net::TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
    let conn = rustls::ClientConnection::new(cfg, name).unwrap();
    let mut s = rustls::StreamOwned::new(conn, tcp);
    write!(
        s,
        "GET /identity HTTP/1.1
Host: x
Origin: {origin}
X-Pvfs-Token: {token}
         Content-Length: 0
Connection: close

"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

#[test]
fn dual_mode_serves_https_and_http_on_one_port() {
    // M3.6 §4a: the same port answers a rustls client (an https desktop
    // page, no loopback-exception reliance) AND a plain-http caller (older
    // pages) — the one-byte peek routes each correctly.
    let (addr, token, id_pub, dir) = start(Box::new(ApproveAll));
    let app = "https://app.example";
    let (code, _) = http(&addr, "POST", "/connect", app, &token, "");
    assert_eq!(code, 200);

    // Plain http still works (this is also every other test's transport).
    let (code, body) = http(&addr, "GET", "/identity", app, &token, "");
    assert_eq!(code, 200);
    assert_eq!(jfield(&body, "pubkey"), hex::encode(&id_pub));

    // https on the SAME port, trusting the generated cert.
    let out = https_get_identity(&addr, &dir, &token, app);
    assert!(out.contains("200 OK"), "https identity over dual-mode port: {out}");
    assert!(out.contains(&hex::encode(&id_pub)), "same identity over TLS: {out}");
}

#[test]
fn connect_sign_in_and_verify() {
    let (addr, token, id_pub, _dir) = start(Box::new(ApproveAll));
    let app = "https://app.example";

    // Wrong token: refused before anything else.
    let (code, _) = http(&addr, "POST", "/connect", app, "nope", "");
    assert_eq!(code, 401);

    // Sign-in before connect: origin-gated.
    let (code, _) = http(&addr, "POST", "/sign-in", app, &token, "{\"challenge\":\"00\"}");
    assert_eq!(code, 403);

    // Connect (the ApproveAll prompter plays the human), then sign in.
    let (code, body) = http(&addr, "POST", "/connect", app, &token, "");
    assert_eq!(code, 200, "{body}");
    let challenge = "7f".repeat(32);
    let (code, body) = http(
        &addr,
        "POST",
        "/sign-in",
        app,
        &token,
        &format!("{{\"challenge\":\"{challenge}\"}}"),
    );
    assert_eq!(code, 200, "{body}");

    // The signature verifies against the identity key — and the reply says so.
    assert_eq!(jfield(&body, "pubkey"), hex::encode(&id_pub));
    let sig = hex::decode(jfield(&body, "sig")).unwrap();
    let digest: [u8; 32] = hex::decode(&challenge).unwrap().try_into().unwrap();
    crypto::verify_digest(&id_pub, &digest, &sig).unwrap();

    // /identity works for the connected origin…
    let (code, body) = http(&addr, "GET", "/identity", app, &token, "");
    assert_eq!(code, 200);
    assert_eq!(jfield(&body, "pubkey"), hex::encode(&id_pub));

    // …but a different origin is NOT connected by that grant.
    let (code, _) = http(&addr, "GET", "/identity", "https://evil.example", &token, "");
    assert_eq!(code, 403);

    // Bad challenge shapes are refused.
    let (code, _) = http(&addr, "POST", "/sign-in", app, &token, "{\"challenge\":\"zz\"}");
    assert_eq!(code, 400);
    let (code, _) = http(&addr, "POST", "/sign-in", app, &token, "{}");
    assert_eq!(code, 400);
}

#[test]
fn headless_connect_is_denied_and_revocation_bites() {
    // Default prompter = deny: the connect is refused.
    let (addr, token, _id, dir) = start(Box::new(pvfs_companion::DenyPrompter));
    let app = "https://app.example";
    let (code, _) = http(&addr, "POST", "/connect", app, &token, "");
    assert_eq!(code, 403);

    // Grant out-of-band (as an approved connect would), prove it works, then
    // revoke through the registry — the running agent notices immediately.
    let reg = OriginRegistry::at(&dir.path().join("origins.json"));
    reg.connect(app, 3600).unwrap();
    let (code, _) = http(&addr, "GET", "/identity", app, &token, "");
    assert_eq!(code, 200);
    assert!(reg.revoke(app).unwrap());
    let (code, _) = http(&addr, "GET", "/identity", app, &token, "");
    assert_eq!(code, 403);
}

// ── PVOS D18 §2.7: invite redemption — the pairing bootstrap ────────────────

/// The acceptance digest must byte-match `pvos-core::invites::
/// acceptance_digest`. This fixture is pinned in BOTH repos, so drift on
/// either side breaks a test loudly instead of breaking members silently.
#[test]
fn invite_acceptance_digest_matches_the_pvos_fixture() {
    let d = pvfs_companion::invite_acceptance_digest("inv-fixture", "02aabbcc", "ABCD1234");
    assert_eq!(
        hex::encode(d),
        "6bc05eba4a9b80bb35a723b60c663d06f00d46da05a6f18faa3e8128b0775344"
    );
    assert_eq!(pvfs_companion::normalize_invite_code(" abcd-12 34 "), "ABCD1234");
}

#[test]
fn redeem_invite_pairs_the_server_and_signs_the_acceptance() {
    struct ApproveInvites;
    impl Prompter for ApproveInvites {
        fn approve(&self, _r: RequestType, _o: Origin) -> bool {
            true
        }
        fn approve_redeem_invite(
            &self,
            member: &str,
            email: &str,
            role: &str,
            capabilities: &[String],
            _server_pubkey_hex: &str,
            origins: &[String],
        ) -> bool {
            // The prompt sees exactly what the human would — email included.
            member == "kim"
                && email == "kim@example.com"
                && role == "member"
                && capabilities.iter().any(|c| c == "use_shared_apps")
                && origins.iter().any(|o| o == "https://pvos.example:7420")
        }
    }

    let mn = identity::generate_mnemonic().unwrap();
    let id_pub = crypto::pubkey_bytes(&identity::identity_key(&mn, "", 0).unwrap());
    let signer = UnlockedSigner::from_phrase(&mn.to_string()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let pairings = pvfs_companion::PairingRegistry::at(&dir.path().join("pairings.json"));
    let agent = Arc::new(
        Agent::new(signer, ApprovalPolicy::default())
            .with_prompter(Box::new(ApproveInvites))
            .with_pairings(pairings),
    );
    let reg = OriginRegistry::at(&dir.path().join("origins.json"));
    let web = Arc::new(WebAgent::new(agent, reg));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    {
        let w = Arc::clone(&web);
        std::thread::spawn(move || w.serve(listener, None));
    }

    // A plausible PVOS server key (any valid secp256k1 point).
    let server_pub = hex::encode(crypto::pubkey_bytes(
        &identity::identity_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap(),
    ));
    let body = format!(
        "{{\"invite_id\":\"inv-1\",\"member\":\"kim\",\"email\":\"kim@example.com\",\
         \"role\":\"member\",\
         \"capabilities\":[\"use_shared_apps\"],\"server_pubkey\":\"{server_pub}\",\
         \"origins\":[\"https://pvos.example:7420\"],\"code\":\"abcd-efgh-ijkl\"}}"
    );
    // Token-exempt: a BOGUS token must not matter — this is the bootstrap,
    // and the invitee's page has no port file.
    let (code, resp) = http(&addr, "POST", "/redeem-invite", "https://pvos.example:7420", "bogus", &body);
    assert_eq!(code, 200, "{resp}");

    // The signature verifies against the identity key over the digest the
    // companion computed itself (normalized code, lowercase pubkey).
    assert_eq!(jfield(&resp, "pubkey"), hex::encode(&id_pub));
    let sig = hex::decode(jfield(&resp, "sig")).unwrap();
    let digest = pvfs_companion::invite_acceptance_digest(
        "inv-1",
        &hex::encode(&id_pub),
        "ABCDEFGHIJKL",
    );
    crypto::verify_digest(&id_pub, &digest, &sig).unwrap();

    // Half 1 really happened: the server is a paired server bound to its
    // origins, so sign-ins now ride the normal relay path.
    let reg2 = pvfs_companion::PairingRegistry::at(&dir.path().join("pairings.json"));
    let pairing = reg2.find_by_pubkey(&server_pub).expect("server enrolled");
    assert!(pairing.origins.iter().any(|o| o == "https://pvos.example:7420"));
    // The derived name pins THIS INSTALL: host + key fingerprint, always
    // (several PVOS instances can share one host).
    assert!(
        pairing.name.starts_with("pvos pvos.example:7420 (") && pairing.name.ends_with(")"),
        "install-pinned name, got {:?}",
        pairing.name
    );

    // Malformed bodies refuse.
    let (code, _) = http(&addr, "POST", "/redeem-invite", "https://pvos.example:7420", "", "{}");
    assert_eq!(code, 400);
}

#[test]
fn redeem_invite_default_deny_and_no_prompter_refuse() {
    // A prompter that has not opted in (DenyPrompter) refuses the invite —
    // and refuses BEFORE any pairing is written.
    let mn = identity::generate_mnemonic().unwrap();
    let signer = UnlockedSigner::from_phrase(&mn.to_string()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let pairings = pvfs_companion::PairingRegistry::at(&dir.path().join("pairings.json"));
    let agent = Arc::new(
        Agent::new(signer, ApprovalPolicy::default())
            .with_prompter(Box::new(pvfs_companion::DenyPrompter))
            .with_pairings(pairings),
    );
    let reg = OriginRegistry::at(&dir.path().join("origins.json"));
    let web = Arc::new(WebAgent::new(agent, reg));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    {
        let w = Arc::clone(&web);
        std::thread::spawn(move || w.serve(listener, None));
    }
    let server_pub = hex::encode(crypto::pubkey_bytes(
        &identity::identity_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap(),
    ));
    let body = format!(
        "{{\"invite_id\":\"inv-1\",\"member\":\"kim\",\"role\":\"member\",\
         \"capabilities\":[\"use_shared_apps\"],\"server_pubkey\":\"{server_pub}\",\
         \"origins\":[\"https://pvos.example:7420\"],\"code\":\"abcd\"}}"
    );
    let (code, resp) = http(&addr, "POST", "/redeem-invite", "https://pvos.example:7420", "", &body);
    assert_eq!(code, 403, "{resp}");
    let reg2 = pvfs_companion::PairingRegistry::at(&dir.path().join("pairings.json"));
    assert!(reg2.find_by_pubkey(&server_pub).is_none(), "denial writes NOTHING");
}
