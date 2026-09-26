//! PVOS D193 — a personal forest served by its box (proto 15).
//!
//! The box's key is a member with no grant: it serves the forest and
//! delivers what the person signed (`CommitSigned`) — a session certificate
//! their browser made — and can write nothing itself. The session key the
//! certificate names writes under an `rw` grant that expires, and can grant,
//! admit or revoke nothing. A delivered event is judged as its author's own
//! commit would be: a forged one is refused, and an anonymous connection
//! delivers nothing.

use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use pvfs_client::Client;
use pvfs_core::personal::{attach_sigs, init_signed_genesis, prepare_personal_genesis, session_cert_events, PersonalGenesis, SessionCert};
use pvfs_core::{crypto, identity};
use pvfsd::{serve, Daemon};

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn connect(sock: &Path, k: &identity::SigningKey) -> Client {
    let k = k.clone();
    Client::connect_signed(sock, &crypto::pubkey_bytes(&k), move |d| crypto::sign_digest(&k, d).unwrap()).unwrap()
}

fn signer(k: &identity::SigningKey) -> impl Fn(&[u8; 32]) -> Vec<u8> {
    let k = k.clone();
    move |d| crypto::sign_digest(&k, d).unwrap()
}

#[test]
fn the_box_delivers_what_the_person_signed_and_writes_nothing_itself() {
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let dir = tempfile::tempdir().unwrap();
    let mn = identity::generate_mnemonic().unwrap();
    let (root, ident) = (identity::root_key(&mn, "").unwrap(), identity::identity_key(&mn, "", 0).unwrap());
    let host = identity::generate_device_key();
    let g = PersonalGenesis {
        root_pub: crypto::pubkey_bytes(&root),
        identity_pub: crypto::pubkey_bytes(&ident),
        host_pub: crypto::pubkey_bytes(&host),
    };
    let events = prepare_personal_genesis(&g).unwrap().sign(&root, &ident).unwrap();
    let engine = init_signed_genesis(&dir.path().join("people-kim"), events, host.clone()).unwrap();
    let (forest_id, root_node) = (engine.identity.forest_id.clone(), engine.identity.root_node_id.clone());

    let sock = dir.path().join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = Arc::new(Daemon::new(engine));
    std::thread::spawn(move || {
        let _ = serve(listener, daemon);
    });

    let mut boxc = connect(&sock, &host);
    assert!(boxc.daemon_proto() >= 15, "CommitSigned is proto 15");
    assert!(boxc.mkdir(&root_node, "mine", signer(&host)).is_err(), "the box's key writes nothing");

    // A session certificate, as a sign-in makes it in the page.
    let cert = |session: &identity::SigningKey, at: u64, expires_at: u64, by: &identity::SigningKey| {
        let prepared = session_cert_events(&SessionCert {
            forest_id: forest_id.clone(),
            root_node_id: root_node.clone(),
            identity_pub: crypto::pubkey_bytes(&ident),
            session_pub: crypto::pubkey_bytes(session),
            at,
            expires_at,
        })
        .unwrap();
        let sigs = prepared.iter().map(|p| crypto::sign_digest(by, &p.digest).unwrap()).collect();
        attach_sigs(prepared, sigs).unwrap()
    };

    // Forged (signed by a stranger, naming kim's identity): refused.
    let forger = identity::generate_device_key();
    let stolen = identity::generate_device_key();
    let t = now_ms();
    assert!(boxc.commit_signed(&cert(&stolen, t, t + 3_600_000, &forger)).is_err(), "a forged certificate");
    // Delivered anonymously: refused, however well signed.
    let session = identity::generate_device_key();
    let good = cert(&session, t, t + 3_600_000, &ident);
    let mut anon = Client::connect_public(&sock).unwrap();
    assert!(anon.commit_signed(&good).is_err(), "an anonymous delivery");
    // Delivered by the box: kept.
    boxc.commit_signed(&good).expect("the box delivers kim's certificate");
    assert!(connect(&sock, &stolen).mkdir(&root_node, "x", signer(&stolen)).is_err(), "the forger's key got nothing");

    // The session writes; it grants, admits and revokes nothing.
    let mut s = connect(&sock, &session);
    s.mkdir(&root_node, "prefs", signer(&session)).expect("the session writes under its grant");
    let other = hex::encode(crypto::pubkey_bytes(&identity::generate_device_key()));
    assert!(s.set_acl(&root_node, &format!("key:{other}"), "rw", signer(&session)).is_err(), "no grants");
    assert!(s.authorize_member(&other, signer(&session)).is_err(), "no admissions");
    assert!(s.revoke(&hex::encode(crypto::pubkey_bytes(&host)), signer(&session)).is_err(), "no revocations");

    // A grant that has expired is inert, though its certificate is genuine.
    let old = identity::generate_device_key();
    boxc.commit_signed(&cert(&old, t - 7_200_000, t - 3_600_000, &ident)).expect("a genuine, expired certificate");
    assert!(connect(&sock, &old).mkdir(&root_node, "late", signer(&old)).is_err(), "an expired grant writes nothing");
}
