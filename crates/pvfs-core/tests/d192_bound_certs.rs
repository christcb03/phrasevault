//! PVOS D192 — root certificates bound to their forest.
//!
//! One phrase per person means one root key in all of a person's forests.
//! Before D192 a device certificate that root signed in one forest verified
//! in every other: a member with write access in forest B could append the
//! certificate from forest A and become a device of B. A bound forest takes
//! only certificates signed for it (v2 digests carry the forest id); a forest
//! made by a D192 build is born bound; an older forest binds with one event.

use pvfs_core::event::{self, Event};
use pvfs_core::{acl, crypto, identity, log_store, Engine, PvfsError};
use rusqlite::{params, Connection};

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

/// Append `ev` to the log behind the engine's back — what a tampered log or a
/// buggy writer would leave for the next replay to judge.
fn append_raw(dir: &std::path::Path, ev: &Event) {
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute("ATTACH DATABASE ?1 AS log", params![dir.join("log.db").to_str().unwrap()]).unwrap();
    let max = log_store::max_seq(&conn).unwrap();
    let last = log_store::read_event(&conn, max).unwrap().unwrap();
    let prev = <[u8; 32]>::try_from(last.chain_hash.as_slice()).unwrap();
    let tx = conn.transaction().unwrap();
    log_store::append_event(&tx, &prev, max + 1, ev, now_ms() + 60_000).unwrap();
    tx.commit().unwrap();
}

/// A member certificate the root signs: for `forest` (v2), or with `None`
/// in the older form (v1).
fn member_cert(root: &identity::SigningKey, root_pub: &[u8], forest: Option<&str>) -> Event {
    let member = crypto::pubkey_bytes(&identity::generate_device_key());
    let (idx, t) = (acl::MEMBER_DEVICE_INDEX, now_ms());
    let sig = crypto::sign_digest(root, &event::msg_device_authorized(forest, &member, idx, t, root_pub)).unwrap();
    Event::DeviceAuthorized { device_pubkey: member, device_index: idx, authorized_at: t, author: root_pub.to_vec(), sig }
}

fn root_of(mn: &pvfs_core::Mnemonic) -> (identity::SigningKey, Vec<u8>) {
    let k = identity::root_key(mn, "").unwrap();
    let pk = crypto::pubkey_bytes(&k);
    (k, pk)
}

fn is_refused(r: Result<(), PvfsError>) -> bool {
    matches!(r, Err(PvfsError::Integrity { .. }) | Err(PvfsError::Forbidden { .. }))
}

#[test]
fn a_new_forest_is_born_bound_and_refuses_an_unbound_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, mn) = Engine::init(dir.path()).unwrap();
    assert_eq!(engine.certificates_bound().unwrap().as_deref(), Some("genesis"));
    let (root, root_pub) = root_of(&mn);
    let forest = engine.identity.forest_id.clone();

    // the engine's own certificates are signed for this forest and replay
    let member = crypto::pubkey_bytes(&identity::generate_device_key());
    engine.authorize_member(&mn, &member).unwrap();
    // the commit path: v1 refused, v2 for this forest accepted
    assert!(is_refused(engine.commit_member_write(vec![member_cert(&root, &root_pub, None)])));
    engine.commit_member_write(vec![member_cert(&root, &root_pub, Some(&forest))]).unwrap();
    engine.close().unwrap();
    Engine::open(dir.path()).expect("its own and v2 certificates replay").close().unwrap();

    // the replay path: a v1 certificate in the log is refused
    append_raw(dir.path(), &member_cert(&root, &root_pub, None));
    assert!(Engine::open(dir.path()).is_err(), "a born-bound forest never takes a v1 certificate");
}

#[test]
fn binding_an_existing_forest_ends_unbound_certificates_from_then_on() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, mn) = Engine::init_unbound(dir.path()).unwrap();
    assert_eq!(engine.certificates_bound().unwrap(), None);
    let (root, root_pub) = root_of(&mn);
    let forest = engine.identity.forest_id.clone();

    // unbound: the older form is valid, as it always was
    engine.commit_member_write(vec![member_cert(&root, &root_pub, None)]).unwrap();
    let before = pvfs_core::mount::peek_tip(dir.path()).unwrap().0;

    assert!(engine.bind_certificates().unwrap(), "the owner device (admin) binds");
    let since = engine.certificates_bound().unwrap().expect("bound");
    assert_eq!(since, (before + 1).to_string(), "the binding's own seq");
    assert!(!engine.bind_certificates().unwrap(), "a second binding changes nothing");

    // bound: v1 refused from here on; v2 for this forest accepted; the
    // engine's own certificates follow
    assert!(is_refused(engine.commit_member_write(vec![member_cert(&root, &root_pub, None)])));
    engine.commit_member_write(vec![member_cert(&root, &root_pub, Some(&forest))]).unwrap();
    engine.authorize_member(&mn, &crypto::pubkey_bytes(&identity::generate_device_key())).unwrap();
    engine.close().unwrap();
    // history stays valid: the v1 certificate before the binding replays
    Engine::open(dir.path()).expect("a v1 certificate from before the binding stays valid").close().unwrap();

    append_raw(dir.path(), &member_cert(&root, &root_pub, None));
    assert!(Engine::open(dir.path()).is_err(), "a v1 certificate after the binding is refused on replay");
}

/// The attack D192 closes: one root key in two forests (one phrase per
/// person). A certificate — or a root rotation — signed for forest A must
/// not be accepted in forest B.
#[test]
fn a_certificate_signed_for_one_forest_is_refused_in_another_with_the_same_root() {
    let mn = identity::generate_mnemonic().unwrap();
    let (root, root_pub) = root_of(&mn);
    let sign = |d: &[u8; 32]| crypto::sign_digest(&root, d);
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let mut a = Engine::init_with_root_signer(dir_a.path(), &root_pub, sign).unwrap();
    let mut b = Engine::init_with_root_signer(dir_b.path(), &root_pub, sign).unwrap();
    let forest_a = a.identity.forest_id.clone();
    assert_ne!(forest_a, b.identity.forest_id);

    let for_a = member_cert(&root, &root_pub, Some(&forest_a));
    a.commit_member_write(vec![for_a.clone()]).unwrap();
    assert!(is_refused(b.commit_member_write(vec![for_a.clone()])), "forest A's certificate is not forest B's");
    b.close().unwrap();
    append_raw(dir_b.path(), &for_a);
    assert!(Engine::open(dir_b.path()).is_err(), "nor through B's log");

    // a root rotation signed for A cannot hijack B either
    let dir_c = tempfile::tempdir().unwrap();
    let mut c = Engine::init_with_root_signer(dir_c.path(), &root_pub, sign).unwrap();
    let new_root = crypto::pubkey_bytes(&identity::generate_device_key());
    let t = now_ms();
    let rot_sig = crypto::sign_digest(&root, &event::msg_root_rotated(Some(&forest_a), &new_root, t, &root_pub)).unwrap();
    let rotation = Event::RootRotated { new_root_pubkey: new_root, rotated_at: t, author: root_pub.clone(), sig: rot_sig };
    assert!(is_refused(c.commit_member_write(vec![rotation.clone()])), "A's rotation does not move C's root");
    assert_eq!(c.current_root().unwrap(), root_pub);
    a.commit_member_write(vec![rotation]).unwrap();
    assert_ne!(a.current_root().unwrap(), root_pub, "in A it is a rotation");
    a.close().unwrap();
    c.close().unwrap();
}

/// A binding earlier in a batch binds the rest of it: replay folds the
/// binding first, so the commit must judge what follows as bound too, or the
/// owner would take what its followers then refuse.
#[test]
fn a_binding_earlier_in_a_batch_binds_the_rest_of_it() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, mn) = Engine::init_unbound(dir.path()).unwrap();
    let (root, root_pub) = root_of(&mn);
    let forest = engine.identity.forest_id.clone();
    let bind = |engine: &Engine| {
        let mut p = engine.prepare_bind_certificates(&root_pub).unwrap().events.remove(0);
        p.event.set_author_sig(crypto::sign_digest(&root, &p.digest).unwrap());
        p.event
    };

    let batch = vec![bind(&engine), member_cert(&root, &root_pub, None)];
    let r = engine.commit_member_write(batch);
    assert!(is_refused(r), "the v1 certificate after the binding in the same batch");
    assert_eq!(engine.certificates_bound().unwrap(), None, "the refused batch wrote nothing");

    let batch = vec![bind(&engine), member_cert(&root, &root_pub, Some(&forest))];
    engine.commit_member_write(batch).unwrap();
    assert!(engine.certificates_bound().unwrap().is_some());
    engine.close().unwrap();
    Engine::open(dir.path()).expect("the owner took only what a follower replays").close().unwrap();
}

#[test]
fn only_the_root_or_an_admin_binds() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, mn) = Engine::init_unbound(dir.path()).unwrap();
    let member = identity::generate_device_key();
    let member_pub = crypto::pubkey_bytes(&member);
    engine.authorize_member(&mn, &member_pub).unwrap(); // a member, not an admin

    assert!(engine.prepare_bind_certificates(&member_pub).is_err(), "a member may not bind");
    let t = now_ms();
    let sig = crypto::sign_digest(&member, &event::msg_certs_bound(&engine.identity.forest_id, t, &member_pub)).unwrap();
    let forged = Event::CertificatesBound { at: t, author: member_pub, sig };
    assert!(is_refused(engine.commit_member_write(vec![forged])), "nor commit one it signed itself");
    assert_eq!(engine.certificates_bound().unwrap(), None);

    // a binding signed for another forest is refused even from the root
    let (root, root_pub) = root_of(&mn);
    let sig = crypto::sign_digest(&root, &event::msg_certs_bound("another-forest", t, &root_pub)).unwrap();
    let elsewhere = Event::CertificatesBound { at: t, author: root_pub.clone(), sig };
    assert!(is_refused(engine.commit_member_write(vec![elsewhere])));

    // the root may
    let mut p = engine.prepare_bind_certificates(&root_pub).unwrap().events.remove(0);
    p.event.set_author_sig(crypto::sign_digest(&root, &p.digest).unwrap());
    engine.commit_member_write(vec![p.event]).unwrap();
    assert!(engine.certificates_bound().unwrap().is_some());
    assert!(engine.prepare_bind_certificates(&root_pub).is_err(), "nothing left to bind");
    engine.close().unwrap();
}
