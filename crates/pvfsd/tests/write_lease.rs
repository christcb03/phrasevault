//! PVOS D67 C3 — the control-plane write lease.
//!
//! The invariant: while one connection holds a lease over a subtree, no OTHER
//! connection may write under it, however well-authorized it is. This is what
//! turns "one authority per served forest" from a convention the CLI honours
//! into something the storage daemon enforces.
//!
//! The bug it exists to prevent, concretely: `pvos grant` run offline wrote a
//! real record into a forest a running daemon was serving from a cached fold,
//! so the record read EFFECTIVE while the daemon went on denying — and the
//! same path on `revoke` failed OPEN.

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::Client;
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, Engine};
use pvfsd::{serve, Daemon};

#[test]
fn lease_refuses_other_connections_and_dies_with_its_holder() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    // The OWNER key: the point of the lease is that owner-authenticated
    // writes are refused, so the intruder below is exactly as privileged as
    // the holder. Identity cannot separate them — only the connection can.
    let key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let pubkey = crypto::pubkey_bytes(&key);
    engine.authorize_member(&owner_mn, &pubkey).unwrap();
    // Enrolment is not authority: give the key rw on the root so every write
    // below is refused (or allowed) by the LEASE, never by an ACL.
    engine
        .set_acl(&root, &Principal::Key(pubkey.clone()), acl::ACL_R | acl::ACL_W)
        .unwrap();

    let daemon = Arc::new(Daemon::new(engine));
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("pvfsd.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }

    let sign = |d: &[u8; 32]| crypto::sign_digest(&key, d).unwrap();
    let connect = || Client::connect_signed(&sock, &pubkey, sign).unwrap();

    // The "control plane": one subtree the holder will claim.
    let mut holder = connect();
    let control = holder.mkdir(&root, "control", sign).unwrap();
    let elsewhere = holder.mkdir(&root, "elsewhere", sign).unwrap();

    // Before any lease a second connection writes freely. Asserted so this
    // test cannot pass because the write failed for an unrelated reason.
    {
        let mut other = connect();
        other
            .mkdir(&control, "before-lease", sign)
            .expect("no lease yet — the write is allowed");
    }

    holder.claim_write_lease(std::slice::from_ref(&control)).unwrap();

    // A second connection under the very same owner key is now refused.
    let mut intruder = connect();
    assert!(
        intruder.mkdir(&control, "sneaky", sign).is_err(),
        "an offline writer must be REFUSED under a leased subtree, not merely noticed"
    );

    // Scope is a subtree, not the forest. This is what keeps pvosd's own
    // per-member session connections working: member homes live outside the
    // leased control trees, so leasing must not reach them.
    intruder
        .mkdir(&elsewhere, "unaffected", sign)
        .expect("the lease covers its roots, not the whole forest");

    // The holder still writes where it holds the lease.
    holder
        .mkdir(&control, "holder-writes", sign)
        .expect("the holder is not locked out by its own lease");

    // Idempotent for the holder — a daemon reclaiming after a reconnect must
    // not lock itself out.
    holder.claim_write_lease(std::slice::from_ref(&control)).unwrap();

    // And it cannot be stolen while the holder lives.
    assert!(
        intruder.claim_write_lease(std::slice::from_ref(&control)).is_err(),
        "the lease is exclusive while its holder is alive"
    );

    // Dropping the holder releases it: a crashed daemon must never leave a
    // forest nobody can write.
    drop(holder);
    // The release runs as the server-side connection scope unwinds; wait for
    // that rather than racing it.
    let mut freed = false;
    for _ in 0..40 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut after = connect();
        if after.mkdir(&control, "after-release", sign).is_ok() {
            freed = true;
            break;
        }
    }
    assert!(freed, "the lease must die with its holder");
}

/// PVOS D235 — the lease blocks every other writer under its roots, so a key
/// that may not write each of them is refused it. Any authenticated key
/// could take it before (D218 §2.2): a member with read rights only, or a
/// key the forest has never enrolled.
#[test]
fn a_key_that_may_not_write_the_roots_cannot_take_the_lease() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let key = || identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let (writer, reader, stranger) = (key(), key(), key());
    for (k, rights) in [(&writer, acl::ACL_R | acl::ACL_W), (&reader, acl::ACL_R)] {
        let pk = crypto::pubkey_bytes(k);
        engine.authorize_member(&owner_mn, &pk).unwrap();
        engine.set_acl(&root, &Principal::Key(pk), rights).unwrap();
    }

    let daemon = Arc::new(Daemon::new(engine));
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("pvfsd.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }
    let connect = |k: &identity::SigningKey| {
        let pk = crypto::pubkey_bytes(k);
        Client::connect_signed(&sock, &pk, |d| crypto::sign_digest(k, d).unwrap()).unwrap()
    };

    let mut r = connect(&reader);
    assert!(r.claim_write_lease(std::slice::from_ref(&root)).is_err(), "a member that may only read is refused");
    let mut s = connect(&stranger);
    assert!(s.claim_write_lease(std::slice::from_ref(&root)).is_err(), "a key the forest never enrolled is refused");
    let mut w = connect(&writer);
    w.claim_write_lease(std::slice::from_ref(&root)).expect("a key that may write every root takes it");
}

/// PVOS D265 — three writes got past the lease: events delivered already
/// signed (`CommitSigned` never asked), a move OUT of a leased subtree (only
/// the destination was checked), and a purge whose first id was unleased
/// (only the first was checked). The intruder holds the holder's own rights,
/// so only the lease can refuse it.
#[test]
fn a_signed_event_a_move_or_a_purge_cannot_get_past_the_lease() {
    use pvfs_core::personal::attach_sigs;
    use pvfs_core::NodeSpec;
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let pubkey = crypto::pubkey_bytes(&key);
    engine.authorize_member(&owner_mn, &pubkey).unwrap();
    // Admin too, so the purge is refused by the lease and not by its ACL.
    engine.set_acl(&root, &Principal::Key(pubkey.clone()), acl::ACL_RWA).unwrap();
    let folder = |label: &str| NodeSpec {
        node_type: "folder".into(),
        label: label.into(),
        payload: vec![],
        is_temp: false,
        creation_nonce: None,
    };
    let control = engine.add_node(&root, folder("control")).unwrap();
    let elsewhere = engine.add_node(&root, folder("elsewhere")).unwrap();
    let inside = engine.add_node(&control, folder("inside")).unwrap();
    let outside = engine.add_node(&root, folder("outside")).unwrap();
    // Events for a node under the leased subtree, signed by the key, as a
    // routed write or an offline signer would deliver them.
    let prepared = engine.prepare_add_node(&pubkey, &control, folder("delivered")).unwrap();
    let sigs = prepared.events.iter().map(|p| crypto::sign_digest(&key, &p.digest).unwrap()).collect();
    let signed = attach_sigs(prepared.events, sigs).unwrap();

    let daemon = Arc::new(Daemon::new(engine));
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("pvfsd.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }
    let sign = |d: &[u8; 32]| crypto::sign_digest(&key, d).unwrap();
    let connect = || Client::connect_signed(&sock, &pubkey, sign).unwrap();
    let mut holder = connect();
    holder.claim_write_lease(std::slice::from_ref(&control)).unwrap();
    let mut intruder = connect();
    let leased = |e: pvfs_client::ClientError| {
        let m = e.to_string();
        assert!(m.contains("write lease"), "refused by the lease, not something else: {m}");
    };

    // 1. Signed events under the leased subtree: refused for the intruder;
    //    the holder delivers the very same events, so they were valid.
    leased(intruder.commit_signed(&signed).expect_err("pre-signed events under a lease"));
    holder.commit_signed(&signed).expect("the holder lands them");
    let names = |c: &mut Client, n: &str| c.ls(n).unwrap().into_iter().map(|x| x.label).collect::<Vec<_>>();
    assert!(names(&mut holder, &control).contains(&"delivered".to_string()));

    // 2. A move OUT of the leased subtree.
    leased(intruder.mv(&inside, &elsewhere, sign).expect_err("a move out of a leased subtree"));
    assert!(names(&mut holder, &control).contains(&"inside".to_string()), "it did not move");

    // 3. A purge whose first id is outside the lease.
    leased(intruder.purge(&[outside.clone(), inside.clone()], sign).expect_err("a purge reaching into the lease"));
    assert!(names(&mut holder, &root).contains(&"outside".to_string()), "nothing was purged");
    assert!(names(&mut holder, &control).contains(&"inside".to_string()));

    // The unleased half alone is still the intruder's to write.
    intruder.mv(&outside, &elsewhere, sign).expect("a move outside the lease is not refused");
    // And the holder may move what it leases.
    holder.mv(&inside, &elsewhere, sign).expect("the holder moves out of its own lease");
}
