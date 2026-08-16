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
