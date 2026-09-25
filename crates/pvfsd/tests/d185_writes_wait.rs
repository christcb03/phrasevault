//! PVOS D185 — an owner that has just started serves reads at once and takes
//! no write from the network until its first health pass (D182's fence) has
//! heard its followers. Before D185 the whole listener waited — a stall a
//! holder-owner's peers would feel on every restart, since they read its
//! regions' files over that listener. The Unix socket, this box's own
//! operator, is never held.

use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::Arc;

use pvfs_client::{Client, ClientError};
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, Engine};
use pvfsd::{serve, serve_connection, Daemon};

/// Serve `daemon` on a fresh Unix socket — as the local socket does, or as
/// the network listener does (`local = false`; TLS is only its wrapper and
/// plays no part in the gate).
fn listen(daemon: Arc<Daemon>, local: bool) -> (tempfile::TempDir, PathBuf) {
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || {
        if local {
            let _ = serve(listener, daemon);
        } else {
            for stream in listener.incoming().flatten() {
                let d = Arc::clone(&daemon);
                std::thread::spawn(move || {
                    let _ = serve_connection(&d, stream, false);
                });
            }
        }
    });
    (sockdir, sock)
}

#[test]
fn a_starting_owner_serves_reads_and_holds_network_writes_until_its_first_pass() {
    let dir = tempfile::tempdir().unwrap();
    let (mut owner, mn) = Engine::init(dir.path()).unwrap();
    let root = owner.identity.root_node_id.clone();
    let key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let public = crypto::pubkey_bytes(&key);
    owner.authorize_member(&mn, &public).unwrap();
    owner.set_acl(&root, &Principal::Key(public.clone()), acl::ACL_RWA).unwrap();
    let data = owner.data_dir().to_path_buf();
    let daemon = Arc::new(Daemon::new(owner));
    // What pvfsd's main() does for an owner with a listener, until the first
    // health pass (or 30 s) has gone by.
    daemon.hold_network_writes(true);
    let (_net_dir, net) = listen(Arc::clone(&daemon), false);
    let (_local_dir, local) = listen(Arc::clone(&daemon), true);

    let k = key.clone();
    let mut peer = Client::connect_signed(&net, &public, move |d| crypto::sign_digest(&k, d).unwrap()).unwrap();

    // Reads go on.
    assert!(peer.ls(&root).is_ok(), "a read is served while the owner starts");

    // A routed write waits: `busy`, the answer a replica retries.
    match peer.mkdir(&root, "while-starting", |d| crypto::sign_digest(&key, d).unwrap()) {
        Err(ClientError::Server { code, message }) => {
            assert_eq!(code, "busy");
            assert!(message.contains("hears its followers"), "{message}");
        }
        other => panic!("expected the write held, got {other:?}"),
    }
    let tip = pvfs_core::mount::peek_tip(&data).unwrap().0;

    // This box's own operator — the Unix socket — is never held.
    let k = key.clone();
    let mut operator = Client::connect_signed(&local, &public, move |d| crypto::sign_digest(&k, d).unwrap()).unwrap();
    operator.mkdir(&root, "operator", |d| crypto::sign_digest(&key, d).unwrap()).unwrap();
    assert!(pvfs_core::mount::peek_tip(&data).unwrap().0 > tip);

    // The first pass done, the network write lands.
    daemon.hold_network_writes(false);
    peer.mkdir(&root, "after-the-pass", |d| crypto::sign_digest(&key, d).unwrap()).unwrap();
    assert!(!daemon.network_writes_held());
}
