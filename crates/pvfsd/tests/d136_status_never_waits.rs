//! D136 — the health probe (`serve status`) answers while the daemon's
//! WRITER lock is held for a long time. Chris's rule (2026-09-11): silence
//! means down, so a live daemon that is working must always answer; the
//! probe's counts therefore read through the pool, never the writer.

use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pvfs_client::Client;
use pvfs_core::{crypto, identity, Engine};
use pvfsd::{serve, Daemon};

#[test]
fn serve_status_answers_while_the_writer_lock_is_held() {
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let dir = tempfile::tempdir().unwrap();
    let (mut owner, mn) = Engine::init(dir.path()).unwrap();
    let me_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let me_pub = crypto::pubkey_bytes(&me_key);
    owner.authorize_member(&mn, &me_pub).unwrap();

    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = Arc::new(Daemon::new(owner));
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }
    let mut member = Client::connect_signed(&sock, &me_pub, |d| crypto::sign_digest(&me_key, d).unwrap()).unwrap();
    // Premise: the probe works at all.
    let st = member.serve_status_full().unwrap();
    assert_eq!(st.runner, "off");

    // A "long write": the writer lock held for 6 s from another thread.
    let hold = {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let guard = d.hold_writer_for_test();
            std::thread::sleep(Duration::from_secs(6));
            drop(guard);
        })
    };
    std::thread::sleep(Duration::from_millis(300)); // let the holder take it
    let t = Instant::now();
    let st = member.serve_status_full().expect("the probe must answer under a held writer");
    let took = t.elapsed();
    assert!(took < Duration::from_secs(2), "serve status waited on the writer: {took:?}");
    assert_eq!((st.conflicts, st.stale), (0, 0));
    assert!(st.capacity.is_some());
    hold.join().unwrap();
    // And a read after the hold is released still works.
    assert!(member.serve_status_full().is_ok());
}
