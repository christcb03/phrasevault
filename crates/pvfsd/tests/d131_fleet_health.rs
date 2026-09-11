//! D131 item 1 — a probe reads a peer's health over the member-gated dial
//! and refuses a foreign forest; the record calls a peer down only on the
//! second consecutive miss, dated from the first, and clears on an answer.

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::health::{probe_peer, FleetHealth, PeerHealth, DOWN_AFTER};
use pvfs_core::{crypto, identity, Engine, ReplicaSource};
use pvfsd::{serve, Daemon};

#[test]
fn a_probe_reads_health_and_the_record_needs_two_misses_to_call_down() {
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let dir = tempfile::tempdir().unwrap();
    let (mut owner, mn) = Engine::init(dir.path()).unwrap();
    let forest = owner.identity.forest_id.clone();
    // The probing identity is a member (serve status is member-gated).
    let me_key = identity::device_key(&identity::client_identity_mnemonic().unwrap(), "", 0).unwrap();
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
    let src = ReplicaSource {
        transport: "socket".into(),
        target: sock.to_string_lossy().into_owned(),
        pin: String::new(),
        region: String::new(),
    };

    let h = probe_peer(&src, &forest);
    assert!(h.reachable && h.forest_ok, "{h:?}");
    assert!(h.ok());
    assert_eq!(h.runner, "off", "a daemon without a runner says so");
    assert_eq!((h.conflicts, h.stale), (0, 0));
    let (free, total) = h.capacity.expect("capacity measured");
    assert!(total > 0 && free <= total);

    let foreign = probe_peer(&src, &"ff".repeat(32));
    assert!(foreign.reachable && !foreign.forest_ok && !foreign.ok());
    assert!(foreign.error.as_deref().unwrap_or("").contains("not ours"));

    let dead = ReplicaSource {
        transport: "socket".into(),
        target: sockdir.path().join("nobody.sock").to_string_lossy().into_owned(),
        pin: String::new(),
        region: String::new(),
    };
    let gone = probe_peer(&dead, &forest);
    assert!(!gone.reachable && gone.error.is_some());

    // The record: one miss is not down (a restart); two are, dated from the first.
    let mut rec = FleetHealth::default();
    let pin = "ab".repeat(32);
    rec.observe(&pin, "10.0.0.2:7421", Some("pvfs 1.4.0".into()), 1_000, h.clone());
    assert!(!rec.peers[&pin].is_down() && rec.peers[&pin].last_ok_ms == Some(1_000));
    rec.observe(&pin, "10.0.0.2:7421", None, 2_000, gone.clone());
    assert!(!rec.peers[&pin].is_down(), "one miss is a restart, not an outage");
    assert_eq!(rec.peers[&pin].unreachable_since_ms, Some(2_000));
    assert_eq!(rec.peers[&pin].misses, 1);
    rec.observe(&pin, "10.0.0.2:7421", None, 3_000, gone.clone());
    assert!(rec.peers[&pin].is_down());
    assert_eq!(rec.peers[&pin].misses, DOWN_AFTER);
    assert_eq!(rec.peers[&pin].unreachable_since_ms, Some(2_000), "dated from the FIRST miss");
    assert_eq!(rec.down().len(), 1);
    assert_eq!(rec.peers[&pin].version.as_deref(), Some("pvfs 1.4.0"), "a version survives a miss");
    rec.observe(&pin, "10.0.0.2:7421", None, 4_000, h.clone());
    assert!(!rec.peers[&pin].is_down() && rec.peers[&pin].unreachable_since_ms.is_none());
    assert_eq!(rec.peers[&pin].last_ok_ms, Some(4_000));

    // Save/load round-trips through the data dir.
    let store = tempfile::tempdir().unwrap();
    rec.save(store.path()).unwrap();
    let back = FleetHealth::load(store.path()).unwrap().expect("saved");
    assert_eq!(back, rec);
    assert!(FleetHealth::load(sockdir.path()).unwrap().is_none(), "no record = None");
    let _ = PeerHealth::default();
}
