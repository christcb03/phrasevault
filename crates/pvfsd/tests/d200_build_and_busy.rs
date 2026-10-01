//! PVOS D200 — over a real socket:
//!
//! 1. `serve status` says the build the daemon runs, the owner's health probe
//!    records it, and the record keeps it through a missed probe;
//! 2. a routed write into an owner that answers `busy` (D185: just started,
//!    network writes held) is waited out on that code and lands;
//! 3. a connection that drops inside an answer fails the write at once, as a
//!    failure of the route (the pass fails and dials again) — not as a
//!    refusal of the write, and not retried on the dead connection. Its text,
//!    `failed to fill whole buffer`, holds none of the words the routed writer
//!    used to retry on.

use std::io::Write;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pvfs_client::advertise::RoutedScanWriter;
use pvfs_client::health::{probe_peer, FleetHealth, PeerHealth};
use pvfs_client::Client;
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, Engine, PvfsError, ReplicaSource, ScanWriter};
use pvfs_proto::{read_msg, write_msg, ClientMsg, ServerMsg};
use pvfsd::{serve, serve_connection, Daemon};

/// Serve `daemon` on a fresh Unix socket: as the local socket (`local`), or
/// as the network listener does (TLS is only its wrapper; D185's hold applies
/// to it).
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
fn serve_status_says_the_build_and_the_record_keeps_it() {
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let dir = tempfile::tempdir().unwrap();
    let (mut owner, mn) = Engine::init(dir.path()).unwrap();
    let forest = owner.identity.forest_id.clone();
    // The probe dials as the client identity, a member (serve status is
    // member-gated).
    let me_key = identity::device_key(&identity::client_identity_mnemonic().unwrap(), "", 0).unwrap();
    let me_pub = crypto::pubkey_bytes(&me_key);
    owner.authorize_member(&mn, &me_pub).unwrap();
    let (_d, sock) = listen(Arc::new(Daemon::new(owner)), true);

    let mut member =
        Client::connect_signed(&sock, &me_pub, |d| crypto::sign_digest(&me_key, d).unwrap()).unwrap();
    let st = member.serve_status_full().unwrap();
    assert_eq!(st.build.as_deref(), Some(env!("PVFS_BUILD")), "serve status says the daemon's build");

    let src = ReplicaSource {
        transport: "socket".into(),
        target: sock.to_string_lossy().into_owned(),
        pin: String::new(),
        region: String::new(),
    };
    let h = probe_peer(&src, &forest);
    assert!(h.ok(), "{h:?}");
    assert_eq!(h.build.as_deref(), Some(env!("PVFS_BUILD")), "the probe records it");

    // The record: the build survives a miss (a box that is down still shows
    // what it ran), and a new answer replaces it.
    let pin = "ab".repeat(32);
    let announced = Some(r#"{"pvfs":"1.4.0","proto":15,"schema":20}"#.to_string());
    let mut rec = FleetHealth::default();
    rec.observe(&pin, "10.0.0.2:7421", announced.clone(), 1_000, h.clone());
    assert_eq!(rec.peers[&pin].build.as_deref(), Some(env!("PVFS_BUILD")));
    let gone = PeerHealth { error: Some("connect: refused".into()), ..PeerHealth::default() };
    rec.observe(&pin, "10.0.0.2:7421", None, 2_000, gone.clone());
    rec.observe(&pin, "10.0.0.2:7421", None, 3_000, gone);
    assert!(rec.peers[&pin].is_down());
    assert_eq!(rec.peers[&pin].build.as_deref(), Some(env!("PVFS_BUILD")), "kept through the misses");
    assert_eq!(rec.peers[&pin].last.build, None, "`last` is this probe's, which heard nothing");
    let rolled = PeerHealth { build: Some("v1.4-999-gfeedbee".into()), ..h };
    rec.observe(&pin, "10.0.0.2:7421", None, 4_000, rolled);
    assert_eq!(rec.peers[&pin].build.as_deref(), Some("v1.4-999-gfeedbee"), "replaced when it answers");
    assert_eq!(rec.peers[&pin].version, announced, "the announced version is kept beside it");

    // Written and read back: the file carries it.
    let data = tempfile::tempdir().unwrap();
    rec.save(data.path()).unwrap();
    let back = FleetHealth::load(data.path()).unwrap().unwrap();
    assert_eq!(back.peers[&pin].build.as_deref(), Some("v1.4-999-gfeedbee"));
}

#[test]
fn a_busy_owner_is_waited_out_on_its_code() {
    let dir = tempfile::tempdir().unwrap();
    let (mut owner, mn) = Engine::init(dir.path()).unwrap();
    let root = owner.identity.root_node_id.clone();
    let key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let public = crypto::pubkey_bytes(&key);
    owner.authorize_member(&mn, &public).unwrap();
    owner.set_acl(&root, &Principal::Key(public.clone()), acl::ACL_RWA).unwrap();
    let daemon = Arc::new(Daemon::new(owner));
    // An owner that has just started: network writes answer `busy` (D185).
    daemon.hold_network_writes(true);
    let (_net_dir, net) = listen(Arc::clone(&daemon), false);

    let k = key.clone();
    let mut client = Client::connect_signed(&net, &public, move |d| crypto::sign_digest(&k, d).unwrap()).unwrap();
    // Its first pass heard, 1.5 s from now.
    let release = {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(1_500));
            d.hold_network_writes(false);
        })
    };
    let sign = move |d: &[u8; 32]| crypto::sign_digest(&key, d).unwrap();
    let signer: &dyn Fn(&[u8; 32]) -> Vec<u8> = &sign;
    let data = tempfile::tempdir().unwrap();
    let t = Instant::now();
    let made = RoutedScanWriter::new(data.path(), &mut client, signer).add_folder(&root, "after-the-wait");
    let took = t.elapsed();
    release.join().unwrap();
    let id = made.expect("the busy owner was waited out, and the write landed");
    assert!(took >= Duration::from_millis(1_400), "it waited for the owner: {took:?}");
    assert!(took < Duration::from_secs(10), "and no longer than the owner was busy: {took:?}");
    assert!(!id.is_empty());
    let names: Vec<String> = client.ls(&root).unwrap().into_iter().map(|c| c.label).collect();
    assert!(names.iter().any(|n| n == "after-the-wait"), "{names:?}");
}

/// A stand-in owner: it completes the handshake, reads the first request,
/// starts an answer and hangs up inside it — a daemon killed mid-reply.
/// Counts the requests it read.
fn hangs_up_mid_answer(sock: &Path, requests: Arc<AtomicU32>) -> std::thread::JoinHandle<()> {
    let listener = UnixListener::bind(sock).unwrap();
    std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let challenge = ServerMsg::Challenge {
            nonce: hex::encode([7u8; 16]),
            forest_id: "ab".repeat(32),
            expiry_ms: u64::MAX,
            version: pvfs_proto::PROTO_VERSION,
        };
        write_msg(&mut s, &challenge).unwrap();
        let _auth: Option<ClientMsg> = read_msg(&mut s).unwrap();
        write_msg(&mut s, &ServerMsg::Ready { principal: "key:ab".into() }).unwrap();
        if let Ok(Some(_)) = read_msg::<_, ClientMsg>(&mut s) {
            requests.fetch_add(1, Ordering::SeqCst);
        }
        // A frame that promises 100 bytes and delivers one, then EOF.
        let _ = s.write_all(&100u32.to_le_bytes());
        let _ = s.write_all(b"{");
        drop(s);
        // Anything that dials again finds nobody.
        drop(listener);
    })
}

#[test]
fn a_connection_that_drops_mid_answer_fails_the_pass_at_once() {
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("gone.sock");
    let requests = Arc::new(AtomicU32::new(0));
    let fake = hangs_up_mid_answer(&sock, Arc::clone(&requests));
    let key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let public = crypto::pubkey_bytes(&key);
    let k = key.clone();
    let mut client = Client::connect_signed(&sock, &public, move |d| crypto::sign_digest(&k, d).unwrap()).unwrap();
    let sign = move |d: &[u8; 32]| crypto::sign_digest(&key, d).unwrap();
    let signer: &dyn Fn(&[u8; 32]) -> Vec<u8> = &sign;
    let data = tempfile::tempdir().unwrap();

    let t = Instant::now();
    let r = RoutedScanWriter::new(data.path(), &mut client, signer).add_folder(&"cd".repeat(32), "never");
    let took = t.elapsed();
    fake.join().unwrap();
    match r {
        // Transient for the scan: the pass fails and the watch dials again.
        // Not `BadInput` (a refusal: the file would be quarantined and the
        // route kept), and not `Busy` (retried on a dead connection).
        Err(PvfsError::Io { source, .. }) => {
            assert_eq!(source.kind(), std::io::ErrorKind::UnexpectedEof, "{source}")
        }
        other => panic!("expected the route's failure (Io), got {other:?}"),
    }
    assert_eq!(requests.load(Ordering::SeqCst), 1, "one request reached the owner");
    assert!(took < Duration::from_secs(2), "nothing waited on the dead connection: {took:?}");
}
