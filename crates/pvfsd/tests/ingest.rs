//! P10.0 end-to-end (doc 23 §3/§9): a real `pvfsd` over a Unix socket runs a
//! whole external-ingest session — catalog-at-add, out-of-order writes,
//! verified-range chunk marking, commit through hash-fill + attest + publish,
//! the closing record, and the abort path.

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::{Client, ClientError};
use pvfs_core::acl::{self, Principal};
use pvfs_core::sync::SWARM_CHUNK;
use pvfs_core::{crypto, identity, Engine, NodeSpec, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

fn folder(label: &str) -> NodeSpec {
    NodeSpec {
        node_type: TYPE_FOLDER.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    }
}

fn bytes(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
}

fn forbidden<T>(r: Result<T, ClientError>) -> bool {
    matches!(r, Err(ClientError::Server { code, .. }) if code == "forbidden")
}

#[test]
fn ingest_session_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let media = engine.add_node(&root, folder("media")).unwrap();

    // The BT-app identity: admin tier on its target subtree (doc 23 §9.5).
    let app_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let app_pub = crypto::pubkey_bytes(&app_key);
    engine.authorize_member(&owner_mn, &app_pub).unwrap();
    engine
        .set_acl(&media, &Principal::Key(app_pub.clone()), acl::ACL_RWA)
        .unwrap();
    // A member with no rights on media — the begin gate must refuse it.
    let other_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let other_pub = crypto::pubkey_bytes(&other_key);
    engine.authorize_member(&owner_mn, &other_pub).unwrap();

    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("pvfsd.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = Arc::new(Daemon::new(engine));
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }
    let mut app = Client::connect_signed(&sock, &app_pub, |d| {
        crypto::sign_digest(&app_key, d).unwrap()
    })
    .unwrap();
    let sign = |d: &[u8; 32]| crypto::sign_digest(&app_key, d).unwrap();

    // ---- begin: catalog a two-file "torrent" in one commit -------------------
    let a_size = (SWARM_CHUNK + SWARM_CHUNK / 2) as usize; // 12 MiB → 2 chunks
    let b_size = 1000usize;
    let s = app
        .ingest_begin(
            &media,
            "pack",
            "bittorrent",
            "aa11bb22cc33dd44ee55",
            262_144,
            &[("d/a.bin".to_string(), a_size as u64), ("b.bin".to_string(), b_size as u64)],
            false,
            sign,
        )
        .unwrap();
    assert_eq!(s.files.len(), 2);
    let node_a = s.files[0].node.clone();
    let node_b = s.files[1].node.clone();

    // The tree exists before any byte: media/{pack/{d/a.bin, b.bin}} plus the
    // origin record beside pack.
    let media_kids = app.ls(&media).unwrap();
    let labels: Vec<&str> = media_kids.iter().map(|c| c.label.as_str()).collect();
    assert!(labels.contains(&"pack"), "torrent folder cataloged: {labels:?}");
    assert!(
        media_kids
            .iter()
            .any(|c| c.node_type == "pvos.download" && c.label.starts_with(".pvos.download-")),
        "origin record cataloged: {labels:?}"
    );
    let origin_payload = app.payload(&s.origin).unwrap();
    let origin_json = String::from_utf8(origin_payload).unwrap();
    assert!(origin_json.contains("\"infohash\":\"aa11bb22cc33dd44ee55\""));
    assert!(origin_json.contains(&format!("\"root\":\"{}\"", s.root)));

    // A member without w on media is refused at begin.
    let mut other = Client::connect_signed(&sock, &other_pub, |d| {
        crypto::sign_digest(&other_key, d).unwrap()
    })
    .unwrap();
    assert!(forbidden(other.ingest_begin(
        &media,
        "x",
        "bittorrent",
        "beef",
        1,
        &[("y.bin".to_string(), 10)],
        false,
        |d| crypto::sign_digest(&other_key, d).unwrap(),
    )));

    // An absurd declared size refuses loudly (§8.3) …
    let huge = 1u64 << 60;
    let refused = app.ingest_begin(
        &media,
        "big",
        "bittorrent",
        "beef",
        1,
        &[("z.bin".to_string(), huge)],
        false,
        sign,
    );
    assert!(
        matches!(&refused, Err(ClientError::Server { code, message })
            if code == "bad_input" && message.contains("allow_shortfall")),
        "expected the space refusal, got {refused:?}"
    );
    // … and allow_shortfall accepts the caller's risk. Abort it: closing
    // record, subtree unlinked, nothing left behind.
    let big = app
        .ingest_begin(
            &media,
            "big",
            "bittorrent",
            "beef",
            1,
            &[("z.bin".to_string(), huge)],
            true,
            sign,
        )
        .unwrap();
    app.ingest_abort(&big.session, false, sign).unwrap();
    let media_kids = app.ls(&media).unwrap();
    assert!(
        !media_kids.iter().any(|c| c.label == "big"),
        "aborted subtree unlinked"
    );
    let closed = media_kids
        .iter()
        .find(|c| c.node_type == "pvos.download.closed")
        .expect("closing record cataloged");
    let closed_json = String::from_utf8(app.payload(&closed.id).unwrap()).unwrap();
    assert!(closed_json.contains("\"outcome\":\"aborted\""));
    assert!(closed_json.contains(&format!("\"origin\":\"{}\"", big.origin)));

    // ---- bytes, out of order; verified ranges mark chunks --------------------
    let data_a = bytes(a_size);
    let data_b = bytes(b_size);
    let half = a_size / 2;
    // second half first, then the first half — the partial is sparse
    assert_eq!(
        app.ingest_write(&s.session, &node_a, half as u64, &data_a[half..]).unwrap(),
        (a_size - half) as u64
    );
    assert_eq!(
        app.ingest_write(&s.session, &node_a, 0, &data_a[..half]).unwrap(),
        half as u64
    );
    assert_eq!(
        app.ingest_write(&s.session, &node_b, 0, &data_b).unwrap(),
        b_size as u64
    );
    // writes past the declared size are refused
    let over = app.ingest_write(&s.session, &node_b, b_size as u64 - 1, &[1, 2, 3]);
    assert!(matches!(over, Err(ClientError::Server { code, .. }) if code == "bad_input"));

    // chunk 0 covers only when its whole span is verified
    let (v, done, total) = app
        .ingest_verified(&s.session, &node_a, &[(0, SWARM_CHUNK / 2)])
        .unwrap();
    assert_eq!((v, done, total), (SWARM_CHUNK / 2, 0, 2));
    let (_, done, _) = app
        .ingest_verified(&s.session, &node_a, &[(SWARM_CHUNK / 2, SWARM_CHUNK)])
        .unwrap();
    assert_eq!(done, 1, "chunk 0 marked once fully covered");
    let (v, done, _) = app
        .ingest_verified(&s.session, &node_a, &[(SWARM_CHUNK, a_size as u64)])
        .unwrap();
    assert_eq!((v, done), (a_size as u64, 2));
    app.ingest_verified(&s.session, &node_b, &[(0, b_size as u64)]).unwrap();

    // list reflects the progress
    let sessions = app.ingest_list().unwrap();
    assert_eq!(sessions.len(), 1);
    let fa = sessions[0].files.iter().find(|f| f.node == node_a).unwrap();
    assert_eq!((fa.bytes_verified, fa.chunks_done, fa.chunks_total), (a_size as u64, 2, 2));

    // ---- commit: hash-fill + attest + publish; last file closes --------------
    let new_a = app.ingest_commit(&s.session, &node_a, sign).unwrap();
    assert_ne!(new_a, node_a, "hash-fill re-identifies the node");
    let mut got = Vec::new();
    app.cat(&new_a, &mut got).unwrap();
    assert_eq!(got, data_a, "published bytes round-trip");
    // not the last file yet — no complete record
    assert!(
        !app.ls(&media)
            .unwrap()
            .iter()
            .filter(|c| c.node_type == "pvos.download.closed")
            .any(|c| {
                let j = String::from_utf8(app.payload(&c.id).unwrap()).unwrap();
                j.contains("\"outcome\":\"complete\"")
            }),
        "no complete record before the last file"
    );

    let new_b = app.ingest_commit(&s.session, &node_b, sign).unwrap();
    let mut got = Vec::new();
    app.cat(&new_b, &mut got).unwrap();
    assert_eq!(got, data_b);

    // the session's deployment state is gone; the ledger is closed complete
    assert!(app.ingest_list().unwrap().is_empty(), "session dropped at commit");
    let complete = app
        .ls(&media)
        .unwrap()
        .iter()
        .filter(|c| c.node_type == "pvos.download.closed")
        .map(|c| String::from_utf8(app.payload(&c.id).unwrap()).unwrap())
        .find(|j| j.contains("\"outcome\":\"complete\""))
        .expect("complete record cataloged");
    assert!(complete.contains(&format!("\"origin\":\"{}\"", s.origin)));

    // list is member-gated
    let mut anon = Client::connect_public(&sock).unwrap();
    assert!(forbidden(anon.ingest_list()));
}

// P10.1 (doc 23 §11): in-flight reads go through ranged Cat — marked chunks
// serve immediately, unmarked ranges BLOCK server-side and surface as hot
// ranges in IngestList (the §8.1 demand signal), and the early-serve license
// (origin author holds admin) gates it all.
#[test]
fn inflight_reads_wait_and_surface_demand() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let media = engine.add_node(&root, folder("media")).unwrap();

    let app_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let app_pub = crypto::pubkey_bytes(&app_key);
    engine.authorize_member(&owner_mn, &app_pub).unwrap();
    engine
        .set_acl(&media, &Principal::Key(app_pub.clone()), acl::ACL_RWA)
        .unwrap();
    // a viewer with read only, and a w-only ingester (license-negative case)
    let viewer_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let viewer_pub = crypto::pubkey_bytes(&viewer_key);
    engine.authorize_member(&owner_mn, &viewer_pub).unwrap();
    engine
        .set_acl(&media, &Principal::Key(viewer_pub.clone()), acl::ACL_R)
        .unwrap();
    let wonly_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let wonly_pub = crypto::pubkey_bytes(&wonly_key);
    engine.authorize_member(&owner_mn, &wonly_pub).unwrap();
    engine
        .set_acl(&media, &Principal::Key(wonly_pub.clone()), acl::ACL_R | acl::ACL_W)
        .unwrap();

    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("pvfsd.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = Arc::new(Daemon::new(engine));
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }
    let mut app = Client::connect_signed(&sock, &app_pub, |d| {
        crypto::sign_digest(&app_key, d).unwrap()
    })
    .unwrap();
    let sign = |d: &[u8; 32]| crypto::sign_digest(&app_key, d).unwrap();

    let size = (SWARM_CHUNK * 2) as usize; // exactly 2 chunks
    let data = bytes(size);
    let s = app
        .ingest_begin(
            &media,
            "",
            "bittorrent",
            "feedc0de",
            262_144,
            &[("show.bin".to_string(), size as u64)],
            false,
            sign,
        )
        .unwrap();
    let node = s.files[0].node.clone();

    // out of order: only chunk 1 is written + verified
    let half = SWARM_CHUNK as usize;
    app.ingest_write(&s.session, &node, half as u64, &data[half..]).unwrap();
    app.ingest_verified(&s.session, &node, &[(SWARM_CHUNK, size as u64)]).unwrap();

    // a marked chunk serves immediately (the third-box seed path)
    let mut viewer = Client::connect_signed(&sock, &viewer_pub, |d| {
        crypto::sign_digest(&viewer_key, d).unwrap()
    })
    .unwrap();
    let mut got = Vec::new();
    viewer
        .cat_range(&node, SWARM_CHUNK, 1024, &mut got)
        .unwrap();
    assert_eq!(got, data[half..half + 1024], "marked chunk served mid-ingest");

    // an UNMARKED range blocks server-side…
    let reader = {
        let sock = sock.clone();
        let viewer_key = viewer_key.clone();
        let viewer_pub = viewer_pub.clone();
        let node = node.clone();
        std::thread::spawn(move || {
            let mut c = Client::connect_signed(&sock, &viewer_pub, |d| {
                crypto::sign_digest(&viewer_key, d).unwrap()
            })
            .unwrap();
            let mut buf = Vec::new();
            c.cat_range(&node, 0, 2048, &mut buf).map(|_| buf)
        })
    };
    // …and surfaces as a hot range in IngestList (§8.1 demand feedback)
    let mut hot_seen = Vec::new();
    for _ in 0..100 {
        let sessions = app.ingest_list().unwrap();
        if let Some(f) = sessions
            .iter()
            .flat_map(|s| s.files.iter())
            .find(|f| f.node == node)
        {
            if !f.hot.is_empty() {
                hot_seen = f.hot.clone();
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert_eq!(hot_seen, vec![(0, 2048)], "blocked reader surfaced as demand");

    // the app supplies the demanded bytes → the reader unblocks, correct
    app.ingest_write(&s.session, &node, 0, &data[..half]).unwrap();
    app.ingest_verified(&s.session, &node, &[(0, SWARM_CHUNK)]).unwrap();
    let got = reader.join().unwrap().expect("blocked read completed");
    assert_eq!(got, data[..2048], "waited bytes are the right bytes");
    // the wait is gone from the demand report
    let sessions = app.ingest_list().unwrap();
    let f = sessions
        .iter()
        .flat_map(|s| s.files.iter())
        .find(|f| f.node == node)
        .unwrap();
    assert!(f.hot.is_empty(), "served wait no longer reported");

    // license-negative: a w-only member's session is not early-servable
    let mut wonly = Client::connect_signed(&sock, &wonly_pub, |d| {
        crypto::sign_digest(&wonly_key, d).unwrap()
    })
    .unwrap();
    let s2 = wonly
        .ingest_begin(
            &media,
            "",
            "bittorrent",
            "0badc0de",
            262_144,
            &[("nolic.bin".to_string(), 1024)],
            false,
            |d| crypto::sign_digest(&wonly_key, d).unwrap(),
        )
        .unwrap();
    let n2 = s2.files[0].node.clone();
    wonly.ingest_write(&s2.session, &n2, 0, &bytes(1024)).unwrap();
    wonly.ingest_verified(&s2.session, &n2, &[(0, 1024)]).unwrap();
    let mut buf = Vec::new();
    assert!(
        forbidden(viewer.cat_range(&n2, 0, 512, &mut buf)),
        "early-serve refused without the admin-tier origin author"
    );
}
