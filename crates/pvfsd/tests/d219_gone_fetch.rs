//! PVOS D219 — the read-through tells "gone" from "out of reach". A file
//! every box asked says it does not hold (deleted or replaced since the
//! reader's catalogue last moved) is GONE: the fetch says so, and its reads
//! fail at once for a few seconds instead of asking every box again (ffprobe
//! retried nine times; each was a round of questions and a log line). A box
//! that cannot be dialed, or no box at all, proves nothing: not gone.

use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pvfs_client::hash_cache::{CacheOpts, HashCache, HashFetch, Opened};
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, BindSpec, Engine, HashPolicy, NodeSpec, ReplicaSource, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

const PIECE: u64 = 64 * 1024;

fn bytes(n: usize, salt: u64) -> Vec<u8> {
    (0..n as u64)
        .map(|i| (i.wrapping_add(salt).wrapping_mul(2_654_435_761).rotate_left(13) >> 7) as u8)
        .collect()
}

fn opts() -> CacheOpts {
    CacheOpts {
        piece: PIECE,
        max_readahead: 4 * PIECE,
        complete_after: 16 * PIECE,
        burst: 8 * PIECE,
        ..CacheOpts::default()
    }
}

fn stream(cache: &HashCache, hash: &str, size: u64) -> Arc<HashFetch> {
    match cache.open(hash, size).unwrap() {
        Opened::Stream(f) => f,
        Opened::Local(p) => panic!("not in the store yet, but got {}", p.display()),
    }
}

fn socket(path: &std::path::Path) -> ReplicaSource {
    ReplicaSource {
        transport: "socket".into(),
        target: path.to_string_lossy().into_owned(),
        pin: String::new(),
        region: String::new(),
    }
}

#[test]
fn every_box_saying_no_is_gone_fails_fast_then_asks_again_and_out_of_reach_is_not_gone() {
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let tmp = tempfile::tempdir().unwrap();

    // ---- the holder: one episode, catalogued, then deleted behind its back
    let files = tmp.path().join("files");
    std::fs::create_dir_all(files.join("TV")).unwrap();
    let ep = bytes(5 * PIECE as usize + 77, 3);
    let path = files.join("TV/ep.mkv");
    std::fs::write(&path, &ep).unwrap();
    let hash = blake3::hash(&ep).to_hex().to_string();
    let (mut holder, mn) = Engine::init(tmp.path().join("holder").as_path()).unwrap();
    let root = holder.identity.root_node_id.clone();
    let lib = holder
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "Library".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    holder.region_mark_as(&lib, "catalogue", None).unwrap();
    holder
        .bind_folder(
            &lib,
            BindSpec {
                source_uri: format!("file://{}", files.display()),
                recursive: true,
                auto_index: true,
                extensions: String::new(),
                hash_policy: HashPolicy::OnAdd,
            },
        )
        .unwrap();
    holder.scan_routed(Some(&lib), None, 0).unwrap();
    assert!(holder.local_path_for_hash(&hash).unwrap().is_some(), "premise: the scan hashed it");
    let me = identity::device_key(&identity::client_identity_mnemonic().unwrap(), "", 0).unwrap();
    let me_pub = crypto::pubkey_bytes(&me);
    holder.authorize_member(&mn, &me_pub).unwrap();
    holder.set_acl(&root, &Principal::Key(me_pub), acl::ACL_R).unwrap();
    let sock = tmp.path().join("holder.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = Arc::new(Daemon::new(holder));
    std::thread::spawn(move || {
        let _ = serve(listener, daemon);
    });
    // Sonarr's upgrade, as the holder sees it: the file is no longer there
    // (its row stays until the watch pass this test never runs).
    let aside = tmp.path().join("aside.mkv");
    std::fs::rename(&path, &aside).unwrap();

    let reader = |sources: Vec<ReplicaSource>| {
        let dir = tempfile::tempdir().unwrap();
        let (e, _) = Engine::init(dir.path()).unwrap();
        e.close().unwrap();
        let cache = HashCache::with_sources(dir.path(), opts(), sources);
        (dir, cache)
    };

    // ---- every box asked says no: gone
    let (_d1, cache) = reader(vec![socket(&sock)]);
    let f = stream(&cache, &hash, ep.len() as u64);
    assert!(f.read_range(0, 4096, Duration::from_secs(20)).is_err(), "no box holds it");
    assert!(f.gone(), "every box said not_found: gone");

    // Back on the holder's disk — but the handle was told "gone" a moment
    // ago, so a read now fails at once without asking.
    std::fs::rename(&aside, &path).unwrap();
    let t = Instant::now();
    assert!(f.read_range(0, 4096, Duration::from_secs(20)).is_err(), "inside the rest: not asked again");
    assert!(t.elapsed() < Duration::from_secs(1), "failed at once ({:?})", t.elapsed());
    assert!(f.gone());

    // After the rest a read asks again, finds it, and is no longer gone.
    std::thread::sleep(Duration::from_millis(5_200));
    let got = f.read_range(0, 4096, Duration::from_secs(20)).expect("asked again after the rest");
    let mut buf = vec![0u8; 4096];
    std::os::unix::fs::FileExt::read_at(&std::fs::File::open(got).unwrap(), &mut buf, 0).unwrap();
    assert_eq!(buf, ep[..4096], "the bytes are the file's");
    assert!(!f.gone(), "a piece landed: not gone");
    std::fs::rename(&path, &aside).unwrap();

    // ---- a box that cannot be dialed: out of reach proves nothing
    let (_d2, cache) = reader(vec![socket(&sock), socket(&tmp.path().join("nobody.sock"))]);
    let f = stream(&cache, &hash, ep.len() as u64);
    assert!(f.read_range(0, 4096, Duration::from_secs(20)).is_err());
    assert!(!f.gone(), "one box was out of reach: not gone");
    assert!(f.error().is_some_and(|e| e.contains("nobody.sock")), "the error names it: {:?}", f.error());

    // ---- no box to ask at all: not gone either
    let (_d3, cache) = reader(Vec::new());
    let f = stream(&cache, &hash, ep.len() as u64);
    assert!(f.read_range(0, 4096, Duration::from_secs(20)).is_err());
    assert!(!f.gone(), "nobody asked: not gone");
}
