//! D165 — the view mount's read-through cache against a real daemon: a probe
//! fetches the pieces it reads and not the file; a consumer ends up with the
//! whole file, verified and kept; closing early stops a completing fetch
//! after its grace unless it is nearly through; wrong bytes are refused and
//! the box named; one stream is enough for two files.

use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use pvfs_client::hash_cache::{CacheOpts, HashCache, HashFetch, Opened};
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, sync, BindSpec, Engine, HashPolicy, NodeSpec, ReplicaSource, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

const PIECE: u64 = 64 * 1024;
/// 40 whole pieces and a 1000-byte last one: the tail a probe reads is
/// exactly the last piece.
const BIG: usize = 40 * PIECE as usize + 1000;

struct Holder {
    src: ReplicaSource,
    big: (String, Vec<u8>),
    two: (String, Vec<u8>),
    bad: String,
    _keep: Vec<tempfile::TempDir>,
}

fn bytes(n: usize, salt: u64) -> Vec<u8> {
    (0..n as u64)
        .map(|i| (i.wrapping_add(salt).wrapping_mul(2_654_435_761).rotate_left(13) >> 7) as u8)
        .collect()
}

/// One daemon for every test in this binary: tests run on threads and the
/// client identity is resolved through the environment.
fn holder() -> &'static Holder {
    static H: OnceLock<Holder> = OnceLock::new();
    H.get_or_init(|| {
        let cfg = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_CONFIG_HOME", cfg.path());
        let dir = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(files.path().join("Shows")).unwrap();
        let big = bytes(BIG, 1);
        let two = bytes(9 * PIECE as usize + 17, 2);
        std::fs::write(files.path().join("Shows/big.mkv"), &big).unwrap();
        std::fs::write(files.path().join("Shows/two.mkv"), &two).unwrap();
        std::fs::write(files.path().join("Shows/bad.mkv"), b"beta").unwrap();

        let (mut owner, mn) = Engine::init(dir.path()).unwrap();
        let root = owner.identity.root_node_id.clone();
        let library = owner
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
        owner.region_mark_as(&library, "catalogue", None).unwrap();
        owner
            .bind_folder(
                &library,
                BindSpec {
                    source_uri: format!("file://{}", files.path().display()),
                    recursive: true,
                    auto_index: true,
                    extensions: String::new(),
                    hash_policy: HashPolicy::OnAdd,
                },
            )
            .unwrap();
        owner.scan_routed(Some(&library), None, 0).unwrap();
        let h_big = blake3::hash(&big).to_hex().to_string();
        assert!(owner.local_path_for_hash(&h_big).unwrap().is_some(), "premise: the scan hashed big.mkv");
        // The row says `beta`; the disk will say `bet!` — same size, other bytes.
        std::fs::write(files.path().join("Shows/bad.mkv"), b"bet!").unwrap();

        let me = identity::device_key(&identity::client_identity_mnemonic().unwrap(), "", 0).unwrap();
        let me_pub = crypto::pubkey_bytes(&me);
        owner.authorize_member(&mn, &me_pub).unwrap();
        owner.set_acl(&root, &Principal::Key(me_pub), acl::ACL_R).unwrap();

        let sockdir = tempfile::tempdir().unwrap();
        let sock = sockdir.path().join("d.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let daemon = Arc::new(Daemon::new(owner));
        std::thread::spawn(move || {
            let _ = serve(listener, daemon);
        });
        Holder {
            src: ReplicaSource {
                transport: "socket".into(),
                target: sock.to_string_lossy().into_owned(),
                pin: String::new(),
                region: String::new(),
            },
            big: (h_big, big),
            two: (blake3::hash(&two).to_hex().to_string(), two),
            bad: blake3::hash(b"beta").to_hex().to_string(),
            _keep: vec![cfg, dir, files, sockdir],
        }
    })
}

/// A box that reads through: any data dir will do, the store is per box.
fn reader(opts: CacheOpts) -> (tempfile::TempDir, HashCache) {
    let h = holder();
    let dir = tempfile::tempdir().unwrap();
    let (e, _) = Engine::init(dir.path()).unwrap();
    e.close().unwrap();
    let cache = HashCache::with_sources(dir.path(), opts, vec![h.src.clone()]);
    (dir, cache)
}

fn small() -> CacheOpts {
    CacheOpts {
        piece: PIECE,
        max_readahead: 4 * PIECE,
        complete_after: 16 * PIECE,
        burst: 8 * PIECE,
        ..CacheOpts::default()
    }
}

fn stream(cache: &HashCache, hash: &str, size: usize) -> Arc<HashFetch> {
    match cache.open(hash, size as u64).unwrap() {
        Opened::Stream(f) => f,
        Opened::Local(p) => panic!("not in the store yet, but got {}", p.display()),
    }
}

fn read(f: &Arc<HashFetch>, off: usize, len: usize) -> Vec<u8> {
    let path = f.read_range(off as u64, len as u64, Duration::from_secs(20)).expect("the read is served");
    let mut buf = vec![0u8; len];
    std::fs::File::open(path).unwrap().read_exact_at(&mut buf, off as u64).unwrap();
    buf
}

fn until(what: &str, limit: Duration, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + limit;
    while !ok() {
        assert!(Instant::now() < deadline, "never happened: {what}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn partial(dir: &Path, hash: &str) -> PathBuf {
    sync::hash_store_path(dir, hash).unwrap().with_extension("partial")
}

#[test]
fn a_probe_fetches_the_pieces_it_reads_not_the_file() {
    let (hash, data) = &holder().big;
    let (dir, cache) = reader(small());
    let f = stream(&cache, hash, BIG);
    assert_eq!(f.pieces_have(), 0, "open starts nothing");
    assert!(!f.worker_running());

    // What a media analysis reads: the last KB, then the first few dozen.
    assert_eq!(read(&f, BIG - 1000, 1000), data[BIG - 1000..]);
    assert_eq!((f.pieces_have(), f.fetched_bytes()), (1, 1000), "the tail costs the last piece");
    assert_eq!(read(&f, 0, 38_550), data[..38_550]);
    assert_eq!((f.pieces_have(), f.fetched_bytes()), (2, 1000 + PIECE), "the head costs the first");
    assert_eq!(f.pieces_total(), 41);

    // The application is done: the fetch ends at once, nothing is kept as
    // whole, and the partial waits for whoever reads next.
    f.handle_closed();
    until("the worker ends with the last handle", Duration::from_secs(3), || !f.worker_running());
    assert!(sync::hash_store_lookup(dir.path(), hash).unwrap().is_none());
    assert_eq!(std::fs::metadata(partial(dir.path(), hash)).unwrap().len(), BIG as u64);
    let again = stream(&cache, hash, BIG);
    assert!(Arc::ptr_eq(&f, &again), "a reopen takes the same fetch up");
    assert_eq!(read(&again, 100, 5000), data[100..5100]);
    assert_eq!(again.fetched_bytes(), 1000 + PIECE, "and pays nothing for what is already here");
    again.handle_closed();
}

#[test]
fn a_consumer_gets_the_whole_file_kept_and_verified() {
    let (hash, data) = &holder().big;
    let (dir, cache) = reader(small());
    let f = stream(&cache, hash, BIG);
    let step = 2 * PIECE as usize;
    // Sixteen pieces in a row make a consumer; it stops reading there.
    for off in (0..=16 * PIECE as usize).step_by(step) {
        assert_eq!(read(&f, off, step), data[off..off + step], "at {off}");
    }
    until("the file is completed behind the reader", Duration::from_secs(20), || {
        sync::hash_store_lookup(dir.path(), hash).unwrap().is_some()
    });
    let kept = sync::hash_store_lookup(dir.path(), hash).unwrap().unwrap();
    assert_eq!(std::fs::read(&kept).unwrap(), *data);
    assert!(!partial(dir.path(), hash).exists(), "the partial became the kept file");
    // The open handle reads on from the kept file; a new open is local.
    assert_eq!(read(&f, BIG - 10, 10), data[BIG - 10..]);
    f.handle_closed();
    assert!(matches!(cache.open(hash, BIG as u64).unwrap(), Opened::Local(p) if p == kept));
    cache.close_local(hash);
}

#[test]
fn closing_early_stops_a_completing_fetch_unless_it_is_nearly_through() {
    let (hash, data) = &holder().big;
    let slow = CacheOpts {
        burst: PIECE,
        background_pause: Duration::from_millis(100),
        grace: Duration::from_millis(200),
        ..small()
    };
    let step = 2 * PIECE as usize;

    // A consumer that closes 18 pieces in: a grace, then the fetch stops.
    let (dir, cache) = reader(slow.clone());
    let f = stream(&cache, hash, BIG);
    for off in (0..=16 * PIECE as usize).step_by(step) {
        assert_eq!(read(&f, off, step), data[off..off + step]);
    }
    f.handle_closed();
    until("the worker stops after the grace", Duration::from_secs(10), || !f.worker_running());
    let have = f.pieces_have();
    assert!(have >= 18 && have * 100 < 75 * 41, "stopped part way: {have} of 41");
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(f.pieces_have(), have, "and stays stopped");
    assert!(sync::hash_store_lookup(dir.path(), hash).unwrap().is_none());
    assert!(partial(dir.path(), hash).exists(), "the partial is kept for a reopen");

    // One that closes 36 pieces in (over three quarters) is finished anyway.
    let (dir, cache) = reader(slow);
    let f = stream(&cache, hash, BIG);
    for off in (0..34 * PIECE as usize).step_by(step) {
        assert_eq!(read(&f, off, step), data[off..off + step]);
    }
    f.handle_closed();
    until("a nearly whole file is finished", Duration::from_secs(20), || {
        sync::hash_store_lookup(dir.path(), hash).unwrap().is_some()
    });
}

#[test]
fn wrong_bytes_are_refused_and_the_box_named() {
    let h = holder();
    let (dir, cache) = reader(small());
    let f = stream(&cache, &h.bad, 4);
    // A small file is verified whole before any of it is served.
    let why = f.read_range(0, 4, Duration::from_secs(20)).expect_err("wrong bytes must not be served");
    assert!(why.contains(&h.src.target) && why.contains("hash"), "names the box and the mismatch: {why}");
    assert!(f.failed());
    assert!(sync::hash_store_lookup(dir.path(), &h.bad).unwrap().is_none());
    assert!(!partial(dir.path(), &h.bad).exists());
    f.handle_closed();
}

#[test]
fn one_stream_is_enough_for_two_files() {
    let h = holder();
    let (_dir, cache) = reader(CacheOpts { streams: 1, ..small() });
    let pull = |hash: String, data: Vec<u8>, cache: HashCache| {
        std::thread::spawn(move || {
            let f = stream(&cache, &hash, data.len());
            let step = 3 * PIECE as usize;
            for off in (0..data.len()).step_by(step) {
                let len = step.min(data.len() - off);
                assert_eq!(read(&f, off, len), data[off..off + len]);
            }
            f.handle_closed();
        })
    };
    let a = pull(h.big.0.clone(), h.big.1.clone(), cache.clone());
    let b = pull(h.two.0.clone(), h.two.1.clone(), cache.clone());
    a.join().unwrap();
    b.join().unwrap();
}
