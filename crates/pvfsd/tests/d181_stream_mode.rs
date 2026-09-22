//! D181 — the read-through cache's stream mode (Plex on the LAN; Chris: no
//! cache) against a real daemon: a reader past `complete_after` gets no
//! background completion, only its readahead — kept ahead of it; pieces
//! behind every reader are dropped from the partial, never those behind the
//! rearmost; a small file is still verified whole and not kept; the partial
//! is deleted at the last close and a reopen fetches again. The holder is
//! D165's (`d165_hash_cache.rs`).

use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use pvfs_client::hash_cache::{CacheMode, CacheOpts, HashCache, HashFetch, Opened};
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
        mode: CacheMode::Stream,
        behind: 64 << 20,
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
fn a_reader_gets_its_readahead_kept_ahead_and_no_completion() {
    let (hash, data) = &holder().big;
    let (dir, cache) = reader(small());
    let f = stream(&cache, hash, BIG);
    let step = 2 * PIECE as usize;
    // Twenty pieces in a row — past `complete_after` (16), which in keep
    // mode would complete the file behind the reader.
    for off in (0..20 * PIECE as usize).step_by(step) {
        assert_eq!(read(&f, off, step), data[off..off + step], "at {off}");
    }
    // The window ahead (4 pieces) is filled without the reader asking...
    // Generous: this asserts WHAT is fetched, never how fast. The whole suite
    // in parallel on the build host once took this past 10 s and failed a
    // correct build (2026-09-22).
    until("the readahead is fetched ahead of the reader", Duration::from_secs(60), || {
        f.fetched_bytes() == 24 * PIECE
    });
    // ...and nothing more: no background completion.
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(f.fetched_bytes(), 24 * PIECE, "stream mode fetches what is read and its readahead");
    assert_eq!(f.pieces_have(), 24);
    assert!(sync::hash_store_lookup(dir.path(), hash).unwrap().is_none(), "nothing is kept");
    f.handle_closed();
}

#[test]
fn the_partial_goes_at_the_last_close_and_a_reopen_fetches_again() {
    let (hash, data) = &holder().big;
    let (dir, cache) = reader(small());
    let a = stream(&cache, hash, BIG);
    let b = stream(&cache, hash, BIG);
    assert!(Arc::ptr_eq(&a, &b), "two handles, one fetch");
    assert_eq!(read(&a, BIG - 1000, 1000), data[BIG - 1000..]);
    assert_eq!(read(&b, 0, 5000), data[..5000]);
    a.handle_closed();
    std::thread::sleep(Duration::from_millis(200));
    assert!(partial(dir.path(), hash).exists(), "one handle is still open");
    b.handle_closed();
    until("the partial is deleted at the last close", Duration::from_secs(5), || {
        !partial(dir.path(), hash).exists()
    });
    let again = stream(&cache, hash, BIG);
    assert!(!Arc::ptr_eq(&a, &again), "a reopen starts afresh");
    assert_eq!(read(&again, 0, 5000), data[..5000]);
    assert_eq!(again.fetched_bytes(), PIECE, "and fetches again");
    again.handle_closed();
    until("and is deleted again", Duration::from_secs(5), || !partial(dir.path(), hash).exists());
    assert!(sync::hash_store_lookup(dir.path(), hash).unwrap().is_none());
}

#[test]
fn pieces_behind_every_reader_are_dropped_never_behind_the_rearmost() {
    let (hash, data) = &holder().big;
    let behind = CacheOpts {
        behind: 8 * PIECE,
        ..small()
    };
    let step = 2 * PIECE as usize;

    // One reader through the whole file: what it left 8 pieces behind is
    // punched out, so the partial never holds much more than its window.
    let (_dir, cache) = reader(behind.clone());
    let f = stream(&cache, hash, BIG);
    let mut most = 0;
    for off in (0..BIG).step_by(step) {
        let len = step.min(BIG - off);
        assert_eq!(read(&f, off, len), data[off..off + len], "at {off}");
        most = most.max(f.pieces_have());
    }
    assert!(most <= 8 + 2 + 2 + 4 + 1, "at most behind + a sweep step + a read + readahead: {most}");
    assert!(f.allocated_bytes() <= 17 * PIECE, "the disk holds the window, not the file: {}", f.allocated_bytes());
    // Read again from the start: dropped pieces are fetched again, right.
    assert_eq!(read(&f, 0, step), data[..step]);
    f.handle_closed();

    // Two readers: the one at the front never drops what the one at the
    // back still has ahead of it.
    let (_dir, cache) = reader(behind);
    let back = stream(&cache, hash, BIG);
    let front = stream(&cache, hash, BIG);
    assert_eq!(read(&back, 0, step), data[..step]);
    for off in (0..30 * PIECE as usize).step_by(step) {
        assert_eq!(read(&front, off, step), data[off..off + step]);
    }
    assert!(back.pieces_have() >= 30, "nothing behind the rearmost reader went: {}", back.pieces_have());
    let fetched = back.fetched_bytes();
    assert_eq!(read(&back, step, step), data[step..2 * step]);
    assert_eq!(back.fetched_bytes(), fetched, "the back reader's next pieces were still there");
    back.handle_closed();
    front.handle_closed();
}

#[test]
fn a_small_file_is_verified_whole_and_not_kept() {
    let (hash, data) = &holder().two;
    let (dir, cache) = reader(small());
    let f = stream(&cache, hash, data.len());
    // ten pieces, under `complete_after`: verified before its last is served
    assert_eq!(read(&f, 0, data.len()), *data);
    assert!(sync::hash_store_lookup(dir.path(), hash).unwrap().is_none(), "verified, not kept");
    assert!(partial(dir.path(), hash).exists(), "served from the partial while open");
    f.handle_closed();
    until("gone at close", Duration::from_secs(5), || !partial(dir.path(), hash).exists());

    // Wrong bytes are refused in stream mode too.
    let h = holder();
    let bad = stream(&cache, &h.bad, 4);
    let why = bad.read_range(0, 4, Duration::from_secs(20)).expect_err("wrong bytes must not be served");
    assert!(why.contains(&h.src.target) && why.contains("hash"), "{why}");
    bad.handle_closed();
}

#[test]
fn the_cache_mode_is_keep_or_stream() {
    assert_eq!("stream".parse::<CacheMode>().unwrap(), CacheMode::Stream);
    assert_eq!(" Keep ".parse::<CacheMode>().unwrap(), CacheMode::Keep);
    assert_eq!(CacheMode::default(), CacheMode::Keep, "D165's behaviour stays the default");
    assert!("none".parse::<CacheMode>().is_err());
    assert_eq!(CacheMode::Stream.to_string(), "stream");
}
