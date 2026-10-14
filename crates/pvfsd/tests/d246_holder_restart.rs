//! PVOS D246 — a read-through survives its holder's restart: a read that
//! dials a holder while its daemon is not listening (the v1.4-649 roll's
//! one-second gap on the NAS) redials for a window and is served, said at
//! debug; a holder that stays down fails the read once at warn, and the
//! next read fails at once without a second warn.

use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use pvfs_client::hash_cache::{CacheOpts, HashCache, HashFetch, Opened};
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, BindSpec, Engine, HashPolicy, NodeSpec, ReplicaSource, TYPE_FOLDER};
use pvfs_log::testing::GlobalCapture;
use pvfsd::{serve, Daemon};

const PIECE: u64 = 64 * 1024;
const SIZE: usize = 6 * PIECE as usize + 333;

fn bytes(n: usize, salt: u64) -> Vec<u8> {
    (0..n as u64)
        .map(|i| (i.wrapping_add(salt).wrapping_mul(2_654_435_761).rotate_left(13) >> 7) as u8)
        .collect()
}

/// A holder whose daemon is built but not yet listening: `listen()` starts
/// it at its socket path, once. Tests run on threads and the client
/// identity is resolved through the environment, so one per binary.
struct Holder {
    sock: PathBuf,
    file: (String, Vec<u8>),
    daemon: Mutex<Option<Daemon>>,
    _keep: Vec<tempfile::TempDir>,
}

impl Holder {
    fn listen(&self) {
        let Some(daemon) = self.daemon.lock().unwrap().take() else { return };
        let listener = UnixListener::bind(&self.sock).unwrap();
        let daemon = Arc::new(daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, daemon);
        });
    }
}

fn holder() -> &'static Holder {
    static H: OnceLock<Holder> = OnceLock::new();
    H.get_or_init(|| {
        let cfg = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_CONFIG_HOME", cfg.path());
        let dir = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(files.path().join("Shows")).unwrap();
        let data = bytes(SIZE, 7);
        std::fs::write(files.path().join("Shows/ep.mkv"), &data).unwrap();

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
        let hash = blake3::hash(&data).to_hex().to_string();
        assert!(owner.local_path_for_hash(&hash).unwrap().is_some(), "premise: the scan hashed ep.mkv");

        let me = identity::device_key(&identity::client_identity_mnemonic().unwrap(), "", 0).unwrap();
        let me_pub = crypto::pubkey_bytes(&me);
        owner.authorize_member(&mn, &me_pub).unwrap();
        owner.set_acl(&root, &Principal::Key(me_pub), acl::ACL_R).unwrap();

        let sockdir = tempfile::tempdir().unwrap();
        Holder {
            sock: sockdir.path().join("holder.sock"),
            file: (hash, data),
            daemon: Mutex::new(Some(Daemon::new(owner))),
            _keep: vec![cfg, dir, files, sockdir],
        }
    })
}

fn source(target: &str) -> ReplicaSource {
    ReplicaSource { transport: "socket".into(), target: target.into(), pin: String::new(), region: String::new() }
}

fn opts(window: Duration) -> CacheOpts {
    CacheOpts { piece: PIECE, max_readahead: 2 * PIECE, redial_window: window, ..CacheOpts::default() }
}

fn stream(cache: &HashCache, hash: &str, size: usize) -> Arc<HashFetch> {
    match cache.open(hash, size as u64).unwrap() {
        Opened::Stream(f) => f,
        Opened::Local(p) => panic!("not in the store yet, but got {}", p.display()),
    }
}

#[test]
fn a_read_waits_out_its_holders_restart_and_says_so_at_debug() {
    let cap = GlobalCapture::start();
    let h = holder();
    let (hash, data) = &h.file;
    let reader = tempfile::tempdir().unwrap();
    let (e, _) = Engine::init(reader.path()).unwrap();
    e.close().unwrap();
    let cache = HashCache::with_sources(
        reader.path(),
        opts(Duration::from_secs(15)),
        vec![source(&h.sock.to_string_lossy())],
    );

    // the holder's daemon comes back 1.5 s after the read asks
    let started = Instant::now();
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(1500));
        holder().listen();
    });
    let f = stream(&cache, hash, SIZE);
    let path = f.read_range(0, 4096, Duration::from_secs(60)).expect("the read is served once the holder is back");
    let mut buf = vec![0u8; 4096];
    std::fs::File::open(path).unwrap().read_exact_at(&mut buf, 0).unwrap();
    assert_eq!(buf, data[..4096], "the right bytes");
    assert!(started.elapsed() >= Duration::from_millis(1400), "it really waited: {:?}", started.elapsed());
    f.handle_closed();

    // this test's records: the ones naming this holder's socket (the other
    // test reads the same file from a socket nobody listens on)
    let mine = |event: &str| -> Vec<pvfs_log::Record> {
        cap.events(event).into_iter().filter(|r| r.line().contains("holder.sock")).collect()
    };
    assert!(mine("pvfs.mount.read_through_failed").is_empty(), "nothing at warn");
    let rec = mine("pvfs.mount.read_through_recovered");
    assert_eq!(rec.len(), 1, "one debug line says it recovered: {rec:?}");
    assert_eq!(rec[0].severity, pvfs_log::Severity::Debug);
    assert!(rec[0].line().contains("redial"), "{}", rec[0].line());
}

#[test]
fn a_holder_that_stays_down_fails_once_at_warn_then_fast() {
    let cap = GlobalCapture::start();
    let h = holder();
    let (hash, _) = &h.file;
    let reader = tempfile::tempdir().unwrap();
    let (e, _) = Engine::init(reader.path()).unwrap();
    e.close().unwrap();
    // nothing ever listens here
    let nowhere = reader.path().join("nobody-home.sock");
    let cache = HashCache::with_sources(reader.path(), opts(Duration::from_secs(1)), vec![source(&nowhere.to_string_lossy())]);

    let f = stream(&cache, hash, SIZE);
    let t = Instant::now();
    assert!(f.read_range(0, 4096, Duration::from_secs(60)).is_err(), "a holder that stays down fails the read");
    let first = t.elapsed();
    assert!(first >= Duration::from_millis(900), "it redialled for its window first: {first:?}");
    assert!(first < Duration::from_secs(10), "and no longer: {first:?}");

    // the next read, straight after: the holder rests, so it fails at once
    let t = Instant::now();
    assert!(f.read_range(2 * PIECE, 4096, Duration::from_secs(60)).is_err());
    assert!(t.elapsed() < Duration::from_millis(600), "the second read fails fast: {:?}", t.elapsed());
    f.handle_closed();

    let warned: Vec<_> = cap
        .events("pvfs.mount.read_through_failed")
        .into_iter()
        .filter(|r| r.line().contains("nobody-home"))
        .collect();
    assert_eq!(warned.len(), 1, "one warn, for the window that ran out: {warned:?}");
    assert!(warned[0].line().contains("attempt"), "it names the attempts: {}", warned[0].line());
}
