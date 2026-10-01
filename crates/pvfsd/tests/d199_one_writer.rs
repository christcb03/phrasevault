//! PVOS D199 — one writer per daemon: jobs share the daemon's engine.
//!
//! 1. A replica's daemon has a read pool: it answers `serve status`, view
//!    listings and `region ls` while its writer is held (D136's test, on a
//!    replica — before D199 a replica's pool was empty and every read took
//!    the writer).
//! 2. Served writes stay fast while each job works through the one writer —
//!    a watch pass (first, then over changed files), a catalogue install (a
//!    first install of many rows, then a two-row bump), and follow catching
//!    up a backlog: no served write fails, none is refused "busy", none waits
//!    seconds; the waits and latencies are printed. `PVFS_D199_STRICT=1` (the
//!    release run on presubuntu's disk, D199 §4.3) also asserts that the
//!    writer wait's p99 is under 100 ms, and `PVFS_D199_SCALE` multiplies the
//!    loads.

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pvfs_client::follow::FollowEvent;
use pvfs_client::Client;
use pvfs_core::acl::{self, Principal};
use pvfs_core::identity::SigningKey;
use pvfs_core::{
    crypto, identity, BindSpec, Engine, HashPolicy, NodeSpec, RegionEntry, ReplicaSource, ReplicaStore,
    SharedDb, TYPE_FOLDER,
};
use pvfsd::{serve, Daemon};

fn test_config_dir() -> &'static Path {
    static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    let d = DIR.get_or_init(|| {
        let d = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_CONFIG_HOME", d.path());
        identity::client_identity_mnemonic().unwrap();
        d
    });
    d.path()
}

fn serve_on(daemon: Arc<Daemon>, sock: &Path) {
    let listener = UnixListener::bind(sock).unwrap();
    std::thread::spawn(move || {
        let _ = serve(listener, daemon);
    });
}

fn folder(e: &mut Engine, parent: &str, label: &str) -> String {
    e.add_node(
        &parent.to_string(),
        NodeSpec {
            node_type: TYPE_FOLDER.into(),
            label: label.into(),
            payload: Vec::new(),
            is_temp: false,
            creation_nonce: None,
        },
    )
    .unwrap()
}

fn bind(e: &mut Engine, region: &str, dir: &Path) {
    e.bind_folder(
        &region.to_string(),
        BindSpec {
            source_uri: format!("file://{}", dir.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
}

/// This test process's client identity: the key every box dials with.
fn client_key() -> (SigningKey, Vec<u8>) {
    test_config_dir();
    let mn = identity::client_identity_mnemonic().unwrap();
    let key = identity::device_key(&mn, "", 0).unwrap();
    let pubkey = crypto::pubkey_bytes(&key);
    (key, pubkey)
}

fn connect(sock: &Path, key: &SigningKey, pubkey: &[u8]) -> Client {
    let k = key.clone();
    Client::connect_signed(sock, pubkey, move |d| crypto::sign_digest(&k, d).unwrap()).unwrap()
}

/// How much bigger than the defaults the loads are (`PVFS_D199_SCALE`).
fn scale() -> usize {
    std::env::var("PVFS_D199_SCALE").ok().and_then(|v| v.parse().ok()).unwrap_or(1).max(1)
}

fn strict() -> bool {
    std::env::var("PVFS_D199_STRICT").is_ok_and(|v| v == "1")
}

/// Run a job's load as the daemon runs its jobs: on a thread lowered below
/// serving (D191 — nice +10 and the idle disk class), so a step that holds
/// the writer holds it at background priority, the inversion D191 §8 named.
fn in_background<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::spawn(move || {
        pvfsd::priority::enter_background("the D199 test's job load");
        f()
    })
    .join()
    .unwrap()
}

#[test]
fn a_replica_reads_while_its_writer_is_held() {
    let (ckey, cpub) = client_key();
    let odir = tempfile::tempdir().unwrap();
    let (mut owner, mn) = Engine::init(odir.path()).unwrap();
    let root = owner.identity.root_node_id.clone();
    owner.authorize_member(&mn, &cpub).unwrap();
    owner.set_acl(&root, &Principal::Key(cpub.clone()), acl::ACL_RWA).unwrap();
    let rows = owner.log_events(1, owner.log_tip().unwrap() as usize).unwrap();
    owner.close().unwrap();

    let rdir = tempfile::tempdir().unwrap();
    let rdata = rdir.path().join(".pvfs");
    ReplicaStore::open(&rdata).unwrap().append(&rows).unwrap();
    ReplicaSource {
        transport: "socket".into(),
        target: rdir.path().join("owner.sock").to_string_lossy().into_owned(),
        pin: String::new(),
        region: String::new(),
    }
    .save(&rdata)
    .unwrap();
    let socks = tempfile::tempdir().unwrap();
    let sock = socks.path().join("replica.sock");
    let daemon = Arc::new(Daemon::new(Engine::open(&rdata).unwrap()));
    // With the daemon's engine open (and the projection built), a replica's
    // read view opens, says it is a replica, and carries no forest key.
    let view = Engine::open_read_view(&rdata).expect("a replica opens a read view (D199)");
    assert!(view.is_replica());
    drop(view);
    serve_on(Arc::clone(&daemon), &sock);
    let mut member = connect(&sock, &ckey, &cpub);
    member.serve_status_full().expect("the premise: the probe answers");

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
    member.serve_status_full().expect("status answers under a held writer");
    member.view_ls("").expect("a view listing answers under a held writer");
    member.catalogue_status().expect("region ls answers under a held writer");
    let took = t.elapsed();
    assert!(took < Duration::from_secs(2), "a replica's reads waited on its writer: {took:?}");
    hold.join().unwrap();
}

/// Served writes, one about every 20 ms on one open connection, until told
/// to stop: each one's latency, or its error.
struct Probe {
    stop: Arc<AtomicBool>,
    handle: std::thread::JoinHandle<(Vec<Duration>, Vec<String>)>,
}

impl Probe {
    fn start(mut op: impl FnMut(u64) -> Result<(), String> + Send + 'static) -> Probe {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let (mut lat, mut errs) = (Vec::new(), Vec::new());
            let mut i = 0u64;
            while !flag.load(Ordering::SeqCst) {
                let t = Instant::now();
                match op(i) {
                    Ok(()) => lat.push(t.elapsed()),
                    Err(e) => errs.push(e),
                }
                i += 1;
                std::thread::sleep(Duration::from_millis(20));
            }
            (lat, errs)
        });
        Probe { stop, handle }
    }

    fn finish(self) -> (Vec<Duration>, Vec<String>) {
        self.stop.store(true, Ordering::SeqCst);
        self.handle.join().unwrap()
    }
}

fn pct(v: &[Duration], p: f64) -> Duration {
    if v.is_empty() {
        return Duration::ZERO;
    }
    let mut v = v.to_vec();
    v.sort();
    v[((v.len() - 1) as f64 * p).round() as usize]
}

/// The verdict on one load: what the probe saw, and what the writer says the
/// served ops waited for it.
fn judge(label: &str, probe: (Vec<Duration>, Vec<String>), waits: Vec<(String, Duration)>) {
    let (lat, errs) = probe;
    let served: Vec<Duration> = waits.into_iter().filter(|(who, _)| who.starts_with("serve: ")).map(|(_, d)| d).collect();
    println!(
        "D199 {label}: {} served writes, latency p50 {:?} p99 {:?} max {:?}; {} writer waits, p50 {:?} p99 {:?} max {:?}",
        lat.len(),
        pct(&lat, 0.5),
        pct(&lat, 0.99),
        pct(&lat, 1.0),
        served.len(),
        pct(&served, 0.5),
        pct(&served, 0.99),
        pct(&served, 1.0),
    );
    assert!(errs.is_empty(), "{label}: served writes failed: {errs:?}");
    assert!(!lat.is_empty(), "{label}: the probe made no write");
    let max = pct(&served, 1.0);
    assert!(max < Duration::from_secs(2), "{label}: a served write waited {max:?} for the writer");
    if strict() {
        let p99 = pct(&served, 0.99);
        assert!(p99 < Duration::from_millis(100), "{label}: the served writes' p99 wait was {p99:?}");
    }
}

/// The region's box (another key) publishes `hash` as its head at `seq`.
fn attest(e: &mut Engine, key: &SigningKey, region: &str, seq: u64, hash: &str) {
    let pubkey = crypto::pubkey_bytes(key);
    let prep = e.prepare_commit_region_head(&pubkey, &region.to_string(), seq, hash).unwrap();
    let mut events = Vec::new();
    for pe in prep.events {
        let mut ev = pe.event;
        ev.set_author_sig(crypto::sign_digest(key, &pe.digest).unwrap());
        events.push(ev);
    }
    e.commit_member_write(events).unwrap();
}

fn manifest_rows(n: usize, bump: u64) -> Vec<RegionEntry> {
    let t = 1_700_000_000_000;
    (0..n)
        .map(|i| RegionEntry {
            rel_path: format!("Shows/{:03}/episode {i:06}.mkv", i % 500),
            kind: "file".into(),
            size_bytes: 1_000 + i as u64 + if i < 2 { bump } else { 0 },
            mtime_ms: t,
            changed_ms: t,
            content_hash: Some(blake3::hash(format!("{i}-{}", if i < 2 { bump } else { 0 }).as_bytes()).to_hex().to_string()),
            quality: None,
            seen_at: 0,
        })
        .collect()
}

#[test]
fn served_writes_wait_one_short_step_while_jobs_work() {
    let (ckey, cpub) = client_key();
    let n = scale();
    let odir = tempfile::tempdir().unwrap();
    let (mut owner, mn) = Engine::init(odir.path().join("forest").as_path()).unwrap();
    let root = owner.identity.root_node_id.clone();
    owner.authorize_member(&mn, &cpub).unwrap();
    owner.set_acl(&root, &Principal::Key(cpub.clone()), acl::ACL_RWA).unwrap();
    let probes = folder(&mut owner, &root, "Probes");
    // The owner's own catalogue region, for the watch.
    let media = odir.path().join("media");
    let files = 3_000 * n;
    for i in 0..files {
        let dir = media.join(format!("Show {:02}/Season {:02}", i % 40, i % 7));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("e{i:06}.mkv")), format!("episode {i}")).unwrap();
    }
    let local = folder(&mut owner, &root, "Local");
    owner.region_mark_as(&local, "catalogue", None).unwrap();
    bind(&mut owner, &local, &media);
    // Another box's catalogue region, for the installs.
    let hkey = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let hpub = crypto::pubkey_bytes(&hkey);
    owner.authorize_member(&mn, &hpub).unwrap();
    let far = folder(&mut owner, &root, "Far");
    owner.region_mark_as(&far, "catalogue", Some(&Principal::Key(hpub))).unwrap();

    let socks = tempfile::tempdir().unwrap();
    let sock = socks.path().join("owner.sock");
    let daemon = Arc::new(Daemon::new(owner));
    serve_on(Arc::clone(&daemon), &sock);
    let writer = Arc::clone(daemon.writer());
    let mkdirs = |tag: &'static str| {
        let (sock, key, pubkey, parent) = (sock.clone(), ckey.clone(), cpub.clone(), probes.clone());
        Probe::start(move |i| {
            // one connection for the whole run: a new one would measure the
            // daemon's accept poll (D202), not the writer
            thread_local!(static C: std::cell::RefCell<Option<Client>> = const { std::cell::RefCell::new(None) });
            C.with(|c| {
                let mut c = c.borrow_mut();
                let client = c.get_or_insert_with(|| connect(&sock, &key, &pubkey));
                let k = key.clone();
                client
                    .mkdir(&parent, &format!("{tag} {i}"), move |d| crypto::sign_digest(&k, d).unwrap())
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            })
        })
    };

    // (a) the watch: a first pass over every file, then a pass that finds a
    // tenth of them changed (and, D199 part 2, writes only those).
    writer.trace_waits(true);
    let probe = mkdirs("watch");
    std::thread::sleep(Duration::from_millis(100));
    let (first, first_took, second) = {
        let (w, media) = (Arc::clone(&writer), media.clone());
        in_background(move || {
            let db = SharedDb::new(w, "watch").unwrap();
            let mut ctx = pvfs_core::fs::CatalogueCtx::new(None);
            let t = Instant::now();
            let first = pvfs_core::fs::scan_catalogues(&db, &mut ctx, None, 0).unwrap();
            let first_took = t.elapsed();
            for i in (0..files).step_by(10) {
                let dir = media.join(format!("Show {:02}/Season {:02}", i % 40, i % 7));
                std::fs::write(dir.join(format!("e{i:06}.mkv")), format!("episode {i}, a better copy")).unwrap();
            }
            let second = pvfs_core::fs::scan_catalogues(&db, &mut ctx, None, 0).unwrap();
            (first, first_took, second)
        })
    };
    judge("watch", probe.finish(), writer.take_waits());
    assert_eq!(first[0].stats.added, files as u64);
    assert_eq!(second[0].stats.changed, files.div_ceil(10) as u64);
    println!("D199 watch: first pass over {files} files took {first_took:?}");

    // (b) the catalogue: a first install of many rows, then a two-row bump.
    let rows = 30_000 * n;
    let head1 = manifest_rows(rows, 0);
    let bytes1 = Engine::region_manifest_bytes(&far, 1, &head1);
    let hash1 = blake3::hash(&bytes1).to_hex().to_string();
    writer.step("test: attest", |e| attest(e, &hkey, &far, 1, &hash1));
    let head2 = manifest_rows(rows, 7);
    let bytes2 = Engine::region_manifest_bytes(&far, 2, &head2);
    let hash2 = blake3::hash(&bytes2).to_hex().to_string();
    writer.take_waits();
    let probe = mkdirs("install");
    std::thread::sleep(Duration::from_millis(100));
    let (got1, install_took, got2) = {
        let (w, far, hkey) = (Arc::clone(&writer), far.clone(), hkey.clone());
        in_background(move || {
            let db = SharedDb::new(Arc::clone(&w), "catalogue").unwrap();
            let t = Instant::now();
            let got1 = pvfs_core::fs::install_region_snapshot_db(&db, &far, 1, &bytes1, "test", || {}).unwrap();
            let install_took = t.elapsed();
            w.step("test: attest", |e| attest(e, &hkey, &far, 2, &hash2));
            let got2 = pvfs_core::fs::install_region_snapshot_db(&db, &far, 2, &bytes2, "test", || {}).unwrap();
            (got1, install_took, got2)
        })
    };
    assert_eq!((got1.rows, got1.added, got1.changed, got1.removed), (rows, rows, 0, 0));
    assert_eq!((got2.added, got2.changed, got2.removed), (0, 2, 0));
    judge("catalogue install", probe.finish(), writer.take_waits());
    println!("D199 catalogue: a first install of {rows} rows took {install_took:?}");
    writer.trace_waits(false);
}

#[test]
fn a_replicas_served_writes_wait_one_short_step_while_follow_catches_up() {
    let (ckey, cpub) = client_key();
    let n = scale();
    let odir = tempfile::tempdir().unwrap();
    let (mut owner, mn) = Engine::init(odir.path().join("forest").as_path()).unwrap();
    let root = owner.identity.root_node_id.clone();
    owner.authorize_member(&mn, &cpub).unwrap();
    owner.set_acl(&root, &Principal::Key(cpub.clone()), acl::ACL_RWA).unwrap();
    let region = folder(&mut owner, &root, "Holder");
    owner.region_mark_as(&region, "catalogue", Some(&Principal::Key(cpub.clone()))).unwrap();
    let seed = owner.log_events(1, owner.log_tip().unwrap() as usize).unwrap();
    // The backlog the replica will follow: events it has not seen.
    let backlog = 1_500 * n;
    let bulk = folder(&mut owner, &root, "Bulk");
    for i in 0..backlog {
        folder(&mut owner, &bulk, &format!("n{i}"));
    }
    let target = owner.log_tip().unwrap();
    let socks = tempfile::tempdir().unwrap();
    let owner_sock: PathBuf = socks.path().join("owner.sock");
    serve_on(Arc::new(Daemon::new(owner)), &owner_sock);

    // The replica holds region `Holder` on its disk: a file the probe renames.
    let rdir = tempfile::tempdir().unwrap();
    let rdata = rdir.path().join(".pvfs");
    ReplicaStore::open(&rdata).unwrap().append(&seed).unwrap();
    ReplicaSource { transport: "socket".into(), target: owner_sock.to_string_lossy().into_owned(), pin: String::new(), region: String::new() }
        .save(&rdata)
        .unwrap();
    let media = rdir.path().join("media");
    std::fs::create_dir_all(media.join("Shows")).unwrap();
    std::fs::write(media.join("Shows/a.mkv"), b"a file the probe moves back and forth").unwrap();
    let hash = blake3::hash(b"a file the probe moves back and forth").to_hex().to_string();
    {
        let mut h = Engine::open(&rdata).unwrap();
        bind(&mut h, &region, &media);
        let mut away = pvfs_core::OwnerAway;
        h.scan_routed(None, Some(&mut away), 0).unwrap();
        h.close().unwrap();
    }
    let rsock = socks.path().join("replica.sock");
    let replica = Arc::new(Daemon::new(Engine::open(&rdata).unwrap()));
    serve_on(Arc::clone(&replica), &rsock);
    let writer = Arc::clone(replica.writer());
    writer.trace_waits(true);

    let probe = {
        let (sock, key, pubkey, region, hash) = (rsock.clone(), ckey.clone(), cpub.clone(), region.clone(), hash.clone());
        let mut client: Option<Client> = None;
        Probe::start(move |i| {
            let c = client.get_or_insert_with(|| connect(&sock, &key, &pubkey));
            let (from, to) = if i % 2 == 0 { ("Shows/a.mkv", "Shows/b.mkv") } else { ("Shows/b.mkv", "Shows/a.mkv") };
            match c.rename_path(&region, from, to, Some((hash.as_str(), 37))) {
                Ok(true) => Ok(()),
                Ok(false) => Err(format!("{from} → {to}: nothing moved")),
                Err(e) => Err(e.to_string()),
            }
        })
    };
    std::thread::sleep(Duration::from_millis(100));
    let stop = Arc::new(AtomicBool::new(false));
    let tip = Arc::new(AtomicU64::new(0));
    let follower = {
        let (w, stop, tip) = (Arc::clone(&writer), Arc::clone(&stop), Arc::clone(&tip));
        std::thread::spawn(move || {
            pvfsd::priority::enter_background("the D199 test's follower");
            pvfs_client::follow::run_shared(w, 200, &stop, |ev| {
                if let FollowEvent::CaughtUp { tip: t } | FollowEvent::UpToDate { tip: t } = ev {
                    tip.store(t, Ordering::SeqCst);
                }
            })
        })
    };
    let t = Instant::now();
    while tip.load(Ordering::SeqCst) < target {
        assert!(t.elapsed() < Duration::from_secs(300), "follow did not catch up");
        std::thread::sleep(Duration::from_millis(50));
    }
    let caught_up = t.elapsed();
    stop.store(true, Ordering::SeqCst);
    follower.join().unwrap().unwrap();
    judge("follow", probe.finish(), writer.take_waits());
    println!("D199 follow: a backlog of {backlog} events caught up in {caught_up:?}");
    // What follow landed is folded: the replica's projection holds the backlog.
    let view = Engine::open_read_view(&rdata).unwrap();
    assert_eq!(view.log_tip().unwrap(), target);
    assert_eq!(view.children(&bulk).unwrap().len(), backlog, "every folder folded");
}
