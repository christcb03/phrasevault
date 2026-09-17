//! D165 — the read-through THROUGH the mount: a file held only by another
//! box reads its tail, its head and the whole of it; the store ends with the
//! verified file; and while a read waits on a box that never answers, the
//! mount goes on answering `ls` (the wait is off fuser's one session thread).

use std::io::{Read, Seek, SeekFrom};
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pvfs_client::hash_cache::CacheOpts;
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, sync, BindSpec, Engine, HashPolicy, NodeSpec, RegionEntry, ReplicaSource, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

const PIECE: u64 = 64 * 1024;
const BIG: usize = 24 * PIECE as usize + 777;

fn fuse_available() -> bool {
    std::path::Path::new("/dev/fuse").exists()
        && std::process::Command::new("sh")
            .args(["-c", "command -v fusermount3 || command -v fusermount"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
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

fn socket(path: &std::path::Path) -> ReplicaSource {
    ReplicaSource {
        transport: "socket".into(),
        target: path.to_string_lossy().into_owned(),
        pin: String::new(),
        region: String::new(),
    }
}

fn names(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|d| d.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn a_file_held_elsewhere_reads_by_the_piece_and_a_waiting_read_does_not_stop_the_mount() {
    if !fuse_available() {
        eprintln!("skipping: no /dev/fuse or fusermount on this host");
        return;
    }
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let tmp = tempfile::tempdir().unwrap();

    // ---- the holder: a forest whose region catalogues big.mkv, served
    let data: Vec<u8> = (0..BIG as u64).map(|i| (i.wrapping_mul(2_654_435_761) >> 9) as u8).collect();
    let files = tmp.path().join("holder-files");
    std::fs::create_dir_all(files.join("Movies/Far (2006)")).unwrap();
    std::fs::write(files.join("Movies/Far (2006)/far.mkv"), &data).unwrap();
    let h_far = blake3::hash(&data).to_hex().to_string();
    let (mut holder, hmn) = Engine::init(tmp.path().join("holder").as_path()).unwrap();
    let hroot = holder.identity.root_node_id.clone();
    let lib = folder(&mut holder, &hroot, "Library");
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
    let me = identity::device_key(&identity::client_identity_mnemonic().unwrap(), "", 0).unwrap();
    let me_pub = crypto::pubkey_bytes(&me);
    holder.authorize_member(&hmn, &me_pub).unwrap();
    holder.set_acl(&hroot, &Principal::Key(me_pub), acl::ACL_R).unwrap();
    let sock = tmp.path().join("holder.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = Arc::new(Daemon::new(holder));
    std::thread::spawn(move || {
        let _ = serve(listener, daemon);
    });

    // ---- a box that accepts and never says a word
    let silent_sock = tmp.path().join("silent.sock");
    let silent = UnixListener::bind(&silent_sock).unwrap();
    let held: Arc<Mutex<Vec<std::os::unix::net::UnixStream>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let held = Arc::clone(&held);
        std::thread::spawn(move || {
            for conn in silent.incoming().flatten() {
                held.lock().unwrap().push(conn);
            }
        });
    }

    // ---- the reader: a forest that knows the far region's rows, no bytes
    let (mut e, mn) = Engine::init(tmp.path().join("reader").as_path()).unwrap();
    let region_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let region_pub = crypto::pubkey_bytes(&region_key);
    e.authorize_member(&mn, &region_pub).unwrap();
    let root = e.identity.root_node_id.clone();
    let far = folder(&mut e, &root, "Far");
    e.region_mark_as(&far, "catalogue", Some(&Principal::Key(region_pub.clone()))).unwrap();
    let h_stuck = blake3::hash(b"bytes only the silent box claims").to_hex().to_string();
    let row = |rel: &str, kind: &str, size: u64, hash: Option<String>| RegionEntry {
        rel_path: rel.into(),
        kind: kind.into(),
        size_bytes: size,
        mtime_ms: 1,
        changed_ms: 1,
        content_hash: hash,
        quality: None,
        seen_at: 0,
    };
    let rows = vec![
        row("Movies", "dir", 0, None),
        row("Movies/Far (2006)", "dir", 0, None),
        row("Movies/Far (2006)/far.mkv", "file", BIG as u64, Some(h_far.clone())),
        row("Movies/Far (2006)/stuck.mkv", "file", 5000, Some(h_stuck)),
    ];
    let manifest = Engine::region_manifest_bytes(&far, 1, &rows);
    let prep = e
        .prepare_commit_region_head(&region_pub, &far, 1, blake3::hash(&manifest).to_hex().as_str())
        .unwrap();
    let mut events = Vec::new();
    for pe in prep.events {
        let mut ev = pe.event;
        ev.set_author_sig(crypto::sign_digest(&region_key, &pe.digest).unwrap());
        events.push(ev);
    }
    e.commit_member_write(events).unwrap();
    e.install_region_snapshot(&far, 1, &manifest, "test").unwrap();
    let data_dir = e.data_dir().to_path_buf();
    e.close().unwrap();

    let mnt = tempfile::tempdir().unwrap();
    let opts = CacheOpts {
        piece: PIECE,
        max_readahead: 4 * PIECE,
        complete_after: 8 * PIECE,
        burst: 8 * PIECE,
        ..CacheOpts::default()
    };
    let session =
        pvfs_fuse::spawn_view_mount_with(&data_dir, mnt.path(), opts, Some(vec![socket(&sock), socket(&silent_sock)])).unwrap();

    // ---- the tail, then the head: what a media analysis reads
    let far_file = mnt.path().join("Movies/Far (2006)/far.mkv");
    assert_eq!(std::fs::metadata(&far_file).unwrap().len(), BIG as u64);
    let mut f = std::fs::File::open(&far_file).unwrap();
    let mut tail = vec![0u8; 700];
    f.seek(SeekFrom::Start(BIG as u64 - 700)).unwrap();
    f.read_exact(&mut tail).unwrap();
    assert_eq!(tail, data[BIG - 700..]);
    let mut head = vec![0u8; 30_000];
    f.seek(SeekFrom::Start(0)).unwrap();
    f.read_exact(&mut head).unwrap();
    assert_eq!(head, data[..30_000]);
    drop(f);
    assert!(sync::hash_store_lookup(&data_dir, &h_far).unwrap().is_none(), "a probe keeps no whole file");
    let part = sync::hash_store_path(&data_dir, &h_far).unwrap().with_extension("partial");
    assert_eq!(std::fs::metadata(&part).unwrap().len(), BIG as u64, "its partial waits");

    // ---- the whole of it: read through the same partial, verified, kept
    assert_eq!(std::fs::read(&far_file).unwrap(), data);
    let deadline = Instant::now() + Duration::from_secs(20);
    while sync::hash_store_lookup(&data_dir, &h_far).unwrap().is_none() {
        assert!(Instant::now() < deadline, "the whole file was never kept");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(std::fs::read(&far_file).unwrap(), data, "and reads from the store afterwards");

    // ---- a read waiting on the silent box does not stop the mount
    let stuck = mnt.path().join("Movies/Far (2006)/stuck.mkv");
    let waiting = std::thread::spawn(move || std::fs::read(stuck));
    std::thread::sleep(Duration::from_millis(700));
    assert!(!waiting.is_finished(), "premise: the read is still waiting");
    let asked = Instant::now();
    assert_eq!(names(&mnt.path().join("Movies/Far (2006)")), vec!["far.mkv", "stuck.mkv"]);
    assert_eq!(std::fs::metadata(&far_file).unwrap().len(), BIG as u64);
    assert!(asked.elapsed() < Duration::from_secs(3), "ls and stat answered in {:?}", asked.elapsed());
    // The silent box hangs up: the dial fails, and the read is an error.
    let release = Instant::now() + Duration::from_secs(20);
    while !waiting.is_finished() {
        held.lock().unwrap().clear();
        assert!(Instant::now() < release, "the waiting read never ended");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(waiting.join().unwrap().is_err(), "nobody holds those bytes");
    drop(session);
}
