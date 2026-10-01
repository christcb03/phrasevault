//! PVOS D210 — a cold read through the view asks the region's holder first.
//! The reader's sources list a box that accepts and never answers (a box that
//! is down, as a dial sees it) BEFORE the holder. A region whose holder the
//! catalogue knows (`region_fetched.source`) reads at once and the silent box
//! is never dialed; a region it does not know keeps today's order — the read
//! waits on the silent box until it hangs up, then the holder serves it.

use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pvfs_client::hash_cache::CacheOpts;
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, BindSpec, Engine, HashPolicy, NodeSpec, RegionEntry, ReplicaSource, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

const PIECE: u64 = 64 * 1024;

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

fn row(rel: &str, kind: &str, size: u64, hash: Option<String>) -> RegionEntry {
    RegionEntry {
        rel_path: rel.into(),
        kind: kind.into(),
        size_bytes: size,
        mtime_ms: 1,
        changed_ms: 1,
        content_hash: hash,
        quality: None,
        seen_at: 0,
    }
}

/// A catalogue region on the reader holding `rows` at head 1, its snapshot
/// installed as fetched from `source`.
fn far_region(e: &mut Engine, mn: &pvfs_core::Mnemonic, label: &str, rows: &[RegionEntry], source: &str) -> String {
    let key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let key_pub = crypto::pubkey_bytes(&key);
    e.authorize_member(mn, &key_pub).unwrap();
    let root = e.identity.root_node_id.clone();
    let region = folder(e, &root, label);
    e.region_mark_as(&region, "catalogue", Some(&Principal::Key(key_pub.clone()))).unwrap();
    let manifest = Engine::region_manifest_bytes(&region, 1, rows);
    let prep = e
        .prepare_commit_region_head(&key_pub, &region, 1, blake3::hash(&manifest).to_hex().as_str())
        .unwrap();
    let mut events = Vec::new();
    for pe in prep.events {
        let mut ev = pe.event;
        ev.set_author_sig(crypto::sign_digest(&key, &pe.digest).unwrap());
        events.push(ev);
    }
    e.commit_member_write(events).unwrap();
    e.install_region_snapshot(&region, 1, &manifest, source).unwrap();
    region
}

#[test]
fn a_cold_read_asks_the_regions_holder_first_and_an_unknown_region_keeps_todays_order() {
    if !fuse_available() {
        eprintln!("skipping: no /dev/fuse or fusermount on this host");
        return;
    }
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let tmp = tempfile::tempdir().unwrap();

    // ---- the holder: one catalogue region with both films, served
    let far: Vec<u8> = (0..(5 * PIECE + 123)).map(|i| (i.wrapping_mul(2_654_435_761) >> 9) as u8).collect();
    let near: Vec<u8> = (0..(3 * PIECE + 45)).map(|i| (i.wrapping_mul(40_503) >> 3) as u8).collect();
    let files = tmp.path().join("holder-files");
    std::fs::create_dir_all(files.join("Movies/Far (2006)")).unwrap();
    std::fs::create_dir_all(files.join("Movies/Near (2007)")).unwrap();
    std::fs::write(files.join("Movies/Far (2006)/far.mkv"), &far).unwrap();
    std::fs::write(files.join("Movies/Near (2007)/near.mkv"), &near).unwrap();
    let (h_far, h_near) = (blake3::hash(&far).to_hex().to_string(), blake3::hash(&near).to_hex().to_string());
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

    // ---- a box that accepts and never says a word; counts its callers
    let silent_sock = tmp.path().join("silent.sock");
    let silent = UnixListener::bind(&silent_sock).unwrap();
    let held: Arc<Mutex<Vec<UnixStream>>> = Arc::new(Mutex::new(Vec::new()));
    let dialed = Arc::new(AtomicUsize::new(0));
    // Once set, the silent box hangs up on everyone: no read is left
    // waiting on it when an assertion fails (a mount torn down under a
    // waiting read hangs the test instead of failing it).
    let hangup = Arc::new(AtomicBool::new(false));
    {
        let (held, dialed, hangup) = (Arc::clone(&held), Arc::clone(&dialed), Arc::clone(&hangup));
        std::thread::spawn(move || {
            for conn in silent.incoming().flatten() {
                dialed.fetch_add(1, Ordering::SeqCst);
                if !hangup.load(Ordering::SeqCst) {
                    held.lock().unwrap().push(conn);
                }
            }
        });
    }
    let release = || {
        hangup.store(true, Ordering::SeqCst);
        held.lock().unwrap().clear();
    };

    // ---- the reader: two regions' rows, no bytes. Far's manifest came
    // from the holder; Near's from a box the fleet no longer announces.
    let (mut e, mn) = Engine::init(tmp.path().join("reader").as_path()).unwrap();
    let holder_addr = sock.to_string_lossy().into_owned();
    let far_r = far_region(
        &mut e,
        &mn,
        "Far",
        &[
            row("Movies", "dir", 0, None),
            row("Movies/Far (2006)", "dir", 0, None),
            row("Movies/Far (2006)/far.mkv", "file", far.len() as u64, Some(h_far.clone())),
        ],
        &holder_addr,
    );
    let near_r = far_region(
        &mut e,
        &mn,
        "Near",
        &[
            row("Movies", "dir", 0, None),
            row("Movies/Near (2007)", "dir", 0, None),
            row("Movies/Near (2007)/near.mkv", "file", near.len() as u64, Some(h_near.clone())),
        ],
        "gone.example:7499",
    );
    let holders = e.region_holders().unwrap();
    assert_eq!(holders.get(&far_r), Some(&holder_addr), "Far's holder is the box its manifest came from");
    assert_eq!(holders.get(&near_r).map(String::as_str), Some("gone.example:7499"));
    let data_dir = e.data_dir().to_path_buf();
    e.close().unwrap();

    let opts = CacheOpts {
        piece: PIECE,
        max_readahead: 4 * PIECE,
        complete_after: 2 * PIECE,
        burst: 8 * PIECE,
        ..CacheOpts::default()
    };
    // The silent box FIRST: today's order would dial it before the holder.
    let sources = || Some(vec![socket(&silent_sock), socket(&sock)]);

    // ---- a fresh mount, a region whose holder is known: read at once
    let mnt = tempfile::tempdir().unwrap();
    // PVOS D211 — the guard unmounts (and waits) before the TempDir goes,
    // also when an assertion fails: removing the directory through a live
    // view would route a trash to the silent box.
    let session = pvfs_fuse::MountGuard::new(
        pvfs_fuse::spawn_view_mount_with(&data_dir, mnt.path(), opts.clone(), sources()).unwrap(),
        mnt.path(),
    );
    let t = Instant::now();
    let far_file = mnt.path().join("Movies/Far (2006)/far.mkv");
    let reading = std::thread::spawn(move || std::fs::read(far_file));
    while !reading.is_finished() && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }
    let took = t.elapsed();
    let asked_silent = dialed.load(Ordering::SeqCst);
    release();
    let got = reading.join().unwrap();
    eprintln!("far: {took:?}, silent box dialed {asked_silent} time(s), read ok: {}", got.is_ok());
    assert_eq!(asked_silent, 0, "the silent box was never dialed");
    assert!(took < Duration::from_secs(5), "the holder answered in {took:?}");
    assert_eq!(got.unwrap(), far);
    assert!(session.unmount(), "{} is still mounted", mnt.path().display());
    hangup.store(false, Ordering::SeqCst);

    // ---- a fresh mount, a region whose holder is not announced: today's
    // order — the silent box is asked first, and the read waits on it
    let mnt2 = tempfile::tempdir().unwrap();
    let session = pvfs_fuse::MountGuard::new(
        pvfs_fuse::spawn_view_mount_with(&data_dir, mnt2.path(), opts, sources()).unwrap(),
        mnt2.path(),
    );
    let near_file = mnt2.path().join("Movies/Near (2007)/near.mkv");
    let waiting = std::thread::spawn(move || std::fs::read(near_file));
    let deadline = Instant::now() + Duration::from_secs(10);
    while dialed.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(300));
    let asked_silent = dialed.load(Ordering::SeqCst);
    let was_waiting = !waiting.is_finished();
    // It hangs up: the dial fails, the holder is asked next and serves.
    release();
    let got = waiting.join().unwrap();
    eprintln!("near: silent box dialed {asked_silent} time(s), waiting on it: {was_waiting}, read ok: {}", got.is_ok());
    assert!(asked_silent > 0, "the silent box was asked first (today's order)");
    assert!(was_waiting, "premise: the read waited on the silent box");
    assert_eq!(got.unwrap(), near, "then the holder served it");
    assert!(session.unmount(), "{} is still mounted", mnt2.path().display());
}
