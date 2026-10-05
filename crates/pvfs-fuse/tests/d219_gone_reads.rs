//! PVOS D219 — a read through the view of a file its holder no longer has.
//! Sonarr upgrading an episode deletes the old copy on the NAS; for up to a
//! minute mediabox's view still listed it, and Bazarr's probe of it was an
//! I/O error ("Could it be corrupted?"). Now: every box asked says it holds no
//! such bytes → the read answers ENOENT and that copy is hidden; the upgrade's
//! new copy (another region, another hash) shows as soon as its head lands;
//! a holder that publishes again and still lists the file brings it back (a
//! false alarm, or a restore); a head without it leaves nothing to hide.

use std::io::ErrorKind;
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::time::Duration;

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

fn bytes(n: usize, salt: u64) -> Vec<u8> {
    (0..n as u64)
        .map(|i| (i.wrapping_add(salt).wrapping_mul(2_654_435_761).rotate_left(11) >> 5) as u8)
        .collect()
}

fn names(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// A catalogue region on the reader, owned by a fresh key; returns the
/// region and the phrase of the key that publishes its heads.
fn region(e: &mut Engine, mn: &pvfs_core::Mnemonic, label: &str) -> (String, pvfs_core::Mnemonic) {
    let seed = identity::generate_mnemonic().unwrap();
    let key_pub = crypto::pubkey_bytes(&identity::device_key(&seed, "", 0).unwrap());
    e.authorize_member(mn, &key_pub).unwrap();
    let root = e.identity.root_node_id.clone();
    let r = folder(e, &root, label);
    e.region_mark_as(&r, "catalogue", Some(&Principal::Key(key_pub))).unwrap();
    (r, seed)
}

/// The region's holder publishes head `seq` with `rows`, and this box fetches
/// it from `source` — what the catalogue job does.
fn head(e: &mut Engine, r: &str, seed: &pvfs_core::Mnemonic, seq: u64, rows: &[RegionEntry], source: &str) {
    let key = identity::device_key(seed, "", 0).unwrap();
    let key_pub = crypto::pubkey_bytes(&key);
    let manifest = Engine::region_manifest_bytes(r, seq, rows);
    let prep = e
        .prepare_commit_region_head(&key_pub, &r.to_string(), seq, blake3::hash(&manifest).to_hex().as_str())
        .unwrap();
    let mut events = Vec::new();
    for pe in prep.events {
        let mut ev = pe.event;
        ev.set_author_sig(crypto::sign_digest(&key, &pe.digest).unwrap());
        events.push(ev);
    }
    e.commit_member_write(events).unwrap();
    e.install_region_snapshot(&r.to_string(), seq, &manifest, source).unwrap();
}

fn not_found<T: std::fmt::Debug>(r: std::io::Result<T>) -> bool {
    matches!(&r, Err(e) if e.kind() == ErrorKind::NotFound)
}

#[test]
fn a_read_of_a_file_its_holder_no_longer_has_is_not_found_and_the_view_moves_on() {
    if !fuse_available() {
        eprintln!("skipping: no /dev/fuse or fusermount on this host");
        return;
    }
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let tmp = tempfile::tempdir().unwrap();

    // ---- the holder (the NAS): the old episode, the upgrade's new one (it
    // serves by hash, so where it sits does not matter), and a neighbour
    let old = bytes(3 * PIECE as usize + 11, 1);
    let new = bytes(4 * PIECE as usize + 22, 2);
    let back = bytes(2 * PIECE as usize + 33, 3);
    let files = tmp.path().join("holder-files");
    for d in ["TV/Show", "TV/New"] {
        std::fs::create_dir_all(files.join(d)).unwrap();
    }
    std::fs::write(files.join("TV/Show/ep.mkv"), &old).unwrap();
    std::fs::write(files.join("TV/New/ep.mkv"), &new).unwrap();
    std::fs::write(files.join("TV/Show/back.mkv"), &back).unwrap();
    let h = |b: &[u8]| blake3::hash(b).to_hex().to_string();
    let (h_old, h_new, h_back) = (h(&old), h(&new), h(&back));
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
    let addr = sock.to_string_lossy().into_owned();

    // ---- the reader (mediabox): the library's rows at head 1, an empty
    // staging region; no bytes of its own
    let (mut e, mn) = Engine::init(tmp.path().join("reader").as_path()).unwrap();
    let (library, lib_key) = region(&mut e, &mn, "Library");
    let (staging, stg_key) = region(&mut e, &mn, "Staging");
    let dirs = || vec![row("TV", "dir", 0, None), row("TV/Show", "dir", 0, None)];
    let mut lib_rows = dirs();
    lib_rows.push(row("TV/Show/ep.mkv", "file", old.len() as u64, Some(h_old.clone())));
    lib_rows.push(row("TV/Show/back.mkv", "file", back.len() as u64, Some(h_back.clone())));
    head(&mut e, &library, &lib_key, 1, &lib_rows, &addr);
    head(&mut e, &staging, &stg_key, 1, &[row("TV", "dir", 0, None)], &addr);
    let data_dir = e.data_dir().to_path_buf();
    e.close().unwrap();

    let opts = CacheOpts {
        piece: PIECE,
        max_readahead: 4 * PIECE,
        complete_after: 2 * PIECE,
        burst: 8 * PIECE,
        ..CacheOpts::default()
    };
    let mnt = tempfile::tempdir().unwrap();
    let source = ReplicaSource { transport: "socket".into(), target: addr.clone(), pin: String::new(), region: String::new() };
    let session = pvfs_fuse::MountGuard::new(
        pvfs_fuse::spawn_view_mount_with(&data_dir, mnt.path(), opts, Some(vec![source])).unwrap(),
        mnt.path(),
    );
    let show = mnt.path().join("TV/Show");
    let ep = show.join("ep.mkv");
    assert_eq!(names(&show), vec!["back.mkv", "ep.mkv"]);
    assert_eq!(std::fs::metadata(&ep).unwrap().len(), old.len() as u64);

    // ---- the upgrade deletes the old copy on the holder; the reader's
    // catalogue has not moved. The probe gets "no such file", not EIO.
    let aside = tmp.path().join("aside");
    std::fs::create_dir_all(&aside).unwrap();
    std::fs::rename(files.join("TV/Show/ep.mkv"), aside.join("ep.mkv")).unwrap();
    let read = std::fs::read(&ep).map(|b| b.len());
    assert!(matches!(&read, Err(e) if e.kind() == ErrorKind::NotFound), "a gone file reads as not found: {read:?}");
    assert_eq!(names(&show), vec!["back.mkv"], "and leaves the listing at once");
    std::thread::sleep(Duration::from_millis(1_100)); // the kernel's 1 s entry cache
    assert!(not_found(std::fs::metadata(&ep)), "stat says so too");
    assert!(not_found(std::fs::File::open(&ep)), "and so does the next open");

    // ---- the upgrade's new copy lands in staging (its head arrives first):
    // it shows at the path, though the library still lists the old one
    let mut w = Engine::open(&data_dir).unwrap();
    let mut stg_rows = dirs();
    stg_rows.push(row("TV/Show/ep.mkv", "file", new.len() as u64, Some(h_new.clone())));
    head(&mut w, &staging, &stg_key, 2, &stg_rows, &addr);
    w.close().unwrap();
    std::thread::sleep(Duration::from_millis(1_100));
    assert_eq!(std::fs::metadata(&ep).unwrap().len(), new.len() as u64, "the new copy is what shows");
    assert_eq!(std::fs::read(&ep).unwrap(), new, "and what reads");

    // ---- a false alarm: the neighbour is missing for a moment, then back,
    // and the holder publishes again still listing it — it shows again.
    // That head also drops the old episode's row, as the NAS's next one did.
    let nb = show.join("back.mkv");
    std::fs::rename(files.join("TV/Show/back.mkv"), aside.join("back.mkv")).unwrap();
    assert!(not_found(std::fs::read(&nb)), "missing on the holder: not found");
    assert!(!names(&show).contains(&"back.mkv".to_string()));
    std::fs::rename(aside.join("back.mkv"), files.join("TV/Show/back.mkv")).unwrap();
    let mut w = Engine::open(&data_dir).unwrap();
    let mut lib_rows2 = dirs();
    lib_rows2.push(row("TV/Show/back.mkv", "file", back.len() as u64, Some(h_back.clone())));
    head(&mut w, &library, &lib_key, 2, &lib_rows2, &addr);
    w.close().unwrap();
    std::thread::sleep(Duration::from_secs(6)); // the listing cache (5 s), and the gone fetch's rest
    assert_eq!(names(&show), vec!["back.mkv", "ep.mkv"], "a republished file is not hidden by a read's memory");
    assert_eq!(std::fs::read(&nb).unwrap(), back, "and reads again");

    // ---- the library's head without the old episode: nothing left to hide,
    // the new copy is the only one
    assert_eq!(std::fs::read(&ep).unwrap(), new);
    assert!(session.unmount(), "the mount is gone before its directory (D211)");
}
