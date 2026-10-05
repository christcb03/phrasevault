//! PVOS D220 — a file half read through the view keeps reading to its end
//! after its holder trashes it (a Plex stream while Sonarr upgrades the
//! episode), as a file open on a local disk does after its unlink. A reader
//! that opens it afterwards gets ENOENT (D219): the trash serves only a
//! reader that was already reading.

use std::io::{ErrorKind, Read};
use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::hash_cache::{CacheMode, CacheOpts};
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, sync, BindSpec, Engine, HashPolicy, NodeSpec, RegionEntry, ReplicaSource, TYPE_FOLDER};
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

#[test]
fn a_file_half_read_through_the_view_reads_to_its_end_after_its_holder_trashes_it() {
    if !fuse_available() {
        eprintln!("skipping: no /dev/fuse or fusermount on this host");
        return;
    }
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let tmp = tempfile::tempdir().unwrap();

    // ---- the holder: one episode, catalogued, its sidecar beside it
    let ep: Vec<u8> = (0..(16 * PIECE + 321)).map(|i| (i.wrapping_mul(2_246_822_519) >> 11) as u8).collect();
    let files = tmp.path().join("holder-files");
    std::fs::create_dir_all(files.join("TV/Show")).unwrap();
    let on_disk = files.join("TV/Show/ep.mkv");
    std::fs::write(&on_disk, &ep).unwrap();
    let hash = blake3::hash(&ep).to_hex().to_string();
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
    assert!(sync::manifest_sidecar_path(&on_disk).is_file(), "premise: a sidecar");
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

    // ---- the reader: the episode's row, fetched from the holder
    let (mut e, mn) = Engine::init(tmp.path().join("reader").as_path()).unwrap();
    let seed = identity::generate_mnemonic().unwrap();
    let key = identity::device_key(&seed, "", 0).unwrap();
    let key_pub = crypto::pubkey_bytes(&key);
    e.authorize_member(&mn, &key_pub).unwrap();
    let root = e.identity.root_node_id.clone();
    let region = folder(&mut e, &root, "Library");
    e.region_mark_as(&region, "catalogue", Some(&Principal::Key(key_pub.clone()))).unwrap();
    let rows = vec![
        row("TV", "dir", 0, None),
        row("TV/Show", "dir", 0, None),
        row("TV/Show/ep.mkv", "file", ep.len() as u64, Some(hash.clone())),
    ];
    let manifest = Engine::region_manifest_bytes(&region, 1, &rows);
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
    e.install_region_snapshot(&region, 1, &manifest, &addr).unwrap();
    let data_dir = e.data_dir().to_path_buf();
    e.close().unwrap();

    // Stream mode, one piece of readahead: what the rest of the file needs is
    // fetched AFTER the trash, not before it.
    let opts = CacheOpts {
        mode: CacheMode::Stream,
        piece: PIECE,
        max_readahead: PIECE,
        complete_after: 1 << 40,
        burst: PIECE,
        ..CacheOpts::default()
    };
    let source = || Some(vec![ReplicaSource { transport: "socket".into(), target: addr.clone(), pin: String::new(), region: String::new() }]);
    let mnt = tempfile::tempdir().unwrap();
    let session = pvfs_fuse::MountGuard::new(
        pvfs_fuse::spawn_view_mount_with(&data_dir, mnt.path(), opts.clone(), source()).unwrap(),
        mnt.path(),
    );
    let path = mnt.path().join("TV/Show/ep.mkv");

    // ---- the stream starts…
    let mut f = std::fs::File::open(&path).unwrap();
    let mut got = vec![0u8; PIECE as usize];
    f.read_exact(&mut got).unwrap();
    assert_eq!(got, ep[..PIECE as usize]);

    // ---- …the upgrade trashes the episode on the holder, and the holder's
    // next head (without it) reaches the reader: the path leaves the view…
    sync::move_to_trash_with_sidecar(&files, &on_disk).unwrap();
    assert!(!on_disk.exists());
    let mut w = Engine::open(&data_dir).unwrap();
    let rows2 = vec![row("TV", "dir", 0, None), row("TV/Show", "dir", 0, None)];
    let manifest2 = Engine::region_manifest_bytes(&region, 2, &rows2);
    let prep = w
        .prepare_commit_region_head(&key_pub, &region, 2, blake3::hash(&manifest2).to_hex().as_str())
        .unwrap();
    let mut events = Vec::new();
    for pe in prep.events {
        let mut ev = pe.event;
        ev.set_author_sig(crypto::sign_digest(&key, &pe.digest).unwrap());
        events.push(ev);
    }
    w.commit_member_write(events).unwrap();
    w.install_region_snapshot(&region, 2, &manifest2, &addr).unwrap();
    w.close().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1_100)); // the kernel's 1 s attribute cache
    assert!(std::fs::metadata(&path).is_err(), "premise: the path has left the view");
    // (fstat on the open file still answers, as on a disk after an unlink)
    assert_eq!(f.metadata().expect("fstat of the open file").len(), ep.len() as u64);

    // ---- …and the stream reads on to the end, past it (the kernel asks
    // for the attributes there), the bytes the file's
    let mut rest = Vec::new();
    f.read_to_end(&mut rest).expect("the rest of the file reads from the holder's trash");
    got.extend_from_slice(&rest);
    assert_eq!(got.len(), ep.len());
    assert!(got == ep, "the bytes are the episode's");
    drop(f);

    // ---- a reader that opens it now finds nothing to open (the view moved
    // on); and one whose view had NOT moved on, opening it after the delete,
    // was not reading it: not found (D219), not the trashed bytes
    let late = std::fs::read(&path).map(|b| b.len());
    assert!(matches!(&late, Err(e) if e.kind() == ErrorKind::NotFound), "a late open: not found, got {late:?}");
    assert!(session.unmount(), "the mount is gone before its directory (D211)");
    let mut w = Engine::open(&data_dir).unwrap();
    let manifest3 = Engine::region_manifest_bytes(&region, 3, &rows);
    let prep = w
        .prepare_commit_region_head(&key_pub, &region, 3, blake3::hash(&manifest3).to_hex().as_str())
        .unwrap();
    let mut events = Vec::new();
    for pe in prep.events {
        let mut ev = pe.event;
        ev.set_author_sig(crypto::sign_digest(&key, &pe.digest).unwrap());
        events.push(ev);
    }
    w.commit_member_write(events).unwrap();
    w.install_region_snapshot(&region, 3, &manifest3, &addr).unwrap();
    w.close().unwrap();
    let mnt2 = tempfile::tempdir().unwrap();
    let session = pvfs_fuse::MountGuard::new(
        pvfs_fuse::spawn_view_mount_with(&data_dir, mnt2.path(), opts, source()).unwrap(),
        mnt2.path(),
    );
    let late = std::fs::read(mnt2.path().join("TV/Show/ep.mkv")).map(|b| b.len());
    assert!(matches!(&late, Err(e) if e.kind() == ErrorKind::NotFound), "a late open of a stale view: not found, got {late:?}");
    assert!(session.unmount(), "the mount is gone before its directory (D211)");
}
