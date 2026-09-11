//! D133 items 2-3 — the receiving side moves bytes: locally when this box
//! holds them, over the wire by hash otherwise (ranged, resumable,
//! cancellable, refusing wrong bytes); a staging winner replaces the library
//! copy; resolve then drains and, past retention, purges.

use std::os::unix::net::UnixListener;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use pvfs_client::receive::{partial_path, pull_into_partial, receive_pass_on};
use pvfs_core::acl::{self, Principal};
use pvfs_core::media::Rules;
use pvfs_core::sync::{self, SWARM_CHUNK};
use pvfs_core::{crypto, identity, BindSpec, Engine, HashPolicy, NodeSpec, ReceiveItem, ReplicaSource, ViewState, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

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

fn region(e: &mut Engine, label: &str, dir: &std::path::Path) -> String {
    let root = e.identity.root_node_id.clone();
    let r = folder(e, &root, label);
    e.region_mark_as(&r, "catalogue", None).unwrap();
    std::fs::create_dir_all(dir).unwrap();
    e.bind_folder(
        &r,
        BindSpec {
            source_uri: format!("file://{}", dir.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    e.scan_routed(Some(&r), None, 0).unwrap();
    r
}

fn write(dir: &std::path::Path, rel: &str, bytes: &[u8]) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

fn mtime_ms(p: &std::path::Path) -> u64 {
    std::fs::metadata(p)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[test]
fn a_box_receives_its_own_staging_files_replaces_a_loser_and_drains_them() {
    let tmp = tempfile::tempdir().unwrap();
    let staging = tmp.path().join("staging");
    let lib = tmp.path().join("lib");
    write(&staging, "Movies/New (2024)/new.mkv", b"new-bytes");
    write(&staging, "Movies/Up (2002)/up.mkv", b"upgraded-much-larger-bytes");
    write(&lib, "Movies/Up (2002)/up.mkv", b"small");
    std::fs::File::options()
        .write(true)
        .open(lib.join("Movies/Up (2002)/up.mkv"))
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(120))
        .unwrap();
    let (mut e, _mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let rs = region(&mut e, "Staging", &staging);
    let rl = region(&mut e, "Library", &lib);
    e.set_region_drain(&rs, true).unwrap();
    sync::set_region_receive(e.data_dir(), &rl, true).unwrap();
    let never = AtomicBool::new(false);

    // Dry run: says what would happen, moves nothing.
    let dry = receive_pass_on(&e, &Rules::default(), true, 0, &never).unwrap();
    assert!(dry.dry_run && dry.received.len() == 2 && dry.replaced == vec!["Movies/Up (2002)/up.mkv".to_string()]);
    assert!(!lib.join("Movies/New (2024)/new.mkv").exists());

    let rep = receive_pass_on(&e, &Rules::default(), false, 0, &never).unwrap();
    assert_eq!(rep.received.len(), 2, "{rep:?}");
    assert!(rep.failed.is_empty() && rep.skipped_no_space.is_empty(), "{rep:?}");
    let new = lib.join("Movies/New (2024)/new.mkv");
    assert_eq!(std::fs::read(&new).unwrap(), b"new-bytes");
    assert_eq!(mtime_ms(&new), mtime_ms(&staging.join("Movies/New (2024)/new.mkv")), "mtime copied from the row");
    let h_new = blake3::hash(b"new-bytes").to_hex().to_string();
    assert_eq!(sync::sidecar_whole_hash(&new, 9).as_deref(), Some(h_new.as_str()), "a sidecar so the watch does not re-hash");
    assert_eq!(std::fs::read(lib.join("Movies/Up (2002)/up.mkv")).unwrap(), b"upgraded-much-larger-bytes");
    let trashed: Vec<_> = walk(&lib.join(".pvfs-trash"));
    assert!(trashed.iter().any(|p| p.ends_with("Movies/Up (2002)/up.mkv")), "the old library copy is in the trash: {trashed:?}");
    assert!(!lib.join(".pvfs-incoming").join(format!("{h_new}.partial")).exists(), "no partial left");

    // The library catalogues what landed; the view now sees agreeing pairs.
    e.scan_routed(Some(&rl), None, 0).unwrap();
    let movies: Vec<_> = e.view_paths().unwrap().into_iter().filter(|v| v.kind == "file").collect();
    for v in &movies {
        assert_eq!(v.state, ViewState::Admitted, "{v:?}");
        assert_eq!(v.sources.len(), 2, "{v:?}");
    }
    // A second pass has nothing to do.
    let again = receive_pass_on(&e, &Rules::default(), false, 0, &never).unwrap();
    assert!(again.received.is_empty(), "{again:?}");

    // The staging side drains: resolve trashes the redundant copies, and a
    // retention of 0 lets the purge free them at once.
    let res = e.resolve_conflicts(&Rules::default(), false, &never).unwrap();
    assert_eq!(res.trashed.len(), 2, "{res:?}");
    assert!(!staging.join("Movies/New (2024)/new.mkv").exists());
    assert!(staging.join(".pvfs-trash").exists());
    let kept = e.purge_draining_trash().unwrap();
    assert_eq!(kept.iter().map(|(_, p)| p.removed).sum::<u64>(), 0, "7-day default keeps today's bucket");
    sync::set_region_retention(e.data_dir(), &rs, 0).unwrap();
    let purged = e.purge_draining_trash().unwrap();
    assert_eq!(purged.iter().map(|(_, p)| p.removed).sum::<u64>(), 1, "{purged:?}");
    assert!(walk(&staging.join(".pvfs-trash")).is_empty());

    // No space: nothing is written, the file is reported.
    write(&staging, "Movies/Late (2025)/late.mkv", b"late");
    e.scan_routed(Some(&rs), None, 0).unwrap();
    let full = receive_pass_on(&e, &Rules::default(), false, u64::MAX, &never).unwrap();
    assert_eq!(full.skipped_no_space, vec!["Movies/Late (2025)/late.mkv".to_string()]);
    assert!(!lib.join("Movies/Late (2025)/late.mkv").exists());
    e.close().unwrap();
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

#[test]
fn over_the_wire_pulls_are_ranged_resumable_cancellable_and_verified() {
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let tmp = tempfile::tempdir().unwrap();
    let files = tmp.path().join("staging");
    let big: Vec<u8> = (0..(SWARM_CHUNK as usize + 1_000_000)).map(|i| (i % 251) as u8).collect();
    write(&files, "Shows/big.mkv", &big);
    write(&files, "Shows/small.mkv", b"small-bytes");
    let h_big = blake3::hash(&big).to_hex().to_string();
    let h_small = blake3::hash(b"small-bytes").to_hex().to_string();

    let (mut owner, mn) = Engine::init(tmp.path().join("holder").as_path()).unwrap();
    let rs = region(&mut owner, "Staging", &files);
    owner.set_region_drain(&rs, true).unwrap();
    let me_key = identity::device_key(&identity::client_identity_mnemonic().unwrap(), "", 0).unwrap();
    let me_pub = crypto::pubkey_bytes(&me_key);
    owner.authorize_member(&mn, &me_pub).unwrap();
    let root = owner.identity.root_node_id.clone();
    owner.set_acl(&root, &Principal::Key(me_pub.clone()), acl::ACL_R).unwrap();
    let big_mtime = mtime_ms(&files.join("Shows/big.mkv"));

    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = Arc::new(Daemon::new(owner));
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }
    let src = ReplicaSource {
        transport: "socket".into(),
        target: sock.to_string_lossy().into_owned(),
        pin: String::new(),
        region: String::new(),
    };
    let lib = tmp.path().join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    let item = |rel: &str, hash: &str, size: u64| ReceiveItem {
        rel_path: rel.into(),
        hash: hash.into(),
        size_bytes: size,
        mtime_ms: big_mtime,
        from_region: rs.clone(),
        dest_region: "ab".repeat(32),
        dest_root: lib.clone(),
        replaces: false,
    };
    let never = AtomicBool::new(false);

    // Two ranges for a file just over one chunk; the chunk hashes match.
    let big_item = item("Shows/big.mkv", &h_big, big.len() as u64);
    let chunks = pull_into_partial(&big_item, None, std::slice::from_ref(&src), &never).unwrap().expect("not cancelled");
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0], *blake3::hash(&big[..SWARM_CHUNK as usize]).as_bytes());
    let part = partial_path(&big_item);
    assert_eq!(std::fs::read(&part).unwrap(), big);

    // Resume: a partial holding exactly the first chunk is kept, not refetched.
    std::fs::write(&part, &big[..SWARM_CHUNK as usize]).unwrap();
    let chunks = pull_into_partial(&big_item, None, std::slice::from_ref(&src), &never).unwrap().unwrap();
    assert_eq!(chunks.len(), 2);
    assert_eq!(std::fs::read(&part).unwrap(), big);
    // A partial that is not chunk-aligned is truncated to the last boundary first.
    std::fs::write(&part, &big[..SWARM_CHUNK as usize + 5]).unwrap();
    assert!(pull_into_partial(&big_item, None, std::slice::from_ref(&src), &never).unwrap().is_some());
    assert_eq!(std::fs::read(&part).unwrap(), big);
    let _ = std::fs::remove_file(&part);

    // Cancel: the pass stops between ranges and keeps what landed.
    let stop = AtomicBool::new(true);
    assert!(pull_into_partial(&big_item, None, std::slice::from_ref(&src), &stop).unwrap().is_none());

    // Wrong bytes: the holder's file changed under its row — the served
    // bytes do not hash to the row's hash, so they are refused and dropped.
    let _ = std::fs::remove_file(&part);
    std::fs::write(files.join("Shows/small.mkv"), b"tampered!!!").unwrap();
    let small_item = item("Shows/small.mkv", &h_small, 11);
    let err = pull_into_partial(&small_item, None, std::slice::from_ref(&src), &never).unwrap_err();
    assert!(err.contains("refused"), "{err}");
    assert!(!partial_path(&small_item).exists());

    // Nobody holds it: a clear error, and the partial (empty) is left for next time.
    let ghost = item("Shows/ghost.mkv", &"00".repeat(32), 10);
    let err = pull_into_partial(&ghost, None, std::slice::from_ref(&src), &never).unwrap_err();
    assert!(err.contains("no announced endpoint") || err.contains("not_found") || err.contains("holds"), "{err}");
}
