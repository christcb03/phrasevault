//! PVOS D185 — a holder promoted to owner keeps its library.
//!
//! A holder's enrollments live in its own `bindings.local` (D71 W4), never in
//! the log, and `forest promote` keeps that file. Before D185 `bindings_for`
//! returned those rows with `bound_by` empty, so every owner-side "is this
//! binding mine?" said no: the promoted box stopped serving its own bytes,
//! reading its own disks in its view, trashing and renaming there, and
//! `pvfs scan <region>` called its region "bound on another machine".

use std::path::Path;

use pvfs_core::{
    crypto, identity, BindSpec, Engine, HashPolicy, NodeSpec, RenameExpect, RenamedHere, ReplicaSource, TrashedHere,
    TYPE_FOLDER,
};

fn write(root: &Path, rel: &str, bytes: &[u8]) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

fn hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// A replica of the data dir `owner` at `dir` — the owner's log plus a marker.
fn replica_of(owner: &Path, dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    for f in ["log.db", "log.db-wal", "log.db-shm"] {
        if owner.join(f).exists() {
            std::fs::copy(owner.join(f), dir.join(f)).unwrap();
        }
    }
    ReplicaSource { transport: "tcp".into(), target: "192.0.2.1:7421".into(), pin: "7".repeat(64), region: String::new() }
        .save(dir)
        .unwrap();
}

fn live_owner_devices(e: &Engine) -> Vec<Vec<u8>> {
    e.devices()
        .unwrap()
        .into_iter()
        .filter(|d| d.revoked_at.is_none())
        .map(|d| hex::decode(d.pubkey).unwrap())
        .collect()
}

#[test]
fn a_promoted_holder_serves_trashes_renames_and_scans_its_own_library() {
    let tmp = tempfile::tempdir().unwrap();
    let (a, b, disk) = (tmp.path().join("owner"), tmp.path().join("holder"), tmp.path().join("disk"));
    write(&disk, "TV/Show/Season 1/e1.mkv", b"episode-one-bytes");
    write(&disk, "TV/Show/Season 1/e2.mkv", b"episode-two-bytes");
    write(&disk, "TV/Show/Season 1/e3.mkv", b"episode-three-bytes");

    // The owner makes the region, as mediabox's were made (D147).
    let (mut owner, mn) = Engine::init(&a).unwrap();
    let root = owner.identity.root_node_id.clone();
    let region = owner
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "mediabox-local".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    owner.region_mark_as(&region, "catalogue", None).unwrap();
    let old = live_owner_devices(&owner);
    owner.close().unwrap();

    // The holder binds it on its own disk: a replica's binding is local.
    replica_of(&a, &b);
    let mut holder = Engine::open(&b).unwrap();
    assert!(holder.is_replica());
    holder
        .bind_folder(
            &region,
            BindSpec {
                source_uri: format!("file://{}", disk.display()),
                recursive: true,
                auto_index: true,
                extensions: String::new(),
                hash_policy: HashPolicy::OnAdd,
            },
        )
        .unwrap();
    holder.close().unwrap();
    assert!(b.join("bindings.local").exists(), "premise: the binding is the holder's own file, not the log");

    // Promoted (D182): the file stays, and the box is the owner now.
    let mut e = Engine::promote_with_phrase(&b, &mn, 1, &old).unwrap();
    assert!(!e.is_replica());
    let mine = e.bindings_for(&region).unwrap();
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].bound_by, e.device_pubkey(), "its local binding is its own");

    // `pvfs scan <region>` scans it — and, as the owner, puts the head
    // straight into the log.
    let before = e.log_tip().unwrap();
    e.scan_routed(Some(&region), None, 0).unwrap();
    assert!(e.log_tip().unwrap() > before, "the head is in the log");

    // It serves its own bytes: a peer's fetch, and its own view's reads.
    let got = e
        .local_path_for_hash(&hash(b"episode-one-bytes"))
        .unwrap()
        .expect("served from its own disk");
    assert_eq!(got.path, disk.join("TV/Show/Season 1/e1.mkv"));
    assert_eq!(got.region, region);

    // `serve status` counts its disk.
    assert!(e.store_filesystems().unwrap().iter().any(|s| s.regions.contains(&region)));

    // A delete through the view lands in the region's trash, on its disk.
    match e.trash_region_path(&region, "TV/Show/Season 1/e2.mkv", &hash(b"episode-two-bytes")).unwrap() {
        TrashedHere::Trashed(_) => {}
        other => panic!("expected the file trashed here, got {other:?}"),
    }
    assert!(!disk.join("TV/Show/Season 1/e2.mkv").exists());

    // A rename through the view lands on its disk.
    let expect = RenameExpect::File { hash: hash(b"episode-three-bytes"), size: b"episode-three-bytes".len() as u64 };
    assert_eq!(
        e.rename_region_path(&region, "TV/Show/Season 1/e3.mkv", "TV/Show/Season 1/e03.mkv", &expect).unwrap(),
        RenamedHere::Moved
    );
    assert!(disk.join("TV/Show/Season 1/e03.mkv").exists());

    // Unbinding its local root edits its own file and logs nothing: the log
    // never held that root.
    let tip = e.log_tip().unwrap();
    e.unbind_folder(&region, None).unwrap();
    assert_eq!(e.log_tip().unwrap(), tip, "nothing logged for a root the log never held");
    assert!(e.bindings_for(&region).unwrap().is_empty(), "and the binding is gone");
    e.close().unwrap();
}

/// Sign a one-event prepared write with `key` and commit it.
fn commit1(engine: &mut Engine, prep: pvfs_core::PreparedWrite, key: &identity::SigningKey) {
    let mut events = Vec::new();
    for pe in prep.events {
        let mut ev = pe.event;
        ev.set_author_sig(crypto::sign_digest(key, &pe.digest).unwrap());
        events.push(ev);
    }
    engine.commit_member_write(events).unwrap();
}

#[test]
fn forest_tip_reads_the_current_root_beside_a_running_engine() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join(".pvfs");
    let (mut e, mn) = Engine::init(&data).unwrap();
    let old_key = identity::root_key(&mn, "").unwrap();
    let old_root = crypto::pubkey_bytes(&old_key);
    let id = pvfs_core::mount::peek_identity(tmp.path()).unwrap();
    assert_eq!(pvfs_core::mount::peek_current_root(&data, &id).unwrap(), old_root);

    let new_root = crypto::pubkey_bytes(&identity::root_key(&identity::generate_mnemonic().unwrap(), "").unwrap());
    let prep = e.prepare_rotate_root(&old_root, &new_root).unwrap();
    commit1(&mut e, prep, &old_key);

    // Read-only, with the engine still open (a running daemon): the key a
    // companion must hold to promote is the NEW root; genesis still names the
    // first one.
    assert_eq!(pvfs_core::mount::peek_current_root(&data, &id).unwrap(), new_root);
    assert_eq!(id.root_pubkey, old_root);
    e.close().unwrap();
}
