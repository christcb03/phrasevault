//! D130 item 0 — one path's view entry agrees with the listing; a hash
//! resolves to this box's own bytes only when they are really there.

use pvfs_core::acl::Principal;
use pvfs_core::{crypto, identity, sync, BindSpec, Engine, HashPolicy, NodeSpec, RegionEntry, ViewState, TYPE_FOLDER};

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

fn region(e: &mut Engine, label: &str, dir: &std::path::Path, policy: HashPolicy) -> String {
    let root = e.identity.root_node_id.clone();
    let r = folder(e, &root, label);
    e.region_mark_as(&r, "catalogue", None).unwrap();
    e.bind_folder(
        &r,
        BindSpec {
            source_uri: format!("file://{}", dir.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: policy,
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

fn hex_of(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

#[test]
fn a_single_path_lookup_agrees_with_the_listing_and_bytes_resolve_only_when_real() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    let c = tmp.path().join("c");
    write(&a, "Movies/Same (2001)/same.mkv", b"identical");
    write(&b, "Movies/Same (2001)/same.mkv", b"identical");
    write(&a, "Movies/Differs (2002)/differs.mkv", b"version-a");
    write(&b, "Movies/Differs (2002)/differs.mkv", b"version-b!");
    write(&a, "Movies/Only A (2003)/only.mkv", b"only-a");
    write(&c, "Movies/Never (2004)/never.mkv", b"never hashed");

    let (mut e, mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let ra = region(&mut e, "A", &a, HashPolicy::OnAdd);
    let rb = region(&mut e, "B", &b, HashPolicy::OnAdd);
    let _rc = region(&mut e, "C", &c, HashPolicy::Never);

    // view_entry == the listing's entry, for every state.
    let listing = e.merged_view("Movies/Same (2001)").unwrap();
    let same = e.view_entry("Movies/Same (2001)/same.mkv").unwrap().expect("admitted");
    assert_eq!(same, listing[0]);
    assert_eq!(same.state, ViewState::Admitted);
    assert_eq!(same.sources.len(), 2);
    let differs = e.view_entry("/Movies/Differs (2002)/differs.mkv/").unwrap().expect("conflict");
    assert!(matches!(differs.state, ViewState::ConflictHashes(ref h) if h.len() == 2));
    assert_eq!(differs, e.merged_view("Movies/Differs (2002)").unwrap()[0]);
    let never = e.view_entry("Movies/Never (2004)/never.mkv").unwrap().expect("listed, unhashed");
    assert_eq!(never.state, ViewState::Unhashed);
    let movies = e.view_entry("Movies").unwrap().expect("a directory");
    assert_eq!(movies.kind, "dir");
    assert_eq!(movies.sources.len(), 3, "three regions hold Movies/");
    assert!(e.view_entry("Movies/Nope").unwrap().is_none());
    assert!(e.view_entry("").unwrap().is_none());

    // A hash resolves to this box's own file, size-checked, first region first.
    let h_same = hex_of(b"identical");
    let lb = e.local_path_for_hash(&h_same).unwrap().expect("held here");
    assert_eq!(lb.size, 9);
    assert_eq!(std::fs::read(&lb.path).unwrap(), b"identical");
    // Regions are visited by id, and ids are random: whichever of A and B
    // sorts first serves first.
    let (first_dir, second_dir) = if ra < rb { (&a, &b) } else { (&b, &a) };
    let p = lb.path.clone();
    assert!(p.starts_with(first_dir), "the first region by id serves first: {p:?}");
    assert_eq!(lb.region, ra.clone().min(rb.clone()), "the first region by id");
    assert!(e.local_path_for_hash(&"00".repeat(32)).unwrap().is_none());
    // The first region's copy shrinks on disk (a half-written file): the
    // other region's copy serves instead.
    std::fs::write(first_dir.join("Movies/Same (2001)/same.mkv"), b"ident").unwrap();
    let p2 = e.local_path_for_hash(&h_same).unwrap().expect("the other region still has it").path;
    assert!(p2.starts_with(second_dir), "{p2:?}");
    std::fs::write(second_dir.join("Movies/Same (2001)/same.mkv"), b"ident").unwrap();
    assert!(e.local_path_for_hash(&h_same).unwrap().is_none(), "no copy of the right size is left");

    // A fetched region's row is never a local path, even with a hash nobody
    // else has: the bytes are on another box.
    let holder_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let holder_pub = crypto::pubkey_bytes(&holder_key);
    e.authorize_member(&mn, &holder_pub).unwrap();
    let root = e.identity.root_node_id.clone();
    let far = folder(&mut e, &root, "Far");
    e.region_mark_as(&far, "catalogue", Some(&Principal::Key(holder_pub.clone()))).unwrap();
    let h_far = hex_of(b"far away bytes");
    let rows = vec![
        RegionEntry { rel_path: "Movies".into(), kind: "dir".into(), size_bytes: 0, mtime_ms: 1, changed_ms: 1, content_hash: None, quality: None, seen_at: 0 },
        RegionEntry { rel_path: "Movies/Far (2005)".into(), kind: "dir".into(), size_bytes: 0, mtime_ms: 1, changed_ms: 1, content_hash: None, quality: None, seen_at: 0 },
        RegionEntry { rel_path: "Movies/Far (2005)/far.mkv".into(), kind: "file".into(), size_bytes: 14, mtime_ms: 1, changed_ms: 1, content_hash: Some(h_far.clone()), quality: None, seen_at: 0 },
    ];
    let bytes = Engine::region_manifest_bytes(&far, 1, &rows);
    let prep = e
        .prepare_commit_region_head(&holder_pub, &far, 1, &hex_of(&bytes))
        .unwrap();
    let mut events = Vec::new();
    for pe in prep.events {
        let mut ev = pe.event;
        ev.set_author_sig(crypto::sign_digest(&holder_key, &pe.digest).unwrap());
        events.push(ev);
    }
    e.commit_member_write(events).unwrap();
    assert_eq!(e.install_region_snapshot(&far, 1, &bytes, "test").unwrap(), 3);
    let far_entry = e.view_entry("Movies/Far (2005)/far.mkv").unwrap().expect("in the view");
    assert_eq!(far_entry.state, ViewState::Admitted);
    assert!(e.local_path_for_hash(&h_far).unwrap().is_none(), "a fetched row is not bytes");

    // The hash store: a separate, hash-keyed corner of the sync store.
    let data_dir = e.data_dir().to_path_buf();
    assert!(sync::hash_store_lookup(&data_dir, &h_far).unwrap().is_none());
    let p = sync::hash_store_path(&data_dir, &h_far).unwrap();
    assert!(p.to_string_lossy().contains("by-hash"));
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, b"far away bytes").unwrap();
    assert_eq!(sync::hash_store_lookup(&data_dir, &h_far).unwrap(), Some(p));
    assert!(sync::hash_store_path(&data_dir, "nope").is_err());
    let _ = (&ra, &rb);
    e.close().unwrap();
}
