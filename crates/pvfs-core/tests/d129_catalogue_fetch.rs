//! D129 item 1 — a catalogue snapshot travels as its manifest and is
//! installed only when it is exactly what the log attests (doc 26 §8).

use pvfs_core::acl::Principal;
use pvfs_core::{crypto, identity, BindSpec, Engine, HashPolicy, NodeSpec, RegionEntry, TYPE_FOLDER};

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

fn row(rel: &str, kind: &str, size: u64, hash: Option<&str>) -> RegionEntry {
    RegionEntry {
        rel_path: rel.into(),
        kind: kind.into(),
        size_bytes: size,
        mtime_ms: 1_700_000_000_000,
        changed_ms: 1_700_000_000_000,
        content_hash: hash.map(|h| h.into()),
        quality: None,
        seen_at: 0,
    }
}

/// The region owner (another box's client key) publishes `hash` as the
/// region's head at `seq`, through the routed op the forest owner accepts.
fn attest(e: &mut Engine, key: &identity::SigningKey, region: &str, seq: u64, hash: &str) {
    let pubkey = crypto::pubkey_bytes(key);
    let prep = e
        .prepare_commit_region_head(&pubkey, &region.to_string(), seq, hash)
        .unwrap();
    let mut events = Vec::new();
    for pe in prep.events {
        let mut ev = pe.event;
        ev.set_author_sig(crypto::sign_digest(key, &pe.digest).unwrap());
        events.push(ev);
    }
    e.commit_member_write(events).unwrap();
}

#[test]
fn a_manifest_round_trips_with_awkward_paths() {
    let region = "ab".repeat(32);
    let rows = vec![
        row("Movies", "dir", 0, None),
        row("Movies/Tab\there.mkv", "file", 5, Some(&"11".repeat(32))),
        row("Movies/back\\slash.mkv", "file", 6, None),
        row("Movies/new\nline.mkv", "file", 7, Some(&"22".repeat(32))),
    ];
    let bytes = Engine::region_manifest_bytes(&region, 3, &rows);
    let (r, seq, back) = Engine::parse_region_manifest(&bytes).unwrap();
    assert_eq!((r, seq), (region, 3));
    assert_eq!(back.len(), 4);
    for (a, b) in rows.iter().zip(&back) {
        assert_eq!((&a.rel_path, &a.kind, a.size_bytes, a.mtime_ms), (&b.rel_path, &b.kind, b.size_bytes, b.mtime_ms));
        assert_eq!(a.content_hash, b.content_hash);
    }
    assert!(Engine::parse_region_manifest(b"pvfs-region-manifest 2\n").is_err());
    assert!(Engine::parse_region_manifest(b"garbage").is_err());
    let mut broken = bytes.clone();
    broken.extend_from_slice(b"file\tonly-two\n");
    assert!(Engine::parse_region_manifest(&broken).is_err(), "a short row is refused");
}

#[test]
fn a_foreign_region_installs_only_what_the_log_attests_and_goes_stale_after() {
    let tmp = tempfile::tempdir().unwrap();
    let mine = tmp.path().join("mine");
    std::fs::create_dir_all(mine.join("Shows")).unwrap();
    std::fs::write(mine.join("Shows/local.mkv"), b"local-bytes").unwrap();

    let (mut e, mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let root = e.identity.root_node_id.clone();

    // The region this box catalogues itself.
    let local = folder(&mut e, &root, "Local");
    e.region_mark_as(&local, "catalogue", None).unwrap();
    e.bind_folder(
        &local,
        BindSpec {
            source_uri: format!("file://{}", mine.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    e.scan_routed(Some(&local), None, 0).unwrap();
    let _ = e.publish_region_snapshot(&local, &mut None).unwrap();
    let _ = e.commit_region_heads().unwrap();

    // A region another box catalogues: owned by that box's key, attested
    // through the routed op, no rows here.
    let holder_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let holder_pub = crypto::pubkey_bytes(&holder_key);
    e.authorize_member(&mn, &holder_pub).unwrap();
    let far = folder(&mut e, &root, "Far");
    e.region_mark_as(&far, "catalogue", Some(&Principal::Key(holder_pub.clone()))).unwrap();
    let rows = vec![
        row("Shows", "dir", 0, None),
        row("Shows/far.mkv", "file", 9, Some(&"33".repeat(32))),
        row("Shows/local.mkv", "file", 11, Some(&"44".repeat(32))),
    ];
    let bytes = Engine::region_manifest_bytes(&far, 1, &rows);
    let hash = blake3::hash(&bytes).to_hex().to_string();

    // Nothing attested yet: refused.
    assert!(e.install_region_snapshot(&far, 1, &bytes, "test").is_err());
    attest(&mut e, &holder_key, &far, 1, &hash);

    // Wrong seq, tampered bytes, a manifest for another region: refused.
    assert!(e.install_region_snapshot(&far, 2, &bytes, "test").is_err());
    let mut tampered = bytes.clone();
    tampered.extend_from_slice(b"file\tShows/extra.mkv\t1\t1\t-\t-\n");
    assert!(e.install_region_snapshot(&far, 1, &tampered, "test").is_err());
    assert!(e.install_region_snapshot(&local, 1, &bytes, "test").is_err(), "a region this box binds is never overwritten");
    assert!(e.merged_view("Shows").unwrap().iter().all(|v| v.rel_path != "Shows/far.mkv"), "nothing installed so far");

    // The attested bytes install; the view unions them; the copy is fresh.
    assert_eq!(e.install_region_snapshot(&far, 1, &bytes, "test").unwrap(), 3);
    let shows = e.merged_view("Shows").unwrap();
    let names: Vec<&str> = shows.iter().map(|v| v.rel_path.as_str()).collect();
    assert_eq!(names, vec!["Shows/far.mkv", "Shows/local.mkv"]);
    let local_entry = shows.iter().find(|v| v.rel_path == "Shows/local.mkv").unwrap();
    assert_eq!(local_entry.sources.len(), 2, "both regions hold Shows/local.mkv");
    assert!(shows.iter().all(|v| v.sources.iter().all(|c| !c.stale)));
    let st = e.catalogue_status().unwrap();
    let far_st = st.iter().find(|s| s.region == far).unwrap();
    assert_eq!((far_st.head_seq, far_st.held_seq, far_st.local, far_st.stale, far_st.entries), (1, Some(1), false, false, 3));
    let local_st = st.iter().find(|s| s.region == local).unwrap();
    assert!(local_st.local && !local_st.stale && local_st.held_seq == Some(local_st.head_seq));

    // A fetched region is never re-published as a head by this box.
    assert_eq!(e.commit_region_heads().unwrap(), 0);

    // The holder publishes head 2: what this box holds is now stale, and
    // every copy from that region says so — until the next fetch.
    let rows2 = vec![row("Shows", "dir", 0, None), row("Shows/far.mkv", "file", 10, Some(&"55".repeat(32)))];
    let bytes2 = Engine::region_manifest_bytes(&far, 2, &rows2);
    let hash2 = blake3::hash(&bytes2).to_hex();
    attest(&mut e, &holder_key, &far, 2, hash2.as_str());
    let far_st = e.catalogue_status().unwrap().into_iter().find(|s| s.region == far).unwrap();
    assert_eq!((far_st.head_seq, far_st.held_seq, far_st.stale), (2, Some(1), true));
    let shows = e.merged_view("Shows").unwrap();
    let far_copy = shows
        .iter()
        .find(|v| v.rel_path == "Shows/far.mkv")
        .and_then(|v| v.sources.iter().find(|c| c.region == far))
        .unwrap();
    assert!(far_copy.stale);
    let local_copy = shows
        .iter()
        .find(|v| v.rel_path == "Shows/local.mkv")
        .and_then(|v| v.sources.iter().find(|c| c.region == local))
        .unwrap();
    assert!(!local_copy.stale, "a local region is never stale");
    assert!(e.install_region_snapshot(&far, 1, &bytes, "test").is_err(), "the old head is no longer installable");
    assert_eq!(e.install_region_snapshot(&far, 2, &bytes2, "test").unwrap(), 2);
    let far_st = e.catalogue_status().unwrap().into_iter().find(|s| s.region == far).unwrap();
    assert_eq!((far_st.held_seq, far_st.stale), (Some(2), false));
    assert!(e.merged_view("Shows").unwrap().iter().all(|v| v.rel_path != "Shows/local.mkv" || v.sources.len() == 1), "the superseded row is gone");
    e.close().unwrap();
}
