//! D113 — the duplicate pairs D112 stopped making, and the amplifier that
//! turned each one into a family.
//!
//! `match_by_identity` returned `Option<NodeId>` and answered `None` both for
//! "never seen this file" and for "more than one candidate". The caller read
//! `None` as "new", so every later sighting of an already-duplicated file added
//! another node — and each new node made the next sighting ambiguous too.
//!
//! Two candidates in DIFFERENT folders really is a tie nothing can break: an
//! unrelated `poster.jpg` of the same size is a different file, and a new node
//! is right (that case is pinned in `d71_identity`). Two under the SAME parent
//! is not a tie at all — it is one file the catalogue holds twice.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FILE, TYPE_FOLDER};

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

fn file_node(e: &mut Engine, parent: &str, label: &str, size: u64) -> String {
    e.add_node(
        &parent.to_string(),
        NodeSpec {
            node_type: TYPE_FILE.into(),
            label: label.into(),
            payload: pvfs_core::FilePayload {
                content_hash: String::new(),
                size_bytes: size,
                mime_type: "video/x-matroska".into(),
                original_name: label.into(),
            }
            .encode(),
            is_temp: false,
            creation_nonce: None,
        },
    )
    .unwrap()
}

/// Exactly production's shape: one file, two nodes, same parent, one holding
/// the location and one holding nothing. That empty half is what `missing`
/// reports, and there are ~1,910 of them.
fn duplicated_pair(e: &mut Engine) -> (String, String, String) {
    let root = e.identity.root_node_id.clone();
    let season = folder(e, &root, "Season 01");
    let ingest_node = file_node(e, &season, "ep04.mkv", 1024);
    let holder_node = file_node(e, &season, "ep04.mkv", 1024);
    e.add_location(&holder_node, "pvfs-host://nas/share/Media/ep04.mkv")
        .unwrap();
    (season, ingest_node, holder_node)
}

/// D114 — the pairs production actually made DISAGREE ABOUT SIZE, and that is
/// the whole reason they exist: the identity match joins on name AND size, so
/// it could never see them as one file.
///
/// The first version of `list_duplicates` grouped by the identity rule and
/// therefore found NOTHING on a forest holding 587 of these. Grouping by the
/// broken rule reproduces the breakage. A directory cannot hold two files with
/// one name, so parent + name is the key and size is evidence.
#[test]
fn duplicates_that_disagree_about_size_are_still_one_file() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let season = folder(&mut e, &root, "Season 01");
    // The real numbers from the production pair, ~50 MB apart.
    let partial = file_node(&mut e, &season, "ep04.mkv", 1_594_457_815);
    let complete = file_node(&mut e, &season, "ep04.mkv", 1_544_349_595);
    e.add_location(&partial, "pvfs-host://nas/share/Media/ep04.mkv")
        .unwrap();

    let r = e.list_duplicates().unwrap();
    assert_eq!(r.groups.len(), 1, "one file, two nodes, two sizes");
    let g = &r.groups[0];
    assert_eq!(g.drop.len(), 1);
    let mut sizes = g.sizes.clone();
    sizes.sort_unstable();
    assert_eq!(
        sizes,
        vec![1_544_349_595, 1_594_457_815],
        "and the report shows the disagreement rather than hiding it"
    );
    assert!(g.keep == partial || g.keep == complete);
    e.close().unwrap();
}

/// The report names the pair, and says which node survives BEFORE anything is
/// merged — so the merge cannot surprise the person who read it.
#[test]
fn a_duplicated_file_is_reported_with_its_keeper_named() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let (_season, ingest_node, holder_node) = duplicated_pair(&mut e);

    let r = e.list_duplicates().unwrap();
    assert_eq!(r.groups.len(), 1, "one file, held twice");
    assert_eq!(r.redundant, 1, "one node would go");
    let g = &r.groups[0];
    assert_eq!(g.label, "ep04.mkv");
    assert_eq!(
        g.keep, holder_node,
        "the node holding the location is the keeper — the fleet already points at it"
    );
    assert_eq!(g.drop, vec![ingest_node]);
    assert_eq!(g.locations, 1);
    e.close().unwrap();
}

/// The merge preserves every location and destroys nothing.
#[test]
fn merging_moves_locations_before_it_unlinks() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let (season, ingest_node, holder_node) = duplicated_pair(&mut e);
    // Give the loser a location too, so the merge has something to move.
    e.add_location(&ingest_node, "file:///mnt/local/Media/ep04.mkv")
        .unwrap();

    let done = e.merge_duplicates(false).unwrap();
    assert_eq!(done.groups.len(), 1);
    assert_eq!(done.locations_moved, 1, "one location had to move");

    // Ask the REPORT which node survived rather than assuming. With a location
    // each, the tie breaks on age, and asserting against a guess would test the
    // test rather than the merge.
    let keep = done.groups[0].keep.clone();
    let loser = done.groups[0].drop[0].clone();
    assert!(keep == holder_node || keep == ingest_node);

    let kept: Vec<String> = e.locations(&keep).unwrap();
    assert_eq!(kept.len(), 2, "both locations now sit on the keeper: {kept:?}");
    assert!(
        e.locations(&loser).unwrap().is_empty(),
        "and none are left claimed by the node that was unlinked — an unlinked \
         node holding a live location is its own bad state (D84 counted 95)"
    );

    let listed: Vec<String> = e
        .children(&season)
        .unwrap()
        .into_iter()
        .map(|c| c.node.id)
        .collect();
    assert_eq!(listed, vec![keep], "only one node left in the tree");

    // Nothing destroyed — unlink is a soft remove on an append-only log.
    assert!(
        e.get_node(&loser).unwrap().is_some(),
        "the loser's record survives; only its place in the tree is gone"
    );
    e.close().unwrap();
}

/// The amplifier. Scanning a file the catalogue already holds twice HERE must
/// not enrol a third — that is how one duplicate became a family.
#[test]
fn a_scan_will_not_make_a_third_copy_of_an_already_duplicated_file() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let season = folder(&mut e, &root, "Season 01");
    file_node(&mut e, &season, "ep04.mkv", 4);
    file_node(&mut e, &season, "ep04.mkv", 4);

    let lib = dir.path().join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    std::fs::write(lib.join("ep04.mkv"), b"abcd").unwrap();
    e.bind_folder(
        &season,
        BindSpec {
            source_uri: format!("file://{}", lib.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();

    let rep = e.scan_routed(Some(&season), None, 0).unwrap();
    assert_eq!(
        rep[0].stats.added, 0,
        "the file is already catalogued — twice. A third node is not a fix"
    );
    assert_eq!(rep[0].stats.ambiguous, 1, "and the scan says why it did nothing");

    let files = e
        .children(&season)
        .unwrap()
        .into_iter()
        .filter(|c| c.node.node_type == TYPE_FILE)
        .count();
    assert_eq!(files, 2, "still two, not three");
    e.close().unwrap();
}

/// …and once merged, the same scan catalogues normally again. The two halves
/// compose: D113 stops the growth, and the merge restores the match.
#[test]
fn after_a_merge_the_scan_matches_instead_of_refusing() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let season = folder(&mut e, &root, "Season 01");
    file_node(&mut e, &season, "ep04.mkv", 4);
    file_node(&mut e, &season, "ep04.mkv", 4);
    e.merge_duplicates(false).unwrap();

    let lib = dir.path().join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    std::fs::write(lib.join("ep04.mkv"), b"abcd").unwrap();
    e.bind_folder(
        &season,
        BindSpec {
            source_uri: format!("file://{}", lib.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();

    let rep = e.scan_routed(Some(&season), None, 0).unwrap();
    assert_eq!(rep[0].stats.ambiguous, 0, "no longer ambiguous");
    assert_eq!(
        rep[0].stats.added, 0,
        "and still not a new node — it matched the survivor"
    );
    assert_eq!(
        rep[0].stats.relocated, 1,
        "the on-disk copy became a LOCATION on the node that survived"
    );
    e.close().unwrap();
}

/// D117 — the check D115 leans on has to know BOTH spellings of a location.
///
/// A replica records its locations pin-qualified (`pvfs-host://<own pin>/path`,
/// D75), not as bare `file://` paths. D115 asked "does this node already have a
/// location under the root I am scanning?" using only the bare form, so on
/// every replica the answer was `false` — and D115 is a no-op exactly on the
/// boxes that scan media. Duplicates kept being minted after it shipped.
///
/// Measured on the live forest at the time: 30,677 of 30,782 locations were
/// `pvfs-host://`.
#[test]
fn a_pin_qualified_location_counts_as_this_box_holding_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    std::fs::write(lib.join("ep01.mkv"), vec![9u8; 4096]).unwrap();

    let (mut e, _mn) = Engine::init(&dir.path().join("forest")).unwrap();
    // Give this forest a transport pin, as a served instance has.
    let pin = "ab".repeat(32);
    let nettls = e.data_dir().join("nettls");
    std::fs::create_dir_all(&nettls).unwrap();
    std::fs::write(nettls.join("pin"), &pin).unwrap();

    let root = e.identity.root_node_id.clone();
    let season = folder(&mut e, &root, "Season 01");
    e.bind_folder(
        &season,
        BindSpec {
            source_uri: format!("file://{}", lib.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    e.scan_routed(Some(&season), None, 0).unwrap();
    e.close().unwrap();

    // Re-open so `own_pin` is read, then rewrite the location the way a replica
    // spells it and change the file's size — the *arr-upgrade shape.
    let mut e = Engine::open(&dir.path().join("forest")).unwrap();
    let id = e
        .children(&season)
        .unwrap()
        .into_iter()
        .find(|c| c.node.node_type == TYPE_FILE)
        .unwrap()
        .node
        .id;
    for uri in e.locations(&id).unwrap() {
        e.remove_location(&id, &uri).unwrap();
    }
    let qualified = format!("{}{}{}/ep01.mkv", "pvfs-host://", pin, lib.display());
    e.add_location(&id, &qualified).unwrap();

    std::fs::write(lib.join("ep01.mkv"), vec![9u8; 8192]).unwrap();
    let rep = e.scan_routed(Some(&season), None, 0).unwrap();

    assert_eq!(
        rep[0].stats.added, 0,
        "the box already holds this file — pin-qualified is still holding it"
    );
    assert_eq!(
        rep[0].stats.changed, 1,
        "a different size at the same path is a CHANGE, not a new file"
    );
    let files = e
        .children(&season)
        .unwrap()
        .into_iter()
        .filter(|c| c.node.node_type == TYPE_FILE)
        .count();
    assert_eq!(files, 1, "and emphatically not two nodes");
    e.close().unwrap();
}

/// D119 — two boxes holding two DIFFERENT files at one tree path is not a
/// duplicate, and merging it destroys a real file's catalogue entry.
///
/// This is what the merge did to `Lanterns - s01e04` on 2026-09-08. The holder
/// had 1,544,349,595 bytes; the ingest had a newer *arr copy at 1,594,289,811.
/// Same name, same folder, two boxes, two versions — an upgrade in flight. The
/// merge saw "two nodes at one path", kept the one with more locations, and
/// unlinked the other: the holder's real file lost its entry, and the surviving
/// node claimed a size no file anywhere had.
///
/// Nothing on the OWNER can tell which version should win — it holds no media.
/// The box that holds a copy settles it on its next scan (D115 flags its own
/// node as changed), so the right thing here is to refuse.
#[test]
fn holders_that_disagree_about_size_are_two_versions_not_a_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let season = folder(&mut e, &root, "Season 01");

    let holders_copy = file_node(&mut e, &season, "ep04.mkv", 1_544_349_595);
    e.add_location(&holders_copy, "pvfs-host://nas/share/Media/ep04.mkv")
        .unwrap();
    let ingests_copy = file_node(&mut e, &season, "ep04.mkv", 1_594_289_811);
    e.add_location(&ingests_copy, "file:///mnt/local/Media/ep04.mkv")
        .unwrap();

    let r = e.list_duplicates().unwrap();
    assert_eq!(r.groups.len(), 1);
    assert_eq!(r.groups[0].holders, 2, "both members hold live bytes");
    assert_eq!(r.contested, 1, "and that makes the group CONTESTED");
    assert_eq!(
        r.redundant, 0,
        "nothing here is redundant — both nodes are a real file somewhere"
    );

    let done = e.merge_duplicates(false).unwrap();
    assert_eq!(done.contested, 1);

    // Both survive, both keep their bytes.
    let live: Vec<String> = e
        .children(&season)
        .unwrap()
        .into_iter()
        .filter(|c| c.node.node_type == TYPE_FILE)
        .map(|c| c.node.id)
        .collect();
    assert_eq!(live.len(), 2, "the merge must not have touched them");
    assert!(live.contains(&holders_copy) && live.contains(&ingests_copy));
    assert_eq!(e.locations(&holders_copy).unwrap().len(), 1);
    assert_eq!(e.locations(&ingests_copy).unwrap().len(), 1);
    e.close().unwrap();
}

/// …while a genuine duplicate — one real file plus a stale artefact holding no
/// bytes at all — still merges. The refusal must be narrow, or the command
/// stops being useful.
#[test]
fn a_group_with_one_holder_still_merges() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let season = folder(&mut e, &root, "Season 01");

    let real = file_node(&mut e, &season, "ep04.mkv", 1_000);
    e.add_location(&real, "pvfs-host://nas/share/Media/ep04.mkv")
        .unwrap();
    let stale = file_node(&mut e, &season, "ep04.mkv", 900); // holds nothing

    let r = e.list_duplicates().unwrap();
    assert_eq!(r.groups[0].holders, 1, "only one member holds bytes");
    assert_eq!(r.contested, 0);
    assert_eq!(r.redundant, 1);

    e.merge_duplicates(false).unwrap();
    let live: Vec<String> = e
        .children(&season)
        .unwrap()
        .into_iter()
        .filter(|c| c.node.node_type == TYPE_FILE)
        .map(|c| c.node.id)
        .collect();
    assert_eq!(live, vec![real], "the stale artefact went, the real file stayed");
    assert!(e.get_node(&stale).unwrap().is_some(), "and nothing was destroyed");
    e.close().unwrap();
}
