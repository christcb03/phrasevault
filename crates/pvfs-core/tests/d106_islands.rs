//! D106 — the island check: live-linked nodes the root cannot reach.
//!
//! Unlink is a soft-remove of ONE link and does not cascade, so removing a
//! folder's only inbound edge detaches everything beneath it in a single
//! operation while leaving the subtree internally perfect — every node still
//! live-linked, every parent still live. Production carried 1,849 such nodes
//! for a fortnight (`Backups`, unlinked 2026-08-24) and no check named one:
//! `orphans` asks whether a NODE has a live link, `missing` whether a FILE is
//! held, `reclaim` whether central BYTES have a live node, and every stranded
//! node answers all three healthily. Only a walk from the root can see it.

use pvfs_core::{Engine, NodeSpec, FilePayload, LINK_CONTAINS, LINK_REF, TYPE_FILE, TYPE_FOLDER};

fn folder(engine: &mut Engine, parent: &str, label: &str) -> String {
    engine
        .add_node(
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

fn file(engine: &mut Engine, parent: &str, label: &str, size: u64) -> String {
    let payload = FilePayload {
        content_hash: String::new(),
        size_bytes: size,
        mime_type: "application/octet-stream".into(),
        original_name: label.into(),
    };
    engine
        .add_node(
            &parent.to_string(),
            NodeSpec {
                node_type: TYPE_FILE.into(),
                label: label.into(),
                payload: payload.encode(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap()
}

/// The live `contains` link a parent holds to this child.
fn link_to(engine: &Engine, parent: &str, child: &str) -> String {
    engine
        .children(&parent.to_string())
        .unwrap()
        .into_iter()
        .find(|c| c.node.id == child && c.link_type == LINK_CONTAINS)
        .expect("a contains link to the child")
        .link_id
}

/// `Backups` in miniature: a folder, three children, files under each.
fn rig() -> (tempfile::TempDir, Engine, String, String) {
    let tmp = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let root = engine.identity.root_node_id.clone();

    let backups = folder(&mut engine, &root, "Backups");
    for (name, sizes) in [
        ("Feederbox", [1000u64, 2000]),
        ("Mac_iCloud_old", [3000, 4000]),
        ("Mediabox", [5000, 6000]),
    ] {
        let sub = folder(&mut engine, &backups, name);
        for (i, s) in sizes.iter().enumerate() {
            file(&mut engine, &sub, &format!("{name}-{i}.tar"), *s);
        }
    }
    // A second, healthy branch that must never appear in any report.
    let media = folder(&mut engine, &root, "Media");
    file(&mut engine, &media, "keep.mkv", 42);

    (tmp, engine, root, backups)
}

/// Nothing detached: the report is empty and the four numbers agree.
#[test]
fn a_whole_forest_reports_no_islands() {
    let (_t, engine, _root, _backups) = rig();
    let r = engine.list_islands().unwrap();
    assert!(r.islands.is_empty(), "a connected forest has no islands");
    assert_eq!(r.stranded, 0);
    // In a whole forest the three counts coincide: everything is reachable,
    // and everything is live-linked — the root included, since `forest init`
    // gives it a `contains` link with a NULL parent.
    assert_eq!(r.reachable, r.nodes_total);
    assert_eq!(r.live_linked, r.nodes_total);
    engine.close().unwrap();
}

/// The production shape: one unlink, a whole subtree gone from the tree and
/// invisible to every existing check.
#[test]
fn unlinking_one_folder_strands_everything_under_it() {
    let (_t, mut engine, root, backups) = rig();
    let link = link_to(&engine, &root, &backups);

    let before = engine.list_islands().unwrap();
    engine.remove_link(&link).unwrap();
    let after = engine.list_islands().unwrap();

    // Nothing was deleted — the same nodes are there.
    assert_eq!(after.nodes_total, before.nodes_total);

    // 3 folders + 6 files stranded; `Backups` itself is not among them,
    // because its own inbound link is the one that was removed.
    assert_eq!(after.stranded, 9);
    assert_eq!(after.islands.len(), 1, "one cut, one island");
    let island = &after.islands[0];
    assert_eq!(island.root.label, "Backups");
    assert_eq!(island.size.nodes, 9);
    assert_eq!(island.size.files, 6);
    assert_eq!(island.size.folders, 3);
    assert_eq!(island.size.bytes, 1000 + 2000 + 3000 + 4000 + 5000 + 6000);
    assert!(island.detached_at.is_some(), "the report dates the cut");

    // The whole point: every stranded node still passes the checks we had.
    // `orphans` sees ONE node — `Backups` — and says nothing about the nine.
    let orphans = engine.list_orphans().unwrap();
    let labels: Vec<&str> = orphans.iter().map(|n| n.label.as_str()).collect();
    assert!(labels.contains(&"Backups"));
    for name in ["Feederbox", "Mac_iCloud_old", "Mediabox"] {
        assert!(
            !labels.contains(&name),
            "{name} still has a live link, so `orphans` calls it healthy"
        );
    }
    engine.close().unwrap();
}

/// A cut above a cut groups to the TOPMOST detached node — the report names
/// the folder that was unlinked, not each of its children.
#[test]
fn nested_cuts_group_to_the_topmost_detached_node() {
    let (_t, mut engine, root, backups) = rig();
    let feederbox = engine
        .children(&backups)
        .unwrap()
        .into_iter()
        .find(|c| c.label == "Feederbox")
        .unwrap()
        .node
        .id;

    // Cut the inner one first, then the outer.
    let inner = link_to(&engine, &backups, &feederbox);
    engine.remove_link(&inner).unwrap();
    let mid = engine.list_islands().unwrap();
    assert_eq!(mid.islands.len(), 1);
    assert_eq!(mid.islands[0].root.label, "Feederbox");
    assert_eq!(mid.islands[0].size.nodes, 2, "its two files");

    let outer = link_to(&engine, &root, &backups);
    engine.remove_link(&outer).unwrap();
    let after = engine.list_islands().unwrap();
    assert_eq!(
        after.islands.len(),
        2,
        "Feederbox's own edge is gone, so it is its own component"
    );
    let labels: Vec<&str> = after.islands.iter().map(|i| i.root.label.as_str()).collect();
    assert!(labels.contains(&"Backups"));
    assert!(labels.contains(&"Feederbox"));
    // Biggest first: Backups keeps the two remaining subfolders and 4 files.
    assert_eq!(after.islands[0].root.label, "Backups");
    assert_eq!(after.islands[0].size.nodes, 6);
    engine.close().unwrap();
}

/// A `ref` child of a reachable folder is listed when you browse its parent,
/// so it is in the tree — flagging it would be crying wolf.
#[test]
fn a_ref_only_child_is_not_an_island() {
    let (_t, mut engine, root, backups) = rig();
    let media = engine
        .children(&root)
        .unwrap()
        .into_iter()
        .find(|c| c.label == "Media")
        .unwrap()
        .node
        .id;
    let loose = folder(&mut engine, &backups, "Loose");
    engine
        .link(&media, &loose, LINK_REF, None, 0)
        .unwrap();

    // Cut Loose's only `contains` edge: it now hangs off the tree by a ref.
    let contains = link_to(&engine, &backups, &loose);
    engine.remove_link(&contains).unwrap();

    let r = engine.list_islands().unwrap();
    assert!(
        r.islands.is_empty(),
        "reachable by a ref from a live folder, so not detached: {:?}",
        r.islands.iter().map(|i| &i.root.label).collect::<Vec<_>>()
    );
    engine.close().unwrap();
}

/// The number `unlink` needs: what this cut is about to strand, counted
/// before it happens. The operator saw one success and no number.
#[test]
fn the_subtree_size_a_cut_would_strand_is_known_before_the_cut() {
    let (_t, engine, root, backups) = rig();
    let link = link_to(&engine, &root, &backups);
    let (label, size) = engine.unlink_would_strand(&link).unwrap().unwrap();
    assert_eq!(label, "Backups");
    assert_eq!(size.nodes, 9);
    assert_eq!(size.files, 6);
    assert_eq!(size.folders, 3);
    assert_eq!(size.bytes, 21_000);
    engine.close().unwrap();
}

/// Nothing to warn about: a file, and an empty folder.
#[test]
fn unlinking_a_leaf_warns_about_nothing() {
    let (_t, mut engine, root, _backups) = rig();
    let media = engine
        .children(&root)
        .unwrap()
        .into_iter()
        .find(|c| c.label == "Media")
        .unwrap()
        .node
        .id;
    let keep = link_to(
        &engine,
        &media,
        &engine
            .children(&media)
            .unwrap()
            .into_iter()
            .find(|c| c.label == "keep.mkv")
            .unwrap()
            .node
            .id,
    );
    assert!(engine.unlink_would_strand(&keep).unwrap().is_none());

    let empty = folder(&mut engine, &root, "Empty");
    let l = link_to(&engine, &root, &empty);
    assert!(engine.unlink_would_strand(&l).unwrap().is_none());

    // And an already-removed link warns once, not twice.
    engine.remove_link(&l).unwrap();
    assert!(engine.unlink_would_strand(&l).unwrap().is_none());
    engine.close().unwrap();
}

/// A forest holds more than one tree, and `walk` deliberately stays inside
/// one. Seeding the reachability walk from the forest root alone reported
/// every other tree as detached — caught by the CLI smoke suite, which makes a
/// second tree and hangs a ref-held file off it.
#[test]
fn a_second_tree_is_not_an_island() {
    let (_t, mut engine, _root, _backups) = rig();
    let other = engine.create_tree("second-tree").unwrap();
    let loose = folder(&mut engine, &other, "under-the-second-tree");
    file(&mut engine, &loose, "held.bin", 7);

    let r = engine.list_islands().unwrap();
    assert!(
        r.islands.is_empty(),
        "a second tree is a tree, not a detached subtree: {:?}",
        r.islands.iter().map(|i| &i.root.label).collect::<Vec<_>>()
    );
    assert_eq!(r.stranded, 0);

    // And a cut inside the second tree is still found — the seed widened,
    // the check did not weaken.
    let link = link_to(&engine, &other, &loose);
    engine.remove_link(&link).unwrap();
    let r = engine.list_islands().unwrap();
    assert_eq!(r.islands.len(), 1);
    assert_eq!(r.islands[0].root.label, "under-the-second-tree");
    assert_eq!(r.islands[0].size.nodes, 1);
    engine.close().unwrap();
}

/// A file whose only remaining link is a `ref` from ANOTHER tree is visible
/// when you browse that tree, so it is not stranded.
#[test]
fn a_file_held_only_by_a_ref_from_another_tree_is_reachable() {
    let (_t, mut engine, root, _backups) = rig();
    let media = engine
        .children(&root)
        .unwrap()
        .into_iter()
        .find(|c| c.label == "Media")
        .unwrap()
        .node
        .id;
    let keep = engine
        .children(&media)
        .unwrap()
        .into_iter()
        .find(|c| c.label == "keep.mkv")
        .unwrap()
        .node
        .id;
    let other = engine.create_tree("second-tree").unwrap();
    engine.link(&other, &keep, LINK_REF, None, 0).unwrap();

    // Drop its `contains` edge: only the cross-tree ref is left.
    let contains = link_to(&engine, &media, &keep);
    engine.remove_link(&contains).unwrap();

    let r = engine.list_islands().unwrap();
    assert!(
        r.islands.is_empty(),
        "listed under the second tree, so not detached: {:?}",
        r.islands.iter().map(|i| &i.root.label).collect::<Vec<_>>()
    );
    engine.close().unwrap();
}

/// Re-linking clears the island — the report is the operator's cue, and it
/// stops saying so once they have acted.
#[test]
fn re_linking_the_island_root_clears_the_report() {
    let (_t, mut engine, root, backups) = rig();
    let link = link_to(&engine, &root, &backups);
    engine.remove_link(&link).unwrap();
    assert_eq!(engine.list_islands().unwrap().islands.len(), 1);

    engine.link(&root, &backups, LINK_CONTAINS, None, 1).unwrap();
    let r = engine.list_islands().unwrap();
    assert!(r.islands.is_empty(), "re-attached, so nothing is stranded");
    assert_eq!(r.stranded, 0);
    engine.close().unwrap();
}
