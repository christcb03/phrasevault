//! D71 W5 — the destination is the file's own tree path.
//!
//! Chris: *I definitely need the files available on the NAS as normal media
//! files in the Plex naming/folder structure.* So a migrated file lands at
//! `…/Media/TV/Show/Season 03/ep.mkv`, not as a hex blob in a node-addressed
//! store — which means PVFS stops being **required** to read the NAS. Lose the
//! forest and it is still a normal media library.
//!
//! These tests cover the path derivation and the ownership question the mover
//! asks before it writes over anything. Getting that wrong on a 130T NAS
//! destroys data, so the rules are pinned here rather than trusted.

use pvfs_core::{Engine, NodeSpec, TYPE_FILE, TYPE_FOLDER};

fn child(engine: &mut Engine, parent: &String, label: &str, kind: &str) -> String {
    engine
        .add_node(
            parent,
            NodeSpec {
                node_type: kind.into(),
                label: label.into(),
                payload: if kind == TYPE_FILE {
                    pvfs_core::FilePayload {
                        content_hash: String::new(),
                        size_bytes: 1234,
                        mime_type: "video/x-matroska".into(),
                        original_name: label.into(),
                    }
                    .encode()
                } else {
                    Vec::new()
                },
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap()
}

/// The whole point: a file's destination is its human path under the root.
#[test]
fn the_tree_path_is_the_destination() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();

    let media = child(&mut engine, &root, "Media", TYPE_FOLDER);
    let tv = child(&mut engine, &media, "TV", TYPE_FOLDER);
    let show = child(&mut engine, &tv, "Show Name (2020)", TYPE_FOLDER);
    let season = child(&mut engine, &show, "Season 03", TYPE_FOLDER);
    let ep = child(&mut engine, &season, "Show Name - s03e01.mkv", TYPE_FILE);

    let segs = engine.tree_path_under(&ep, &media).unwrap().unwrap();
    assert_eq!(
        segs,
        vec!["TV", "Show Name (2020)", "Season 03", "Show Name - s03e01.mkv"],
        "spaces, parentheses and all — the layout Plex expects"
    );

    // Relative to a deeper root, the path is correspondingly shorter.
    let segs = engine.tree_path_under(&ep, &season).unwrap().unwrap();
    assert_eq!(segs, vec!["Show Name - s03e01.mkv"]);
    engine.close().unwrap();
}

/// A node outside the placement root has no destination, and the mover must
/// refuse rather than invent one somewhere on a 130T NAS.
#[test]
fn a_node_outside_the_root_has_no_path() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let media = child(&mut engine, &root, "Media", TYPE_FOLDER);
    let other = child(&mut engine, &root, "Elsewhere", TYPE_FOLDER);
    let stray = child(&mut engine, &other, "stray.mkv", TYPE_FILE);

    assert!(
        engine.tree_path_under(&stray, &media).unwrap().is_none(),
        "not under the root ⇒ no destination, so the mover refuses"
    );
    engine.close().unwrap();
}

/// The root itself resolves to an empty path — also "no destination", which is
/// why the mover checks for empty as well as None.
#[test]
fn the_root_itself_is_an_empty_path() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let media = child(&mut engine, &root, "Media", TYPE_FOLDER);
    assert_eq!(engine.tree_path_under(&media, &media).unwrap(), Some(vec![]));
    engine.close().unwrap();
}

/// Who owns the bytes at a destination decides whether replacing them is an
/// upgrade or a data loss. Unknown to the catalog ⇒ nobody ⇒ the mover refuses.
#[test]
fn location_ownership_answers_who_holds_a_path() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let f = child(&mut engine, &root, "ep.mkv", TYPE_FILE);
    let uri = "file:///nas/Media/TV/Show/Season 01/ep.mkv";
    engine.add_location(&f, uri).unwrap();

    assert_eq!(engine.location_owner(uri).unwrap(), Some(f.clone()));
    assert_eq!(
        engine.location_owner("file:///nas/Media/TV/Show/poster.jpg").unwrap(),
        None,
        "a file the catalog has never seen has no owner — never overwrite it"
    );

    // A retired location no longer claims the path: that is the upgrade window,
    // where the old entry is gone and the new file may take its place.
    engine.remove_location(&f, uri).unwrap();
    assert_eq!(engine.location_owner(uri).unwrap(), None);
    engine.close().unwrap();
}

/// Tree layout belongs with `central-keep` (mirror) as much as with `central`:
/// a mirror's destination is a DIFFERENT box, so the same tree path under a
/// different root is the whole point — an identical, browsable second library.
/// (An earlier version of this work wrongly refused the combination.)
#[test]
fn tree_layout_is_valid_for_a_mirror_to_another_root() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let media = child(&mut engine, &root, "Media", TYPE_FOLDER);
    let show = child(&mut engine, &media, "Show", TYPE_FOLDER);
    let ep = child(&mut engine, &show, "ep.mkv", TYPE_FILE);
    let segs = engine.tree_path_under(&ep, &media).unwrap().unwrap();

    // The same relative path resolves under two independent roots without any
    // possibility of collision — which is exactly what a backup mirror wants.
    let primary = std::path::Path::new("/mnt/nas/Media");
    let backup = std::path::Path::new("/mnt/backup-nas/Media");
    let under = |base: &std::path::Path| segs.iter().fold(base.to_path_buf(), |a, s| a.join(s));
    assert_eq!(under(primary), std::path::Path::new("/mnt/nas/Media/Show/ep.mkv"));
    assert_eq!(
        under(backup),
        std::path::Path::new("/mnt/backup-nas/Media/Show/ep.mkv")
    );
    assert_ne!(under(primary), under(backup));
    engine.close().unwrap();
}
