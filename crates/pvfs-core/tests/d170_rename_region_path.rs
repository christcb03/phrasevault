//! D170 — a rename and an `rmdir` that came through the view, done on THIS
//! box's disk: only what the caller saw, only inside a region this box
//! catalogues, a file's sidecar with it — and D169's delete of a file that
//! was renamed a moment ago (no row yet: its sidecar says which file it is).

use std::path::Path;

use pvfs_core::{sync, BindSpec, DirRemovedHere, Engine, HashPolicy, NodeSpec, RenameExpect, RenamedHere, TrashedHere, TYPE_FOLDER};

fn write(root: &Path, rel: &str, bytes: &[u8]) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

fn folder(e: &mut Engine, label: &str) -> String {
    let root = e.identity.root_node_id.clone();
    e.add_node(
        &root,
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

fn library(tmp: &Path) -> (Engine, String, std::path::PathBuf) {
    let lib = tmp.join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    let (mut e, _) = Engine::init(tmp.join("forest").as_path()).unwrap();
    let r = folder(&mut e, "Library");
    e.region_mark_as(&r, "catalogue", None).unwrap();
    e.bind_folder(
        &r,
        BindSpec {
            source_uri: format!("file://{}", lib.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    (e, r, lib)
}

fn file_of(e: &Engine, rel: &str) -> RenameExpect {
    let v = e.view_entry(rel).unwrap().expect("listed");
    RenameExpect::File { hash: v.content_hash.expect("hashed"), size: v.size_bytes }
}

#[test]
fn a_file_is_renamed_on_this_boxs_disk_only_if_it_is_the_file_that_was_seen() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut e, r, lib) = library(tmp.path());
    let old = "TV/Show/Season 01/show.s01e01.mkv";
    let new = "TV/Show/Season 01/Show - S01E01 - Pilot.mkv";
    write(&lib, old, b"an episode the arr renames");
    write(&lib, "TV/Show/Season 01/show.s01e02.mkv", b"its neighbour");
    e.scan_routed(Some(&r), None, 0).unwrap();
    let seen = file_of(&e, old);
    let RenameExpect::File { hash, size } = seen.clone() else { unreachable!() };

    let elsewhere = folder(&mut e, "Elsewhere");
    e.region_mark_as(&elsewhere, "catalogue", None).unwrap();

    // ---- refusals move nothing
    let other = RenameExpect::File { hash: "00".repeat(32), size };
    assert_eq!(e.rename_region_path(&r, old, new, &other).unwrap(), RenamedHere::Changed, "another hash");
    let longer = RenameExpect::File { hash: hash.clone(), size: size + 1 };
    assert_eq!(e.rename_region_path(&r, old, new, &longer).unwrap(), RenamedHere::Changed, "another size");
    assert_eq!(e.rename_region_path(&r, old, new, &RenameExpect::Dir).unwrap(), RenamedHere::Changed, "not a folder");
    assert_eq!(e.rename_region_path(&elsewhere, old, new, &seen).unwrap(), RenamedHere::NotHere);
    assert_eq!(e.rename_region_path(&"ab".repeat(32), old, new, &seen).unwrap(), RenamedHere::NotHere);
    assert_eq!(
        e.rename_region_path(&r, old, "TV/Show/Season 01/show.s01e02.mkv", &seen).unwrap(),
        RenamedHere::InTheWay
    );
    for bad in ["", "../x.mkv", "TV/../../x", "TV//x", "./TV"] {
        assert!(e.rename_region_path(&r, old, bad, &seen).is_err(), "to {bad:?}");
        assert!(e.rename_region_path(&r, bad, new, &seen).is_err(), "from {bad:?}");
    }
    // nothing is renamed to a name the catalogue does not see
    for hidden in [".pvfs-trash/x.mkv", "TV/Show/.x.mkv.manifest", "TV/.@__thumb/x.mkv", "TV/Show/._x.mkv"] {
        assert!(e.rename_region_path(&r, old, hidden, &seen).is_err(), "to {hidden:?}");
    }
    assert!(lib.join(old).is_file());
    assert!(!lib.join(new).exists());

    // ---- the file the caller saw: renamed, and its hash goes with it
    assert_eq!(e.rename_region_path(&r, old, new, &seen).unwrap(), RenamedHere::Moved);
    assert!(!lib.join(old).exists());
    assert_eq!(std::fs::read(lib.join(new)).unwrap(), b"an episode the arr renames");
    assert!(!sync::manifest_sidecar_path(&lib.join(old)).exists(), "no sidecar is left behind");
    assert_eq!(sync::sidecar_whole_hash(&lib.join(new), size), Some(hash.clone()), "carried, or written");

    // ---- asked again (mergerfs renamed the local branch first): done already
    assert_eq!(e.rename_region_path(&r, old, new, &seen).unwrap(), RenamedHere::AlreadyDone);
    assert_eq!(e.rename_region_path(&r, "TV/nothing.mkv", "TV/nowhere.mkv", &seen).unwrap(), RenamedHere::Gone);

    // ---- the row followed the file: found by hash at its new path at once, with no pass
    let moved = e.view_entry(new).unwrap().expect("the row moved with the file");
    assert_eq!(moved.content_hash, Some(hash.clone()));
    assert!(e.view_entry(old).unwrap().is_none());
    assert_eq!(e.local_path_for_hash(&hash).unwrap().map(|l| l.path), Some(lib.join(new)));

    // ---- a row the rename could not write (a busy database, a read-only view): no row at the
    // new name until a pass — the sidecar says which file it is
    {
        let conn = rusqlite::Connection::open(e.data_dir().join("index.db")).unwrap();
        assert_eq!(conn.execute("DELETE FROM region_entries WHERE rel_path = ?1", [new]).unwrap(), 1);
    }
    let newer = "TV/Show (2020)/Season 01/Show - S01E01 - Pilot.mkv";
    assert_eq!(e.rename_region_path(&r, new, newer, &other).unwrap(), RenamedHere::Changed);
    assert_eq!(e.rename_region_path(&r, new, newer, &seen).unwrap(), RenamedHere::Moved, "into folders it makes");
    assert_eq!(sync::sidecar_whole_hash(&lib.join(newer), size), Some(hash.clone()));
    assert_eq!(e.view_entry("TV/Show (2020)/Season 01").unwrap().map(|d| d.kind), Some("dir".into()), "and lists");
    {
        let conn = rusqlite::Connection::open(e.data_dir().join("index.db")).unwrap();
        conn.execute("DELETE FROM region_entries WHERE rel_path = ?1", [newer]).unwrap();
    }

    // ---- D169's delete of a file with no row yet: the sidecar decides, never "gone" while it is on disk
    assert_eq!(e.trash_region_path(&r, newer, &"00".repeat(32)).unwrap(), TrashedHere::Changed);
    assert!(lib.join(newer).is_file());

    // ---- the next pass finds a new path and does not read it again: same hash
    e.scan_routed(Some(&r), None, 0).unwrap();
    assert!(e.view_entry(old).unwrap().is_none());
    assert_eq!(e.view_entry(newer).unwrap().unwrap().content_hash, Some(hash.clone()));
    assert!(matches!(e.trash_region_path(&r, newer, &hash).unwrap(), TrashedHere::Trashed(_)));
}

#[test]
fn a_file_renamed_a_moment_ago_can_be_deleted_before_any_pass() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut e, r, lib) = library(tmp.path());
    write(&lib, "Movies/Film (1999)/film.mkv", b"a film");
    write(&lib, "Movies/Film (1999)/extra.mkv", b"an extra");
    e.scan_routed(Some(&r), None, 0).unwrap();
    for (old, new, bytes, keep_row) in [
        ("Movies/Film (1999)/film.mkv", "Movies/Film (1999)/Film (1999) Bluray-1080p.mkv", &b"a film"[..], true),
        ("Movies/Film (1999)/extra.mkv", "Movies/Film (1999)/Film (1999) - extra.mkv", &b"an extra"[..], false),
    ] {
        let seen = file_of(&e, old);
        let RenameExpect::File { hash, .. } = seen.clone() else { unreachable!() };
        assert_eq!(e.rename_region_path(&r, old, new, &seen).unwrap(), RenamedHere::Moved);
        if !keep_row {
            // the row the rename could not write: a file on disk with no row is still not `Gone`
            let conn = rusqlite::Connection::open(e.data_dir().join("index.db")).unwrap();
            conn.execute("DELETE FROM region_entries WHERE rel_path = ?1", [new]).unwrap();
        }
        let TrashedHere::Trashed(to) = e.trash_region_path(&r, new, &hash).unwrap() else {
            panic!("{new}: renamed a moment ago, and deletable");
        };
        assert_eq!(std::fs::read(to).unwrap(), bytes);
        assert!(!lib.join(new).exists());
    }
}

#[test]
fn a_folder_moves_with_everything_under_it() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut e, r, lib) = library(tmp.path());
    write(&lib, "TV/Show/Season 01/e1.mkv", b"one");
    write(&lib, "TV/Show/Season 02/e1.mkv", b"two");
    write(&lib, "TV/Other/x.mkv", b"x");
    e.scan_routed(Some(&r), None, 0).unwrap();
    let h1 = e.view_entry("TV/Show/Season 01/e1.mkv").unwrap().unwrap().content_hash;

    assert_eq!(e.rename_region_path(&r, "TV/Show", "TV/Other", &RenameExpect::Dir).unwrap(), RenamedHere::InTheWay);
    assert!(e.rename_region_path(&r, "TV/Show", "TV/Show/inside", &RenameExpect::Dir).is_err(), "into itself");
    let as_file = RenameExpect::File { hash: "00".repeat(32), size: 3 };
    assert_eq!(e.rename_region_path(&r, "TV/Show", "TV/S", &as_file).unwrap(), RenamedHere::Changed, "not a file");

    assert_eq!(e.rename_region_path(&r, "TV/Show", "TV/Show (2020)", &RenameExpect::Dir).unwrap(), RenamedHere::Moved);
    assert!(!lib.join("TV/Show").exists());
    assert_eq!(std::fs::read(lib.join("TV/Show (2020)/Season 02/e1.mkv")).unwrap(), b"two");
    assert_eq!(
        e.rename_region_path(&r, "TV/Show", "TV/Show (2020)", &RenameExpect::Dir).unwrap(),
        RenamedHere::AlreadyDone
    );
    // the subtree's rows followed it, before any pass: listed, and found by hash
    assert!(e.view_entry("TV/Show").unwrap().is_none() && e.merged_view("TV/Show").unwrap().is_empty());
    assert_eq!(e.view_entry("TV/Show (2020)/Season 01/e1.mkv").unwrap().unwrap().content_hash, h1);
    let listed: Vec<String> = e.merged_view("TV").unwrap().into_iter().map(|v| v.rel_path).collect();
    assert_eq!(listed, ["TV/Other", "TV/Show (2020)"]);
    assert_eq!(
        e.local_path_for_hash(h1.as_deref().unwrap()).unwrap().map(|l| l.path),
        Some(lib.join("TV/Show (2020)/Season 01/e1.mkv"))
    );

    e.scan_routed(Some(&r), None, 0).unwrap();
    assert!(e.view_entry("TV/Show").unwrap().is_none());
    assert_eq!(e.view_entry("TV/Show (2020)/Season 01/e1.mkv").unwrap().unwrap().content_hash, h1);
}

#[test]
fn a_folder_is_removed_only_when_nothing_of_the_operators_is_in_it() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut e, r, lib) = library(tmp.path());
    write(&lib, "TV/Show/Season 01/e1.mkv", b"one");
    write(&lib, "TV/Show/Season 01/.@__thumb/e1.jpg", b"a thumbnail the NAS made");
    write(&lib, "TV/Show/Season 01/.DS_Store", b"finder");
    std::fs::create_dir_all(lib.join("TV/Show/Season 02")).unwrap();
    e.scan_routed(Some(&r), None, 0).unwrap();
    let elsewhere = folder(&mut e, "Elsewhere");
    e.region_mark_as(&elsewhere, "catalogue", None).unwrap();

    assert_eq!(e.remove_region_dir(&elsewhere, "TV/Show/Season 02").unwrap(), DirRemovedHere::NotHere);
    assert_eq!(e.remove_region_dir(&r, "TV/Show/Season 01").unwrap(), DirRemovedHere::NotEmpty);
    assert_eq!(e.remove_region_dir(&r, "TV/Show").unwrap(), DirRemovedHere::NotEmpty, "folders count");
    assert!(e.remove_region_dir(&r, "TV/Show/Season 01/e1.mkv").is_err(), "a file");
    assert!(e.remove_region_dir(&r, "").is_err(), "never the region's root");
    assert!(lib.join("TV/Show/Season 01/.DS_Store").is_file(), "a refusal touches nothing");

    assert_eq!(e.remove_region_dir(&r, "TV/Show/Season 02").unwrap(), DirRemovedHere::Removed);
    assert!(e.view_entry("TV/Show/Season 02").unwrap().is_none(), "its row went with it");
    assert_eq!(e.remove_region_dir(&r, "TV/Show/Season 02").unwrap(), DirRemovedHere::Gone);

    // the episode leaves (an arr deleted it); what the view never showed is all that is left
    let h = e.view_entry("TV/Show/Season 01/e1.mkv").unwrap().unwrap().content_hash.unwrap();
    assert!(matches!(e.trash_region_path(&r, "TV/Show/Season 01/e1.mkv", &h).unwrap(), TrashedHere::Trashed(_)));
    assert_eq!(e.remove_region_dir(&r, "TV/Show/Season 01").unwrap(), DirRemovedHere::Removed);
    assert!(!lib.join("TV/Show/Season 01").exists());
    let trashed: Vec<String> = sync::list_trash(&lib).into_iter().map(|t| t.rel_path).collect();
    assert!(trashed.iter().any(|p| p == "TV/Show/Season 01/e1.mkv"));
    // litter is moved, not deleted — it is in the trash's tree even though `trash ls` passes over it
    let day = std::fs::read_dir(sync::trash_root(&lib))
        .unwrap()
        .flatten()
        .map(|d| d.path())
        .find(|d| d.is_dir() && d.file_name().is_some_and(|n| n.to_string_lossy().parse::<u64>().is_ok()))
        .expect("a day bucket");
    assert!(day.join("TV/Show/Season 01/.@__thumb/e1.jpg").is_file());
    assert!(day.join("TV/Show/Season 01/.DS_Store").is_file());
}
