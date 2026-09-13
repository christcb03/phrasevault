//! D145 — the drain asks before it discards (doc 26 §7.3 as amended). A
//! staging copy goes only against a library copy of the same bytes that reads
//! back now; a disagreement never drains the staging copy, and the receiving
//! side replaces the library's copy with it; the sidecar goes with its file;
//! the folders only staging has are made in the library, and a staging folder
//! goes once it is empty and the library holds it.

use std::sync::atomic::AtomicBool;

use pvfs_core::media::Rules;
use pvfs_core::{sync, BindSpec, DrainCheck, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

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

fn write(dir: &std::path::Path, rel: &str, bytes: &[u8], age_secs: u64) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, bytes).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&p)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(age_secs))
        .unwrap();
}

fn in_trash(root: &std::path::Path, rel: &str) -> bool {
    std::fs::read_dir(root.join(".pvfs-trash"))
        .map(|days| days.flatten().any(|d| d.path().join(rel).exists()))
        .unwrap_or(false)
}

fn never() -> AtomicBool {
    AtomicBool::new(false)
}

/// For tests whose regions are all bound on this box: the drain confirms by
/// reading, and the over-the-wire check is never asked.
fn remote_never(_: &DrainCheck) -> bool {
    false
}

const EP: &str = "TV/Show (2015)/Season 10/Show - s10e05 - Bad Habits.mkv";

#[test]
fn the_arrs_smaller_newer_import_is_kept_and_replaces_the_library_copy() {
    let tmp = tempfile::tempdir().unwrap();
    let staging = tmp.path().join("staging");
    let library = tmp.path().join("library");
    // The 2026-09-12 shape: the arr's new import on staging is smaller and
    // newer; the library's copy is older and nearly twice the size. With no
    // quality measured, the ladder alone would keep the library's.
    write(&staging, EP, &vec![b'N'; 1700], 10);
    write(&library, EP, &vec![b'O'; 3200], 3600);
    let (mut e, _mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let rs = region(&mut e, "Staging", &staging);
    let rl = region(&mut e, "Library", &library);
    e.set_region_drain(&rs, true).unwrap();
    sync::set_region_receive(e.data_dir(), &rl, true).unwrap();

    let entry = e.view_paths().unwrap().into_iter().find(|v| v.rel_path == EP).unwrap();
    assert_eq!(
        Engine::served_copy(&entry, &Rules::default()).unwrap().region,
        rl,
        "serving still follows the ladder (§7.1)"
    );
    let draining = |r: &str| r == rs;
    assert_eq!(
        Engine::drain_winner(&entry, &Rules::default(), &draining).unwrap().region,
        rs,
        "the drain follows the arr"
    );

    let rep = e.resolve_conflicts(false, &never(), &mut remote_never).unwrap();
    assert!(rep.trashed.is_empty(), "{rep:?}");
    assert_eq!(rep.kept_winners, vec![EP.to_string()]);
    assert!(staging.join(EP).exists());

    let (items, _) = e.receive_plan(&Rules::default()).unwrap();
    assert_eq!(items.len(), 1, "{items:?}");
    assert!(items[0].replaces && items[0].from_region == rs && items[0].size_bytes == 1700, "{items:?}");

    // The arr deletes the library copy through the union; the library's rows
    // stay until its box rescans. Still nothing is trashed.
    std::fs::remove_file(library.join(EP)).unwrap();
    let rep = e.resolve_conflicts(false, &never(), &mut remote_never).unwrap();
    assert!(rep.trashed.is_empty() && staging.join(EP).exists(), "{rep:?}");
    e.close().unwrap();
}

#[test]
fn a_twin_is_confirmed_by_its_bytes_not_its_row_and_the_sidecar_goes_with_the_file() {
    let tmp = tempfile::tempdir().unwrap();
    let staging = tmp.path().join("staging");
    let library = tmp.path().join("library");
    // Just over one chunk, so the last chunk is a short one past the boundary.
    let bytes: Vec<u8> = (0..(sync::SWARM_CHUNK as usize + 4096)).map(|i| (i % 251) as u8).collect();
    let rel = "Movies/A (2001)/A (2001).mkv";
    let side = "Movies/A (2001)/.A (2001).mkv.manifest";
    write(&staging, rel, &bytes, 60);
    write(&library, rel, &bytes, 60);
    let (mut e, _mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let rs = region(&mut e, "Staging", &staging);
    let _rl = region(&mut e, "Library", &library);
    e.set_region_drain(&rs, true).unwrap();
    let hash = blake3::hash(&bytes).to_hex().to_string();
    sync::write_manifest_sidecar(&staging.join(rel), Some(&hash), &[]).unwrap();
    assert!(staging.join(side).exists());

    // The library's file is gone since its scan; its row says otherwise.
    let lib_file = library.join(rel);
    std::fs::rename(&lib_file, library.join("moved-away")).unwrap();
    let rep = e.resolve_conflicts(false, &never(), &mut remote_never).unwrap();
    assert!(rep.trashed.is_empty() && rep.unconfirmed == vec![rel.to_string()], "{rep:?}");
    assert!(staging.join(rel).exists());

    // Changed in place, same size, another last chunk: not the same bytes.
    let mut other = bytes.clone();
    *other.last_mut().unwrap() ^= 0xff;
    std::fs::write(&lib_file, &other).unwrap();
    let rep = e.resolve_conflicts(false, &never(), &mut remote_never).unwrap();
    assert!(rep.trashed.is_empty() && rep.unconfirmed == vec![rel.to_string()], "{rep:?}");

    // The real bytes back: a dry run says so and moves nothing; the pass
    // trashes the file AND its sidecar; the library copy never moves.
    std::fs::write(&lib_file, &bytes).unwrap();
    let dry = e.resolve_conflicts(true, &never(), &mut remote_never).unwrap();
    assert_eq!(dry.trashed, vec![(rel.to_string(), rs.clone())]);
    assert!(staging.join(rel).exists() && staging.join(side).exists());
    let rep = e.resolve_conflicts(false, &never(), &mut remote_never).unwrap();
    assert_eq!(rep.trashed, vec![(rel.to_string(), rs.clone())]);
    assert!(!staging.join(rel).exists() && in_trash(&staging, rel));
    assert!(!staging.join(side).exists() && in_trash(&staging, side), "the sidecar went with its file");
    assert!(library.join(rel).exists(), "the library copy never moves");
    e.close().unwrap();
}

#[test]
fn a_twin_on_another_box_is_asked_about_and_a_no_keeps_the_copy() {
    let tmp = tempfile::tempdir().unwrap();
    let staging = tmp.path().join("staging");
    let library = tmp.path().join("library");
    let rel = "Movies/B (2002)/B (2002).mkv";
    let bytes = b"the-same-bytes-on-both-boxes";
    write(&staging, rel, bytes, 60);
    write(&library, rel, bytes, 60);
    let (mut e, _mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let rs = region(&mut e, "Staging", &staging);
    let rl = region(&mut e, "Library", &library);
    e.set_region_drain(&rs, true).unwrap();
    // The library region stops being this box's: its rows stay, as a fetched
    // region's do, and its bytes are somewhere else.
    e.unbind_folder(&rl, None).unwrap();
    let entry = e.view_paths().unwrap().into_iter().find(|v| v.rel_path == rel).unwrap();
    assert_eq!(entry.sources.len(), 2, "the library's rows outlive the binding: {entry:?}");

    let mut asked: Vec<DrainCheck> = Vec::new();
    let rep = e
        .resolve_conflicts(false, &never(), &mut |c: &DrainCheck| {
            asked.push(c.clone());
            false
        })
        .unwrap();
    assert!(rep.trashed.is_empty() && rep.unconfirmed == vec![rel.to_string()], "{rep:?}");
    assert!(staging.join(rel).exists());
    assert_eq!(asked.len(), 1, "{asked:?}");
    let (off, len, tail) = sync::tail_chunk(&staging.join(rel), bytes.len() as u64).unwrap();
    assert_eq!((off, len), (0, bytes.len() as u64));
    assert_eq!(asked[0].region, rl);
    assert_eq!(asked[0].hash, blake3::hash(bytes).to_hex().to_string());
    assert_eq!((asked[0].size, asked[0].tail_offset, asked[0].tail_len, asked[0].tail_hash), (len, off, len, tail));

    // A yes from the holder lets it go.
    let rep = e.resolve_conflicts(false, &never(), &mut |_: &DrainCheck| true).unwrap();
    assert_eq!(rep.trashed, vec![(rel.to_string(), rs.clone())]);
    assert!(!staging.join(rel).exists() && in_trash(&staging, rel));
    e.close().unwrap();
}

#[test]
fn nothing_is_received_when_a_library_region_already_holds_the_winners_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let staging = tmp.path().join("staging");
    let library = tmp.path().join("library");
    let ext = tmp.path().join("ext");
    let rel = "Movies/C (2003)/C (2003).mkv";
    write(&staging, rel, b"the-arrs-copy", 10);
    write(&library, rel, b"the-arrs-copy", 10);
    write(&ext, rel, &vec![b'E'; 4000], 5); // another library region, other bytes
    let (mut e, _mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let rs = region(&mut e, "Staging", &staging);
    let rl = region(&mut e, "Library", &library);
    let _re = region(&mut e, "Ext", &ext);
    e.set_region_drain(&rs, true).unwrap();
    sync::set_region_receive(e.data_dir(), &rl, true).unwrap();

    let (items, _) = e.receive_plan(&Rules::default()).unwrap();
    assert!(items.is_empty(), "the receiving region holds the winner already: {items:?}");
    let rep = e.resolve_conflicts(false, &never(), &mut remote_never).unwrap();
    assert_eq!(rep.trashed, vec![(rel.to_string(), rs.clone())], "{rep:?}");
    assert!(ext.join(rel).exists() && library.join(rel).exists());
    e.close().unwrap();
}

#[test]
fn folders_drain_like_files_and_the_top_level_stays() {
    let tmp = tempfile::tempdir().unwrap();
    let staging = tmp.path().join("staging");
    let library = tmp.path().join("library");
    std::fs::create_dir_all(staging.join("TV/Show (2020)/Season 01")).unwrap();
    std::fs::create_dir_all(staging.join("Movies/Only Here (2024)")).unwrap();
    write(&staging, "Movies/Busy (2023)/x.mkv", b"only-staging-has-me", 60);
    std::fs::create_dir_all(library.join("TV")).unwrap();
    std::fs::create_dir_all(library.join("Movies")).unwrap();
    let (mut e, _mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let rs = region(&mut e, "Staging", &staging);
    let rl = region(&mut e, "Library", &library);
    e.set_region_drain(&rs, true).unwrap();
    sync::set_region_receive(e.data_dir(), &rl, true).unwrap();

    let want = vec![
        "Movies/Busy (2023)".to_string(),
        "Movies/Only Here (2024)".to_string(),
        "TV/Show (2020)".to_string(),
        "TV/Show (2020)/Season 01".to_string(),
    ];
    let dry = e.receive_folders(true).unwrap();
    assert_eq!(dry, want, "only the folders the library lacks");
    assert!(!library.join("TV/Show (2020)").exists(), "a dry run makes nothing");
    assert_eq!(e.receive_folders(false).unwrap(), want);
    assert!(library.join("TV/Show (2020)/Season 01").is_dir());

    // Made, but not yet catalogued by the library: nothing drains.
    let rep = e.resolve_conflicts(false, &never(), &mut remote_never).unwrap();
    assert!(rep.folders_removed.is_empty(), "{rep:?}");

    e.scan_routed(Some(&rl), None, 0).unwrap();
    assert!(e.receive_folders(false).unwrap().is_empty(), "the library holds them all now");
    let rep = e.resolve_conflicts(false, &never(), &mut remote_never).unwrap();
    assert_eq!(
        rep.folders_removed,
        vec![
            "TV/Show (2020)/Season 01".to_string(),
            "TV/Show (2020)".to_string(),
            "Movies/Only Here (2024)".to_string(),
        ],
        "deepest first; a folder holding a file stays"
    );
    assert!(staging.join("TV").is_dir() && staging.join("Movies").is_dir(), "a region's top level stays");
    assert!(staging.join("Movies/Busy (2023)/x.mkv").exists());
    assert!(!staging.join("TV/Show (2020)").exists() && !staging.join("Movies/Only Here (2024)").exists());
    assert!(library.join("TV/Show (2020)/Season 01").is_dir(), "the library's folders never move");
    e.close().unwrap();
}
