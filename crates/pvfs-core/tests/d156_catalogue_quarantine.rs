//! D156 — one unreadable file does not stop a catalogue pass.
//!
//! `scan_region_catalogue` hashed each file with `?`, so one file's read error
//! (EIO on a bad sector, a chmod, a file renamed away mid-pass) ended the whole
//! pass. A file that failed every time stopped every pass at the same place,
//! and since the sweep and the head wait for a complete pass (D154), the
//! region would never publish again. Now the file is quarantined and the pass
//! carries on; a file that is merely gone is left to the sweep; an error that
//! may be the volume's fails the pass as before.
//!
//! `Engine::on_catalogue_read` runs a hook just before each read: it acts on
//! the disk (a real delete, a real chmod, a whole root emptied), or stands in
//! for the read with an errno.

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use nix::errno::Errno;
use pvfs_core::engine::CatalogueReadHook;
use pvfs_core::fs::ScanStats;
use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

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

/// A forest at `data` whose `Library` is a catalogue region bound to `lib`.
fn catalogue_forest(data: &Path, lib: &Path) -> (Engine, String) {
    let (mut e, _mn) = Engine::init(data).unwrap();
    let root = e.identity.root_node_id.clone();
    let region = folder(&mut e, &root, "Library");
    e.region_mark_as(&region, "catalogue", None).unwrap();
    e.bind_folder(
        &region,
        BindSpec {
            source_uri: format!("file://{}", lib.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    (e, region)
}

/// `e0.mkv` … `e{n-1}.mkv`, flat, each a different size, taken in name order.
fn flat_library(dir: &Path, name: &str, n: usize) -> std::path::PathBuf {
    let lib = dir.join(name);
    std::fs::create_dir_all(&lib).unwrap();
    for i in 0..n {
        std::fs::write(lib.join(format!("e{i}.mkv")), vec![i as u8; 100 + i]).unwrap();
    }
    lib
}

fn pass(e: &mut Engine, region: &str) -> ScanStats {
    e.scan_routed(Some(&region.to_string()), None, 0).unwrap().remove(0).stats
}

fn file_rows(e: &Engine, region: &str) -> Vec<String> {
    e.region_entries(&region.to_string())
        .unwrap()
        .into_iter()
        .filter(|r| r.kind == "file")
        .map(|r| r.rel_path)
        .collect()
}

/// A row as the pass last wrote it: size, mtime, hash, and the pass stamp.
fn row(e: &Engine, region: &str, rel: &str) -> (u64, u64, Option<String>, u64) {
    e.region_entries(&region.to_string())
        .unwrap()
        .into_iter()
        .find(|r| r.rel_path == rel)
        .map(|r| (r.size_bytes, r.mtime_ms, r.content_hash, r.seen_at))
        .unwrap_or_else(|| panic!("no row for {rel}"))
}

fn heads(e: &Engine, region: &str) -> Vec<u64> {
    e.region_snapshots(&region.to_string())
        .unwrap()
        .into_iter()
        .map(|s| s.seq)
        .collect()
}

fn names(n: std::ops::Range<usize>) -> Vec<String> {
    n.map(|i| format!("e{i}.mkv")).collect()
}

fn is(p: &Path, name: &str) -> bool {
    p.file_name() == Some(OsStr::new(name))
}

/// Every read of `name` fails with `errno`, every pass, until the hook goes.
fn failing(name: &'static str, errno: Errno) -> Option<CatalogueReadHook> {
    Some(Box::new(move |p: &Path| {
        is(p, name).then(|| std::io::Error::from_raw_os_error(errno as i32))
    }))
}

/// `name` is deleted between the walk and its read — an *arr renaming it.
fn removing(name: &'static str) -> Option<CatalogueReadHook> {
    Some(Box::new(move |p: &Path| {
        if is(p, name) {
            let _ = std::fs::remove_file(p);
        }
        None
    }))
}

fn root_user() -> bool {
    if nix::unistd::geteuid().is_root() {
        eprintln!("skipped: root reads and searches through mode 000 anyway");
        return true;
    }
    false
}

/// The bad sector: a first pass meets a file it cannot read. The file is
/// named and skipped; every other row is committed and the head publishes.
#[test]
fn an_unreadable_file_is_quarantined_and_the_pass_publishes() {
    let dir = tempfile::tempdir().unwrap();
    let lib = flat_library(dir.path(), "lib", 6);
    let (mut e, region) = catalogue_forest(&dir.path().join("forest"), &lib);
    let tip = e.log_tip().unwrap();
    e.on_catalogue_read(failing("e3.mkv", Errno::EIO));

    let st = pass(&mut e, &region);
    assert!(!st.cancelled);
    assert_eq!((st.added, st.needs_attention), (5, 1));
    assert_eq!(st.quarantined.len(), 1);
    let (what, why) = &st.quarantined[0];
    assert!(what.ends_with("/lib/e3.mkv"), "the file is named: {what}");
    assert!(why.contains(&format!("os error {}", Errno::EIO as i32)), "with its reason: {why}");
    let mut want = names(0..6);
    want.remove(3);
    assert_eq!(file_rows(&e, &region), want, "no row for the file nobody could read");
    assert_eq!(heads(&e, &region), vec![1], "and the region publishes all the same");
    assert_eq!(e.log_tip().unwrap(), tip + 1);
    assert_eq!(e.region_snapshots(&region.to_string()).unwrap()[0].entries, 5);
}

/// The case that motivated D156: a file that fails EVERY pass. Its row, from
/// the last pass that could read it, is kept untouched; the passes around it
/// complete, sweep and publish; and once it can be read, it is.
#[test]
fn a_file_that_fails_every_pass_never_stops_the_region_publishing() {
    let dir = tempfile::tempdir().unwrap();
    let lib = flat_library(dir.path(), "lib", 4);
    let (mut e, region) = catalogue_forest(&dir.path().join("forest"), &lib);
    pass(&mut e, &region);
    assert_eq!(heads(&e, &region), vec![1]);
    let before = row(&e, &region, "e2.mkv");

    // e2 is replaced, and the new copy sits on a bad sector. Its row can't
    // vouch for the new size, so every pass has to read it.
    let upgrade = b"an upgraded copy of e2";
    std::fs::write(lib.join("e2.mkv"), upgrade).unwrap();
    e.on_catalogue_read(failing("e2.mkv", Errno::EIO));
    std::fs::write(lib.join("e9.mkv"), b"new").unwrap();

    let st = pass(&mut e, &region);
    assert_eq!((st.added, st.changed, st.needs_attention), (1, 0, 1));
    assert_eq!(row(&e, &region, "e2.mkv"), before, "the prior row, exactly as the last read left it");
    assert_eq!(heads(&e, &region), vec![1, 2], "e9 is published regardless");

    // Again, with something to sweep: the quarantine does not stop that either.
    std::fs::remove_file(lib.join("e9.mkv")).unwrap();
    let st = pass(&mut e, &region);
    assert_eq!((st.removed, st.needs_attention), (1, 1));
    assert_eq!(row(&e, &region, "e2.mkv"), before);
    assert_eq!(heads(&e, &region), vec![1, 2, 3]);

    // The sector is remapped: the next pass reads e2 and says so.
    e.on_catalogue_read(None);
    let st = pass(&mut e, &region);
    assert_eq!((st.changed, st.needs_attention), (1, 0));
    assert_eq!(row(&e, &region, "e2.mkv").0, upgrade.len() as u64);
    assert_eq!(heads(&e, &region), vec![1, 2, 3, 4]);
}

/// A permission race, for real: the walk found e1 readable (`access(R_OK)`),
/// and the chmod lands between the walk and the read.
#[test]
fn a_file_made_unreadable_after_the_walk_is_quarantined() {
    if root_user() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let lib = flat_library(dir.path(), "lib", 4);
    let (mut e, region) = catalogue_forest(&dir.path().join("forest"), &lib);
    e.on_catalogue_read(Some(Box::new(|p: &Path| {
        if is(p, "e1.mkv") {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        None
    })));

    let st = pass(&mut e, &region);
    assert_eq!((st.added, st.needs_attention, st.unreadable), (3, 1, 0));
    let why = &st.quarantined[0].1;
    assert!(why.contains(&format!("os error {}", Errno::EACCES as i32)), "{why}");
    assert_eq!(file_rows(&e, &region), vec!["e0.mkv", "e2.mkv", "e3.mkv"]);
    assert_eq!(heads(&e, &region), vec![1]);
}

/// A file renamed or deleted between the walk and its read is nobody's
/// problem: not quarantined, and left to the sweep, which asks the disk.
#[test]
fn a_file_gone_after_the_walk_is_left_to_the_sweep() {
    let dir = tempfile::tempdir().unwrap();
    let lib = flat_library(dir.path(), "lib", 4);
    let (mut e, region) = catalogue_forest(&dir.path().join("forest"), &lib);

    // A new file: it simply never gets a row.
    e.on_catalogue_read(removing("e1.mkv"));
    let st = pass(&mut e, &region);
    assert_eq!((st.added, st.needs_attention), (3, 0), "gone is not a fault");
    assert_eq!(file_rows(&e, &region), vec!["e0.mkv", "e2.mkv", "e3.mkv"]);
    assert_eq!(heads(&e, &region), vec![1]);

    // A file with a row, changed and then deleted before its read: the sweep
    // finds it gone and takes the row.
    std::fs::write(lib.join("e2.mkv"), b"recut").unwrap();
    e.on_catalogue_read(removing("e2.mkv"));
    let st = pass(&mut e, &region);
    assert_eq!((st.changed, st.removed, st.needs_attention), (0, 1, 0));
    assert_eq!(file_rows(&e, &region), vec!["e0.mkv", "e3.mkv"]);
    assert_eq!(heads(&e, &region), vec![1, 2]);
}

/// An error that may be the whole volume's still fails the pass, and so does
/// any errno nobody named (default-deny). The rows the pass already holds are
/// committed first; the next pass takes them from their rows.
#[test]
fn a_volume_level_read_error_still_fails_the_pass_and_keeps_its_rows() {
    let dir = tempfile::tempdir().unwrap();
    let lib = flat_library(dir.path(), "lib", 6);
    let (mut e, region) = catalogue_forest(&dir.path().join("forest"), &lib);
    // What a FUSE mount answers once its daemon has died.
    e.on_catalogue_read(failing("e2.mkv", Errno::ENOTCONN));
    let err = e.scan_routed(Some(&region), None, 0).unwrap_err().to_string();
    assert!(err.contains(&format!("os error {}", Errno::ENOTCONN as i32)), "{err}");
    assert_eq!(file_rows(&e, &region), names(0..2), "committed though no batch (1,000 rows, 30 s) had closed");
    assert!(heads(&e, &region).is_empty(), "no head for a failed pass");

    e.on_catalogue_read(None);
    let st = pass(&mut e, &region);
    assert_eq!((st.added, st.unchanged), (4, 2));
    assert_eq!(heads(&e, &region), vec![1]);

    for errno in [Errno::ESTALE, Errno::EMFILE, Errno::ENOMEM, Errno::EAGAIN, Errno::EXDEV] {
        let d = tempfile::tempdir().unwrap();
        let lib = flat_library(d.path(), "lib", 3);
        let (mut e, region) = catalogue_forest(&d.path().join("forest"), &lib);
        e.on_catalogue_read(failing("e1.mkv", errno));
        assert!(e.scan_routed(Some(&region), None, 0).is_err(), "{errno} is not one file's fault");
        assert!(heads(&e, &region).is_empty(), "{errno}");
    }
}

/// The guard the quarantine needs: a volume unmounted mid-pass turns every
/// later read into ENOENT ("gone"), and a pass that carried on would sweep
/// every row it had not reached. The root marker, checked again before the
/// sweep, fails the pass instead: not a row swept, no head published.
#[test]
fn an_unmount_mid_pass_sweeps_nothing_and_publishes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let lib = flat_library(dir.path(), "lib", 6);
    std::fs::create_dir_all(lib.join("Season 01")).unwrap();
    let (mut e, region) = catalogue_forest(&dir.path().join("forest"), &lib);
    pass(&mut e, &region);
    assert_eq!(heads(&e, &region), vec![1]);

    // Every file is replaced (an upgrade run), so the pass must read each.
    for i in 0..6 {
        std::fs::write(lib.join(format!("e{i}.mkv")), vec![9u8; 50 + i]).unwrap();
    }
    // As the pass reaches e1, the volume goes: the mountpoint is left as a
    // bare skeleton of directories, no files and no marker.
    let root = lib.clone();
    e.on_catalogue_read(Some(Box::new(move |p: &Path| {
        if is(p, "e1.mkv") {
            empty_of_files(&root);
        }
        None
    })));
    let err = e.scan_routed(Some(&region), None, 0).unwrap_err().to_string();
    assert!(err.contains("UNMOUNTED"), "the marker says why: {err}");
    assert_eq!(file_rows(&e, &region), names(0..6), "not one row swept");
    assert_eq!(heads(&e, &region), vec![1], "and nothing published");
}

fn empty_of_files(dir: &Path) {
    for ent in std::fs::read_dir(dir).unwrap() {
        let p = ent.unwrap().path();
        if p.is_dir() {
            empty_of_files(&p);
        } else {
            std::fs::remove_file(&p).unwrap();
        }
    }
}

/// The sweep's other half: a stat that fails is not a file that is gone. A
/// directory that stops being searchable is skipped by the walk as
/// `unreadable`, and `Path::exists` then called every file beneath it
/// deleted, so a complete pass swept their rows.
#[test]
fn a_directory_that_cannot_be_searched_is_not_a_deleted_one() {
    if root_user() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let lib = flat_library(dir.path(), "lib", 2);
    let season = lib.join("Season 01");
    std::fs::create_dir_all(&season).unwrap();
    std::fs::write(season.join("s01e01.mkv"), b"pilot").unwrap();
    let (mut e, region) = catalogue_forest(&dir.path().join("forest"), &lib);
    pass(&mut e, &region);
    assert_eq!(heads(&e, &region), vec![1]);

    std::fs::set_permissions(&season, std::fs::Permissions::from_mode(0o000)).unwrap();
    let st = pass(&mut e, &region);
    std::fs::set_permissions(&season, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!((st.unreadable, st.removed), (1, 0), "not being able to look is not the files going");
    assert!(file_rows(&e, &region).contains(&"Season 01/s01e01.mkv".to_string()));
    assert_eq!(heads(&e, &region), vec![1], "nothing changed, so nothing published");
}
