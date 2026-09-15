//! D158 — one unreadable new file does not stop a log-region pass.
//!
//! `ingest_file` hashed a brand-new file with `?`, and the read's error is
//! `Io`, which `is_transient` calls transient: one file's read error (EIO on a
//! bad sector, a chmod, a rename between the walk and the read) ended the
//! whole pass. A file that failed every time stopped every pass at the same
//! place, and the pass's deletions never ran. Now D156's classifier judges
//! that read, and only that read: the file's own trouble is quarantined, a
//! file gone since the walk is skipped, and an error that may be the volume's
//! fails the pass as before. A WRITER's error is still the pass's, whatever
//! its errno.
//!
//! `Engine::on_catalogue_read` (D156's seam, which the log pass now calls
//! too) runs a hook just before the read: it acts on the disk, or stands in
//! for the read with an errno.

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use nix::errno::Errno;
use pvfs_core::engine::CatalogueReadHook;
use pvfs_core::fs::ScanStats;
use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, PvfsError, ScanWriter, TYPE_FILE, TYPE_FOLDER};

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

/// A forest at `data` whose `Library` is a log region (not marked catalogue:
/// the scan ingests nodes) bound to `lib`.
fn log_forest(data: &Path, lib: &Path) -> (Engine, String) {
    let (mut e, _mn) = Engine::init(data).unwrap();
    let root = e.identity.root_node_id.clone();
    let region = folder(&mut e, &root, "Library");
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

/// The files the catalog holds here, by name: file nodes with a live
/// location. A deletion retires the location; the node itself stays until
/// D112's grace (`UNLINK_GRACE_MS`) runs out, so the location is what says a
/// file has gone.
fn files(e: &Engine, region: &str) -> Vec<String> {
    let mut v: Vec<String> = e
        .children(&region.to_string())
        .unwrap()
        .into_iter()
        .filter(|c| c.node.node_type == TYPE_FILE)
        .filter(|c| !e.locations(&c.node.id).unwrap().is_empty())
        .map(|c| c.label)
        .collect();
    v.sort();
    v
}

fn node_of(e: &Engine, region: &str, name: &str) -> String {
    e.children(&region.to_string())
        .unwrap()
        .into_iter()
        .find(|c| c.label == name)
        .map(|c| c.node.id)
        .unwrap_or_else(|| panic!("no node for {name}"))
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

/// The bad sector: a first pass meets a new file it cannot read. The file is
/// named and skipped; every other file, before it and after it, gets its node.
#[test]
fn an_unreadable_new_file_is_quarantined_and_the_pass_carries_on() {
    let dir = tempfile::tempdir().unwrap();
    let lib = flat_library(dir.path(), "lib", 6);
    let (mut e, region) = log_forest(&dir.path().join("forest"), &lib);
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
    assert_eq!(files(&e, &region), want, "no node for the file nobody could read");
}

/// The case that motivated D158: a new file that fails EVERY pass. The passes
/// around it complete — they add, and their deletions run — and once it can
/// be read, it is.
#[test]
fn a_new_file_that_fails_every_pass_never_stops_the_region() {
    let dir = tempfile::tempdir().unwrap();
    let lib = flat_library(dir.path(), "lib", 4);
    let (mut e, region) = log_forest(&dir.path().join("forest"), &lib);
    assert_eq!(pass(&mut e, &region).added, 4);

    // e9 arrives on a bad sector, e5 arrives readable, and e0 is deleted.
    std::fs::write(lib.join("e9.mkv"), b"an episode on a bad sector").unwrap();
    std::fs::write(lib.join("e5.mkv"), b"a readable one").unwrap();
    std::fs::remove_file(lib.join("e0.mkv")).unwrap();
    e.on_catalogue_read(failing("e9.mkv", Errno::EIO));

    let st = pass(&mut e, &region);
    assert_eq!((st.added, st.removed, st.needs_attention), (1, 1, 1));
    assert_eq!(files(&e, &region), vec!["e1.mkv", "e2.mkv", "e3.mkv", "e5.mkv"]);

    // Again: the same file, the same verdict, and the deletions still run.
    std::fs::remove_file(lib.join("e1.mkv")).unwrap();
    let st = pass(&mut e, &region);
    assert_eq!((st.added, st.removed, st.needs_attention), (0, 1, 1));
    assert_eq!(files(&e, &region), vec!["e2.mkv", "e3.mkv", "e5.mkv"]);

    // The sector is remapped: the next pass reads e9 and adds it.
    e.on_catalogue_read(None);
    let st = pass(&mut e, &region);
    assert_eq!((st.added, st.needs_attention), (1, 0));
    assert_eq!(files(&e, &region), vec!["e2.mkv", "e3.mkv", "e5.mkv", "e9.mkv"]);
}

/// A permission race, for real: the walk found e1 readable (`access(R_OK)`),
/// and the chmod lands between the walk and the read.
#[test]
fn a_new_file_made_unreadable_after_the_walk_is_quarantined() {
    if root_user() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let lib = flat_library(dir.path(), "lib", 4);
    let (mut e, region) = log_forest(&dir.path().join("forest"), &lib);
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
    assert_eq!(files(&e, &region), vec!["e0.mkv", "e2.mkv", "e3.mkv"]);
}

/// A new file renamed or deleted between the walk and its read is nobody's
/// problem: not quarantined, not added, and the pass completes. The next
/// pass's walk does not list it, so there is nothing left to say.
#[test]
fn a_new_file_gone_after_the_walk_is_skipped_not_quarantined() {
    let dir = tempfile::tempdir().unwrap();
    let lib = flat_library(dir.path(), "lib", 4);
    let (mut e, region) = log_forest(&dir.path().join("forest"), &lib);
    e.on_catalogue_read(removing("e1.mkv"));

    let st = pass(&mut e, &region);
    assert_eq!((st.added, st.removed, st.needs_attention), (3, 0, 0), "gone is not a fault");
    assert!(st.quarantined.is_empty());
    assert_eq!(files(&e, &region), vec!["e0.mkv", "e2.mkv", "e3.mkv"]);

    e.on_catalogue_read(None);
    let st = pass(&mut e, &region);
    assert_eq!((st.added, st.removed, st.needs_attention, st.unchanged), (0, 0, 0, 3));
}

/// An error that may be the whole volume's still fails the pass, and so does
/// any errno nobody named (default-deny). The files before it keep the nodes
/// they got; the next pass takes them as unchanged.
#[test]
fn a_volume_level_read_error_still_fails_the_pass() {
    let dir = tempfile::tempdir().unwrap();
    let lib = flat_library(dir.path(), "lib", 6);
    let (mut e, region) = log_forest(&dir.path().join("forest"), &lib);
    // What a FUSE mount answers once its daemon has died.
    e.on_catalogue_read(failing("e2.mkv", Errno::ENOTCONN));
    let err = e.scan_routed(Some(&region), None, 0).unwrap_err().to_string();
    assert!(err.contains(&format!("os error {}", Errno::ENOTCONN as i32)), "{err}");
    assert_eq!(files(&e, &region), names(0..2), "the files before it keep their nodes");

    e.on_catalogue_read(None);
    let st = pass(&mut e, &region);
    assert_eq!((st.added, st.unchanged), (4, 2));

    for errno in [Errno::ESTALE, Errno::EMFILE, Errno::ENOMEM, Errno::EAGAIN, Errno::EXDEV] {
        let d = tempfile::tempdir().unwrap();
        let lib = flat_library(d.path(), "lib", 3);
        let (mut e, region) = log_forest(&d.path().join("forest"), &lib);
        e.on_catalogue_read(failing("e1.mkv", errno));
        assert!(e.scan_routed(Some(&region), None, 0).is_err(), "{errno} is not one file's fault");
    }
}

/// The owner's end of a routed scan, refusing every new file with an I/O
/// error of one errno. `RoutedScanWriter` turns a lost owner into `Busy`
/// today, but `ScanWriter` does not say what a writer may return.
struct RefusingOwner(Errno);

impl ScanWriter for RefusingOwner {
    fn add_folder(&mut self, _parent: &str, label: &str) -> pvfs_core::Result<String> {
        Ok(label.to_string())
    }
    fn add_file(
        &mut self,
        _parent: &str,
        _label: &str,
        _size: u64,
        _mime: &str,
        _content_hash: &str,
    ) -> pvfs_core::Result<String> {
        Err(PvfsError::io("routed add_file", std::io::Error::from_raw_os_error(self.0 as i32)))
    }
    fn add_location(&mut self, _file: &str, _uri: &str) -> pvfs_core::Result<()> {
        Ok(())
    }
    fn remove_location(&mut self, _file: &str, _uri: &str) -> pvfs_core::Result<()> {
        Ok(())
    }
    fn set_content_hash(&mut self, file: &str, _hash: &str, _size: u64) -> pvfs_core::Result<String> {
        Ok(file.to_string())
    }
    fn remove_link(&mut self, _link_id: &str) -> pvfs_core::Result<()> {
        Ok(())
    }
    fn commit_region_head(&mut self, _region: &str, _seq: u64, _hash: &str) -> pvfs_core::Result<()> {
        Ok(())
    }
}

/// The classification is the READ's, and nothing else's. A write that fails
/// with EACCES is not the file's fault, and one that fails with ENOENT (an
/// owner socket gone from `/run/pvfs`) is not the file being gone: both fail
/// the pass, as they did before D158, and neither file is quarantined or
/// silently dropped.
#[test]
fn a_writers_io_error_is_the_passs_whatever_its_errno() {
    for errno in [Errno::EACCES, Errno::ENOENT] {
        let dir = tempfile::tempdir().unwrap();
        let lib = flat_library(dir.path(), "lib", 3);
        let (mut e, region) = log_forest(&dir.path().join("forest"), &lib);
        let mut owner = RefusingOwner(errno);
        let err = match e.scan_routed(Some(&region), Some(&mut owner as &mut dyn ScanWriter), 0) {
            Ok(r) => panic!(
                "{errno} from the owner was taken for the file's: needs_attention {}, quarantined {:?}",
                r[0].stats.needs_attention, r[0].stats.quarantined
            ),
            Err(err) => err.to_string(),
        };
        assert!(err.contains(&format!("os error {}", errno as i32)), "{err}");
    }
}

/// The guard the carry-on needs: a volume unmounted mid-pass turns every later
/// new file's read into ENOENT ("gone"), which no longer ends the pass. The
/// deletions would then retire each tracked location the walk held back,
/// since its path no longer stats. The root marker, checked again before them,
/// fails the pass instead: nothing is retired.
#[test]
fn an_unmount_mid_pass_retires_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let lib = flat_library(dir.path(), "lib", 4);
    let (mut e, region) = log_forest(&dir.path().join("forest"), &lib);
    assert_eq!(pass(&mut e, &region).added, 4);
    let held = node_of(&e, &region, "e3.mkv");
    let before = e.locations(&held).unwrap();
    assert_eq!(before.len(), 1);

    // Two new files, settled by the time the pass walks...
    std::fs::write(lib.join("n0.mkv"), b"new zero").unwrap();
    std::fs::write(lib.join("n1.mkv"), b"new one").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1_500));
    // ...and e3 being rewritten: inside the settle window, so the walk holds
    // it back, and the deletions meet a tracked file the walk did not list.
    std::fs::write(lib.join("e3.mkv"), b"an upgrade, mid-copy").unwrap();

    // As the pass reaches n0, the volume goes: the mountpoint is left bare,
    // no files and no marker. n1 is then gone too.
    let root = lib.clone();
    e.on_catalogue_read(Some(Box::new(move |p: &Path| {
        if is(p, "n0.mkv") {
            empty_of_files(&root);
        }
        None
    })));
    let err = e.scan_routed(Some(&region), None, 1_000).unwrap_err().to_string();
    assert!(err.contains("UNMOUNTED"), "the marker says why: {err}");
    assert_eq!(e.locations(&held).unwrap(), before, "the held-back file keeps its location");
    assert_eq!(files(&e, &region), names(0..4), "and every node stays");
}
