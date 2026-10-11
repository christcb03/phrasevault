//! PVOS D233 — the writable view, made safe (D218 §2.1).
//!
//! D217's writable view looked a file up by its HASH to edit it, so with two
//! byte-identical files an edit of one changed the other; the free-space floor
//! was passed over; a created file vanished from the mount after ten minutes
//! (or at the watch's first, unhashed row); deleting one was a hard delete;
//! renaming or truncating one answered EIO; and the kernel checked nobody's
//! permissions. Each test here is one of those, on a real FUSE mount.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use pvfs_client::hash_cache::CacheOpts;
use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

fn fuse_available() -> bool {
    Path::new("/dev/fuse").exists()
        && std::process::Command::new("sh")
            .args(["-c", "command -v fusermount3 || command -v fusermount"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

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

struct Forest {
    data_dir: PathBuf,
    lib: PathBuf,
    spare: PathBuf,
    lib_id: String,
}

/// Two local catalogue regions: `lib` holds what `files` names, `spare` is
/// empty (and so, on free space alone, the emptier). Both are scanned, with
/// `policy`, and keep a 1 MiB floor (`floor`: another for every region).
fn forest(tmp: &Path, files: &[(&str, &[u8])], policy: HashPolicy, floor: u64) -> Forest {
    let lib = tmp.join("lib");
    let spare = tmp.join("spare");
    std::fs::create_dir_all(lib.join("TV/Show/Season 01")).unwrap();
    std::fs::create_dir_all(&spare).unwrap();
    for (rel, bytes) in files {
        let p = lib.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }
    let (mut e, _mn) = Engine::init(&tmp.join("forest")).unwrap();
    let root = e.identity.root_node_id.clone();
    let mut lib_id = String::new();
    for (label, path) in [("Library", &lib), ("Spare", &spare)] {
        let r = folder(&mut e, &root, label);
        e.region_mark_as(&r, "catalogue", None).unwrap();
        e.bind_folder(
            &r,
            BindSpec {
                source_uri: format!("file://{}", path.display()),
                recursive: true,
                auto_index: true,
                extensions: String::new(),
                hash_policy: policy,
            },
        )
        .unwrap();
        e.scan_routed(Some(&r), None, 0).unwrap();
        if label == "Library" {
            lib_id = r;
        }
    }
    for b in e.local_bindings().unwrap() {
        pvfs_core::sync::set_region_floor(e.data_dir(), &b.folder_id, floor).unwrap();
    }
    let data_dir = e.data_dir().to_path_buf();
    e.close().unwrap();
    Forest { data_dir, lib, spare, lib_id }
}

fn mount(data_dir: &Path, at: &Path, writable: bool) -> pvfs_fuse::MountGuard {
    pvfs_fuse::MountGuard::new(
        pvfs_fuse::spawn_view_mount_writable(data_dir, at, CacheOpts::default(), Some(Vec::new()), writable).unwrap(),
        at,
    )
}

/// Every file under `dir` named `name`, however deep (the trash keeps the
/// region path under a day bucket).
fn find(dir: &Path, name: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else { return out };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(find(&p, name));
        } else if e.file_name() == name {
            out.push(p);
        }
    }
    out
}

fn in_trash(root: &Path, name: &str) -> Vec<Vec<u8>> {
    find(&root.join(".pvfs-trash"), name).into_iter().map(|p| std::fs::read(p).unwrap()).collect()
}

macro_rules! need_fuse {
    () => {
        if !fuse_available() {
            eprintln!("skipping: no /dev/fuse or fusermount on this host");
            return;
        }
        let cfg = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    };
}

const S1: &str = "TV/Show/Season 01";

/// D218 §2.1 item 1 — an edit of the SECOND of two byte-identical files
/// changes the second, and leaves the first alone. D217 found "a local file
/// with this hash" — the first by region and path — and wrote to that.
#[test]
fn an_edit_writes_the_file_opened_not_its_twin() {
    need_fuse!();
    let tmp = tempfile::tempdir().unwrap();
    let same: &[u8] = b"1\n00:00:01,000 --> 00:00:02,000\nthe same words\n";
    let f = forest(
        tmp.path(),
        &[
            ("TV/Show/Season 01/a.en.srt", same),
            ("TV/Show/Season 02/b.en.srt", same),
            ("TV/Show/Season 01/c.en.srt", same),
            ("TV/Show/Season 02/d.en.srt", same),
            ("Notes/empty-1.txt", b""),
            ("Notes/empty-2.txt", b""),
        ],
        HashPolicy::OnAdd,
        1 << 20,
    );
    let mnt = tempfile::tempdir().unwrap();
    let _m = mount(&f.data_dir, mnt.path(), true);

    // an edit in place
    {
        let mut h = std::fs::OpenOptions::new()
            .write(true)
            .open(mnt.path().join("TV/Show/Season 02/b.en.srt"))
            .expect("opens for writing");
        h.seek(SeekFrom::Start(0)).unwrap();
        h.write_all(b"2").unwrap();
    }
    let b = std::fs::read(f.lib.join("TV/Show/Season 02/b.en.srt")).unwrap();
    let a = std::fs::read(f.lib.join("TV/Show/Season 01/a.en.srt")).unwrap();
    assert_eq!(b[0], b'2', "the file opened took the write");
    assert_eq!(a, same, "and its twin is untouched");

    // a truncate by path (no handle) — of the second again
    let p = std::ffi::CString::new(mnt.path().join("TV/Show/Season 02/d.en.srt").into_os_string().into_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::truncate(p.as_ptr(), 5) }, 0, "truncate(2) through the mount");
    assert_eq!(std::fs::read(f.lib.join("TV/Show/Season 02/d.en.srt")).unwrap().len(), 5, "the file named was cut");
    assert_eq!(std::fs::read(f.lib.join("TV/Show/Season 01/c.en.srt")).unwrap(), same, "its twin was not");

    // every empty file is a twin of every other
    std::fs::write(mnt.path().join("Notes/empty-2.txt"), b"now with words").expect("an empty file takes a write");
    assert_eq!(std::fs::read(f.lib.join("Notes/empty-2.txt")).unwrap(), b"now with words");
    assert!(std::fs::read(f.lib.join("Notes/empty-1.txt")).unwrap().is_empty(), "the other empty file stays empty");
}

/// D233 decision 1 — a path with copies in two regions is refused: an edit
/// of one copy would set them against each other.
#[test]
fn a_path_with_two_copies_refuses_an_edit_and_still_reads() {
    need_fuse!();
    let tmp = tempfile::tempdir().unwrap();
    let f = forest(tmp.path(), &[("TV/Show/Season 01/dup.en.srt", b"one copy of two")], HashPolicy::OnAdd, 1 << 20);
    // the same bytes at the same path on the spare disk, catalogued there
    std::fs::create_dir_all(f.spare.join(S1)).unwrap();
    std::fs::write(f.spare.join("TV/Show/Season 01/dup.en.srt"), b"one copy of two").unwrap();
    {
        let mut e = Engine::open(&f.data_dir).unwrap();
        for b in e.local_bindings().unwrap() {
            e.scan_routed(Some(&b.folder_id), None, 0).unwrap();
        }
        e.close().unwrap();
    }
    let mnt = tempfile::tempdir().unwrap();
    let _m = mount(&f.data_dir, mnt.path(), true);
    let p = mnt.path().join("TV/Show/Season 01/dup.en.srt");
    let err = std::fs::OpenOptions::new().write(true).open(&p).expect_err("an edit of one of two copies");
    assert_eq!(err.raw_os_error(), Some(libc::EROFS), "{err}");
    assert_eq!(std::fs::read(&p).unwrap(), b"one copy of two", "reads are unaffected");
}

/// D218 §2.1 item 3 — a created file stays in the mount after the catalogue
/// writes a row for it that it has not hashed, and past the old ten-minute
/// clock's two-second prune: D217 forgot it at either.
#[test]
fn a_created_file_outlives_an_unhashed_row() {
    need_fuse!();
    let tmp = tempfile::tempdir().unwrap();
    // `Never` writes rows with no hash: what the watch's first row for a new
    // file looks like to the view (not shown).
    let f = forest(tmp.path(), &[], HashPolicy::Never, 1 << 20);
    let mnt = tempfile::tempdir().unwrap();
    let _m = mount(&f.data_dir, mnt.path(), true);
    let srt = mnt.path().join("TV/Show/Season 01/new.en.srt");
    std::fs::write(&srt, b"made through the mount").expect("create");
    {
        let mut e = Engine::open(&f.data_dir).unwrap();
        e.scan_routed(Some(&f.lib_id), None, 0).unwrap();
        let row = e.view_entry("TV/Show/Season 01/new.en.srt").unwrap().expect("the catalogue has a row for it");
        assert!(row.sources.iter().all(|c| c.content_hash.is_none()), "an unhashed row: {row:?}");
        e.close().unwrap();
    }
    std::thread::sleep(std::time::Duration::from_millis(2500)); // past the overlay's prune interval
    assert_eq!(std::fs::read(&srt).expect("still readable"), b"made through the mount");
    let listed: Vec<String> = std::fs::read_dir(mnt.path().join(S1))
        .unwrap()
        .map(|d| d.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(listed.iter().any(|n| n == "new.en.srt"), "still listed: {listed:?}");
}

/// D218 §2.1 item 4 — deleting a just-created file sends it to its region's
/// trash; and a file made where a catalogued one was just deleted shows (D217
/// answered ENOENT for it until the catalogue caught up).
#[test]
fn a_delete_goes_to_the_trash_and_a_new_file_shows_where_one_was_deleted() {
    need_fuse!();
    let tmp = tempfile::tempdir().unwrap();
    let f = forest(tmp.path(), &[("TV/Show/Season 01/old.en.srt", b"the catalogued subtitle")], HashPolicy::OnAdd, 1 << 20);
    let mnt = tempfile::tempdir().unwrap();
    let _m = mount(&f.data_dir, mnt.path(), true);
    let season = mnt.path().join(S1);

    std::fs::write(season.join("scratch.en.srt"), b"kept in the trash").expect("create");
    std::fs::remove_file(season.join("scratch.en.srt")).expect("delete");
    assert!(!season.join("scratch.en.srt").exists(), "gone from the mount");
    assert!(!f.lib.join("TV/Show/Season 01/scratch.en.srt").exists(), "and from its folder");
    assert_eq!(in_trash(&f.lib, "scratch.en.srt"), vec![b"kept in the trash".to_vec()], "in the region's trash");

    // an arr's delete-then-write of a subtitle at one path
    std::fs::remove_file(season.join("old.en.srt")).expect("delete the catalogued one");
    std::fs::write(season.join("old.en.srt"), b"the new subtitle").expect("create at the same path");
    assert_eq!(std::fs::read(season.join("old.en.srt")).expect("the new file shows"), b"the new subtitle");
    assert_eq!(in_trash(&f.lib, "old.en.srt"), vec![b"the catalogued subtitle".to_vec()]);
}

/// D218 §2.1 item 5 — write a temp, rename it over the real name: the old
/// bytes go to the trash, the new ones are at the name, no temp is left.
/// Also a made file renamed onto another made file, and a made file cut.
#[test]
fn write_a_temp_then_rename_and_truncate_a_new_file() {
    need_fuse!();
    let tmp = tempfile::tempdir().unwrap();
    let f = forest(tmp.path(), &[("TV/Show/Season 01/Show - s01e01.en.srt", b"old words")], HashPolicy::OnAdd, 1 << 20);
    let mnt = tempfile::tempdir().unwrap();
    let _m = mount(&f.data_dir, mnt.path(), true);
    let season = mnt.path().join(S1);

    // an own name (`.x.tmp`): the catalogue passes over it; the mount shows it
    std::fs::write(season.join(".Show - s01e01.en.srt.tmp"), b"new words").expect("create the temp");
    std::fs::rename(season.join(".Show - s01e01.en.srt.tmp"), season.join("Show - s01e01.en.srt"))
        .expect("rename the temp over the real name");
    assert_eq!(std::fs::read(season.join("Show - s01e01.en.srt")).unwrap(), b"new words", "through the mount");
    assert_eq!(std::fs::read(f.lib.join("TV/Show/Season 01/Show - s01e01.en.srt")).unwrap(), b"new words", "on its disk");
    assert!(!f.lib.join("TV/Show/Season 01/.Show - s01e01.en.srt.tmp").exists(), "no temp left");
    assert!(!season.join(".Show - s01e01.en.srt.tmp").exists());
    assert_eq!(in_trash(&f.lib, "Show - s01e01.en.srt"), vec![b"old words".to_vec()], "the old bytes are restorable");

    // a made file onto a made file
    std::fs::write(season.join("x.part"), b"second").unwrap();
    std::fs::write(season.join("x.en.srt"), b"first").unwrap();
    std::fs::rename(season.join("x.part"), season.join("x.en.srt")).expect("made onto made");
    assert_eq!(std::fs::read(season.join("x.en.srt")).unwrap(), b"second");
    assert_eq!(in_trash(&f.lib, "x.en.srt"), vec![b"first".to_vec()]);

    // a made file cut, by handle and by path
    std::fs::write(season.join("cut.en.srt"), b"0123456789").unwrap();
    std::fs::OpenOptions::new().write(true).open(season.join("cut.en.srt")).unwrap().set_len(6).expect("ftruncate");
    let p = std::ffi::CString::new(season.join("cut.en.srt").into_os_string().into_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::truncate(p.as_ptr(), 3) }, 0, "truncate(2)");
    assert_eq!(std::fs::read(season.join("cut.en.srt")).unwrap(), b"012");
}

/// D233 decision 6 — a folder renamed while it holds a file made through the
/// mount on another disk (one the catalogue does not list the folder in yet):
/// the file moves with its folder.
#[test]
fn a_folder_rename_takes_a_new_file_along() {
    need_fuse!();
    let tmp = tempfile::tempdir().unwrap();
    let f = forest(tmp.path(), &[("TV/Show/Season 01/e01.mkv", b"episode")], HashPolicy::OnAdd, 1 << 20);
    // Both regions are on one test disk, so free space ties; hold `lib` to a
    // floor it cannot meet so the new file goes to `spare`.
    pvfs_core::sync::set_region_floor(&f.data_dir, &f.lib_id, u64::MAX).unwrap();
    let mnt = tempfile::tempdir().unwrap();
    let _m = mount(&f.data_dir, mnt.path(), true);
    // no disk has Season 03, and lib has no room: spare takes it
    std::fs::create_dir(mnt.path().join("TV/Show/Season 03")).unwrap();
    std::fs::write(mnt.path().join("TV/Show/Season 03/new.mkv"), b"new episode").unwrap();
    assert!(f.spare.join("TV/Show/Season 03/new.mkv").exists(), "placed on the spare disk");

    std::fs::rename(mnt.path().join("TV/Show"), mnt.path().join("TV/Show (2020)")).expect("rename the show");
    assert!(f.spare.join("TV/Show (2020)/Season 03/new.mkv").exists(), "the new file moved with its folder");
    assert!(f.lib.join("TV/Show (2020)/Season 01/e01.mkv").exists(), "and the catalogued one");
    assert_eq!(std::fs::read(mnt.path().join("TV/Show (2020)/Season 03/new.mkv")).unwrap(), b"new episode");
}

/// D233 decision 7 — an append, read back past the attribute TTL, comes back
/// whole: D217 handed the kernel the catalogue's old size again.
#[test]
fn an_append_reads_back_whole() {
    need_fuse!();
    let tmp = tempfile::tempdir().unwrap();
    let f = forest(tmp.path(), &[("Notes/log.txt", b"abc")], HashPolicy::OnAdd, 1 << 20);
    let mnt = tempfile::tempdir().unwrap();
    let _m = mount(&f.data_dir, mnt.path(), true);
    let p = mnt.path().join("Notes/log.txt");
    std::fs::OpenOptions::new().append(true).open(&p).unwrap().write_all(b"def").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2200));
    let mut back = Vec::new();
    std::fs::File::open(&p).unwrap().read_to_end(&mut back).unwrap();
    assert_eq!(back, b"abcdef");
    assert_eq!(std::fs::metadata(&p).unwrap().len(), 6);
}

/// D233 decision 10 — a writable mount reports room; a read-only one, none.
#[test]
fn statfs_says_whether_and_how_much_can_be_written() {
    need_fuse!();
    let tmp = tempfile::tempdir().unwrap();
    let f = forest(tmp.path(), &[], HashPolicy::OnAdd, 1 << 20);
    let avail = |at: &Path| {
        let c = std::ffi::CString::new(at.as_os_str().as_encoded_bytes()).unwrap();
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::statvfs(c.as_ptr(), &mut st) }, 0);
        st.f_bavail as u64 * st.f_frsize as u64
    };
    let rw = tempfile::tempdir().unwrap();
    let m = mount(&f.data_dir, rw.path(), true);
    assert!(avail(rw.path()) > 0, "a writable mount has room");
    drop(m);
    let ro = tempfile::tempdir().unwrap();
    let _m = mount(&f.data_dir, ro.path(), false);
    assert_eq!(avail(ro.path()), 0, "a read-only one says nothing can be written (D82)");
}

/// D218 §2.1 item 2 — with every disk under its floor, a create is refused
/// with ENOSPC and writes nothing.
#[test]
fn every_disk_under_its_floor_refuses_a_create() {
    need_fuse!();
    let tmp = tempfile::tempdir().unwrap();
    let f = forest(tmp.path(), &[], HashPolicy::OnAdd, u64::MAX);
    let mnt = tempfile::tempdir().unwrap();
    let _m = mount(&f.data_dir, mnt.path(), true);
    let err = std::fs::write(mnt.path().join("TV/Show/Season 01/e02.mkv"), b"x").expect_err("no room above any floor");
    assert_eq!(err.raw_os_error(), Some(libc::ENOSPC), "{err}");
    assert!(find(&f.lib, "e02.mkv").is_empty() && find(&f.spare, "e02.mkv").is_empty(), "nothing written");
}
