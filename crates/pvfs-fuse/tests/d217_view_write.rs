//! D217 — writing through the view mount.
//!
//! Tier 1 is an edit of a file this box already holds: the write goes to the
//! real file and the `watch` job re-hashes it. `create` is the other half, and
//! the one that takes mergerfs out of the decision — a new file lands on the
//! disk D216's rule picks (the region that already holds its folder), not on
//! whichever branch happened to be writable. Both are refused unless the mount
//! was told to allow writes.

use pvfs_client::hash_cache::CacheOpts;
use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

fn fuse_available() -> bool {
    std::path::Path::new("/dev/fuse").exists()
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

/// Two local catalogue regions: `lib` holds the show, `spare` is empty. On
/// free space alone `spare` would win every time, so a file that lands in
/// `lib` landed there because of the folder.
fn forest(tmp: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let lib = tmp.join("lib");
    let spare = tmp.join("spare");
    std::fs::create_dir_all(lib.join("TV/Show/Season 01")).unwrap();
    std::fs::create_dir_all(&spare).unwrap();
    std::fs::write(lib.join("TV/Show/Season 01/Show - s01e01.mkv"), b"the episode bytes").unwrap();

    let (mut e, _mn) = Engine::init(&tmp.join("forest")).unwrap();
    let root = e.identity.root_node_id.clone();
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
                hash_policy: HashPolicy::OnAdd,
            },
        )
        .unwrap();
        e.scan_routed(Some(&r), None, 0).unwrap();
    }
    // D216 — the floor is per region, and the default (500 GB) is larger than
    // any test disk: without setting it, every candidate is "nearly full" and
    // the folder rule quietly never fires. The lab needs the same.
    for b in e.local_bindings().unwrap() {
        pvfs_core::sync::set_region_floor(e.data_dir(), &b.folder_id, 1 << 20).unwrap();
    }
    let data_dir = e.data_dir().to_path_buf();
    e.close().unwrap();
    (data_dir, lib, spare)
}

#[test]
fn a_read_only_mount_still_refuses_every_write() {
    if !fuse_available() {
        eprintln!("skipping: no /dev/fuse or fusermount on this host");
        return;
    }
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let tmp = tempfile::tempdir().unwrap();
    let (data_dir, _lib, _spare) = forest(tmp.path());
    let mnt = tempfile::tempdir().unwrap();
    let _session = pvfs_fuse::MountGuard::new(
        pvfs_fuse::spawn_view_mount_with(&data_dir, mnt.path(), CacheOpts::default(), Some(Vec::new()))
            .unwrap(),
        mnt.path(),
    );
    let season = mnt.path().join("TV/Show/Season 01");
    assert!(
        std::fs::write(season.join("Show - s01e01.en.srt"), b"nope").is_err(),
        "a mount that was not told to allow writes creates nothing"
    );
    assert!(
        std::fs::OpenOptions::new().write(true).open(season.join("Show - s01e01.mkv")).is_err(),
        "...and opens nothing for writing"
    );
}

#[test]
fn a_writable_mount_edits_what_this_box_holds_and_creates_beside_the_folder() {
    if !fuse_available() {
        eprintln!("skipping: no /dev/fuse or fusermount on this host");
        return;
    }
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let tmp = tempfile::tempdir().unwrap();
    let (data_dir, lib, spare) = forest(tmp.path());
    let mnt = tempfile::tempdir().unwrap();
    let _session = pvfs_fuse::MountGuard::new(
        pvfs_fuse::spawn_view_mount_writable(
            &data_dir,
            mnt.path(),
            CacheOpts::default(),
            Some(Vec::new()),
            true,
        )
        .unwrap(),
        mnt.path(),
    );
    let season = mnt.path().join("TV/Show/Season 01");

    // ---- create: the subtitle joins its episode, not the emptier disk
    let srt = season.join("Show - s01e01.en.srt");
    std::fs::write(&srt, b"1\n00:00:01,000 --> 00:00:02,000\nhello\n").expect("the create succeeds");
    assert!(
        lib.join("TV/Show/Season 01/Show - s01e01.en.srt").exists(),
        "the new file is on the disk that already holds the folder"
    );
    assert!(
        !spare.join("TV/Show/Season 01/Show - s01e01.en.srt").exists(),
        "and not on the emptier one, which free space alone would have chosen"
    );

    // ---- and it can be read straight back, before any scan has run
    let back = std::fs::read_to_string(&srt).expect("the file reads back through the mount");
    assert!(back.contains("hello"), "{back:?}");

    // ---- and `ls` shows it at once, before any scan
    let listed: Vec<String> = std::fs::read_dir(&season)
        .unwrap()
        .map(|d| d.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        listed.iter().any(|n| n == "Show - s01e01.en.srt"),
        "a just-created file is in the listing: {listed:?}"
    );

    // ---- and it can be deleted again straight away, before any scan.
    // Refusing that cost an `rm` an I/O error on the fleet (2026-10-04).
    let scratch = season.join("Show - s01e01.scratch.srt");
    std::fs::write(&scratch, b"temporary").expect("create");
    std::fs::remove_file(&scratch).expect("a just-created file deletes again");
    assert!(!scratch.exists(), "gone from the mount");
    assert!(
        !lib.join("TV/Show/Season 01/Show - s01e01.scratch.srt").exists(),
        "and gone from the disk"
    );

    // ---- edit: a file this box holds takes a write in place
    let ep = season.join("Show - s01e01.mkv");
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new().write(true).open(&ep).expect("opens for writing");
        f.seek(SeekFrom::Start(4)).unwrap();
        f.write_all(b"EDIT").unwrap();
    }
    let on_disk = std::fs::read(lib.join("TV/Show/Season 01/Show - s01e01.mkv")).unwrap();
    assert_eq!(&on_disk[4..8], b"EDIT", "the write reached the real file in its region");
    assert_eq!(on_disk.len(), b"the episode bytes".len(), "and changed nothing else");
}
