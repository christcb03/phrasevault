//! D170 — `rename`, `mkdir`, `rmdir` and `setattr` through the view mount.
//! What an arr does to a library file it did not just create: a verified
//! move (rename, then the target must be there with the source's size — at
//! once, before any pass has told the catalogue), a folder renamed with
//! everything under it, a rename into a folder made a moment ago (mergerfs's
//! path clone), an emptied folder removed. The other-box path is
//! `pvfsd/tests/d170_rename_path.rs` and the lab pair.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use pvfs_client::hash_cache::CacheOpts;
use pvfs_core::acl::Principal;
use pvfs_core::{crypto, identity, sync, BindSpec, Engine, HashPolicy, NodeSpec, RegionEntry, TYPE_FOLDER};

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

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|d| d.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn write(root: &Path, rel: &str, bytes: &[u8]) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

/// What an arr calls a move: rename, then the target is there with the
/// source's size, and the source is not.
fn verified_move(from: &Path, to: &Path) {
    let size = std::fs::metadata(from).expect("the source is there").len();
    std::fs::rename(from, to).unwrap_or_else(|e| panic!("rename {} → {}: {e}", from.display(), to.display()));
    assert_eq!(std::fs::metadata(to).expect("the target is there at once").len(), size);
    assert!(std::fs::metadata(from).is_err(), "and the source is not");
}

#[test]
fn an_arr_renames_files_and_folders_through_the_mount_and_sees_it_at_once() {
    if !fuse_available() {
        eprintln!("skipping: no /dev/fuse or fusermount on this host");
        return;
    }
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let tmp = tempfile::tempdir().unwrap();
    let lib = tmp.path().join("lib");
    write(&lib, "TV/Show/Season 01/show.s01e01.mkv", b"episode one");
    write(&lib, "TV/Show/Season 01/show.s01e02.mkv", b"episode two, longer");
    write(&lib, "TV/Old Name/Season 01/e1.mkv", b"old name one");
    write(&lib, "TV/Old Name/Season 01/e2.mkv", b"old name two!");
    write(&lib, "TV/Emptied/.@__thumb/poster.jpg", b"what the NAS left behind");
    write(&lib, "Movies/Film (1999)/film.mkv", b"the film");
    write(&lib, "Movies/Film (1999)/Film (1999).mkv", b"an older copy under the name the arr wants");

    let (mut e, mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let r = folder(&mut e, &root, "Library");
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
    e.scan_routed(Some(&r), None, 0).unwrap();

    // A region another box catalogues: its rows are here, its holder is not.
    let other_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let other_pub = crypto::pubkey_bytes(&other_key);
    e.authorize_member(&mn, &other_pub).unwrap();
    let far = folder(&mut e, &root, "Far");
    e.region_mark_as(&far, "catalogue", Some(&Principal::Key(other_pub.clone()))).unwrap();
    let row = |rel: &str, kind: &str, size: u64, hash: Option<String>| RegionEntry {
        rel_path: rel.into(),
        kind: kind.into(),
        size_bytes: size,
        mtime_ms: 1,
        changed_ms: 1,
        content_hash: hash,
        quality: None,
        seen_at: 0,
    };
    let rows = vec![
        row("Far", "dir", 0, None),
        row("Far/far.mkv", "file", 9, Some(blake3::hash(b"far bytes").to_hex().to_string())),
    ];
    let manifest = Engine::region_manifest_bytes(&far, 1, &rows);
    let prep = e
        .prepare_commit_region_head(&other_pub, &far, 1, blake3::hash(&manifest).to_hex().as_str())
        .unwrap();
    let mut events = Vec::new();
    for pe in prep.events {
        let mut ev = pe.event;
        ev.set_author_sig(crypto::sign_digest(&other_key, &pe.digest).unwrap());
        events.push(ev);
    }
    e.commit_member_write(events).unwrap();
    e.install_region_snapshot(&far, 1, &manifest, "test").unwrap();
    let data_dir = e.data_dir().to_path_buf();
    e.close().unwrap();

    let mnt = tempfile::tempdir().unwrap();
    let session = pvfs_fuse::spawn_view_mount_with(&data_dir, mnt.path(), CacheOpts::default(), Some(Vec::new())).unwrap();
    let m = |rel: &str| mnt.path().join(rel);

    // ---- "Rename files": a verified move, in place
    verified_move(&m("TV/Show/Season 01/show.s01e01.mkv"), &m("TV/Show/Season 01/Show - S01E01.mkv"));
    assert_eq!(names(&m("TV/Show/Season 01")), vec!["Show - S01E01.mkv", "show.s01e02.mkv"]);
    assert_eq!(std::fs::read(m("TV/Show/Season 01/Show - S01E01.mkv")).unwrap(), b"episode one", "and it reads");
    assert_eq!(std::fs::read(lib.join("TV/Show/Season 01/Show - S01E01.mkv")).unwrap(), b"episode one", "the holder's disk agrees");
    assert!(!lib.join("TV/Show/Season 01/show.s01e01.mkv").exists());
    // This box holds the file, so its own rows followed the rename (bytes are
    // found by hash → row → path). What the mount REMEMBERS of a rename — for a
    // region another box holds, whose rows arrive with its next head — is
    // `overlay`'s unit tests and the lab pair.
    let catalogue = Engine::open(&data_dir).unwrap();
    assert!(catalogue.view_entry("TV/Show/Season 01/show.s01e01.mkv").unwrap().is_none());
    assert!(catalogue.view_entry("TV/Show/Season 01/Show - S01E01.mkv").unwrap().is_some());
    catalogue.close().unwrap();

    // ---- renamed again straight away (no pass between), and back
    verified_move(&m("TV/Show/Season 01/Show - S01E01.mkv"), &m("TV/Show/Season 01/Show - S01E01 - Pilot.mkv"));
    verified_move(&m("TV/Show/Season 01/Show - S01E01 - Pilot.mkv"), &m("TV/Show/Season 01/Show - S01E01.mkv"));
    assert_eq!(names(&m("TV/Show/Season 01")), vec!["Show - S01E01.mkv", "show.s01e02.mkv"]);

    // ---- a rename into a folder made a moment ago (what mergerfs's path clone does first)
    std::fs::create_dir(m("TV/Show/Season 02")).expect("mkdir through the view");
    assert!(std::fs::create_dir(m("TV/Show/Season 02")).is_err(), "it exists now");
    assert!(m("TV/Show/Season 02").is_dir());
    assert_eq!(names(&m("TV/Show")), vec!["Season 01", "Season 02"]);
    verified_move(&m("TV/Show/Season 01/show.s01e02.mkv"), &m("TV/Show/Season 02/Show - S02E01.mkv"));
    assert_eq!(names(&m("TV/Show/Season 02")), vec!["Show - S02E01.mkv"]);
    assert_eq!(std::fs::read(lib.join("TV/Show/Season 02/Show - S02E01.mkv")).unwrap(), b"episode two, longer");

    // ---- a folder, with everything under it; then a file inside the renamed folder
    std::fs::rename(m("TV/Old Name"), m("TV/New Name (2020)")).expect("a folder renames");
    assert_eq!(names(&m("TV")), vec!["Emptied", "New Name (2020)", "Show"]);
    assert_eq!(names(&m("TV/New Name (2020)/Season 01")), vec!["e1.mkv", "e2.mkv"]);
    assert_eq!(std::fs::read(m("TV/New Name (2020)/Season 01/e2.mkv")).unwrap(), b"old name two!");
    assert!(std::fs::metadata(m("TV/Old Name/Season 01/e1.mkv")).is_err());
    assert!(lib.join("TV/New Name (2020)/Season 01/e1.mkv").is_file() && !lib.join("TV/Old Name").exists());
    verified_move(&m("TV/New Name (2020)/Season 01/e1.mkv"), &m("TV/New Name (2020)/Season 01/New Name - S01E01.mkv"));
    assert_eq!(names(&m("TV/New Name (2020)/Season 01")), vec!["New Name - S01E01.mkv", "e2.mkv"]);
    assert_eq!(std::fs::read(m("TV/New Name (2020)/Season 01/New Name - S01E01.mkv")).unwrap(), b"old name one");

    // ---- renamed ONTO a file: the one in the way goes to the trash, the moved one is what reads
    verified_move(&m("Movies/Film (1999)/film.mkv"), &m("Movies/Film (1999)/Film (1999).mkv"));
    assert_eq!(names(&m("Movies/Film (1999)")), vec!["Film (1999).mkv"]);
    assert_eq!(std::fs::read(m("Movies/Film (1999)/Film (1999).mkv")).unwrap(), b"the film");
    let trashed: Vec<String> = sync::list_trash(&lib).into_iter().map(|t| t.rel_path).collect();
    assert_eq!(trashed, vec!["Movies/Film (1999)/Film (1999).mkv"], "replaced softly");

    // ---- renamed, then deleted, before any pass
    verified_move(&m("TV/New Name (2020)/Season 01/e2.mkv"), &m("TV/New Name (2020)/Season 01/New Name - S01E02.mkv"));
    std::fs::remove_file(m("TV/New Name (2020)/Season 01/New Name - S01E02.mkv")).expect("and deleted");
    assert_eq!(names(&m("TV/New Name (2020)/Season 01")), vec!["New Name - S01E01.mkv"]);
    assert!(!lib.join("TV/New Name (2020)/Season 01/New Name - S01E02.mkv").exists(), "it really left the disk");
    assert!(sync::list_trash(&lib).iter().any(|t| t.rel_path == "TV/New Name (2020)/Season 01/New Name - S01E02.mkv"));

    // ---- an emptied folder goes (what the view never showed goes to the trash); a full one stays
    assert!(names(&m("TV/Emptied")).is_empty(), "the view shows it empty");
    std::fs::remove_dir(m("TV/Emptied")).expect("rmdir through the view");
    assert_eq!(names(&m("TV")), vec!["New Name (2020)", "Show"]);
    assert!(!lib.join("TV/Emptied").exists());
    assert!(std::fs::remove_dir(m("TV/Show")).is_err(), "not empty");
    std::fs::create_dir(m("TV/Made And Unmade")).unwrap();
    std::fs::remove_dir(m("TV/Made And Unmade")).expect("a folder only the mount remembered");
    assert_eq!(names(&m("TV")), vec!["New Name (2020)", "Show"]);

    // ---- refusals: names the catalogue passes over, a folder onto a full folder, a holder nobody can ask
    assert!(std::fs::rename(m("TV/Show/Season 01/Show - S01E01.mkv"), m("TV/Show/Season 01/.hidden.mkv.manifest")).is_err());
    assert!(std::fs::rename(m("TV/Show"), m("TV/New Name (2020)")).is_err(), "a folder is never replaced");
    assert!(std::fs::rename(m("Far/far.mkv"), m("Far/far2.mkv")).is_err(), "its holder cannot be asked");
    assert_eq!(names(&m("Far")), vec!["far.mkv"], "and nothing is hidden or shown for it");

    // ---- modes and times are accepted and ignored; bytes still do not come through
    let ep = m("TV/Show/Season 01/Show - S01E01.mkv");
    std::fs::set_permissions(&ep, std::fs::Permissions::from_mode(0o664)).expect("chmod is accepted");
    assert!(std::process::Command::new("touch").arg("-c").arg(&ep).status().unwrap().success(), "and so is touch");
    assert!(std::fs::OpenOptions::new().write(true).open(&ep).is_err(), "a write-open is refused");
    assert!(std::fs::write(m("TV/Show/Season 01/new.mkv"), b"x").is_err(), "and a create");

    // ---- the catalogue catches up: what the mount remembered becomes what the catalogue says — the same thing
    let tree = |mnt: &Path| {
        let mut out = Vec::new();
        let mut stack = vec![mnt.to_path_buf()];
        while let Some(d) = stack.pop() {
            for n in names(&d) {
                let p = d.join(&n);
                if p.is_dir() {
                    stack.push(p);
                } else {
                    out.push((p.strip_prefix(mnt).unwrap().to_string_lossy().into_owned(), std::fs::read(&p).ok()));
                }
            }
        }
        out.sort();
        out
    };
    let before = tree(mnt.path());
    let mut scanner = Engine::open(&data_dir).unwrap();
    scanner.scan_routed(Some(&r), None, 0).unwrap();
    assert!(scanner.view_entry("TV/Show/Season 01/Show - S01E01.mkv").unwrap().is_some(), "the pass found the new names");
    assert!(scanner.view_entry("TV/Old Name").unwrap().is_none());
    scanner.close().unwrap();
    std::thread::sleep(std::time::Duration::from_secs(6)); // the mount's 5 s listing cache
    assert_eq!(tree(mnt.path()), before);
    let paths: Vec<&str> = before.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(
        paths,
        vec![
            "Far/far.mkv",
            "Movies/Film (1999)/Film (1999).mkv",
            "TV/New Name (2020)/Season 01/New Name - S01E01.mkv",
            "TV/Show/Season 01/Show - S01E01.mkv",
            "TV/Show/Season 02/Show - S02E01.mkv",
        ]
    );
    drop(session);
}
