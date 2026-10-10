//! PVOS D232 — clearing what the trash purge could not, by a person
//! (`pvfs trash unstick`), never by giving the daemon sudo; and the root-run
//! repairs that walk a tree another user can write without following a link.
//!
//! The test user is not root (the pipeline's is chris), so "another user's"
//! is a locked folder, or an expected owner that is not this user. The smoke
//! suite runs the same with real root.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use pvfs_core::sync::{give_back_trash_dir, open_dir_nofollow, trash_bucket_path, unstick_bucket, Unstick};
use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

fn me() -> (u32, u32) {
    (nix::unistd::geteuid().as_raw(), nix::unistd::getegid().as_raw())
}

/// A temp dir by its real path (no link anywhere in it: `/tmp` is one on
/// some systems, and the walk refuses links on the way).
fn tmp() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let p = fs::canonicalize(t.path()).unwrap();
    (t, p)
}

fn write(p: &Path, bytes: &[u8]) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, bytes).unwrap();
}

fn bucket(root: &Path, day: u64) -> PathBuf {
    let b = root.join(".pvfs-trash").join(day.to_string());
    write(&b.join("TV/Show/Season 1/ep.mkv"), &[7u8; 1_000]);
    b
}

#[test]
fn only_a_trash_bucket_path_is_one() {
    let (b, d) = trash_bucket_path(Path::new("/mnt/local/Media/.pvfs-trash/20729")).unwrap();
    assert_eq!((b, d), (PathBuf::from("/mnt/local/Media/.pvfs-trash"), 20729));
    for p in [
        "/mnt/local/Media/trash/20729",
        "/mnt/local/Media/.pvfs-trash/TV",
        "/mnt/local/Media/.pvfs-trash/",
        "mnt/.pvfs-trash/20729",
        "/mnt/../etc/.pvfs-trash/20729",
        "/mnt/local/Media/.pvfs-trash/20729/TV",
    ] {
        assert!(trash_bucket_path(Path::new(p)).is_none(), "{p}");
    }
}

/// As the forest's own user it removes what that user may; what it may not
/// is named (sudo removes the rest); once allowed, the bucket goes.
#[test]
fn unstick_removes_what_it_may_and_names_the_rest() {
    let (_t, root) = tmp();
    let (uid, _) = me();
    let b = bucket(&root, 20000);
    write(&b.join("Movies/film.mkv"), &[1u8; 4_000]);
    let locked = b.join("TV/Show/Season 1");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).unwrap();

    let out = unstick_bucket(&b, uid).unwrap();
    let still_root = nix::unistd::geteuid().is_root();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    if still_root {
        assert!(matches!(out, Unstick::Removed { .. }), "root removes it all: {out:?}");
    } else {
        let Unstick::Left(s) = out else { panic!("{out:?}") };
        assert_eq!(s.first, locked.join("ep.mkv"), "{s:?}");
        assert!(s.error.contains("Permission denied"), "{s:?}");
        assert!(!b.join("Movies").exists(), "what it could remove went");
        assert_eq!(unstick_bucket(&b, uid).unwrap(), Unstick::Removed { freed_bytes: 1_000 });
    }
    assert!(!b.exists());
    assert_eq!(unstick_bucket(&b, uid).unwrap(), Unstick::NotThere, "a second run finds it gone");
}

/// Refused: not a trash path; a trash that is not the forest user's; a
/// bucket that is a link; a link anywhere on the way.
#[test]
fn unstick_refuses_what_is_not_a_pvfs_trash_bucket() {
    let (_t, root) = tmp();
    let (uid, _) = me();
    let b = bucket(&root, 20000);

    let e = unstick_bucket(&root.join("elsewhere/20000"), uid).unwrap_err().to_string();
    assert!(e.contains("not a trash bucket"), "{e}");

    let e = unstick_bucket(&b, uid + 1).unwrap_err().to_string();
    assert!(e.contains("not to the forest's user"), "a trash this user owns, for a forest of uid+1's: {e}");
    assert!(b.exists());

    // the bucket is a link to a folder outside the trash
    let outside = root.join("outside");
    write(&outside.join("keep.mkv"), b"keep");
    std::os::unix::fs::symlink(&outside, root.join(".pvfs-trash/20001")).unwrap();
    let e = unstick_bucket(&root.join(".pvfs-trash/20001"), uid).unwrap_err().to_string();
    assert!(e.contains("not a folder"), "{e}");
    assert!(outside.join("keep.mkv").exists());

    // a link on the way: <root>/via -> <root>, so <root>/via/.pvfs-trash/20000
    std::os::unix::fs::symlink(&root, root.join("via")).unwrap();
    let e = unstick_bucket(&root.join("via/.pvfs-trash/20000"), uid).unwrap_err().to_string();
    assert!(e.contains("without following a link"), "{e}");
    assert!(b.exists(), "nothing removed through the link");
}

#[test]
fn the_anchored_open_refuses_a_link_at_any_component() {
    let (_t, root) = tmp();
    fs::create_dir_all(root.join("a/b")).unwrap();
    std::os::unix::fs::symlink(root.join("a"), root.join("l")).unwrap();
    assert!(open_dir_nofollow(&root.join("a/b")).is_ok());
    assert!(open_dir_nofollow(&root.join("l/b")).is_err(), "a link in the middle");
    assert!(open_dir_nofollow(&root.join("l")).is_err(), "a link at the end");
    assert!(open_dir_nofollow(Path::new("relative/b")).is_err());
}

/// A region's trash folder that its user cannot read is given back: owner
/// and `u+rwx`, this folder only. A folder of another name is refused.
#[test]
fn a_trash_folder_is_given_back_and_only_a_trash_folder() {
    let (_t, root) = tmp();
    let (uid, gid) = me();
    let trash = root.join(".pvfs-trash");
    fs::create_dir_all(trash.join("20000")).unwrap();
    fs::set_permissions(&trash, fs::Permissions::from_mode(0o000)).unwrap();
    assert!(give_back_trash_dir(&trash, uid, gid).unwrap(), "changed");
    let mode = fs::metadata(&trash).unwrap().mode();
    assert_eq!(mode & 0o700, 0o700, "{mode:o}");
    assert!(!give_back_trash_dir(&trash, uid, gid).unwrap(), "nothing to change the second time");
    let e = give_back_trash_dir(&root, uid, gid).unwrap_err().to_string();
    assert!(e.contains("not a `.pvfs-trash` folder"), "{e}");
}

/// `fix-permissions`' walk changes what is in the tree and never what a
/// link points at. Shown with a group change: a link to an outside file
/// must leave that file's group as it was.
#[test]
fn chown_tree_never_follows_a_link() {
    let (_t, root) = tmp();
    let (uid, gid) = me();
    let tree = root.join("tree");
    write(&tree.join("index.db"), b"db");
    let outside = root.join("outside.txt");
    write(&outside, b"not the tree's");
    std::os::unix::fs::symlink(&outside, tree.join("link")).unwrap();
    std::os::unix::fs::symlink(&root, tree.join("dirlink")).unwrap();
    // another group this user is in, when there is one
    let other = nix::unistd::getgroups().unwrap_or_default().into_iter().map(|g| g.as_raw()).find(|g| *g != gid);
    let target = other.unwrap_or(gid);

    pvfs_core::mount::chown_tree(&tree, uid, target).unwrap();

    assert_eq!(fs::metadata(tree.join("index.db")).unwrap().gid(), target, "the tree's file changed");
    assert_eq!(fs::metadata(&outside).unwrap().gid(), gid, "the link's target did not");
    assert!(fs::symlink_metadata(tree.join("link")).unwrap().file_type().is_symlink());
    assert_eq!(fs::metadata(&root).unwrap().gid(), gid, "nor a linked folder");
}

// ---- purge_region_trash, region by region ----------------------------------

fn region(e: &mut Engine, label: &str, dir: &Path) -> String {
    let root = e.identity.root_node_id.clone();
    let r = e
        .add_node(
            &root,
            NodeSpec { node_type: TYPE_FOLDER.into(), label: label.into(), payload: Vec::new(), is_temp: false, creation_nonce: None },
        )
        .unwrap();
    e.region_mark_as(&r, "catalogue", None).unwrap();
    fs::create_dir_all(dir).unwrap();
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

/// One region whose trash cannot be read no longer costs the others their
/// purge (`receive` and `resolve` call this; `resolve`'s pass failed on it).
#[test]
fn one_unreadable_region_does_not_stop_the_others_purge() {
    let (_t, root) = tmp();
    let (a, b) = (root.join("a"), root.join("b"));
    write(&a.join("TV/Show/e1.mkv"), b"one");
    write(&b.join("TV/Other/e2.mkv"), b"two");
    let (mut e, _m) = Engine::init(&root.join("forest")).unwrap();
    let ra = region(&mut e, "a", &a);
    let rb = region(&mut e, "b", &b);
    let today = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() / 86_400;
    let old = bucket(&a, today - 30);
    write(&b.join(".pvfs-trash"), b"a file where the trash folder should be");

    let p = e.purge_region_trash().unwrap();
    assert!(!old.exists(), "a's old bucket is purged");
    assert_eq!(p.done.iter().map(|t| t.region.as_str()).collect::<Vec<_>>(), [ra.as_str()], "{p:?}");
    assert_eq!(p.done[0].root, a);
    assert_eq!(p.failed.len(), 1, "{p:?}");
    assert_eq!((p.failed[0].region.as_str(), &p.failed[0].root), (rb.as_str(), &b));
    assert!(p.failed[0].error.contains("read trash"), "{p:?}");
    e.close().unwrap();
}
