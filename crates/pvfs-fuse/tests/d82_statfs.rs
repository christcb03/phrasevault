//! D82 — `statfs`, so the mount can answer "how big is this and can I write to
//! it?" instead of the zeroes the default trait impl returns.
//!
//! The consumer is Sonarr/Radarr on the ingest box, reading through mergerfs.
//! Plex is NOT one — it stays on its own rclone mount from the NAS — so what
//! this has to survive is a library scan, not a transcode.
//!
//! Two answers matter, and only one of them is a measurement:
//!   * the byte total, which makes `df` meaningful; and
//!   * ZERO available, which is the load-bearing one. Nothing can be created
//!     here, and a union's create policy must never pick this branch over the
//!     writable staging disk beside it.

use std::io::Write as _;

use pvfs_core::{Engine, FilePayload, NodeSpec, TYPE_FILE, TYPE_FOLDER};

fn fuse_available() -> bool {
    std::path::Path::new("/dev/fuse").exists()
        && (which("fusermount3") || which("fusermount"))
}

fn which(bin: &str) -> bool {
    std::process::Command::new("sh")
        .args(["-c", &format!("command -v {bin}")])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn statvfs(path: &std::path::Path) -> libc::statvfs {
    let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
    assert_eq!(rc, 0, "statvfs failed on {}", path.display());
    st
}

/// Build a forest with three files of known sizes and mount it.
fn forest_with_files(sizes: &[u64]) -> (tempfile::TempDir, tempfile::TempDir, std::path::PathBuf, String) {
    let dir = tempfile::tempdir().unwrap();
    let bytes_dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let folder = e
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "Media".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    for (i, sz) in sizes.iter().enumerate() {
        let body = vec![b'a' + i as u8; *sz as usize];
        let p = bytes_dir.path().join(format!("f{i}.mkv"));
        std::fs::File::create(&p).unwrap().write_all(&body).unwrap();
        let node = e
            .add_node(
                &folder,
                NodeSpec {
                    node_type: TYPE_FILE.into(),
                    label: format!("f{i}.mkv"),
                    payload: FilePayload {
                        content_hash: blake3::hash(&body).to_hex().to_string(),
                        size_bytes: *sz,
                        mime_type: "video/x-matroska".into(),
                        original_name: format!("f{i}.mkv"),
                    }
                    .encode(),
                    is_temp: false,
                    creation_nonce: None,
                },
            )
            .unwrap();
        e.add_location(
            &node,
            &pvfs_core::storage::path_to_uri(&std::fs::canonicalize(&p).unwrap()).unwrap(),
        )
        .unwrap();
    }
    let data_dir = e.data_dir().to_path_buf();
    e.close().unwrap();
    (dir, bytes_dir, data_dir, root)
}

/// The whole point: a truthful size, and no room to write.
#[test]
fn statfs_reports_the_tree_and_refuses_to_offer_space() {
    if !fuse_available() {
        eprintln!("skipping: no /dev/fuse or fusermount on this host");
        return;
    }
    let sizes = [4096u64, 8192, 1500];
    let (_d, _b, data_dir, root) = forest_with_files(&sizes);
    let mnt = tempfile::tempdir().unwrap();
    let session = pvfs_fuse::spawn_mount(&data_dir, &root, mnt.path()).unwrap();

    let st = statvfs(mnt.path());

    // ZERO available is the load-bearing answer — a union create policy must
    // never choose this branch. Nothing here can be created.
    assert_eq!(st.f_bavail, 0, "the mount must offer no space to write");
    assert_eq!(st.f_bfree, 0, "and no free blocks either");

    // The byte total makes `df` mean something.
    let total: u64 = sizes.iter().sum();
    let blocks_expected = total.div_ceil(st.f_bsize as u64);
    assert_eq!(
        st.f_blocks, blocks_expected,
        "blocks should be the tree's bytes at {}-byte blocks",
        st.f_bsize
    );

    assert_eq!(st.f_files, sizes.len() as u64, "one inode per live file");
    assert_eq!(st.f_namemax, 255, "NAME_MAX");

    drop(session);
}

/// A file the catalog remembers but nothing links is not in the filesystem, so
/// it must not inflate `df`. This is the shape of the 97 episodes kept as a
/// record of a drive failure: real nodes, deliberately unlinked from the tree.
#[test]
fn an_unlinked_file_is_not_counted() {
    let sizes = [4096u64, 8192];
    let (_d, _b, data_dir, _root) = forest_with_files(&sizes);
    let mut e = Engine::open(&data_dir).unwrap();

    let (bytes, files) = e.total_file_bytes().unwrap();
    assert_eq!(files, 2);
    assert_eq!(bytes, 12288);

    // Unlink one — the node survives, its place in the tree does not.
    let root = e.identity.root_node_id.clone();
    let media = e
        .children(&root)
        .unwrap()
        .into_iter()
        .find(|c| c.label == "Media")
        .unwrap()
        .node
        .id;
    let victim = e.children(&media).unwrap()[0].link_id.clone();
    e.remove_link(&victim).unwrap();

    let (bytes, files) = e.total_file_bytes().unwrap();
    assert_eq!(files, 1, "an unlinked file is not part of the filesystem");
    assert_eq!(bytes, 8192, "and its bytes must not show up in df");
    e.close().unwrap();
}
