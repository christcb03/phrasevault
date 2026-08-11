//! P7.3 — the mount serves a real kernel filesystem: readdir, lookup, and
//! byte-exact reads. Skips (loudly, but green) where fuse isn't available.

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

#[test]
fn mount_lists_and_streams_bytes() {
    if !fuse_available() {
        eprintln!("skipping: no /dev/fuse or fusermount on this host");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let albums = e
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "albums".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    let bytes_dir = tempfile::tempdir().unwrap();
    let clip_path = bytes_dir.path().join("clip.mkv");
    std::fs::File::create(&clip_path)
        .unwrap()
        .write_all(b"streaming-bytes")
        .unwrap();
    let clip = e
        .add_node(
            &albums,
            NodeSpec {
                node_type: TYPE_FILE.into(),
                label: "clip.mkv".into(),
                payload: FilePayload {
                    content_hash: blake3::hash(b"streaming-bytes").to_hex().to_string(),
                    size_bytes: 15,
                    mime_type: "video/x-matroska".into(),
                    original_name: "clip.mkv".into(),
                }
                .encode(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    e.add_location(
        &clip,
        &pvfs_core::storage::path_to_uri(&std::fs::canonicalize(&clip_path).unwrap()).unwrap(),
    )
    .unwrap();
    let data_dir = e.data_dir().to_path_buf();
    e.close().unwrap();

    let mnt = tempfile::tempdir().unwrap();
    let session = pvfs_fuse::spawn_mount(&data_dir, &root, mnt.path()).unwrap();

    // readdir + lookup through the kernel
    let names: Vec<String> = std::fs::read_dir(mnt.path())
        .unwrap()
        .map(|d| d.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(names.contains(&"albums".to_string()), "readdir: {names:?}");
    // metadata: size from the catalog before any bytes are read
    let md = std::fs::metadata(mnt.path().join("albums/clip.mkv")).unwrap();
    assert_eq!(md.len(), 15);
    // byte-exact kernel read
    let got = std::fs::read(mnt.path().join("albums/clip.mkv")).unwrap();
    assert_eq!(got, b"streaming-bytes");
    // read-only: writes refuse
    assert!(std::fs::write(mnt.path().join("albums/clip.mkv"), b"x").is_err());

    drop(session); // unmount
}
