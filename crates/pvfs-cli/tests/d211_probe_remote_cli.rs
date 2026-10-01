//! PVOS D211 — `pvfs region probe-remote`: names the regions this box
//! measures for their holders; bare off a terminal only lists; a region this
//! box catalogues itself is refused (its own watch measures it).

use pvfs_core::{sync, BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};
use std::process::{Command, Output, Stdio};

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new() -> Scratch {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let p = std::env::temp_dir().join(format!("pvfs-d211-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn pvfs(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pvfs"))
        .args(args)
        .env_remove("PVFS_DATA_DIR")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn catalogue_region(e: &mut Engine, label: &str) -> String {
    let root = e.identity.root_node_id.clone();
    let r = e
        .add_node(
            &root,
            NodeSpec { node_type: TYPE_FOLDER.into(), label: label.into(), payload: Vec::new(), is_temp: false, creation_nonce: None },
        )
        .unwrap();
    e.region_mark_as(&r, "catalogue", None).unwrap();
    r
}

#[test]
fn probe_remote_names_other_boxes_regions_and_refuses_this_boxs_own() {
    let s = Scratch::new();
    let data = s.0.join("data");
    let files = s.0.join("files");
    std::fs::create_dir_all(&files).unwrap();
    std::fs::write(files.join("a.mkv"), b"a film").unwrap();
    let (mut e, _mn) = Engine::init_unbound(&data).unwrap();
    let nas = catalogue_region(&mut e, "Data");
    let own = catalogue_region(&mut e, "Local");
    e.bind_folder(
        &own,
        BindSpec {
            source_uri: format!("file://{}", files.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    e.scan_routed(Some(&own), None, 0).unwrap();
    e.close().unwrap();
    let d = data.to_str().unwrap();

    let out = pvfs(&["--data-dir", d, "region", "probe-remote"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("measures no other box's regions"));

    let out = pvfs(&["--data-dir", d, "region", "probe-remote", &nas, "on"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(sync::probe_remote_regions(&data).unwrap(), vec![nas.clone()]);
    let out = pvfs(&["--data-dir", d, "--json", "region", "probe-remote"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["probe_remote"][0]["region"], nas.as_str());
    assert_eq!(v["probe_remote"][0]["label"], "Data");

    // bare state off a terminal: refused, nothing changed
    let out = pvfs(&["--data-dir", d, "region", "probe-remote", &nas]);
    assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stderr));
    // this box's own region: its watch measures it
    let out = pvfs(&["--data-dir", d, "region", "probe-remote", &own, "on"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("its own watch measures it"));
    assert_eq!(sync::probe_remote_regions(&data).unwrap(), vec![nas.clone()]);

    let out = pvfs(&["--data-dir", d, "region", "probe-remote", &nas, "off"]);
    assert!(out.status.success());
    assert!(sync::probe_remote_regions(&data).unwrap().is_empty());
}
