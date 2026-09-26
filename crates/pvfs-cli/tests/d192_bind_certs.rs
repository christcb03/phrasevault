//! PVOS D192 — `pvfs forest bind-certs`: refused while any box the fleet
//! knows announces an older protocol (or none — a silent box), done once
//! every box announces 14; then `forest tip` and `fleet versions` say so.

use pvfs_core::{Engine, NodeSpec};

/// A scratch directory, removed when dropped (this crate has no tempfile).
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new() -> Scratch {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let p = std::env::temp_dir().join(format!("pvfs-d192-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn pvfs(data: &std::path::Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_pvfs"))
        .arg("--data-dir")
        .arg(data)
        .args(args)
        .env_remove("PVFS_DATA_DIR")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap()
}

fn node(engine: &mut Engine, parent: &str, label: &str, node_type: &str, payload: &str) -> String {
    engine
        .add_node(
            &parent.to_string(),
            NodeSpec {
                node_type: node_type.into(),
                label: label.into(),
                payload: payload.as_bytes().to_vec(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap()
}

fn version(proto: u32) -> String {
    format!(r#"{{"pvfs":"1.4.0","proto":{proto},"schema":20}}"#)
}

#[test]
fn binding_waits_for_every_box_the_fleet_knows() {
    let dir = Scratch::new();
    let (mut engine, _mn) = Engine::init_unbound(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let fleet = node(&mut engine, &root, ".fleet", "folder", "");
    let eps = node(&mut engine, &fleet, "endpoints", "folder", "");
    let vers = node(&mut engine, &fleet, "versions", "folder", "");
    let (a, b) = ("a".repeat(64), "b".repeat(64));
    node(&mut engine, &eps, &a, "fleet.endpoint", "10.0.0.1:7481");
    node(&mut engine, &vers, &a, "fleet.version", &version(13));
    node(&mut engine, &eps, &b, "fleet.endpoint", "10.0.0.2:7481"); // silent: no version record
    engine.close().unwrap();

    // one box on protocol 13, one silent: refused, nothing written
    let out = pvfs(dir.path(), &["forest", "bind-certs", "--yes"]);
    assert!(!out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("2 box(es) do not announce protocol 14"), "{err}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("BEHIND") && text.contains("silent"), "{text}");
    let tip = pvfs(dir.path(), &["--json", "forest", "tip"]);
    let tip: serde_json::Value = serde_json::from_slice(&tip.stdout).unwrap();
    assert_eq!(tip["certs_bound"], serde_json::Value::Null);

    // both boxes announce 14
    let mut engine = Engine::open(dir.path()).unwrap();
    for c in engine.children(&vers).unwrap() {
        engine.remove_link(&c.link_id).unwrap();
    }
    node(&mut engine, &vers, &a, "fleet.version", &version(14));
    node(&mut engine, &vers, &b, "fleet.version", &version(14));
    engine.close().unwrap();

    // not at a terminal and no --yes: asked for, not assumed
    let out = pvfs(dir.path(), &["forest", "bind-certs"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--yes"));

    let out = pvfs(dir.path(), &["--json", "forest", "bind-certs", "--yes"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let done: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(done["changed"], true);
    let seq = done["bound"].as_str().unwrap().to_string();
    assert!(seq.parse::<u64>().is_ok(), "bound at a seq: {seq}");

    let out = pvfs(dir.path(), &["forest", "bind-certs", "--yes"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("already"));

    let tip = pvfs(dir.path(), &["--json", "forest", "tip"]);
    let tip: serde_json::Value = serde_json::from_slice(&tip.stdout).unwrap();
    assert_eq!(tip["certs_bound"], seq.as_str());
    let v = pvfs(dir.path(), &["--json", "fleet", "versions"]);
    let v: serde_json::Value = serde_json::from_slice(&v.stdout).unwrap();
    assert_eq!(v["certificates"]["bound"], seq.as_str());
}
