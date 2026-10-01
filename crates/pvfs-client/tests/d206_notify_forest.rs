//! PVOS D206 — every notifier event names its forest: the registry alias,
//! else the mount directory's name. Lab and production events differed only
//! by address, so the lab notifier stayed off (D142).
use pvfs_client::health::{FleetHealth, PeerHealth};
use pvfs_client::notify::{self, Event, Notify};
use pvfs_core::mount::Registry;
use pvfs_core::Engine;

fn notify_as(format: &str) -> Notify {
    Notify { url: "http://ha:8123/api/webhook/pvfs-fleet".into(), format: format.into(), labels: Default::default() }
}

fn down_event(forest: Option<&str>) -> Event {
    Event {
        event: "peer_down".into(),
        at_ms: 600_000,
        peer: Some("abababab".into()),
        addr: Some("10.0.0.9:7433".into()),
        since_ms: Some(0),
        detail: None,
        up: 1,
        down: 1,
        until_ms: None,
        forest: forest.map(String::from),
    }
}

/// A forest at `<tmp>/<dir>`, its state in `<tmp>/<dir>/.pvfs`.
fn forest(tmp: &std::path::Path, dir: &str) -> std::path::PathBuf {
    let mount = tmp.join(dir);
    let state = pvfs_core::mount::state_dir(&mount);
    let (e, _mn) = Engine::init(&state).unwrap();
    e.close().unwrap();
    state
}

#[test]
fn the_name_is_the_alias_else_the_mount_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let reg = Registry::new(tmp.path().join("registry"));
    let lab = forest(tmp.path(), "lab5-plex");
    assert_eq!(notify::forest_name_in(&reg, &lab).as_deref(), Some("lab5-plex"), "unregistered: the directory");
    reg.register(lab.parent().unwrap(), Some("lab5m")).unwrap();
    assert_eq!(notify::forest_name_in(&reg, &lab).as_deref(), Some("lab5m"), "registered: its alias");
    let other = forest(tmp.path(), "media");
    reg.register(other.parent().unwrap(), None).unwrap();
    assert_eq!(notify::forest_name_in(&reg, &other).as_deref(), Some("media"), "registered without an alias");
}

#[test]
fn every_format_carries_the_forest_and_an_unnamed_event_reads_as_before() {
    let named = down_event(Some("media"));
    let (body, _) = notify::payload(&notify_as("ha"), &named);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["forest"], "media");
    assert_eq!(v["event"], "peer_down");
    assert!(!v["summary"].as_str().unwrap().contains("media"), "the sentence is unchanged");
    let (body, _) = notify::payload(&notify_as("json"), &named);
    assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["forest"], "media");
    for f in ["slack", "discord"] {
        let (body, _) = notify::payload(&notify_as(f), &named);
        assert!(body.contains("\"PVFS media: 10.0.0.9:7433 is down."), "{f}: {body}");
    }
    let (_, headers) = notify::payload(&notify_as("ntfy"), &named);
    assert!(headers.contains(&("Title".to_string(), "PVFS media peer_down".to_string())), "{headers:?}");

    let plain = down_event(None);
    let (body, _) = notify::payload(&notify_as("ha"), &plain);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(v.get("forest").is_none(), "no forest key when unknown: {body}");
    assert_eq!(notify::line(&notify_as("slack"), &plain), "PVFS: 10.0.0.9:7433 is down. It has not answered for 10 minutes. The owner will try to restart it if it supervises that box.");
    let (_, headers) = notify::payload(&notify_as("ntfy"), &plain);
    assert!(headers.contains(&("Title".to_string(), "PVFS peer_down".to_string())), "{headers:?}");
    // an older owner's state or a captured payload without the field still reads
    let back: Event = serde_json::from_str(&serde_json::to_string(&plain).unwrap()).unwrap();
    assert_eq!(back, plain);
}

#[test]
fn emit_names_the_forest_on_what_it_sends() {
    let tmp = tempfile::tempdir().unwrap();
    let capture = tmp.path().join("captured");
    let script = tmp.path().join("fake-curl");
    std::fs::write(&script, format!("#!/bin/sh\ncat >> {c}\necho >> {c}\n", c = capture.display())).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    // The only test in this binary that touches the environment.
    std::env::set_var("PVFS_NOTIFY_CMD", &script);
    std::env::set_var("PVFS_REGISTRY_DIR", tmp.path().join("no-registry"));
    let data = forest(tmp.path(), "lab4-media");
    notify::set(&data, "http://ha:8123/api/webhook/pvfs-fleet", "ha").unwrap();
    let pin = "ab".repeat(32);
    let up = PeerHealth { reachable: true, forest_ok: true, ..Default::default() };
    let gone = PeerHealth { error: Some("refused".into()), ..Default::default() };
    let mut r0 = FleetHealth::default();
    r0.observe(&pin, "10.0.0.9:7433", None, 1_000, up);
    let mut r1 = r0.clone();
    r1.observe(&pin, "10.0.0.9:7433", None, 2_000, gone.clone());
    r1.observe(&pin, "10.0.0.9:7433", None, 3_000, gone);
    let lines = notify::emit(&data, Some(&r0), &r1, 3_000).unwrap();
    assert!(lines.iter().any(|l| l == "peer_down abababab → sent"), "{lines:?}");
    let sent = std::fs::read_to_string(&capture).unwrap();
    let bodies: Vec<serde_json::Value> =
        sent.lines().filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str(l).unwrap()).collect();
    assert!(!bodies.is_empty());
    for b in &bodies {
        assert_eq!(b["forest"], "lab4-media", "every event names its forest: {b}");
    }
}
