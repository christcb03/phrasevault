//! D142 — transitions fire once, a steady fleet says nothing, and the send
//! goes through the command the environment names.
use pvfs_client::health::{FleetHealth, JobHealth, PeerHealth};
use pvfs_client::notify::{self, Notify};
use pvfs_client::supervise::Action;

fn up() -> PeerHealth {
    PeerHealth { reachable: true, forest_ok: true, ..Default::default() }
}
fn gone() -> PeerHealth {
    PeerHealth { error: Some("refused".into()), ..Default::default() }
}
fn pin(c: &str) -> String {
    c.repeat(32)
}

#[test]
fn a_peer_going_down_is_said_once_and_its_return_once() {
    let a = pin("ab");
    let mut r0 = FleetHealth::default();
    r0.observe(&a, "10.0.0.9:7433", None, 1_000, up());
    // one miss: not down yet, nothing to say
    let mut r1 = r0.clone();
    r1.observe(&a, "10.0.0.9:7433", None, 2_000, gone());
    assert!(notify::transitions(Some(&r0), &r1, 2_000).is_empty());
    // second miss: DOWN, said once
    let mut r2 = r1.clone();
    r2.observe(&a, "10.0.0.9:7433", None, 3_000, gone());
    let ev = notify::transitions(Some(&r1), &r2, 3_000);
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].event, "peer_down");
    assert_eq!(ev[0].peer.as_deref(), Some("abababab"));
    assert_eq!(ev[0].down, 1);
    // still down next poll: silence
    let mut r3 = r2.clone();
    r3.observe(&a, "10.0.0.9:7433", None, 4_000, gone());
    assert!(notify::transitions(Some(&r2), &r3, 4_000).is_empty());
    // back: said once, with how long
    let mut r4 = r3.clone();
    r4.observe(&a, "10.0.0.9:7433", None, 122_000, up());
    let ev = notify::transitions(Some(&r3), &r4, 122_000);
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].event, "peer_up");
    assert!(ev[0].detail.as_deref().unwrap_or("").contains("was down 2 min"), "{:?}", ev[0].detail);
    // and then nothing
    let mut r5 = r4.clone();
    r5.observe(&a, "10.0.0.9:7433", None, 123_000, up());
    assert!(notify::transitions(Some(&r4), &r5, 123_000).is_empty());
}

#[test]
fn a_supervise_action_and_a_new_job_error_are_each_said_once() {
    let a = pin("cd");
    let mut r0 = FleetHealth::default();
    r0.observe(&a, "10.0.0.9:7433", None, 1_000, up());
    let mut r1 = r0.clone();
    r1.peers.get_mut(&a).unwrap().actions.push(Action { at_ms: 2_000, verb: "start".into(), rc: 0, output: "started 42".into() });
    let ev = notify::transitions(Some(&r0), &r1, 2_000);
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].event, "supervise");
    assert!(ev[0].detail.as_deref().unwrap().contains("started 42"));
    assert!(notify::transitions(Some(&r1), &r1, 3_000).is_empty(), "the same action is not repeated");

    let mut with_err = up();
    with_err.jobs.push(JobHealth { name: "receive".into(), state: "idle".into(), last_ok_ms: None, last_error: Some("boom".into()) });
    let mut r2 = r1.clone();
    r2.observe(&a, "10.0.0.9:7433", None, 4_000, with_err.clone());
    let ev = notify::transitions(Some(&r1), &r2, 4_000);
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].event, "job_error");
    assert_eq!(ev[0].detail.as_deref(), Some("receive: boom"));
    let mut r3 = r2.clone();
    r3.observe(&a, "10.0.0.9:7433", None, 5_000, with_err);
    assert!(notify::transitions(Some(&r2), &r3, 5_000).is_empty(), "a persisting error is said once");
}

#[test]
fn the_heartbeat_is_daily_and_the_first_poll_reports_only_what_is_already_down() {
    let a = pin("ef");
    let mut r = FleetHealth::default();
    r.observe(&a, "10.0.0.9:7433", None, 1_000, gone());
    r.observe(&a, "10.0.0.9:7433", None, 2_000, gone());
    let ev = notify::transitions(None, &r, 2_000);
    assert_eq!(ev.len(), 1, "first poll, peer already down: one message");
    let mut st = notify::State::default();
    assert!(notify::heartbeat(&mut st, &r, 10_000).is_some());
    assert!(notify::heartbeat(&mut st, &r, 10_000 + notify::HEARTBEAT_EVERY_MS - 1).is_none());
    assert!(notify::heartbeat(&mut st, &r, 10_000 + notify::HEARTBEAT_EVERY_MS).is_some());
}

#[test]
fn payload_shapes_follow_the_format() {
    let ev = notify::test_event(7);
    let ha = Notify { url: "http://ha:8123/api/webhook/pvfs".into(), format: "ha".into() };
    let (body, headers) = notify::payload(&ha, &ev);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["event"], "test");
    assert!(headers.iter().any(|(k, v)| k == "Content-Type" && v == "application/json"));
    let slack = Notify { format: "slack".into(), ..ha.clone() };
    let (body, _) = notify::payload(&slack, &ev);
    assert!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["text"].as_str().unwrap().starts_with("PVFS test"));
    let ntfy = Notify { format: "ntfy".into(), ..ha };
    let (body, headers) = notify::payload(&ntfy, &ev);
    assert!(body.starts_with("PVFS test"));
    assert!(headers.iter().any(|(k, _)| k == "Title"));
}

#[test]
fn send_runs_the_named_command_with_the_url_and_the_body_on_stdin() {
    let tmp = tempfile::tempdir().unwrap();
    let capture = tmp.path().join("captured");
    let script = tmp.path().join("fake-curl");
    std::fs::write(&script, format!("#!/bin/sh\necho \"$@\" > {c}\ncat >> {c}\n", c = capture.display())).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::env::set_var("PVFS_NOTIFY_CMD", &script);
    let data = tmp.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    assert!(notify::load(&data).unwrap().is_none());
    assert!(notify::set(&data, "ftp://nope", "ha").is_err(), "a webhook is http(s)");
    assert!(notify::set(&data, "http://ha:8123/api/webhook/pvfs", "carrier-pigeon").is_err());
    let n = notify::set(&data, "http://ha:8123/api/webhook/pvfs", "ha").unwrap();
    assert_eq!(notify::load(&data).unwrap(), Some(n.clone()));

    let a = pin("aa");
    let mut r0 = FleetHealth::default();
    r0.observe(&a, "10.0.0.9:7433", None, 1_000, up());
    let mut r2 = r0.clone();
    r2.observe(&a, "10.0.0.9:7433", None, 2_000, gone());
    r2.observe(&a, "10.0.0.9:7433", None, 3_000, gone());
    let lines = notify::emit(&data, Some(&r0), &r2, 3_000).unwrap();
    assert_eq!(lines.len(), 2, "peer_down and the first heartbeat: {lines:?}");
    assert!(lines.iter().all(|l| l.ends_with("→ sent")), "{lines:?}");
    let got = std::fs::read_to_string(&capture).unwrap();
    assert!(got.contains("http://ha:8123/api/webhook/pvfs"), "{got}");
    assert!(got.contains("\"event\":\"heartbeat\"") , "the last call was the heartbeat: {got}");
    // nothing changed: nothing sent, the state file remembers the heartbeat
    let lines = notify::emit(&data, Some(&r2), &r2, 4_000).unwrap();
    assert!(lines.is_empty(), "{lines:?}");
    assert!(notify::clear(&data).unwrap());
    assert!(notify::emit(&data, Some(&r0), &r2, 5_000).unwrap().is_empty(), "off means silent");
}
