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
    let mut st = notify::State::default();
    let mut r2 = r1.clone();
    r2.observe(&a, "10.0.0.9:7433", None, 4_000, with_err.clone());
    assert!(notify::job_errors(&mut st, Some(&r1), &r2, 4_000).is_empty(), "first sighting: a restart's transient, wait");
    let mut r3 = r2.clone();
    r3.observe(&a, "10.0.0.9:7433", None, 5_000, with_err.clone());
    let ev = notify::job_errors(&mut st, Some(&r2), &r3, 5_000);
    assert_eq!(ev.len(), 1, "the second consecutive poll with the same error says it");
    assert_eq!(ev[0].event, "job_error");
    assert_eq!(ev[0].detail.as_deref(), Some("receive: boom"));
    let mut r4 = r3.clone();
    r4.observe(&a, "10.0.0.9:7433", None, 6_000, with_err);
    assert!(notify::job_errors(&mut st, Some(&r3), &r4, 6_000).is_empty(), "a persisting error is said once");
    let mut r5 = r4.clone();
    r5.observe(&a, "10.0.0.9:7433", None, 7_000, up());
    assert!(notify::job_errors(&mut st, Some(&r4), &r5, 7_000).is_empty());
    assert!(st.reported_job_errors.is_empty(), "cleared with the error, so it can be said again later");
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
fn every_event_reads_as_a_sentence_that_names_the_box() {
    use std::collections::BTreeMap;
    let mut labels = BTreeMap::new();
    labels.insert("10.0.0.9".to_string(), "the NAS".to_string());
    let n = Notify { url: "http://ha:8123/api/webhook/pvfs".into(), format: "ha".into(), labels };
    let a = pin("ab");
    let mut r0 = FleetHealth::default();
    r0.observe(&a, "10.0.0.9:7433", None, 1_000, up());
    let mut r2 = r0.clone();
    r2.observe(&a, "10.0.0.9:7433", None, 2_000, gone());
    r2.observe(&a, "10.0.0.9:7433", None, 302_000, gone());
    let down = &notify::transitions(Some(&r0), &r2, 302_000)[0];
    let text = notify::summary(&n, down);
    assert!(text.starts_with("the NAS is down."), "{text}");
    assert!(text.contains("5 minutes"), "{text}");
    assert_eq!(notify::severity(down), "critical");
    let mut r3 = r2.clone();
    r3.peers.get_mut(&a).unwrap().actions.push(Action { at_ms: 303_000, verb: "start".into(), rc: 0, output: "started 42".into() });
    let sup = &notify::transitions(Some(&r2), &r3, 303_000)[0];
    assert_eq!(notify::summary(&n, sup), "The owner restarted PVFS on the NAS (started 42).");
    assert_eq!(notify::severity(sup), "info", "a restart that worked is news, not a task");
    let mut st = notify::State::default();
    let hb = notify::heartbeat(&mut st, &r4, 1_789_000_000_000).unwrap();
    assert_eq!(notify::summary(&n, &hb), "All good: 1 boxes up, nothing to do.");
    assert_eq!(notify::severity(&hb), "info");
    // an "overdue" notice from the stall detector is not an error anyone can act on
    let mut overdue = up();
    overdue.jobs.push(JobHealth { name: "follow".into(), state: "overdue".into(), last_ok_ms: None, last_error: Some("no pass has completed in 34 min (interval is 300s) — overdue, which is not the same as stuck".into()) });
    let mut o1 = r4.clone();
    o1.observe(&a, "10.0.0.9:7433", None, 401_000, overdue.clone());
    let mut o2 = o1.clone();
    o2.observe(&a, "10.0.0.9:7433", None, 402_000, overdue);
    assert!(notify::job_errors(&mut st, Some(&o1), &o2, 402_000).is_empty(), "overdue is filtered");
    let mut r4 = r3.clone();
    r4.observe(&a, "10.0.0.9:7433", None, 400_000, up());
    let back = &notify::transitions(Some(&r3), &r4, 400_000)[0];
    assert_eq!(notify::summary(&n, back), "the NAS is back after 6 minutes down.");
    // unnamed boxes read by address
    let bare = Notify { labels: Default::default(), ..n.clone() };
    assert!(notify::summary(&bare, back).starts_with("10.0.0.9:7433 is back"));
    assert_eq!(notify::summary(&n, &notify::test_event(1)), "PVFS can reach this webhook — notifications are working.");
    // and the JSON carries it
    let (body, _) = notify::payload(&n, back);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["name"], "the NAS");
    assert_eq!(v["severity"], "info");
    assert!(v["summary"].as_str().unwrap().contains("is back"));
}

#[test]
fn payload_shapes_follow_the_format() {
    let ev = notify::test_event(7);
    let ha = Notify { url: "http://ha:8123/api/webhook/pvfs".into(), format: "ha".into(), labels: Default::default() };
    let (body, headers) = notify::payload(&ha, &ev);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["event"], "test");
    assert!(headers.iter().any(|(k, v)| k == "Content-Type" && v == "application/json"));
    let slack = Notify { format: "slack".into(), ..ha.clone() };
    let (body, _) = notify::payload(&slack, &ev);
    assert!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["text"].as_str().unwrap().starts_with("PVFS: PVFS can reach"));
    let ntfy = Notify { format: "ntfy".into(), ..ha };
    let (body, headers) = notify::payload(&ntfy, &ev);
    assert!(body.starts_with("PVFS can reach"));
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
    let n = notify::label(&data, &[("10.0.0.9".to_string(), "the NAS".to_string())]).unwrap();
    assert_eq!(n.name_for("10.0.0.9:7433"), "the NAS");
    assert_eq!(notify::set(&data, &n.url, "ha").unwrap().labels.len(), 1, "re-setting the URL keeps the names");

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
