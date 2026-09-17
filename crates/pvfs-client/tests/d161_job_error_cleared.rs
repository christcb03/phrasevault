//! D161 — an alert that reached the phone says when it has cleared. A sent
//! job error that goes away is said cleared once it has been gone for
//! `JOB_ERROR_AFTER_MS` (the same wait an error has before it is said); back
//! before that it is one episode; an error never sent is never cleared.
use pvfs_client::health::{FleetHealth, JobHealth, PeerHealth};
use pvfs_client::notify::{self, Event, Notify, State};

const MIN: u64 = 60_000;
/// What the NAS's receive job said on 2026-09-16, twice.
const FULL: &str = "database error during view conflicts: database or disk is full";

fn pin() -> String {
    "93".repeat(32)
}

fn receive(err: Option<&str>) -> PeerHealth {
    PeerHealth {
        reachable: true,
        forest_ok: true,
        jobs: vec![JobHealth { name: "receive".into(), state: "idle".into(), last_ok_ms: None, last_error: err.map(str::to_string) }],
        ..Default::default()
    }
}

fn unanswered() -> PeerHealth {
    PeerHealth { error: Some("refused".into()), ..Default::default() }
}

/// One health pass: the peer as polled at `at_ms`, then `job_errors`.
fn pass(st: &mut State, rec: &mut FleetHealth, at_ms: u64, h: PeerHealth) -> Vec<Event> {
    rec.observe(&pin(), "192.168.1.237:7433", None, at_ms, h);
    notify::job_errors(st, rec, at_ms)
}

fn kinds(ev: &[Event]) -> Vec<&str> {
    ev.iter().map(|e| e.event.as_str()).collect()
}

fn nas() -> Notify {
    let mut n = Notify { url: "http://ha:8123/api/webhook/pvfs-fleet".into(), format: "ha".into(), labels: Default::default() };
    n.labels.insert("192.168.1.237".into(), "the NAS".into());
    n
}

#[test]
fn a_sent_error_that_goes_away_is_said_cleared_once_after_the_wait() {
    let (mut st, mut rec) = (State::default(), FleetHealth::default());
    let t = 1_789_570_000_000;
    assert!(pass(&mut st, &mut rec, t, receive(Some(FULL))).is_empty());
    assert_eq!(kinds(&pass(&mut st, &mut rec, t + 4 * MIN, receive(Some(FULL)))), ["job_error"]);
    assert!(pass(&mut st, &mut rec, t + 6 * MIN, receive(Some(FULL))).is_empty());

    // Gone at 8 min: not yet; still gone at 10 min (two minutes): not yet.
    assert!(pass(&mut st, &mut rec, t + 8 * MIN, receive(None)).is_empty(), "one clean pass is not a clear");
    assert!(pass(&mut st, &mut rec, t + 10 * MIN, receive(None)).is_empty(), "two minutes is not long enough");
    let ev = pass(&mut st, &mut rec, t + 12 * MIN, receive(None));
    assert_eq!(kinds(&ev), ["job_error_cleared"], "gone four minutes: said");
    let e = &ev[0];
    assert_eq!(e.peer.as_deref(), Some("93939393"));
    assert_eq!(e.detail.as_deref(), Some(&*format!("receive: {FULL}")));
    assert_eq!(e.since_ms, Some(t), "the episode began at the first sighting");
    assert_eq!(e.until_ms, Some(t + 8 * MIN), "and ended at the first pass without it");
    assert_eq!(notify::severity(e), "info");
    assert_eq!(
        notify::summary(&nas(), e),
        format!("On the NAS, the receive job's error has cleared, after 8 minutes. It had reported: {FULL}")
    );
    assert_eq!(st, State::default(), "every memory of the episode is gone");

    // Said once; the same text later is a new episode: waited for, sent, cleared.
    assert!(pass(&mut st, &mut rec, t + 14 * MIN, receive(None)).is_empty());
    assert!(pass(&mut st, &mut rec, t + 60 * MIN, receive(Some(FULL))).is_empty(), "a fresh wait");
    assert_eq!(kinds(&pass(&mut st, &mut rec, t + 64 * MIN, receive(Some(FULL)))), ["job_error"]);
    assert!(pass(&mut st, &mut rec, t + 66 * MIN, receive(None)).is_empty());
    assert_eq!(kinds(&pass(&mut st, &mut rec, t + 70 * MIN, receive(None))), ["job_error_cleared"]);
}

#[test]
fn an_error_that_goes_away_before_it_was_sent_is_never_cleared() {
    let (mut st, mut rec) = (State::default(), FleetHealth::default());
    assert!(pass(&mut st, &mut rec, 0, receive(Some(FULL))).is_empty());
    assert!(pass(&mut st, &mut rec, 2 * MIN, receive(Some(FULL))).is_empty());
    for at in [4, 6, 8, 20] {
        assert!(pass(&mut st, &mut rec, at * MIN, receive(None)).is_empty(), "at {at} min");
    }
    assert_eq!(st, State::default());
}

#[test]
fn a_flap_inside_the_wait_is_one_episode() {
    let (mut st, mut rec) = (State::default(), FleetHealth::default());
    pass(&mut st, &mut rec, 0, receive(Some(FULL)));
    assert_eq!(kinds(&pass(&mut st, &mut rec, 4 * MIN, receive(Some(FULL)))), ["job_error"]);
    assert!(pass(&mut st, &mut rec, 6 * MIN, receive(None)).is_empty());
    assert!(pass(&mut st, &mut rec, 8 * MIN, receive(Some(FULL))).is_empty(), "back inside the wait: not said again");
    assert!(pass(&mut st, &mut rec, 12 * MIN, receive(Some(FULL))).is_empty(), "and not later either");
    // The gone clock restarted: 14 → 16 is not enough, 14 → 18 is.
    assert!(pass(&mut st, &mut rec, 14 * MIN, receive(None)).is_empty());
    assert!(pass(&mut st, &mut rec, 16 * MIN, receive(None)).is_empty());
    let ev = pass(&mut st, &mut rec, 18 * MIN, receive(None));
    assert_eq!(kinds(&ev), ["job_error_cleared"]);
    assert_eq!((ev[0].since_ms, ev[0].until_ms), (Some(0), Some(14 * MIN)), "one episode, 0 to 14 min");
}

#[test]
fn a_changed_text_then_a_clear_names_the_last_text_and_the_first_sighting() {
    let (mut st, mut rec) = (State::default(), FleetHealth::default());
    pass(&mut st, &mut rec, 0, receive(Some("first")));
    assert_eq!(kinds(&pass(&mut st, &mut rec, 4 * MIN, receive(Some("first")))), ["job_error"]);
    assert!(pass(&mut st, &mut rec, 6 * MIN, receive(Some("second"))).is_empty());
    assert_eq!(kinds(&pass(&mut st, &mut rec, 10 * MIN, receive(Some("second")))), ["job_error"]);
    assert!(pass(&mut st, &mut rec, 12 * MIN, receive(None)).is_empty());
    let ev = pass(&mut st, &mut rec, 16 * MIN, receive(None));
    assert_eq!(kinds(&ev), ["job_error_cleared"]);
    assert_eq!(ev[0].detail.as_deref(), Some("receive: second"));
    assert_eq!(ev[0].since_ms, Some(0), "the episode began with the first text");
}

#[test]
fn an_unanswered_pass_is_neither_a_clear_nor_a_reason_to_hold_one_back() {
    let (mut st, mut rec) = (State::default(), FleetHealth::default());
    pass(&mut st, &mut rec, 0, receive(Some(FULL)));
    assert_eq!(kinds(&pass(&mut st, &mut rec, 4 * MIN, receive(Some(FULL)))), ["job_error"]);
    for at in [6, 8, 10, 12] {
        assert!(pass(&mut st, &mut rec, at * MIN, unanswered()).is_empty(), "unknown at {at} min is not clear");
    }
    assert_eq!(st.reported_job_errors.len(), 1, "{st:?}");
    assert!(pass(&mut st, &mut rec, 14 * MIN, receive(None)).is_empty(), "answered clean: the wait starts now");
    assert!(pass(&mut st, &mut rec, 16 * MIN, receive(None)).is_empty());
    assert_eq!(kinds(&pass(&mut st, &mut rec, 18 * MIN, receive(None))), ["job_error_cleared"]);

    // Gone, then unanswered past the wait, then answered clean: said at once.
    let (mut st, mut rec) = (State::default(), FleetHealth::default());
    pass(&mut st, &mut rec, 0, receive(Some(FULL)));
    pass(&mut st, &mut rec, 4 * MIN, receive(Some(FULL)));
    assert!(pass(&mut st, &mut rec, 6 * MIN, receive(None)).is_empty());
    assert!(pass(&mut st, &mut rec, 8 * MIN, unanswered()).is_empty());
    assert!(pass(&mut st, &mut rec, 10 * MIN, unanswered()).is_empty());
    assert_eq!(kinds(&pass(&mut st, &mut rec, 12 * MIN, receive(None))), ["job_error_cleared"]);
}

#[test]
fn a_job_that_stops_being_listed_or_only_shows_the_overdue_notice_is_clear() {
    let (mut st, mut rec) = (State::default(), FleetHealth::default());
    pass(&mut st, &mut rec, 0, receive(Some(FULL)));
    pass(&mut st, &mut rec, 4 * MIN, receive(Some(FULL)));
    let overdue = receive(Some("overdue: no pass for 20 min — not the same as stuck"));
    assert!(pass(&mut st, &mut rec, 6 * MIN, overdue.clone()).is_empty());
    assert_eq!(kinds(&pass(&mut st, &mut rec, 10 * MIN, overdue)), ["job_error_cleared"]);

    let (mut st, mut rec) = (State::default(), FleetHealth::default());
    pass(&mut st, &mut rec, 0, receive(Some(FULL)));
    pass(&mut st, &mut rec, 4 * MIN, receive(Some(FULL)));
    let no_jobs = PeerHealth { reachable: true, forest_ok: true, ..Default::default() };
    assert!(pass(&mut st, &mut rec, 6 * MIN, no_jobs.clone()).is_empty());
    assert_eq!(kinds(&pass(&mut st, &mut rec, 10 * MIN, no_jobs)), ["job_error_cleared"]);
}

#[test]
fn a_state_file_from_before_d161_loads_and_its_sent_error_still_clears() {
    let old = r#"{"last_heartbeat_ms":1789578776101,"reported_job_errors":{"93939393/receive":"boom"},"job_errors_seen":{"93939393/receive":{"error":"boom","first_seen_ms":1789570000000}}}"#;
    let mut st: State = serde_json::from_str(old).unwrap();
    assert!(st.reported_since_ms.is_empty() && st.job_errors_gone.is_empty());
    let mut rec = FleetHealth::default();
    let t = 1_789_580_000_000;
    assert!(pass(&mut st, &mut rec, t, receive(Some("boom"))).is_empty(), "already sent before the upgrade: not again");
    assert!(pass(&mut st, &mut rec, t + 2 * MIN, receive(None)).is_empty());
    let ev = pass(&mut st, &mut rec, t + 6 * MIN, receive(None));
    assert_eq!(kinds(&ev), ["job_error_cleared"]);
    assert_eq!(ev[0].since_ms, None, "the old file never recorded when it began");
    assert_eq!(notify::summary(&nas(), &ev[0]), "On the NAS, the receive job's error has cleared. It had reported: boom");
    // And a new file round-trips.
    let back: State = serde_json::from_str(&serde_json::to_string(&st).unwrap()).unwrap();
    assert_eq!(back, st);
}

#[test]
fn the_payload_carries_the_clear_and_every_other_event_is_unchanged() {
    let ev = Event {
        event: "job_error_cleared".into(),
        at_ms: 20 * MIN,
        peer: Some("93939393".into()),
        addr: Some("192.168.1.237:7433".into()),
        since_ms: Some(0),
        detail: Some(format!("receive: {FULL}")),
        up: 3,
        down: 0,
        until_ms: Some(12 * MIN),
    };
    let (body, _) = notify::payload(&nas(), &ev);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["event"], "job_error_cleared");
    assert_eq!(v["severity"], "info");
    assert_eq!(v["name"], "the NAS");
    assert_eq!(v["until_ms"], 12 * MIN);
    assert!(v["summary"].as_str().unwrap().starts_with("On the NAS, the receive job's error has cleared, after 12 minutes."));

    let (body, _) = notify::payload(&nas(), &notify::test_event(1));
    assert!(!body.contains("until_ms"), "absent from other events: {body}");
}

#[test]
fn emit_posts_the_clear_once() {
    let tmp = tempfile::tempdir().unwrap();
    let capture = tmp.path().join("captured");
    let script = tmp.path().join("fake-curl");
    std::fs::write(&script, format!("#!/bin/sh\ncat >> {c}\necho >> {c}\n", c = capture.display())).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::env::set_var("PVFS_NOTIFY_CMD", &script);
    let data = tmp.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    notify::set(&data, "http://ha:8123/api/webhook/pvfs-fleet", "ha").unwrap();

    let t = 1_789_570_000_000;
    let mut prev = FleetHealth::default();
    prev.observe(&pin(), "192.168.1.237:7433", None, t, receive(None));
    let mut lines = Vec::new();
    for (m, err) in [(0, Some(FULL)), (2, Some(FULL)), (4, Some(FULL)), (6, None), (8, None), (10, None), (12, None), (14, None)] {
        let mut next = prev.clone();
        next.observe(&pin(), "192.168.1.237:7433", None, t + m * MIN + 1, receive(err));
        lines.extend(notify::emit(&data, Some(&prev), &next, t + m * MIN + 1).unwrap());
        prev = next;
    }
    let lines: Vec<&String> = lines.iter().filter(|l| !l.starts_with("heartbeat")).collect();
    assert_eq!(lines, ["job_error 93939393 → sent", "job_error_cleared 93939393 → sent"], "{lines:?}");
    let got = std::fs::read_to_string(&capture).unwrap();
    assert_eq!(got.matches("\"event\":\"job_error_cleared\"").count(), 1, "{got}");
    assert!(got.contains("the receive job's error has cleared, after 6 minutes"), "{got}");
}
