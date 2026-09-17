//! D151 — a job's error waits for time, not for records. A restart burst on
//! the owner (every daemon start polls at once, so several records land
//! seconds apart) says nothing; an error that persists is said once, about
//! four minutes after it was first seen; a changed one waits its own time.
use std::path::Path;

use pvfs_client::health::{FleetHealth, JobHealth, PeerHealth};
use pvfs_client::notify::{self, State, JOB_ERROR_AFTER_MS};

const MIN: u64 = 60_000;
/// What feederbox's and mediabox's follow jobs said on 2026-09-13.
const REFUSED: &str = "I/O error during dial 192.168.1.120:7431: Connection refused (os error 111)";

fn pin() -> String {
    "26".repeat(32)
}

fn job(err: Option<&str>) -> PeerHealth {
    PeerHealth {
        reachable: true,
        forest_ok: true,
        jobs: vec![JobHealth { name: "follow".into(), state: "idle".into(), last_ok_ms: None, last_error: err.map(str::to_string) }],
        ..Default::default()
    }
}

fn gone() -> PeerHealth {
    PeerHealth { error: Some("refused".into()), ..Default::default() }
}

/// The record one health pass writes: the peer as polled at `at_ms`.
fn pass(rec: &FleetHealth, at_ms: u64, h: PeerHealth) -> FleetHealth {
    let mut r = rec.clone();
    r.observe(&pin(), "192.168.1.142:7434", None, at_ms, h);
    r
}

/// One pass through `job_errors`: how many events it made.
fn said(st: &mut State, rec: &mut FleetHealth, at_ms: u64, h: PeerHealth) -> usize {
    *rec = pass(rec, at_ms, h);
    notify::job_errors(st, rec, at_ms).len()
}

/// One pass through `emit`, as the health job runs it — the notify state
/// loaded from disk and saved again, exactly as a freshly started daemon's
/// first pass would: nothing carried in memory. How many `job_error`s it sent.
fn emit_pass(data: &Path, prev: &mut FleetHealth, at_ms: u64, h: PeerHealth) -> usize {
    let next = pass(prev, at_ms, h);
    let lines = notify::emit(data, Some(&*prev), &next, at_ms).unwrap();
    assert!(lines.iter().all(|l| l.ends_with("→ sent")), "{lines:?}");
    *prev = next;
    lines.iter().filter(|l| l.starts_with("job_error")).count()
}

#[test]
fn a_restart_burst_says_nothing_and_a_real_error_keeps_its_clock_across_restarts() {
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
    let mut prev = pass(&FleetHealth::default(), 0, job(None));

    // 2026-09-13, 22:17:36–58 UTC: four starts in 21 s, each polling at once,
    // the peer's follow job still holding its refused dial; the regular pass
    // two minutes after the last start finds it redialled and clear. The rule
    // before D151 sent a job_error on the second of these.
    let t = 1_789_000_000_000;
    let mut sent = emit_pass(&data, &mut prev, t, job(None));
    for s in [36, 50, 58, 62] {
        sent += emit_pass(&data, &mut prev, t + s * 1_000, job(Some(REFUSED)));
    }
    sent += emit_pass(&data, &mut prev, t + 182_000, job(None));
    sent += emit_pass(&data, &mut prev, t + 302_000, job(None));
    assert_eq!(sent, 0, "a restart burst is not an error anyone can act on");

    // A REAL error that happens to begin during a burst: the restarts neither
    // reset its clock nor count as the wait. Said on the third regular pass.
    let u = t + 3_600_000;
    for s in [0, 10, 20] {
        assert_eq!(emit_pass(&data, &mut prev, u + s * 1_000, job(Some("disk full"))), 0, "the burst");
    }
    assert_eq!(emit_pass(&data, &mut prev, u + 140_000, job(Some("disk full"))), 0, "140 s is not long enough");
    assert_eq!(emit_pass(&data, &mut prev, u + 260_000, job(Some("disk full"))), 1, "there ~4 min: said");
    assert_eq!(emit_pass(&data, &mut prev, u + 380_000, job(Some("disk full"))), 0, "once");

    let got = std::fs::read_to_string(&capture).unwrap();
    assert_eq!(got.matches("\"event\":\"job_error\"").count(), 1, "{got}");
    assert!(got.contains("the follow job reports an error: disk full"), "{got}");
    assert!(!got.contains("Connection refused"), "{got}");
}

#[test]
fn a_persisting_error_is_said_once_on_the_third_pass_not_the_second() {
    let mut st = State::default();
    let mut rec = FleetHealth::default();
    assert_eq!(said(&mut st, &mut rec, 0, job(Some(REFUSED))), 0, "first sighting");
    assert_eq!(said(&mut st, &mut rec, 2 * MIN, job(Some(REFUSED))), 0, "two minutes: the old rule said it here");
    assert_eq!(said(&mut st, &mut rec, 4 * MIN, job(Some(REFUSED))), 1, "four minutes: said");
    assert_eq!(said(&mut st, &mut rec, 6 * MIN, job(Some(REFUSED))), 0, "said once");
    assert_eq!(said(&mut st, &mut rec, 60 * MIN, job(Some(REFUSED))), 0, "and stays said");

    // The boundary, and a third pass that lands a little under 240 s because
    // `now` is stamped after the probes: it still reports.
    let mut st = State::default();
    let mut rec = FleetHealth::default();
    assert_eq!(said(&mut st, &mut rec, 0, job(Some("boom"))), 0);
    assert_eq!(said(&mut st, &mut rec, JOB_ERROR_AFTER_MS - 1, job(Some("boom"))), 0);
    assert_eq!(said(&mut st, &mut rec, JOB_ERROR_AFTER_MS, job(Some("boom"))), 1);
    let mut st = State::default();
    let mut rec = FleetHealth::default();
    for at in [0, 121_000] {
        assert_eq!(said(&mut st, &mut rec, at, job(Some("boom"))), 0);
    }
    assert_eq!(said(&mut st, &mut rec, 238_000, job(Some("boom"))), 1, "the third pass, a little early");

    assert!(notify::job_errors(&mut State::default(), &rec, 238_000).is_empty(), "a fresh memory starts the clock now");
    let mut st = State::default();
    assert!(notify::job_errors(&mut st, &rec, 0).is_empty());
    let ev = notify::job_errors(&mut st, &rec, 4 * MIN);
    assert_eq!(ev[0].event, "job_error");
    assert_eq!(ev[0].peer.as_deref(), Some("26262626"));
    assert_eq!(ev[0].detail.as_deref(), Some("follow: boom"));
}

#[test]
fn a_changed_error_waits_its_own_time_then_is_said_once() {
    let mut st = State::default();
    let mut rec = FleetHealth::default();
    assert_eq!(said(&mut st, &mut rec, 0, job(Some("first"))), 0);
    assert_eq!(said(&mut st, &mut rec, 4 * MIN, job(Some("first"))), 1);
    assert_eq!(said(&mut st, &mut rec, 6 * MIN, job(Some("second"))), 0, "a new text starts its own clock");
    assert_eq!(said(&mut st, &mut rec, 8 * MIN, job(Some("second"))), 0);
    assert_eq!(said(&mut st, &mut rec, 10 * MIN, job(Some("second"))), 1, "said after its own four minutes");
    assert_eq!(said(&mut st, &mut rec, 12 * MIN, job(Some("second"))), 0, "once");

    // A text that changes before it was ever said: the wait is the new one's.
    let mut st = State::default();
    let mut rec = FleetHealth::default();
    assert_eq!(said(&mut st, &mut rec, 0, job(Some("a"))), 0);
    assert_eq!(said(&mut st, &mut rec, 2 * MIN, job(Some("b"))), 0);
    assert_eq!(said(&mut st, &mut rec, 4 * MIN, job(Some("b"))), 0, "b is two minutes old");
    assert_eq!(said(&mut st, &mut rec, 6 * MIN, job(Some("b"))), 1);
}

/// D161 changed this on purpose: a sent error's memory clears when its clear
/// is said — gone for `JOB_ERROR_AFTER_MS` — not on the first clean pass. So
/// the same text back two minutes later is the same episode (not said again),
/// and only after the clear is it a new one, waited for and said again.
#[test]
fn the_memory_clears_with_the_error_so_the_same_text_is_said_again_later() {
    let mut st = State::default();
    let mut rec = FleetHealth::default();
    said(&mut st, &mut rec, 0, job(Some("boom")));
    assert_eq!(said(&mut st, &mut rec, 4 * MIN, job(Some("boom"))), 1);
    assert_eq!(said(&mut st, &mut rec, 6 * MIN, job(None)), 0);
    assert_eq!(st.reported_job_errors.len(), 1, "kept until the clear is said: {st:?}");
    assert_eq!(said(&mut st, &mut rec, 8 * MIN, job(Some("boom"))), 0, "back inside the wait: one episode");
    assert_eq!(said(&mut st, &mut rec, 12 * MIN, job(Some("boom"))), 0, "and not said twice");
    assert_eq!(said(&mut st, &mut rec, 14 * MIN, job(None)), 0);
    assert_eq!(said(&mut st, &mut rec, 18 * MIN, job(None)), 1, "gone four minutes: the clear");
    assert!(st.reported_job_errors.is_empty() && st.job_errors_seen.is_empty(), "{st:?}");
    assert_eq!(said(&mut st, &mut rec, 20 * MIN, job(Some("boom"))), 0, "back again: a fresh wait");
    assert_eq!(said(&mut st, &mut rec, 24 * MIN, job(Some("boom"))), 1, "and said again");
}

#[test]
fn a_pass_the_peer_did_not_answer_is_not_a_clear() {
    // Already said: a blip does not make it said twice.
    let mut st = State::default();
    let mut rec = FleetHealth::default();
    said(&mut st, &mut rec, 0, job(Some("boom")));
    assert_eq!(said(&mut st, &mut rec, 4 * MIN, job(Some("boom"))), 1);
    assert_eq!(said(&mut st, &mut rec, 6 * MIN, gone()), 0);
    assert_eq!(st.reported_job_errors.len(), 1, "unknown is not cleared: {st:?}");
    assert_eq!(said(&mut st, &mut rec, 8 * MIN, job(Some("boom"))), 0, "not said a second time after a blip");
    assert_eq!(said(&mut st, &mut rec, 12 * MIN, job(Some("boom"))), 0);

    // Not yet said: a blip does not restart the clock.
    let mut st = State::default();
    let mut rec = FleetHealth::default();
    said(&mut st, &mut rec, 0, job(Some("boom")));
    said(&mut st, &mut rec, 2 * MIN, gone());
    assert_eq!(said(&mut st, &mut rec, 4 * MIN, job(Some("boom"))), 1, "first seen at 0, still there");

    // A peer gone from the record entirely takes its memory with it.
    rec.peers.clear();
    assert!(notify::job_errors(&mut st, &rec, 6 * MIN).is_empty());
    assert!(st.reported_job_errors.is_empty() && st.job_errors_seen.is_empty(), "{st:?}");
}

#[test]
fn a_state_file_written_before_d151_still_loads() {
    let old = r#"{"last_heartbeat_ms":1789000000000,"reported_job_errors":{"26262626/follow":"boom"}}"#;
    let mut st: State = serde_json::from_str(old).unwrap();
    assert_eq!(st.last_heartbeat_ms, 1_789_000_000_000, "the heartbeat is not re-sent on upgrade");
    assert_eq!(st.reported_job_errors.len(), 1);
    assert!(st.job_errors_seen.is_empty());
    let mut rec = FleetHealth::default();
    assert_eq!(said(&mut st, &mut rec, 1_789_000_060_000, job(Some("boom"))), 0, "the clock starts on upgrade");
    assert_eq!(said(&mut st, &mut rec, 1_789_000_300_000, job(Some("boom"))), 0, "already said before the upgrade: not again");
}
