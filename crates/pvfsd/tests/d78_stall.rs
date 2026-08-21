//! D78 — a job that cannot finish must say so.
//!
//! Twice this milestone a serve job sat in state `running` with no error while
//! doing nothing: production feederbox for 6.4 HOURS, a lab ingest for 40+
//! minutes. Both times connectivity, bindings and the peer were healthy. The
//! cause was a socket read with no timeout (fixed separately) — but what let it
//! go unnoticed for hours was the REPORTING, and the next cause will differ.
//!
//! A stall detector that is itself never exercised would be the same failure
//! one level up, so these run it.

use std::time::Duration;

use pvfsd::jobs::stalled_reason;

const EVERY: Duration = Duration::from_secs(300);
const MIN: u64 = 60_000;

/// The production case: 6.4 hours past the last completed pass, on a 5 minute
/// interval, still calling itself `running`.
#[test]
fn a_job_stuck_for_hours_is_reported_stalled() {
    let now = 100 * 60 * MIN;
    let since = now - (384 * MIN); // 6.4 h
    let why = stalled_reason("running", since, now, EVERY).expect("must be stalled");
    assert!(why.contains("384 min"), "says how long: {why}");
    assert!(
        why.contains("stuck, not working"),
        "and says plainly what that means: {why}"
    );
}

/// A pass that is merely SLOW is not stalled. The lab's real tier pass took 41
/// minutes legitimately; calling that a stall would train everyone to ignore
/// the signal.
#[test]
fn a_slow_pass_within_tolerance_is_not_stalled() {
    let now = 100 * MIN;
    assert!(
        stalled_reason("running", now - (10 * MIN), now, EVERY).is_none(),
        "10 min on a 5 min interval is slow, not stuck (tolerance is 3x)"
    );
    assert!(
        stalled_reason("running", now - (14 * MIN), now, EVERY).is_none(),
        "just inside 3x must still pass"
    );
    assert!(
        stalled_reason("running", now - (16 * MIN), now, EVERY).is_some(),
        "past 3x is stalled"
    );
}

/// Only a RUNNING job can stall. An idle or disabled one is not stuck, it is
/// simply not going.
#[test]
fn only_a_running_job_can_stall() {
    let now = 1000 * MIN;
    let ancient = 0;
    for state in ["idle", "disabled", "backoff", "stalled"] {
        assert!(
            stalled_reason(state, ancient, now, EVERY).is_none(),
            "{state} must not be reported as stalled"
        );
    }
    assert!(
        stalled_reason("running", ancient, now, EVERY).is_some(),
        "but running certainly can be"
    );
}

/// A job that has NEVER completed a pass is the first-run hang — the caller
/// passes the runner's start time, and it must still trip.
#[test]
fn a_job_that_never_completed_a_pass_still_trips() {
    let started = 0;
    let now = 60 * MIN;
    assert!(
        stalled_reason("running", started, now, EVERY).is_some(),
        "never having finished is not an excuse for never reporting"
    );
}
