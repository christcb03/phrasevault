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

// ---------------------------------------------------------------------------
// D81 — the sharp signal: a pass IN FLIGHT, judged against this job's own
// typical pass duration rather than against an interval nobody chose.
// ---------------------------------------------------------------------------

use pvfsd::jobs::{pass_stalled_reason, PASS_STALL_FLOOR};

/// A pass running far longer than this job's passes normally take is stuck.
#[test]
fn a_pass_running_far_past_its_own_typical_duration_is_stalled() {
    let now = 10_000_000u64;
    let typical = 20_000u64; // 20s passes
    // Well inside the floor: not stalled, however long "typical" is.
    assert!(
        pass_stalled_reason(now - 60_000, now, Some(typical), PASS_STALL_FLOOR).is_none(),
        "a minute is nothing when the floor is five"
    );
    let why = pass_stalled_reason(now - 400_000, now, Some(typical), PASS_STALL_FLOOR)
        .expect("6+ minutes on a 20-second pass is stuck");
    assert!(why.contains("20s"), "it must say what normal looks like: {why}");
    assert!(why.contains("stuck"), "{why}");
}

/// A slow library is not a stalled one — the threshold scales with the job.
#[test]
fn a_job_whose_passes_are_slow_is_judged_against_itself() {
    let now = 10_000_000u64;
    let typical = 600_000u64; // 10-minute passes: a big library
    assert!(
        pass_stalled_reason(now - 1_500_000, now, Some(typical), PASS_STALL_FLOOR).is_none(),
        "25 minutes into a pass that normally takes 10 is not yet stuck; a \
         fixed threshold would have cried wolf on every large forest"
    );
    assert!(
        pass_stalled_reason(now - 2_000_000, now, Some(typical), PASS_STALL_FLOOR).is_some(),
        "but 33 minutes is"
    );
}

/// A first pass that never finishes is exactly the case with no baseline.
#[test]
fn a_first_pass_that_never_completes_is_caught_without_a_baseline() {
    let now = 10_000_000u64;
    assert!(
        pass_stalled_reason(now - 60_000, now, None, PASS_STALL_FLOOR).is_none(),
        "still inside the floor"
    );
    let why = pass_stalled_reason(now - 400_000, now, None, PASS_STALL_FLOOR)
        .expect("past the floor with nothing ever completed");
    assert!(
        why.contains("never completed"),
        "and it must say so plainly, because this is the first-run hang: {why}"
    );
}

/// A watcher with NO pass in flight is quiet, not stuck — the distinction the
/// whole change exists to draw.
#[test]
fn quiet_is_not_stuck() {
    // The caller only consults this when a pass is in flight; the property is
    // that an idle watcher never reaches it. Pinned here as documentation of
    // the contract, since getting this backwards is what produced a 3-HOUR
    // alarm on a job whose real passes take seconds.
    let now = 10_000_000u64;
    assert!(
        pass_stalled_reason(now, now, Some(20_000), PASS_STALL_FLOOR).is_none(),
        "a pass that just started is not stalled"
    );
}
