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

use pvfsd::jobs::{stall_floor, stalled_reason, PASS_STALL_FLOOR};

const EVERY: Duration = Duration::from_secs(300);
const MIN: u64 = 60_000;

/// The production case: 6.4 hours past the last completed pass, on a 5 minute
/// interval, still calling itself `running`. It must be REPORTED — that part
/// was always right and is what D78 exists for.
///
/// D100 changed what it is reported AS. This check knows exactly one thing:
/// no pass has completed lately. It cannot see whether the job is working,
/// because nothing reports progress within a pass — so it used to turn one
/// observation into the diagnosis "the pass is stuck, not working", and that
/// diagnosis was wrong all three times it fired on the live holder, against a
/// `watch` steadily writing sidecars and a `tier` steadily fetching.
///
/// `overdue` is what this evidence supports. `stalled` is reserved for
/// `pass_stalled_reason`, which HAS evidence: a pass in flight far past this
/// job's own measured typical duration.
#[test]
fn a_job_past_its_interval_is_reported_overdue() {
    let now = 100 * 60 * MIN;
    let since = now - (384 * MIN); // 6.4 h
    let why =
        stalled_reason("running", since, now, EVERY, PASS_STALL_FLOOR).expect("must be reported");
    assert!(why.contains("384 min"), "says how long: {why}");
    assert!(
        why.contains("overdue"),
        "and names it as overdue, not diagnosed as stuck: {why}"
    );
    assert!(
        !why.contains("stuck, not working"),
        "must NOT claim a diagnosis it has no evidence for: {why}"
    );
}

/// A pass that is merely SLOW is not stalled. The lab's real tier pass took 41
/// minutes legitimately; calling that a stall would train everyone to ignore
/// the signal.
#[test]
fn a_slow_pass_within_tolerance_is_not_stalled() {
    let now = 100 * MIN;
    assert!(
        stalled_reason("running", now - (10 * MIN), now, EVERY, PASS_STALL_FLOOR).is_none(),
        "10 min on a 5 min interval is slow, not stuck (tolerance is 3x)"
    );
    assert!(
        stalled_reason("running", now - (14 * MIN), now, EVERY, PASS_STALL_FLOOR).is_none(),
        "just inside 3x must still pass"
    );
    assert!(
        stalled_reason("running", now - (16 * MIN), now, EVERY, PASS_STALL_FLOOR).is_some(),
        "past 3x is stalled"
    );
}

/// Only a RUNNING job can stall. An idle or disabled one is not stuck, it is
/// simply not going.
#[test]
fn only_a_running_job_can_stall() {
    let now = 1000 * MIN;
    let ancient = 0;
    for state in ["idle", "disabled", "backoff", "stalled", "overdue"] {
        assert!(
            stalled_reason(state, ancient, now, EVERY, PASS_STALL_FLOOR).is_none(),
            "{state} must not be reported as stalled"
        );
    }
    assert!(
        stalled_reason("running", ancient, now, EVERY, PASS_STALL_FLOOR).is_some(),
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
        stalled_reason("running", started, now, EVERY, PASS_STALL_FLOOR).is_some(),
        "never having finished is not an excuse for never reporting"
    );
}

// ---------------------------------------------------------------------------
// D81 — the sharp signal: a pass IN FLIGHT, judged against this job's own
// typical pass duration rather than against an interval nobody chose.
// ---------------------------------------------------------------------------

use pvfsd::jobs::pass_stalled_reason;

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

/// D96 — a job whose real passes take HOURS must not be called stalled at
/// three times its poll interval.
///
/// `tier` polls every 300s and moves hundreds of GB across a WAN; `watch` polls
/// hourly and now hashes whatever it finds unhashed. D85 wrote `stall_floor`
/// for exactly this and wired it into the in-flight check — but execution falls
/// through to THIS one, which was still judging by interval * 3. On the live
/// holder that reported tier stalled at 34 min and watch at 464 min, both while
/// working perfectly. A detector that cries wolf on healthy work is worse than
/// no detector, because it is the one people learn to ignore.
#[test]
fn a_long_running_job_is_judged_by_its_own_floor() {
    let now = 1000 * MIN;
    let tier_every = Duration::from_secs(300);

    // 34 minutes: what the holder actually reported, and it must NOT be stalled
    assert!(
        stalled_reason("running", now - (34 * MIN), now, tier_every, stall_floor("tier")).is_none(),
        "tier at 34 min is working, not stuck — its floor is 6h"
    );
    // 464 minutes on watch: the other false alarm from the same night
    assert!(
        stalled_reason(
            "running",
            now - (464 * MIN),
            now,
            Duration::from_secs(3600),
            stall_floor("watch")
        )
        .is_none(),
        "watch at 464 min is working — its floor is 36h"
    );
    // but genuinely past its own floor, it still reports
    assert!(
        stalled_reason("running", now - (7 * 60 * MIN), now, tier_every, stall_floor("tier"))
            .is_some(),
        "past 6h, tier really is stuck and must still say so"
    );
    // a job with no special floor keeps the old tolerance
    assert!(
        stalled_reason("running", now - (16 * MIN), now, EVERY, stall_floor("sync")).is_some(),
        "an ordinary job is still judged at 3x its interval"
    );
}
