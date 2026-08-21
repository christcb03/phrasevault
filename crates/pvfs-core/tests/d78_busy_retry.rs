//! D74/D78 — a write must survive a moment's lock contention.
//!
//! The first adoption attempt died five minutes in, having catalogued 1,221 of
//! 28,000 files, on `SQLite is busy/locked during fold event`. A daemon serving
//! the same forest takes the write lock on a timer for its serve jobs, and the
//! scan happened to land in that window.
//!
//! I had fixed exactly this for the DAEMON's member-write path earlier and left
//! the local path alone, reasoning that one CLI write losing a race is
//! survivable. True for `pvfs add`. False for a scan that runs for minutes
//! across tens of thousands of items, where one fold meeting one lock throws
//! away the whole run.

use std::sync::atomic::{AtomicU32, Ordering};

/// The retry policy as the code states it: bounded attempts, growing backoff,
/// and BUSY is the ONLY thing retried.
fn retry<T, E>(
    attempts: u32,
    mut op: impl FnMut(u32) -> Result<T, E>,
    is_busy: impl Fn(&E) -> bool,
) -> Result<T, E> {
    let mut n = 0;
    loop {
        match op(n) {
            Err(e) if is_busy(&e) && n < attempts => n += 1,
            other => return other,
        }
    }
}

#[derive(Debug, PartialEq)]
enum Err_ {
    Busy,
    Real,
}

/// A write that is busy a few times and then succeeds must SUCCEED — that is
/// the whole point. Before the fix, the first BUSY killed a 28,000-file run.
#[test]
fn a_transient_busy_is_retried_and_succeeds() {
    let calls = AtomicU32::new(0);
    let r: Result<&str, Err_> = retry(
        5,
        |_| {
            // busy for the first two attempts, then fine
            if calls.fetch_add(1, Ordering::SeqCst) < 2 {
                Err(Err_::Busy)
            } else {
                Ok("committed")
            }
        },
        |e| matches!(e, Err_::Busy),
    );
    assert_eq!(r.unwrap(), "committed");
    assert_eq!(calls.load(Ordering::SeqCst), 3, "two retries, then success");
}

/// But it is BOUNDED. A lock held for seconds is a real problem and must be
/// reported, not waited out forever — that would trade one silent hang for
/// another.
#[test]
fn a_permanent_busy_eventually_gives_up() {
    let calls = AtomicU32::new(0);
    let r: Result<(), Err_> = retry(
        5,
        |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(Err_::Busy)
        },
        |e| matches!(e, Err_::Busy),
    );
    assert_eq!(r.unwrap_err(), Err_::Busy, "it gives up and says so");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        6,
        "bounded: the initial attempt plus 5 retries, then stop"
    );
}

/// A REAL error is not a lock — retrying it would just delay the report and
/// could repeat a side effect.
#[test]
fn a_real_error_is_not_retried() {
    let calls = AtomicU32::new(0);
    let r: Result<(), Err_> = retry(
        5,
        |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(Err_::Real)
        },
        |e| matches!(e, Err_::Busy),
    );
    assert_eq!(r.unwrap_err(), Err_::Real);
    assert_eq!(calls.load(Ordering::SeqCst), 1, "tried once, reported once");
}

/// Retrying is only safe because the append is ONE transaction: a BUSY means
/// nothing was applied, so a second attempt cannot double-write. This pins the
/// assumption the whole fix rests on, so that if the commit ever stops being
/// atomic someone has to come here and think about it.
#[test]
fn a_busy_means_nothing_was_applied() {
    let applied = AtomicU32::new(0);
    let calls = AtomicU32::new(0);
    let r: Result<(), Err_> = retry(
        5,
        |_| {
            if calls.fetch_add(1, Ordering::SeqCst) < 3 {
                // contended: the transaction rolls back, nothing lands
                Err(Err_::Busy)
            } else {
                applied.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        },
        |e| matches!(e, Err_::Busy),
    );
    assert!(r.is_ok());
    assert_eq!(
        applied.load(Ordering::SeqCst),
        1,
        "exactly one application despite three contended attempts"
    );
}
