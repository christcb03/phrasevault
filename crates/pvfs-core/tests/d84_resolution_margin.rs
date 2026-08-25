//! D84 — a crop is not a resolution.
//!
//! The resolution rung fired on ANY pixel difference, so 1438x1080 beat
//! 1440x1080 — 0.14% — and short-circuited every rung below it. Measured on the
//! live library, 3 of the 13 fully-measured collisions were being decided that
//! way. Chris: "when they are that close it probably doesn't matter that much".
//!
//! The margin has to be loose enough to absorb a crop and far tighter than any
//! real tier: 1080p vs 720p is 55% apart, 1080p vs 1440p is 44%.

use pvfs_core::media::{choose, Candidate, MediaQuality, Rules};

fn cand(label: &str, w: u32, h: u32, size: u64) -> Candidate {
    let q = MediaQuality {
        width: w,
        height: h,
        ..Default::default()
    };
    Candidate {
        label: label.into(),
        quality: q,
        size_bytes: size,
        mtime_ms: 1,
        integrity_ok: true,
    }
}

/// THE TINY TOONS CASE: 2,160 pixels out of 1.55 million must not decide it.
/// With resolution tied the ladder falls through to size, which is Chris's rule.
#[test]
fn a_two_pixel_crop_does_not_decide() {
    let rules = Rules::default();
    // the 1438-wide copy is SMALLER; if resolution decided, it would still win
    let cropped = cand("ep.mkv", 1438, 1080, 497_000_000);
    let full = cand("ep.mkv", 1440, 1080, 776_000_000);

    let (a_wins, verdict) = choose(&cropped, &full, &rules);
    assert!(
        !verdict.reason().contains("resolution"),
        "a 0.14% difference is a crop, not a resolution: {}",
        verdict.reason()
    );
    assert!(!a_wins, "with resolution tied, the larger copy wins");
}

/// …and a REAL tier difference still decides, or the margin has eaten the rung.
#[test]
fn a_real_tier_difference_still_decides() {
    let rules = Rules::default();
    let hd = cand("ep.mkv", 1920, 1080, 100);
    let sd = cand("ep.mkv", 1280, 720, 900_000_000); // far larger, still loses
    let (a_wins, verdict) = choose(&hd, &sd, &rules);
    assert!(
        verdict.reason().contains("resolution"),
        "1080p vs 720p is 55% apart and must decide on resolution: {}",
        verdict.reason()
    );
    assert!(a_wins, "the higher resolution wins regardless of size");
}

/// The margin is a rule, not a constant — tightening it restores the old
/// behaviour, which is what makes it reviewable.
#[test]
fn the_margin_is_tunable() {
    let strict = Rules {
        resolution_margin_pct: 0,
        ..Default::default()
    };
    let cropped = cand("ep.mkv", 1438, 1080, 497_000_000);
    let full = cand("ep.mkv", 1440, 1080, 776_000_000);
    let (_, verdict) = choose(&cropped, &full, &strict);
    assert!(
        verdict.reason().contains("resolution"),
        "at a 0% margin the old exact comparison returns: {}",
        verdict.reason()
    );
}
