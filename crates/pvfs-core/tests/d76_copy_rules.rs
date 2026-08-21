//! D76 — which copy survives.
//!
//! These pin the ORDERING, not the plumbing. A wrong ordering here deletes the
//! better copy of someone's media, so each rule is tested for what it decides
//! AND for what it refuses to decide.

use pvfs_core::media::{choose, choose_non_media, Candidate, MediaQuality, Rules, Verdict};

fn q(w: u32, h: u32, depth: u8, hdr: &str, dur: u64) -> MediaQuality {
    MediaQuality {
        width: w,
        height: h,
        bit_depth: depth,
        hdr: hdr.into(),
        bitrate: 0,
        video_codec: "x264".into(),
        duration_s: dur,
        decoded_ok: None,
    }
}

fn cand(label: &str, quality: MediaQuality, size: u64, mtime: u64) -> Candidate {
    Candidate {
        label: label.into(),
        quality,
        size_bytes: size,
        mtime_ms: mtime,
        integrity_ok: true,
    }
}

/// RULE 1 — and specifically that it compares PIXELS, not labels.
///
/// Sonarr calls 1440x1080 and 1920x1080 both "1080p". They are not the same
/// picture, and a rule that matched on the label would call this a tie and
/// fall through to size — where the smaller-but-wider file could lose.
#[test]
fn resolution_is_compared_by_pixels_not_by_label() {
    let a = cand("1920x1080", q(1920, 1080, 8, "", 1342), 700_000_000, 100);
    let b = cand("1440x1080", q(1440, 1080, 8, "", 1342), 900_000_000, 200);
    let (a_wins, v) = choose(&a, &b, &Rules::default());
    assert!(a_wins, "more pixels wins even though it is smaller and older");
    assert!(matches!(v, Verdict::Quality { .. }), "got {v:?}");
    assert!(v.reason().contains("1920x1080"), "reason names the numbers: {}", v.reason());
}

/// HDR outranks size, and is only consulted when resolution ties.
#[test]
fn hdr_breaks_a_resolution_tie() {
    let a = cand("hdr", q(1920, 1080, 10, "PQ", 1342), 500_000_000, 100);
    let b = cand("sdr", q(1920, 1080, 8, "", 1342), 900_000_000, 200);
    let (a_wins, v) = choose(&a, &b, &Rules::default());
    assert!(a_wins, "HDR wins at equal resolution despite being smaller");
    assert!(v.reason().contains("HDR"), "{}", v.reason());
}

/// RULE 2 — the real-world case: the `Alone` episode.
#[test]
fn equal_quality_significantly_larger_wins() {
    let a = cand("4.1GB", q(1920, 1080, 8, "", 2700), 4_449_921_920, 100);
    let b = cand("1.8GB", q(1920, 1080, 8, "", 2700), 1_949_637_187, 200);
    let (a_wins, v) = choose(&a, &b, &Rules::default());
    assert!(a_wins, "at equal quality the much larger file wins, even though older");
    assert!(matches!(v, Verdict::Larger { .. }), "got {v:?}");
}

/// ...but a trivial size difference is NOT a quality signal, and must fall
/// through to rule 3 rather than pretending 2% means something.
#[test]
fn a_marginal_size_difference_falls_through_to_newer() {
    let a = cand("older", q(1920, 1080, 8, "", 1342), 1_000_000_000, 100);
    let b = cand("newer", q(1920, 1080, 8, "", 1342), 1_020_000_000, 200);
    let (a_wins, v) = choose(&a, &b, &Rules::default());
    assert!(!a_wins, "2% is not 'significantly larger'");
    assert!(matches!(v, Verdict::Newer { .. }), "got {v:?}");
}

/// INTEGRITY FIRST — Chris wrote rule 3 to cover corruption, but newness
/// cannot detect it. A copy that fails its recorded hash loses regardless of
/// being bigger, newer and higher resolution.
#[test]
fn a_copy_that_fails_its_hash_never_wins() {
    let mut a = cand("corrupt-but-better", q(3840, 2160, 10, "PQ", 1342), 9_000_000_000, 999);
    a.integrity_ok = false;
    let b = cand("intact", q(1280, 720, 8, "", 1342), 500_000_000, 1);
    let (a_wins, v) = choose(&a, &b, &Rules::default());
    assert!(!a_wins, "integrity disqualifies before any quality rule");
    assert!(v.reason().contains("failed its recorded hash"), "{}", v.reason());
}

/// A SHORT copy is a truncated download, not an incomparable different cut.
///
/// Chris: "we aren't going to have a file half the length for the same
/// episode." An earlier version of this rule refused to compare on a large
/// duration gap — which threw away the most useful cheap signal there is, and
/// would have let a half-downloaded file survive on being newer.
#[test]
fn a_short_copy_is_treated_as_truncated_and_loses() {
    let full = cand("complete", q(1920, 1080, 8, "", 1342), 700_000_000, 100);
    let cut = cand("truncated", q(1920, 1080, 8, "", 600), 320_000_000, 999);
    let (full_wins, v) = choose(&full, &cut, &Rules::default());
    assert!(full_wins, "the complete copy wins even though the stub is newer");
    assert!(v.reason().contains("truncated"), "{}", v.reason());
}

/// ...but a small difference is a cut variation, NOT truncation, and must fall
/// through to the later rules.
#[test]
fn a_small_duration_difference_is_not_truncation() {
    let a = cand("older", q(1920, 1080, 8, "", 1342), 1_000_000_000, 100);
    let b = cand("newer", q(1920, 1080, 8, "", 1320), 1_010_000_000, 200);
    let (a_wins, v) = choose(&a, &b, &Rules::default());
    assert!(!a_wins, "a ~2% difference is a cut variation");
    assert!(matches!(v, Verdict::Newer { .. }), "got {v:?}");
}

/// THE CORRUPTION CASE CHRIS ACTUALLY MEANT.
///
/// A file that arrived broken has a perfectly valid hash — PVFS hashed whatever
/// bytes it was handed. `integrity_ok` cannot see it; only something that has
/// DECODED the file can. So a recorded decode failure disqualifies a copy that
/// is otherwise better on every axis.
#[test]
fn a_file_that_fails_to_decode_loses_despite_looking_better() {
    let mut better = q(3840, 2160, 10, "PQ", 1342);
    better.decoded_ok = Some(false);
    let a = cand("4k-but-broken", better, 9_000_000_000, 999);
    let b = cand("1080p-plays", q(1920, 1080, 8, "", 1342), 700_000_000, 1);
    let (a_wins, v) = choose(&a, &b, &Rules::default());
    assert!(!a_wins, "a file that will not play is not the better copy");
    assert!(v.reason().contains("failed to decode"), "{}", v.reason());
}

/// And an UNCHECKED file is not assumed bad — nobody has looked, which is the
/// normal state until the re-encoder gets to it.
#[test]
fn an_unchecked_file_is_not_treated_as_broken() {
    let a = cand("unchecked-4k", q(3840, 2160, 10, "PQ", 1342), 9_000_000_000, 1);
    let b = cand("checked-1080p", q(1920, 1080, 8, "", 1342), 700_000_000, 999);
    let (a_wins, v) = choose(&a, &b, &Rules::default());
    assert!(a_wins, "unknown decode health must not lose to a lesser copy");
    assert!(matches!(v, Verdict::Quality { .. }), "got {v:?}");
}

/// Nothing to choose between them ⇒ REFUSE. Silence here would mean deleting
/// one of two identical-looking copies on a coin flip.
#[test]
fn identical_copies_are_refused() {
    let a = cand("a", q(1920, 1080, 8, "", 1342), 700_000_000, 100);
    let b = cand("b", q(1920, 1080, 8, "", 1342), 700_000_000, 100);
    let (_, v) = choose(&a, &b, &Rules::default());
    assert!(!v.decided(), "got {v:?}");
}

/// Rule 3 for non-media: newest wins, no ladder involved.
#[test]
fn a_non_media_file_takes_the_newest() {
    let a = cand("new.nfo", MediaQuality::default(), 900, 200);
    let b = cand("old.nfo", MediaQuality::default(), 4000, 100);
    let (a_wins, v) = choose_non_media(&a, &b);
    assert!(a_wins, "newest wins for non-media even when smaller");
    assert!(matches!(v, Verdict::Newer { .. }), "got {v:?}");
}

/// The wire form must round-trip, and tolerate a field a newer binary added —
/// the same forward-compatibility rule D72 Part A set for events.
#[test]
fn quality_round_trips_and_tolerates_unknown_fields() {
    let mut m = MediaQuality::default();
    m.set_resolution("1920x1080").unwrap();
    m.bit_depth = 10;
    m.hdr = "PQ".into();
    m.duration_s = 1342;
    let back = MediaQuality::decode(&m.encode()).unwrap();
    assert_eq!(back, m);

    let future = r#"{"w":1920,"h":1080,"depth":10,"hdr":"PQ","bitrate":0,"codec":"","dur":1342,"grain":"heavy"}"#;
    let parsed = MediaQuality::decode(future).unwrap();
    assert_eq!(parsed.width, 1920, "an unknown field must not break the parse");
}

/// Bitrate derivation — because Sonarr reports 0 with analysis off, while size
/// and runTime are present in 100% of sampled files.
#[test]
fn bitrate_is_derivable_from_size_and_duration() {
    // the measured example: 790,503,828 bytes over 22:22
    let bps = MediaQuality::derive_bitrate(790_503_828, 1342);
    let mbps = bps as f64 / 1_000_000.0;
    assert!((4.0..5.5).contains(&mbps), "expected ~4.7 Mbps, got {mbps:.2}");
    assert_eq!(MediaQuality::derive_bitrate(1000, 0), 0, "no duration ⇒ no guess");
}
