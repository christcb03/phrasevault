//! D76 — what a media file IS, and which of two copies should survive.
//!
//! The rules, in Chris's words: higher quality wins; then larger wins when the
//! quality is equal and the sizes differ significantly; then newer wins.
//!
//! What that leaves unsaid is what "quality" means, and the answer matters more
//! than the rules do — a wrong ordering here silently deletes the better copy.

use crate::engine::bad;
use crate::error::{PvfsError, Result};

/// A measurement of one file. Every field is optional because the sources
/// disagree about what they can tell us: the *arrs give resolution and bit
/// depth but (with analysis off) no bitrate, a probe gives everything, and a
/// file with neither still has a size and an mtime.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MediaQuality {
    pub width: u32,
    pub height: u32,
    pub bit_depth: u8,
    /// Empty = SDR. Anything else is the reported HDR flavour.
    pub hdr: String,
    /// Bits per second. May be DERIVED from size and duration — see
    /// `derive_bitrate`; for comparing two copies of the same title an average
    /// is arguably more honest than a stream figure anyway.
    pub bitrate: u64,
    pub video_codec: String,
    /// Seconds. Two copies of one episode should agree closely; a large
    /// disagreement is the cheap signal for a TRUNCATED download.
    pub duration_s: u64,
    /// Has something actually decoded this file end to end?
    ///
    /// `None` = nobody has checked. This is the ONLY thing that catches a file
    /// that arrived corrupt: PVFS hashes whatever bytes it was given, so a
    /// download that was broken before it ever reached the catalog has a
    /// perfectly valid hash and looks healthy right up until Plex tries to
    /// play it. A recorded hash proves the bytes have not changed SINCE — it
    /// says nothing about whether they were right to begin with.
    ///
    /// Cheap checks (duration, size) narrow it. Only a decode settles it, and
    /// the re-encoder is already decoding every file it touches — so it can
    /// write this as a side effect of work it was doing anyway.
    pub decoded_ok: Option<bool>,
}

impl MediaQuality {
    /// Pixels — the primary axis, and NOT the label.
    ///
    /// Sonarr reports `1440x1080`, `1916x1076` and `1920x804` all as "1080p".
    /// Comparing labels would call those equal; comparing pixels does not.
    pub fn pixels(&self) -> u64 {
        self.width as u64 * self.height as u64
    }

    pub fn is_empty(&self) -> bool {
        self.pixels() == 0 && self.bitrate == 0 && self.bit_depth == 0
    }

    /// `size / duration`, when both are known.
    pub fn derive_bitrate(size_bytes: u64, duration_s: u64) -> u64 {
        if duration_s == 0 {
            return 0;
        }
        size_bytes.saturating_mul(8) / duration_s
    }

    /// Canonical JSON — stable field order, so the same measurement always
    /// signs to the same bytes.
    pub fn encode(&self) -> String {
        format!(
            "{{\"w\":{},\"h\":{},\"depth\":{},\"hdr\":\"{}\",\"bitrate\":{},\"codec\":\"{}\",\"dur\":{},\"decoded\":\"{}\"}}",
            self.width,
            self.height,
            self.bit_depth,
            esc(&self.hdr),
            self.bitrate,
            esc(&self.video_codec),
            self.duration_s,
            match self.decoded_ok {
                Some(true) => "ok",
                Some(false) => "bad",
                None => "",
            }
        )
    }

    pub fn decode(s: &str) -> Result<Self> {
        let mut q = MediaQuality::default();
        for (k, v) in raw_pairs(s) {
            match k.as_str() {
                "w" => q.width = v.parse().unwrap_or(0),
                "h" => q.height = v.parse().unwrap_or(0),
                "depth" => q.bit_depth = v.parse().unwrap_or(0),
                "hdr" => q.hdr = v,
                "bitrate" => q.bitrate = v.parse().unwrap_or(0),
                "codec" => q.video_codec = v,
                "dur" => q.duration_s = v.parse().unwrap_or(0),
                "decoded" => {
                    q.decoded_ok = match v.as_str() {
                        "ok" => Some(true),
                        "bad" => Some(false),
                        _ => None,
                    }
                }
                _ => {} // tolerate fields a newer binary added
            }
        }
        Ok(q)
    }

    /// Parse `"1920x1080"` — the shape Sonarr/Radarr v4 actually return.
    pub fn set_resolution(&mut self, res: &str) -> Result<()> {
        let (w, h) = res
            .split_once('x')
            .ok_or_else(|| bad("resolution", "expected WIDTHxHEIGHT"))?;
        self.width = w.trim().parse().map_err(|_| bad("resolution", "width"))?;
        self.height = h.trim().parse().map_err(|_| bad("resolution", "height"))?;
        Ok(())
    }
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Minimal flat-JSON reader — the encoder above is the only writer, so this
/// does not need to be a general parser.
fn raw_pairs(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for part in s.trim().trim_matches(|c| c == '{' || c == '}').split(',') {
        if let Some((k, v)) = part.split_once(':') {
            out.push((
                k.trim().trim_matches('"').to_string(),
                v.trim().trim_matches('"').to_string(),
            ));
        }
    }
    out
}

/// Which rule decided, and the numbers it decided on. Every automatic deletion
/// should be explainable without reading the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Higher quality.
    Quality { reason: String },
    /// Equal quality, significantly larger.
    Larger { reason: String },
    /// Equal quality and comparable size — newest wins.
    Newer { reason: String },
    /// Nothing separates them. REFUSE rather than guess.
    TooClose { reason: String },
}

impl Verdict {
    pub fn reason(&self) -> &str {
        match self {
            Verdict::Quality { reason }
            | Verdict::Larger { reason }
            | Verdict::Newer { reason }
            | Verdict::TooClose { reason } => reason,
        }
    }
    pub fn decided(&self) -> bool {
        !matches!(self, Verdict::TooClose { .. })
    }
}

/// One side of a comparison.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub label: String,
    pub quality: MediaQuality,
    pub size_bytes: u64,
    pub mtime_ms: u64,
    /// A candidate that failed its recorded hash is not a candidate at all.
    pub integrity_ok: bool,
}

/// How much bigger counts as "significantly" — Chris's ~10%, made explicit and
/// tunable per scope rather than hidden in the code.
#[derive(Debug, Clone, Copy)]
pub struct Rules {
    pub size_margin_pct: u32,
    /// How much SHORTER a copy may be before it is treated as truncated.
    ///
    /// Two copies of one episode should agree closely on length — cuts vary a
    /// little, but nothing legitimate is half as long. So a large shortfall is
    /// not "a different cut we cannot compare", it is the cheap tell for a
    /// broken download, and the longer copy should win.
    pub truncation_pct: u32,
}

impl Default for Rules {
    fn default() -> Self {
        Rules {
            size_margin_pct: 10,
            truncation_pct: 10,
        }
    }
}

/// Decide which of two copies survives. `Ok(true)` = `a` wins.
///
/// INTEGRITY FIRST, and deliberately before any rule: a corrupt file is not
/// "older", it is corrupt. Chris's rule 3 was written to cover corruption, but
/// newness cannot detect it — PVFS already has content hashes for that, and
/// using them here is the difference between a real check and a proxy for one.
pub fn choose(a: &Candidate, b: &Candidate, rules: &Rules) -> (bool, Verdict) {
    match (a.integrity_ok, b.integrity_ok) {
        (true, false) => {
            return (
                true,
                Verdict::Quality {
                    reason: format!("{} failed its recorded hash", b.label),
                },
            )
        }
        (false, true) => {
            return (
                false,
                Verdict::Quality {
                    reason: format!("{} failed its recorded hash", a.label),
                },
            )
        }
        (false, false) => {
            return (
                false,
                Verdict::TooClose {
                    reason: "both copies failed their recorded hashes".into(),
                },
            )
        }
        (true, true) => {}
    }

    // A file something has FAILED to decode is out, whatever else it has going
    // for it. This is the only check that catches a download that was corrupt
    // before PVFS ever saw it — a hash proves the bytes have not changed
    // since, not that they were ever right.
    match (a.quality.decoded_ok, b.quality.decoded_ok) {
        (Some(false), Some(false)) => {
            return (
                false,
                Verdict::TooClose {
                    reason: "both copies failed to decode".into(),
                },
            )
        }
        (Some(false), _) => {
            return (
                false,
                Verdict::Quality {
                    reason: format!("{} failed to decode", a.label),
                },
            )
        }
        (_, Some(false)) => {
            return (
                true,
                Verdict::Quality {
                    reason: format!("{} failed to decode", b.label),
                },
            )
        }
        _ => {}
    }

    // RULE 1 — quality, as a ladder. Each rung is consulted only when the one
    // above ties, because a single "quality score" would have to weigh pixels
    // against bit depth against bitrate, and any such weighting is a guess
    // dressed as arithmetic.
    let (pa, pb) = (a.quality.pixels(), b.quality.pixels());
    if pa != pb && pa != 0 && pb != 0 {
        let win = pa > pb;
        return (
            win,
            Verdict::Quality {
                reason: format!(
                    "resolution {}x{} vs {}x{}",
                    a.quality.width, a.quality.height, b.quality.width, b.quality.height
                ),
            },
        );
    }
    let (ha, hb) = (!a.quality.hdr.is_empty(), !b.quality.hdr.is_empty());
    if ha != hb {
        return (
            ha,
            Verdict::Quality {
                reason: format!(
                    "HDR: {} vs {}",
                    if ha { &a.quality.hdr } else { "SDR" },
                    if hb { &b.quality.hdr } else { "SDR" }
                ),
            },
        );
    }
    if a.quality.bit_depth != b.quality.bit_depth
        && a.quality.bit_depth != 0
        && b.quality.bit_depth != 0
    {
        return (
            a.quality.bit_depth > b.quality.bit_depth,
            Verdict::Quality {
                reason: format!(
                    "bit depth {} vs {}",
                    a.quality.bit_depth, b.quality.bit_depth
                ),
            },
        );
    }

    // COMPLETENESS, before size and date.
    //
    // Chris: "we aren't going to have a file half the length for the same
    // episode." So a large shortfall is not an incomparable different cut — it
    // is a truncated download, and the complete copy wins. This is the closest
    // PVFS gets to catching corruption without decoding, and it costs nothing.
    let (da, db) = (a.quality.duration_s, b.quality.duration_s);
    if da > 0 && db > 0 {
        let short = da.min(db) as f64;
        let long = da.max(db) as f64;
        let shortfall = (long - short) / long * 100.0;
        if shortfall >= rules.truncation_pct as f64 {
            return (
                da > db,
                Verdict::Quality {
                    reason: format!(
                        "{}s vs {}s — the shorter copy is {shortfall:.0}% short and looks \
                         truncated",
                        da.max(db),
                        da.min(db)
                    ),
                },
            );
        }
    }

    // RULE 2 — larger, but only when it is a real margin.
    let (sa, sb) = (a.size_bytes, b.size_bytes);
    if sa > 0 && sb > 0 {
        let bigger = sa.max(sb);
        let margin = (bigger - sa.min(sb)) as f64 / sa.min(sb).max(1) as f64 * 100.0;
        if margin >= rules.size_margin_pct as f64 {
            return (
                sa > sb,
                Verdict::Larger {
                    reason: format!(
                        "same quality; {} vs {} bytes (+{margin:.0}%)",
                        sa.max(sb),
                        sa.min(sb)
                    ),
                },
            );
        }
    }

    // RULE 3 — newer, the final tiebreak.
    if a.mtime_ms != b.mtime_ms {
        return (
            a.mtime_ms > b.mtime_ms,
            Verdict::Newer {
                reason: format!(
                    "same quality and comparable size; newer copy ({} vs {})",
                    a.mtime_ms.max(b.mtime_ms),
                    a.mtime_ms.min(b.mtime_ms)
                ),
            },
        );
    }

    (
        false,
        Verdict::TooClose {
            reason: "identical quality, size and mtime — nothing to choose between them".into(),
        },
    )
}

/// Is this a media file — judged by what it IS, not by what we happened to
/// measure.
///
/// Deciding this from "did we record a resolution?" was wrong and it showed
/// immediately: two unmeasured copies of one episode were treated as non-media
/// and decided on DATE, skipping size entirely — the exact opposite of the
/// order Chris asked for. An unmeasured film is still a film.
pub fn is_media_file(label: &str, mime: &str) -> bool {
    if mime.starts_with("video/") || mime.starts_with("audio/") {
        return true;
    }
    let lower = label.to_lowercase();
    [
        ".mkv", ".mp4", ".avi", ".m4v", ".mov", ".wmv", ".mpg", ".mpeg", ".ts", ".m2ts", ".webm",
        ".flac", ".mp3", ".m4a",
    ]
    .iter()
    .any(|e| lower.ends_with(e))
}

/// A non-media file has no quality ladder to climb: newest wins, per Chris's
/// rule 3. Kept separate so the caller must decide which it is looking at
/// rather than a quality of zero silently meaning "not media".
pub fn choose_non_media(a: &Candidate, b: &Candidate) -> (bool, Verdict) {
    match (a.integrity_ok, b.integrity_ok) {
        (true, false) => return (true, Verdict::Quality { reason: format!("{} failed its recorded hash", b.label) }),
        (false, true) => return (false, Verdict::Quality { reason: format!("{} failed its recorded hash", a.label) }),
        _ => {}
    }
    if a.mtime_ms == b.mtime_ms {
        return (
            false,
            Verdict::TooClose {
                reason: "not a media file, and the timestamps match".into(),
            },
        );
    }
    (
        a.mtime_ms > b.mtime_ms,
        Verdict::Newer {
            reason: "not a media file — newest wins".into(),
        },
    )
}

impl From<PvfsError> for Verdict {
    fn from(e: PvfsError) -> Self {
        Verdict::TooClose {
            reason: e.to_string(),
        }
    }
}
