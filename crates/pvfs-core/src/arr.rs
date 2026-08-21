//! D76 — quality from the *arrs.
//!
//! Sonarr and Radarr run MediaInfo at import and keep the result, so their
//! `mediaInfo` is a real probe result, not a guess. Measured against Chris's
//! live library: 94% of Sonarr episode files carry it, Radarr 50/50 sampled.
//!
//! WHY THIS IS CAPTURED AT INGEST AND NOT LOOKED UP LATER: once an arr replaces
//! a file it forgets the old one. History keeps the coarse quality label and
//! the size but NOT `mediaInfo` — so by the time a collision needs deciding,
//! the losing copy's detail is gone for good. Every upgrade closes that window
//! for one more file, permanently.

use crate::error::Result;
use crate::media::MediaQuality;

/// One file as an arr describes it. Only the fields the ladder needs.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ArrFile {
    /// The arr's own path — used to match its file to a catalog node.
    pub path: String,
    pub size_bytes: u64,
    /// `"1920x1080"`. v4 reports this; v3's `width`/`height` are absent.
    pub resolution: String,
    pub bit_depth: u8,
    pub dynamic_range: String,
    /// Often 0 — Sonarr with "Analyse video files" OFF reports no bitrate at
    /// all (measured: 0 in 2,373/2,373). Derived from size and runtime instead.
    pub bitrate: u64,
    pub codec: String,
    /// `"22:22"` or `"1:34:05"`.
    pub run_time: String,
    /// The arr's file id, kept so a file it later forgets can still be looked
    /// up in history.
    pub file_id: u64,
}

impl ArrFile {
    /// Turn an arr's description into a measurement the ladder can use.
    pub fn to_quality(&self) -> Result<MediaQuality> {
        let mut q = MediaQuality {
            bit_depth: self.bit_depth,
            hdr: self.dynamic_range.clone(),
            bitrate: self.bitrate,
            video_codec: self.codec.clone(),
            duration_s: parse_runtime(&self.run_time),
            ..Default::default()
        };
        if !self.resolution.is_empty() {
            // A malformed resolution must not poison the whole import; leave it
            // at zero and let the later rungs decide.
            let _ = q.set_resolution(&self.resolution);
        }
        // DERIVED, when the arr did not measure it. size/duration is an average
        // rather than a stream bitrate — but for two copies of the SAME title
        // that is arguably the more honest number, and it needs no analysis
        // pass at all.
        if q.bitrate == 0 && q.duration_s > 0 {
            q.bitrate = MediaQuality::derive_bitrate(self.size_bytes, q.duration_s);
        }
        Ok(q)
    }
}

/// `"22:22"` → 1342, `"1:34:05"` → 5645. Anything else → 0 (unknown, not zero
/// length — the ladder treats 0 as "cannot compare" rather than "instant").
pub fn parse_runtime(s: &str) -> u64 {
    let parts: Vec<&str> = s.trim().split(':').collect();
    let nums: Option<Vec<u64>> = parts.iter().map(|p| p.trim().parse::<u64>().ok()).collect();
    match nums.as_deref() {
        Some([h, m, sec]) => h * 3600 + m * 60 + sec,
        Some([m, sec]) => m * 60 + sec,
        Some([sec]) => *sec,
        _ => 0,
    }
}

/// Match an arr path to a tree path under the library root.
///
/// The arr reports an absolute path on ITS filesystem
/// (`/mnt/unionfs/Media/TV/Show/…`); the catalog knows a tree path relative to
/// the library node (`TV/Show/…`). Matching on the tail after the library
/// segment is what lets one arr describe files that PVFS reaches by an
/// entirely different route.
pub fn tree_path_of(arr_path: &str, library_segment: &str) -> Option<String> {
    let needle = format!("/{library_segment}/");
    let idx = arr_path.find(&needle)?;
    let tail = &arr_path[idx + needle.len()..];
    (!tail.is_empty()).then(|| tail.to_string())
}
