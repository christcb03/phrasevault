//! D81 — measure a media file by reading it, rather than believing an index.
//!
//! The arrs are the cheapest source of quality data and they had a hole in
//! them: 5,868 of Chris's episodes carry no `mediaInfo` at all, and those are
//! exactly the files his pending collisions are in. The obvious fix — let
//! Sonarr analyse them — is the wrong shape here, because **the arrs run at
//! Hetzner and the library lives on the NAS at home**, so every analysis would
//! drag bytes across the VPN. Chris caught that; measure where the bytes are.
//!
//! Two depths, because they answer different questions:
//!
//! * **headers** (`ffprobe`) — resolution, codec, bit depth, HDR, duration, in
//!   about 0.17s per file. Fills the ladder's upper rungs.
//! * **deep** (`ffmpeg -f null`) — decodes every frame. This is the only thing
//!   that catches Chris's actual corruption worry: "when the file was
//!   downloaded corrupt and gets into PVFS corrupt in a way that looks like
//!   it's ok and only discovered when actually played by Plex". It reads the
//!   WHOLE file, so it is opt-in and priced accordingly.

use crate::media::MediaQuality;
use crate::{PvfsError, Result};
use std::path::Path;

/// Is a prober available on this box?
pub fn prober_available() -> bool {
    std::process::Command::new("ffprobe")
        .arg("-version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Read a file's headers into a `MediaQuality`.
pub fn probe_headers(path: &Path) -> Result<MediaQuality> {
    let out = std::process::Command::new("ffprobe")
        .args([
            "-v", "error",
            "-select_streams", "v:0",
            "-show_entries",
            "stream=width,height,codec_name,bits_per_raw_sample,color_transfer:format=duration,size",
            // Flat `key=value` lines rather than JSON: pvfs-core carries no
            // serde, and this shape is both trivial to parse and less prone to
            // drift than ffprobe's nested JSON.
            "-of", "default=noprint_wrappers=1",
        ])
        .arg(path)
        .output()
        .map_err(|e| PvfsError::io("run ffprobe", e))?;
    if !out.status.success() {
        return Err(PvfsError::BadInput {
            field: "probe".into(),
            reason: format!(
                "ffprobe failed on {}: {}",
                path.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        });
    }
    Ok(parse_ffprobe(&String::from_utf8_lossy(&out.stdout)))
}

/// Map ffprobe's `key=value` output onto the ladder's inputs.
///
/// Split out so the mapping is testable on a box with no ffprobe installed —
/// this output's shape is the thing most likely to drift under us.
pub fn parse_ffprobe(text: &str) -> MediaQuality {
    let get = |want: &str| -> String {
        text.lines()
            .find_map(|l| l.split_once('='). filter(|(k, _)| *k == want).map(|(_, v)| v.trim().to_string()))
            .unwrap_or_default()
    };
    let width = get("width").parse::<u32>().unwrap_or(0);
    let height = get("height").parse::<u32>().unwrap_or(0);
    // Absent on plenty of streams. 0 means UNKNOWN, which the ladder treats as
    // an empty rung to fall through — not as 0-bit video.
    let bit_depth = get("bits_per_raw_sample").parse::<u8>().unwrap_or(0);
    let codec = get("codec_name");
    let duration_s = get("duration").parse::<f64>().unwrap_or(0.0) as u64;
    let size = get("size").parse::<u64>().unwrap_or(0);

    // HDR is reported as a TRANSFER FUNCTION, not a flag. `smpte2084` (PQ) and
    // `arib-std-b67` (HLG) are the HDR ones; `bt709` is SDR. Normalising here
    // keeps the ladder comparing like with like whatever the source was — the
    // arrs report their own vocabulary for the same thing.
    let hdr = match get("color_transfer").as_str() {
        "smpte2084" | "bt2020-10" | "bt2020-12" => "PQ".to_string(),
        "arib-std-b67" => "HLG".to_string(),
        _ => String::new(),
    };

    MediaQuality {
        width,
        height,
        bit_depth,
        hdr,
        bitrate: MediaQuality::derive_bitrate(size, duration_s),
        video_codec: codec,
        duration_s,
        // A header read proves the container parses. It says NOTHING about
        // whether every frame decodes, which is Chris's actual corruption
        // worry — so it stays unknown until something has really looked.
        decoded_ok: None,
    }
}

/// Decode every frame, and report whether it came through clean.
///
/// The expensive one, and the only answer to "it hashes fine and will not
/// play". Reads the whole file: on Chris's NAS that is minutes per title at
/// 510 MB/s read, and the reason `--deep` is opt-in.
pub fn decode_check(path: &Path) -> Result<bool> {
    let out = std::process::Command::new("ffmpeg")
        .args(["-v", "error", "-xerror", "-i"])
        .arg(path)
        .args(["-f", "null", "-"])
        .output()
        .map_err(|e| PvfsError::io("run ffmpeg", e))?;
    Ok(out.status.success() && out.stderr.is_empty())
}
