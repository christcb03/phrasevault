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
        probe_failed: false,
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

/// PVOS D208 — what one probe of the catalogue's probe step came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// ffprobe read the file: its measurement (resolution may be unknown —
    /// a container with no video stream — and is recorded as it is).
    Measured(MediaQuality),
    /// ffprobe ran and could not read the file, with its first error line.
    Failed(String),
    /// Still running at the timeout: killed, nothing learned, not recorded.
    TimedOut,
    /// The pass was asked to stop: killed, not recorded.
    Cancelled,
    /// The prober could not be started at all (gone since it was found).
    Unavailable(String),
}

/// PVOS D208 — the header prober the catalogue's probe step runs: ffprobe,
/// or the binary `PVFS_FFPROBE` names (a static build on a box with no
/// package; a test's stand-in).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prober {
    pub program: std::path::PathBuf,
}

/// The arguments [`probe_headers`] passes, shared so both read the same
/// fields.
const PROBE_ARGS: &[&str] = &[
    "-v", "error",
    "-select_streams", "v:0",
    "-show_entries",
    "stream=width,height,codec_name,bits_per_raw_sample,color_transfer:format=duration,size",
    "-of", "default=noprint_wrappers=1",
];

impl Prober {
    /// The prober this box has: `PVFS_FFPROBE` if set, else `ffprobe` on
    /// PATH — `None` when it does not answer `-version`.
    pub fn detect() -> Option<Prober> {
        let program = std::env::var_os("PVFS_FFPROBE")
            .filter(|p| !p.is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("ffprobe"));
        let prober = Prober { program };
        prober.available().then_some(prober)
    }

    /// Does this prober run?
    pub fn available(&self) -> bool {
        std::process::Command::new(&self.program)
            .arg("-version")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Probe `path`'s headers, killing the child at `timeout` or as soon as
    /// `cancel` is raised (checked every 20 ms). Its output is read on
    /// threads of its own, so a child with a lot to say on stderr (a corrupt
    /// file's error per packet) never blocks on a full pipe.
    pub fn probe(
        &self,
        path: &Path,
        timeout: std::time::Duration,
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> ProbeOutcome {
        use std::io::Read;
        let child = std::process::Command::new(&self.program)
            .args(PROBE_ARGS)
            .arg(path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => return ProbeOutcome::Unavailable(format!("{}: {e}", self.program.display())),
        };
        fn drain<R: Read + Send + 'static>(r: Option<R>) -> std::thread::JoinHandle<String> {
            std::thread::spawn(move || {
                let mut b = Vec::new();
                if let Some(mut r) = r {
                    // Bounded: a runaway stderr is cut at 64 KiB.
                    let _ = r.by_ref().take(64 * 1024).read_to_end(&mut b);
                    let _ = std::io::copy(&mut r, &mut std::io::sink());
                }
                String::from_utf8_lossy(&b).into_owned()
            })
        }
        let out_t = drain(child.stdout.take());
        let err_t = drain(child.stderr.take());
        let started = std::time::Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) => {}
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return ProbeOutcome::Failed(format!("wait for ffprobe: {e}"));
                }
            }
            if cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::SeqCst)) {
                let _ = child.kill();
                let _ = child.wait();
                return ProbeOutcome::Cancelled;
            }
            if started.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                return ProbeOutcome::TimedOut;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let out = out_t.join().unwrap_or_default();
        let err = err_t.join().unwrap_or_default();
        if status.success() {
            ProbeOutcome::Measured(parse_ffprobe(&out))
        } else {
            let first = err.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("no message");
            ProbeOutcome::Failed(format!("{status}: {first}"))
        }
    }
}
