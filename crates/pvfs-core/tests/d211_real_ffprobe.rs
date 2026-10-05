//! PVOS D211 — the remote probe's range server with a REAL ffprobe. It makes
//! its own media with ffmpeg (PVOS D221: it used to be ignored and need a
//! folder of files; the pipeline installs ffmpeg now): an H.264 MP4 with its
//! index at the end, an MPEG-4 Matroska, a raw-video Matroska over 64 MiB, a
//! file of noise, and an unreadable copy. `D211_MEDIA_DIR=/path` adds a
//! folder of real media when run by hand:
//!
//! ```text
//! D211_MEDIA_DIR=/path/to/files cargo test -p pvfs-core --test d211_real_ffprobe -- --nocapture
//! ```
//!
//! For every file it probes the file directly and through the range server
//! (as the remote probe does, with a source that reads the file's ranges),
//! and checks the two agree: the same measurement, or both "broken" — and
//! that a probe over HTTP reads ranges, not the file. A file named
//! `*unreadable*` is expected to be an error locally (no permission).

use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;
use std::time::Duration;

use pvfs_core::probe::{ProbeOutcome, Prober, RangeServer, RangeSource, REMOTE_PROBE_MAX_BYTES};

struct FileSource(std::path::PathBuf);

impl RangeSource for FileSource {
    fn read_range(&self, offset: u64, len: u64, out: &mut Vec<u8>) -> Result<(), String> {
        let mut f = std::fs::File::open(&self.0).map_err(|e| e.to_string())?;
        f.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
        let start = out.len();
        out.resize(start + len as usize, 0);
        f.read_exact(&mut out[start..]).map_err(|e| e.to_string())
    }
}

fn kind(o: &ProbeOutcome) -> String {
    match o {
        ProbeOutcome::Measured(q) => format!("measured {}x{} {} {}s depth {} hdr {:?}", q.width, q.height, q.video_codec, q.duration_s, q.bit_depth, q.hdr),
        ProbeOutcome::Broken(_) => "broken".into(),
        ProbeOutcome::Error(_) => "error".into(),
        ProbeOutcome::TimedOut => "timed out".into(),
        ProbeOutcome::Cancelled => "cancelled".into(),
        ProbeOutcome::Unavailable(_) => "unavailable".into(),
    }
}

/// Run ffmpeg quietly; a failure names its arguments and its stderr.
fn ffmpeg(args: &[&str]) {
    let out = std::process::Command::new("ffmpeg")
        .args(["-hide_banner", "-loglevel", "error", "-y"])
        .args(args)
        .output()
        .expect("ffmpeg on PATH — the PVFS pipeline installs it (apt: ffmpeg)");
    assert!(out.status.success(), "ffmpeg {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

/// The media this test probes, made in `dir`.
fn made_media(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let p = |n: &str| dir.join(n);
    let s = |q: &std::path::Path| q.to_string_lossy().into_owned();
    // H.264 in MP4, index (moov) at the end: the probe has to seek to the tail.
    ffmpeg(&["-f", "lavfi", "-i", "testsrc2=size=1280x720:rate=24", "-t", "2", "-c:v", "libx264", "-pix_fmt", "yuv420p", &s(&p("h264-moov-at-end.mp4"))]);
    // MPEG-4 Part 2 in Matroska, with a sine for audio.
    ffmpeg(&[
        "-f", "lavfi", "-i", "testsrc=size=640x360:rate=24", "-f", "lavfi", "-i", "sine=frequency=440",
        "-t", "2", "-c:v", "mpeg4", "-c:a", "pcm_s16le", &s(&p("mpeg4.mkv")),
    ]);
    // Raw video, 56 frames of 1280x720 yuv420p: ~74 MB, over the 64 MiB a
    // header probe must stay well below half of.
    ffmpeg(&["-f", "lavfi", "-i", "testsrc=size=1280x720:rate=25", "-frames:v", "56", "-c:v", "rawvideo", "-pix_fmt", "yuv420p", &s(&p("raw-big.mkv"))]);
    // Noise with a video name: broken either way.
    let noise: Vec<u8> = (0..3_000_000u64).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    std::fs::write(p("noise.mkv"), noise).unwrap();
    let mut out = vec![p("h264-moov-at-end.mp4"), p("mpeg4.mkv"), p("raw-big.mkv"), p("noise.mkv")];
    // An unreadable copy — unless this runs as root, which reads it anyway.
    let locked = p("unreadable.mkv");
    std::fs::copy(p("mpeg4.mkv"), &locked).unwrap();
    std::fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o000)).unwrap();
    if std::fs::File::open(&locked).is_err() {
        out.push(locked);
    }
    out
}

#[test]
fn real_ffprobe_agrees_through_the_range_server() {
    let prober = Prober::detect().expect("ffprobe on PATH (or PVFS_FFPROBE) — the PVFS pipeline installs ffmpeg");
    let tmp = tempfile::tempdir().unwrap();
    let mut names = made_media(tmp.path());
    let big = std::fs::metadata(tmp.path().join("raw-big.mkv")).unwrap().len();
    assert!(big > 64 * 1024 * 1024, "premise: the raw file is over 64 MiB ({big} bytes)");
    if let Ok(dir) = std::env::var("D211_MEDIA_DIR") {
        let mut more: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.path()).collect();
        more.sort();
        names.extend(more);
    }
    let mut failures = Vec::new();
    for path in names {
        let size = std::fs::metadata(&path).unwrap().len();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let local = prober.probe(&path, Duration::from_secs(30), None);
        let ext = name.rsplit_once('.').map(|(_, e)| e).unwrap_or("bin");
        let server = RangeServer::start(Arc::new(FileSource(path.clone())), size, ext, REMOTE_PROBE_MAX_BYTES).unwrap();
        let remote = prober.probe_input(
            std::ffi::OsStr::new(server.url()),
            &["-protocol_whitelist", "http,tcp"],
            Duration::from_secs(30),
            None,
        );
        let served = server.served();
        let fault = server.fault();
        drop(server);
        println!(
            "{name}: {size} bytes; local: {} | over HTTP: {} — {} bytes fetched ({:.1}%){}",
            kind(&local),
            kind(&remote),
            served,
            served as f64 * 100.0 / size.max(1) as f64,
            fault.as_ref().map(|f| format!("; fault: {f}")).unwrap_or_default()
        );
        for o in [&local, &remote] {
            if let ProbeOutcome::Broken(w) | ProbeOutcome::Error(w) = o {
                println!("    {w}");
            }
        }
        if name.contains("unreadable") {
            if !matches!(local, ProbeOutcome::Error(_)) {
                failures.push(format!("{name}: an unreadable file must be an error, not {}", kind(&local)));
            }
            continue;
        }
        if kind(&local) != kind(&remote) {
            failures.push(format!("{name}: local {} vs over HTTP {}", kind(&local), kind(&remote)));
        }
        if size > 64 * 1024 * 1024 && served > size / 2 {
            failures.push(format!("{name}: read {served} of {size} bytes over HTTP — not a header probe"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
