//! PVOS D211 — the remote probe's range server with a REAL ffprobe (ignored:
//! the test server has none). Run where ffprobe is, on a directory of
//! media files:
//!
//! ```text
//! D211_MEDIA_DIR=/path/to/files cargo test -p pvfs-core --test d211_real_ffprobe -- --ignored --nocapture
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

#[test]
#[ignore]
fn real_ffprobe_agrees_through_the_range_server() {
    let dir = std::env::var("D211_MEDIA_DIR").expect("D211_MEDIA_DIR");
    let prober = Prober::detect().expect("ffprobe on PATH (or PVFS_FFPROBE)");
    let mut names: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.path()).collect();
    names.sort();
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
