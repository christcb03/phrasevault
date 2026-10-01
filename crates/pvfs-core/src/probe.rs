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
        probe_suspect_ms: 0,
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
    /// PVOS D211 — ffprobe ran to its end and said the file's DATA is
    /// invalid ([`classify_failure`]), with its first error line. Recorded:
    /// a suspect the first time, a confirmed failure the second.
    Broken(String),
    /// PVOS D211 — ffprobe could not do its job: an I/O or permission
    /// error, a signal, a message that is not about the data, or (a remote
    /// probe) a fault fetching the bytes. Says nothing about the file, so
    /// nothing is recorded; it is tried again on a later pass.
    Error(String),
    /// Still running at the timeout: killed, nothing learned, not recorded.
    TimedOut,
    /// The pass was asked to stop: killed, not recorded.
    Cancelled,
    /// The prober could not be started at all (gone since it was found).
    Unavailable(String),
}

/// PVOS D211 — ffprobe's words for data it cannot read: the container's
/// header is not there or not valid. (`AVERROR_INVALIDDATA`, an MP4 with no
/// `moov`, a Matroska file with no EBML header.)
const BROKEN_SIGNS: &[&str] = &[
    "invalid data found when processing input",
    "moov atom not found",
    "ebml header parsing failed",
];

/// PVOS D211 — words that mean the probe could not read, not that the data
/// is bad. Any of them makes the failure an [`ProbeOutcome::Error`], even
/// beside a [`BROKEN_SIGNS`] message: a short read shows up as invalid data
/// too. "End of file" is here on purpose — a file cut short by a copy that
/// has not finished, or by a network read, says it.
const ERROR_SIGNS: &[&str] = &[
    "input/output error",
    "permission denied",
    "no such file or directory",
    "connection",
    "server returned",
    "resource temporarily unavailable",
    "operation timed out",
    "end of file",
    "cannot allocate memory",
];

/// PVOS D211 — is a failed ffprobe run's stderr a statement that the file
/// is BROKEN (`true`), or only that the probe could not run (`false`)?
/// `exited` is whether the child exited with a code (a signal is never
/// "broken"). Conservative: only a known invalid-data message, and no sign
/// of an I/O problem, counts.
pub fn classify_failure(stderr: &str, exited: bool) -> bool {
    if !exited {
        return false;
    }
    let lower = stderr.to_lowercase();
    BROKEN_SIGNS.iter().any(|s| lower.contains(s)) && !ERROR_SIGNS.iter().any(|s| lower.contains(s))
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
        self.probe_input(path.as_os_str(), &[], timeout, cancel)
    }

    /// PVOS D211 — [`Prober::probe`] of any input ffprobe can open (a URL
    /// for a remote probe), with `input_args` before it (input options such
    /// as `-protocol_whitelist`).
    pub fn probe_input(
        &self,
        input: &std::ffi::OsStr,
        input_args: &[&str],
        timeout: std::time::Duration,
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> ProbeOutcome {
        use std::io::Read;
        let child = std::process::Command::new(&self.program)
            .args(PROBE_ARGS)
            .args(input_args)
            .arg(input)
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
                    return ProbeOutcome::Error(format!("wait for ffprobe: {e}"));
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
            return ProbeOutcome::Measured(parse_ffprobe(&out));
        }
        let first = err.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("no message");
        let why = format!("{status}: {first}");
        if classify_failure(&err, status.code().is_some()) {
            ProbeOutcome::Broken(why)
        } else {
            ProbeOutcome::Error(why)
        }
    }
}

// ---- PVOS D211: a one-probe HTTP range server ---------------------------------

/// PVOS D211 — where a [`RangeServer`] gets the bytes it serves: a range
/// of one file, `len` bytes from `offset`, appended to `out`. The remote
/// probe's source reads them from the holder's daemon (`CatHash`).
pub trait RangeSource: Send + Sync {
    fn read_range(&self, offset: u64, len: u64, out: &mut Vec<u8>) -> std::result::Result<(), String>;
}

/// PVOS D211 — the most bytes one remote probe may read. A header probe
/// reads a few MB (the head; an MP4's `moov` at the end); a reader asking
/// for more is not probing a header, and the probe is an error.
pub const REMOTE_PROBE_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// The piece a [`RangeServer`] fetches and sends at a time.
const RANGE_PIECE: u64 = 1024 * 1024;

#[derive(Default)]
struct RangeState {
    /// Why a fetch failed (the first reason), or the cap was passed.
    fault: std::sync::Mutex<Option<String>>,
    served: std::sync::atomic::AtomicU64,
    stop: std::sync::atomic::AtomicBool,
}

/// PVOS D211 — serves ONE file to ONE local ffprobe over HTTP, so ffprobe
/// can read the ranges it needs (the head; the tail for an MP4 whose `moov`
/// is at the end) and nothing else: bound to 127.0.0.1 on a free port, one
/// unguessable path, `GET`/`HEAD` with a single `Range` (answered `206`).
/// Each range is fetched from the [`RangeSource`] as ffprobe reads it.
/// Dropping it stops it.
pub struct RangeServer {
    url: String,
    state: std::sync::Arc<RangeState>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl RangeServer {
    /// Serve `size` bytes from `source`, named with extension `ext` (ffprobe
    /// guesses the format by content; the extension helps), reading at most
    /// `cap` bytes in all.
    pub fn start(
        source: std::sync::Arc<dyn RangeSource>,
        size: u64,
        ext: &str,
        cap: u64,
    ) -> std::io::Result<RangeServer> {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let token = {
            use rand::RngCore;
            let mut b = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut b);
            hex::encode(b)
        };
        let ext: String = ext.chars().filter(|c| c.is_ascii_alphanumeric()).take(8).collect();
        let path = format!("/{token}/probe.{}", if ext.is_empty() { "bin" } else { &ext });
        let url = format!("http://127.0.0.1:{port}{path}");
        let state = std::sync::Arc::new(RangeState::default());
        let st = state.clone();
        let thread = std::thread::spawn(move || {
            while !st.stop.load(std::sync::atomic::Ordering::SeqCst) {
                match listener.accept() {
                    Ok((conn, _)) => {
                        let (st, source, path) = (st.clone(), source.clone(), path.clone());
                        std::thread::spawn(move || serve_range_conn(conn, &path, size, cap, &*source, &st));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10))
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
                }
            }
        });
        Ok(RangeServer { url, state, thread: Some(thread) })
    }

    /// The URL ffprobe opens.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Why the server could not give ffprobe what it asked for, if it could
    /// not: a fetch that failed, or more than the cap asked for.
    pub fn fault(&self) -> Option<String> {
        self.state.fault.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Bytes fetched from the source so far.
    pub fn served(&self) -> u64 {
        self.state.served.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for RangeServer {
    fn drop(&mut self) {
        self.state.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn range_fault(st: &RangeState, why: String) {
    let mut f = st.fault.lock().unwrap_or_else(|p| p.into_inner());
    if f.is_none() {
        *f = Some(why);
    }
}

/// One HTTP request on `conn`: the headers (5 s to arrive), then the range.
fn serve_range_conn(
    mut conn: std::net::TcpStream,
    path: &str,
    size: u64,
    cap: u64,
    source: &dyn RangeSource,
    st: &RangeState,
) {
    use std::io::{Read, Write};
    let _ = conn.set_nonblocking(false);
    let _ = conn.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let _ = conn.set_write_timeout(Some(std::time::Duration::from_secs(30)));
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 || !matches!(conn.read(&mut byte), Ok(1)) {
            return;
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let (method, target) = (first.next().unwrap_or_default(), first.next().unwrap_or_default());
    let reply = |conn: &mut std::net::TcpStream, status: &str, extra: &str| {
        let _ = conn.write_all(
            format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n{extra}\r\n").as_bytes(),
        );
    };
    if target != path {
        return reply(&mut conn, "404 Not Found", "");
    }
    if method != "GET" && method != "HEAD" {
        return reply(&mut conn, "405 Method Not Allowed", "");
    }
    let range = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("range"))
        .map(|(_, v)| v.trim().to_string());
    let (from, to, partial) = match range.as_deref().and_then(|r| r.strip_prefix("bytes=")) {
        None => (0, size.saturating_sub(1), false),
        Some(spec) => {
            let (a, b) = spec.split_once('-').unwrap_or((spec, ""));
            match (a.trim().parse::<u64>(), b.trim()) {
                (Ok(a), "") => (a, size.saturating_sub(1), true),
                (Ok(a), b) => match b.parse::<u64>() {
                    Ok(b) => (a, b.min(size.saturating_sub(1)), true),
                    Err(_) => return reply(&mut conn, "416 Range Not Satisfiable", &format!("Content-Range: bytes */{size}\r\n")),
                },
                // A suffix range (`bytes=-N`): the last N bytes.
                (Err(_), _) if a.trim().is_empty() => match b.trim().parse::<u64>() {
                    Ok(n) => (size.saturating_sub(n), size.saturating_sub(1), true),
                    Err(_) => return reply(&mut conn, "416 Range Not Satisfiable", &format!("Content-Range: bytes */{size}\r\n")),
                },
                _ => return reply(&mut conn, "416 Range Not Satisfiable", &format!("Content-Range: bytes */{size}\r\n")),
            }
        }
    };
    if size == 0 || from >= size || to < from {
        return reply(&mut conn, "416 Range Not Satisfiable", &format!("Content-Range: bytes */{size}\r\n"));
    }
    let len = to - from + 1;
    let status = if partial { "206 Partial Content" } else { "200 OK" };
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/octet-stream\r\nAccept-Ranges: bytes\r\n{}Content-Length: {len}\r\nConnection: close\r\n\r\n",
        if partial { format!("Content-Range: bytes {from}-{to}/{size}\r\n") } else { String::new() }
    );
    if conn.write_all(headers.as_bytes()).is_err() || method == "HEAD" {
        return;
    }
    let mut off = from;
    let mut buf = Vec::with_capacity(RANGE_PIECE as usize);
    while off <= to {
        if st.stop.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let n = RANGE_PIECE.min(to - off + 1);
        let before = st.served.fetch_add(n, std::sync::atomic::Ordering::SeqCst);
        if before + n > cap {
            range_fault(st, format!("ffprobe read more than {} MiB; not a header probe", cap / (1024 * 1024)));
            return;
        }
        buf.clear();
        if let Err(e) = source.read_range(off, n, &mut buf) {
            range_fault(st, format!("fetching bytes {off}+{n}: {e}"));
            return;
        }
        if buf.len() as u64 != n {
            range_fault(st, format!("fetching bytes {off}+{n}: {} came", buf.len()));
            return;
        }
        // The reader hung up (ffprobe has what it wanted, or seeks): not a fault.
        if conn.write_all(&buf).is_err() {
            return;
        }
        off += n;
    }
}

#[cfg(test)]
mod range_server_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::Arc;

    struct Mem {
        bytes: Vec<u8>,
        fail_at: Option<u64>,
    }

    impl RangeSource for Mem {
        fn read_range(&self, offset: u64, len: u64, out: &mut Vec<u8>) -> std::result::Result<(), String> {
            if self.fail_at.is_some_and(|f| offset + len > f) {
                return Err("the holder went away".into());
            }
            out.extend_from_slice(&self.bytes[offset as usize..(offset + len) as usize]);
            Ok(())
        }
    }

    /// One request; the status line, the headers and the body.
    fn get(url: &str, method: &str, range: Option<&str>) -> (String, String, Vec<u8>) {
        let rest = url.strip_prefix("http://").unwrap();
        let (host, path) = rest.split_at(rest.find('/').unwrap());
        let mut c = std::net::TcpStream::connect(host).unwrap();
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
        if let Some(r) = range {
            req.push_str(&format!("Range: {r}\r\n"));
        }
        req.push_str("\r\n");
        c.write_all(req.as_bytes()).unwrap();
        let mut all = Vec::new();
        c.read_to_end(&mut all).unwrap();
        let split = all.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let head = String::from_utf8_lossy(&all[..split]).into_owned();
        let (status, headers) = head.split_once("\r\n").unwrap_or((&head, ""));
        (status.to_string(), headers.to_string(), all[split + 4..].to_vec())
    }

    fn bytes(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 % 251) as u8).collect()
    }

    #[test]
    fn ranges_are_served_as_asked_and_nothing_else() {
        let data = bytes(3 * 1024 * 1024 + 17);
        let size = data.len() as u64;
        let s = RangeServer::start(Arc::new(Mem { bytes: data.clone(), fail_at: None }), size, "mkv", 64 << 20).unwrap();
        assert!(s.url().starts_with("http://127.0.0.1:") && s.url().ends_with("/probe.mkv"));
        let (st, h, body) = get(s.url(), "GET", Some("bytes=10-19"));
        assert!(st.contains("206"), "{st}");
        assert!(h.contains(&format!("Content-Range: bytes 10-19/{size}")), "{h}");
        assert_eq!(body, data[10..20]);
        // open-ended and suffix ranges
        let (_, _, body) = get(s.url(), "GET", Some(&format!("bytes={}-", size - 5)));
        assert_eq!(body, data[data.len() - 5..]);
        let (_, _, body) = get(s.url(), "GET", Some("bytes=-3"));
        assert_eq!(body, data[data.len() - 3..]);
        // a piece boundary inside the range
        let (_, _, body) = get(s.url(), "GET", Some("bytes=1048570-1048590"));
        assert_eq!(body, data[1_048_570..1_048_591]);
        // HEAD: the size, no bytes; no range: 200 and all of it
        let (st, h, body) = get(s.url(), "HEAD", None);
        assert!(st.contains("200") && h.contains(&format!("Content-Length: {size}")) && body.is_empty(), "{st} {h}");
        let (st, _, body) = get(s.url(), "GET", None);
        assert!(st.contains("200"));
        assert_eq!(body, data);
        // past the end; another path; another method
        assert!(get(s.url(), "GET", Some(&format!("bytes={size}-"))).0.contains("416"));
        let other = s.url().replace("/probe.mkv", "/other.mkv");
        assert!(get(&other, "GET", None).0.contains("404"));
        assert!(get(s.url(), "PUT", None).0.contains("405"));
        assert_eq!(s.fault(), None);
    }

    #[test]
    fn a_fetch_that_fails_or_a_read_past_the_cap_is_a_fault() {
        let data = bytes(4 * 1024 * 1024);
        let size = data.len() as u64;
        let s = RangeServer::start(Arc::new(Mem { bytes: data.clone(), fail_at: Some(2 * 1024 * 1024) }), size, "mp4", 64 << 20).unwrap();
        let (_, _, body) = get(s.url(), "GET", Some("bytes=0-99"));
        assert_eq!(body, data[..100], "what it could fetch it served");
        assert_eq!(s.fault(), None);
        let (_, _, body) = get(s.url(), "GET", Some(&format!("bytes={}-", size - 10)));
        assert!(body.is_empty(), "cut off");
        assert!(s.fault().unwrap().contains("the holder went away"));

        let s = RangeServer::start(Arc::new(Mem { bytes: data, fail_at: None }), size, "mp4", 2 * 1024 * 1024).unwrap();
        let (_, _, body) = get(s.url(), "GET", None);
        assert_eq!(body.len(), 2 * 1024 * 1024, "served up to the cap");
        assert!(s.fault().unwrap().contains("more than 2 MiB"), "{:?}", s.fault());
    }
}
