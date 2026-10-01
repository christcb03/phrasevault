//! PVOS D211 — measure video quality for a box that cannot: the NAS has no
//! ffprobe (Chris, 2026-10-01: "I do not want to install ffprobe on the NAS.
//! If we need to probe those, let's do it from mediabox over the LAN.").
//!
//! A box that has ffprobe and the holder's catalogue (mediabox has every
//! NAS region's rows, installed from the NAS's manifests) probes the regions
//! named in its `probe-remote` file:
//!
//! * **LAN only** — the holder is the box the region's manifest came from
//!   (D210's `region_holders`); a plain TCP connect to it must take under
//!   [`LAN_MAX_CONNECT`] or the region is skipped (feederbox is a WAN away).
//! * **Ranges, not files** — ffprobe reads `http://127.0.0.1:…` from a
//!   one-probe server ([`pvfs_core::probe::RangeServer`]) that fetches each
//!   range it asks for from the holder by hash (`CatHash`), at most
//!   64 MiB a probe; a fault fetching is an error, never "broken".
//! * **D208's limits** — 300 files or 60 s a pass (all regions), 30 s a
//!   file, newest first, one ffprobe at a time, no lock held: the pass reads
//!   a read view and writes nothing on this box (D199).
//! * **The holder writes its own row** — `SetRegionQuality`, gated by `w` on
//!   the region; the holder checks the copy and applies its rule (a first
//!   "invalid data" is only a suspect). Its next watch pass publishes it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pvfs_core::media::Observed;
use pvfs_core::probe::{ProbeOutcome, Prober, RangeServer, RangeSource, REMOTE_PROBE_MAX_BYTES};
use pvfs_core::{Engine, PvfsError, ReplicaSource};

use crate::ClientError;

/// A holder that takes longer than this to accept a TCP connection is not on
/// this box's LAN (best of three tries).
pub const LAN_MAX_CONNECT: Duration = Duration::from_millis(10);
/// What the probe step leaves alone after it handed a result over: the
/// holder publishes it at its next pass (hourly at worst), and until this box
/// installs that head its own copy of the row still reads unmeasured.
pub const SENT_KEEP: Duration = Duration::from_secs(3 * 3600);

/// The options and the memory of the probe step, kept by the daemon's
/// runner between passes.
pub struct RemoteProbe {
    pub prober: Prober,
    pub max_files: usize,
    pub max_time: Duration,
    pub timeout: Duration,
    /// The LAN test; `None` skips it (tests on Unix sockets have no TCP).
    pub lan_max_connect: Option<Duration>,
    /// A test's clock for the candidates (ms); `None` = the system's.
    pub now_ms: Option<u64>,
    /// `(region, rel_path, size, mtime)` handed to the holder, and when.
    sent: Mutex<HashMap<(String, String, u64, u64), Instant>>,
    /// `(region, rel_path)` whose probe could not run, and when.
    errored: Mutex<HashMap<(String, String), Instant>>,
}

impl RemoteProbe {
    /// The daemon's settings with `prober`: D208's budget.
    pub fn new(prober: Prober) -> RemoteProbe {
        RemoteProbe {
            prober,
            max_files: pvfs_core::fs::PROBE_MAX_FILES,
            max_time: Duration::from_secs(pvfs_core::fs::PROBE_MAX_SECS),
            timeout: Duration::from_secs(pvfs_core::fs::PROBE_TIMEOUT_SECS),
            lan_max_connect: Some(LAN_MAX_CONNECT),
            now_ms: None,
            sent: Mutex::new(HashMap::new()),
            errored: Mutex::new(HashMap::new()),
        }
    }

    fn now(&self) -> u64 {
        self.now_ms.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0)
        })
    }

    fn resting(&self, region: &str, rel: &str, size: u64, mtime: u64) -> bool {
        let mut sent = self.sent.lock().unwrap_or_else(|p| p.into_inner());
        sent.retain(|_, at| at.elapsed() < SENT_KEEP);
        let mut errored = self.errored.lock().unwrap_or_else(|p| p.into_inner());
        errored.retain(|_, at| at.elapsed() < pvfs_core::fs::PROBE_ERROR_BACKOFF);
        sent.contains_key(&(region.to_string(), rel.to_string(), size, mtime))
            || errored.contains_key(&(region.to_string(), rel.to_string()))
    }
}

/// What one pass did for one region.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegionProbeReport {
    pub region: String,
    /// Why the region was not probed this pass (not listed is fine: empty).
    pub skipped: Option<String>,
    /// Measurements handed to the holder (read here, or reused by hash).
    pub measured: u64,
    /// …of which reused from a row with the same bytes (nothing read).
    pub reused: u64,
    /// "Invalid data" observations handed to the holder.
    pub broken: u64,
    /// Probes that could not run (nothing handed over).
    pub errors: u64,
    /// Files left for a later pass.
    pub pending: u64,
    /// The holder's refusals, one line each.
    pub refused: Vec<String>,
}

/// Bytes of one file, by hash, from the holder's daemon.
struct HolderBytes {
    client: Arc<Mutex<crate::Client>>,
    hash: String,
}

impl RangeSource for HolderBytes {
    fn read_range(&self, offset: u64, len: u64, out: &mut Vec<u8>) -> Result<(), String> {
        let mut c = self.client.lock().unwrap_or_else(|p| p.into_inner());
        c.cat_hash_range(&self.hash, offset, len, out).map(|_| ()).map_err(|e| e.to_string())
    }
}

/// The best of three TCP connects to `addr`, or why none connected.
fn connect_time(addr: &str) -> Result<Duration, String> {
    use std::net::ToSocketAddrs;
    let sa = addr
        .to_socket_addrs()
        .map_err(|e| format!("{addr}: {e}"))?
        .next()
        .ok_or_else(|| format!("{addr}: no address"))?;
    let mut best: Option<Duration> = None;
    let mut why = String::new();
    for _ in 0..3 {
        let t = Instant::now();
        match std::net::TcpStream::connect_timeout(&sa, Duration::from_secs(2)) {
            Ok(_) => best = Some(best.map_or(t.elapsed(), |b| b.min(t.elapsed()))),
            Err(e) => why = format!("{addr}: {e}"),
        }
    }
    best.ok_or(why)
}

/// One pass of the remote probe step over the regions listed in this box's
/// `probe-remote` file, reading candidates from `view` and dialing the
/// holders among `sources`. Stops at the budget or when `cancel` is raised.
pub fn remote_probe_pass(
    view: &Engine,
    sources: &[ReplicaSource],
    rp: &RemoteProbe,
    cancel: &AtomicBool,
) -> Result<Vec<RegionProbeReport>, PvfsError> {
    let regions = pvfs_core::sync::probe_remote_regions(view.data_dir())?;
    remote_probe_regions(view, &regions, sources, rp, cancel)
}

/// [`remote_probe_pass`] over `regions`.
pub fn remote_probe_regions(
    view: &Engine,
    regions: &[String],
    sources: &[ReplicaSource],
    rp: &RemoteProbe,
    cancel: &AtomicBool,
) -> Result<Vec<RegionProbeReport>, PvfsError> {
    let mut out = Vec::new();
    if regions.is_empty() {
        return Ok(out);
    }
    let holders = view.region_holders()?;
    let local: std::collections::HashSet<String> =
        view.catalogue_status()?.into_iter().filter(|s| s.local).map(|s| s.region).collect();
    let started = Instant::now();
    let mut tried = 0usize;
    let now = rp.now();
    for region in regions {
        let mut rep = RegionProbeReport { region: region.clone(), ..Default::default() };
        let short = &region[..region.len().min(8)];
        if local.contains(region) {
            rep.skipped = Some("this box holds it: its own watch measures it".into());
            out.push(rep);
            continue;
        }
        let Some(addr) = holders.get(region) else {
            rep.skipped = Some("no holder known (its manifest has not been fetched)".into());
            out.push(rep);
            continue;
        };
        let Some(src) = sources.iter().find(|s| &s.target == addr) else {
            rep.skipped = Some(format!("its holder {addr} is not an announced box"));
            out.push(rep);
            continue;
        };
        let candidates: Vec<(String, u64, u64, String)> = view
            .quality_candidates_hashed_at(region, now)?
            .into_iter()
            .filter_map(|(rel, size, mtime, hash)| hash.map(|h| (rel, size, mtime, h)))
            .filter(|(rel, size, mtime, _)| !rp.resting(region, rel, *size, *mtime))
            .collect();
        if candidates.is_empty() {
            out.push(rep);
            continue;
        }
        if let (Some(max), "tcp") = (rp.lan_max_connect, src.transport.as_str()) {
            match connect_time(&src.target) {
                Ok(t) if t <= max => {}
                Ok(t) => {
                    rep.skipped = Some(format!(
                        "its holder {addr} looks remote ({} ms to connect); D211 probes over the LAN only",
                        t.as_millis()
                    ));
                    rep.pending = candidates.len() as u64;
                    out.push(rep);
                    continue;
                }
                Err(e) => {
                    rep.skipped = Some(format!("its holder does not answer: {e}"));
                    rep.pending = candidates.len() as u64;
                    out.push(rep);
                    continue;
                }
            }
        }
        let client = match crate::follow::dial_source(src) {
            Ok(c) => Arc::new(Mutex::new(c)),
            Err(e) => {
                rep.skipped = Some(format!("dialing its holder: {e}"));
                rep.pending = candidates.len() as u64;
                out.push(rep);
                continue;
            }
        };
        let mut done = 0u64;
        for (rel, size, mtime, hash) in &candidates {
            if tried >= rp.max_files || started.elapsed() >= rp.max_time || cancel.load(Ordering::SeqCst) {
                break;
            }
            // Quality belongs to the bytes: a measurement of the same hash
            // anywhere this box knows is handed over without a read.
            let observed = match view.measured_quality_by_hash(hash)? {
                Some(q) => {
                    rep.reused += 1;
                    Observed::decode_wire(&q)
                }
                None => {
                    tried += 1;
                    let ext = rel.rsplit_once('.').map(|(_, e)| e).unwrap_or("bin");
                    let source = Arc::new(HolderBytes { client: Arc::clone(&client), hash: hash.clone() });
                    let outcome = match RangeServer::start(source, *size, ext, REMOTE_PROBE_MAX_BYTES) {
                        Err(e) => ProbeOutcome::Error(format!("a local server for ffprobe: {e}")),
                        Ok(server) => {
                            let o = rp.prober.probe_input(
                                std::ffi::OsStr::new(server.url()),
                                &["-protocol_whitelist", "http,tcp"],
                                rp.timeout,
                                Some(cancel),
                            );
                            match (server.fault(), o) {
                                // A fetch that failed or a read past the cap:
                                // whatever ffprobe made of it, not the file.
                                (Some(f), ProbeOutcome::Measured(_) | ProbeOutcome::Broken(_) | ProbeOutcome::Error(_)) => {
                                    ProbeOutcome::Error(f)
                                }
                                (_, o) => o,
                            }
                        }
                    };
                    match outcome {
                        ProbeOutcome::Measured(q) => Some(Observed::Measured(q)),
                        ProbeOutcome::Broken(why) => {
                            eprintln!("pvfsd: probe: ffprobe could not read {rel} ({short}, over the LAN): {why}");
                            Some(Observed::Broken)
                        }
                        ProbeOutcome::Error(why) => {
                            rep.errors += 1;
                            rp.errored
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .insert((region.clone(), rel.clone()), Instant::now());
                            eprintln!("pvfsd: probe: {rel} ({short}) could not be probed: {why}; nothing recorded");
                            None
                        }
                        ProbeOutcome::TimedOut => {
                            eprintln!("pvfsd: probe: {rel} ({short}) still running after {} s; killed", rp.timeout.as_secs());
                            None
                        }
                        ProbeOutcome::Cancelled => break,
                        ProbeOutcome::Unavailable(why) => {
                            eprintln!("pvfsd: probe: the prober would not start ({why}); measuring stops for this pass");
                            break;
                        }
                    }
                }
            };
            let Some(observed) = observed else {
                done += 1;
                continue;
            };
            let sent = client
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .set_region_quality(region, rel, hash, *size, *mtime, &observed.encode());
            done += 1;
            match sent {
                Ok(_) => {
                    rp.sent
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert((region.clone(), rel.clone(), *size, *mtime), Instant::now());
                    match observed {
                        Observed::Measured(_) => rep.measured += 1,
                        Observed::Broken => rep.broken += 1,
                    }
                }
                Err(ClientError::Server { code, message }) if code == "conflict" || code == "not_found" => {
                    // the holder's copy moved on: its next head says how
                    rep.refused.push(format!("{rel}: {code}: {message}"));
                    rp.sent
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert((region.clone(), rel.clone(), *size, *mtime), Instant::now());
                }
                Err(ClientError::Server { code, message }) => {
                    rep.refused.push(format!("{rel}: {code}: {message}"));
                    break; // forbidden, an old holder: the rest would say the same
                }
                Err(e) => {
                    rep.refused.push(format!("{rel}: {e}"));
                    break; // the connection is gone
                }
            }
        }
        rep.pending = (candidates.len() as u64).saturating_sub(done);
        out.push(rep);
        if cancel.load(Ordering::SeqCst) {
            break;
        }
    }
    Ok(out)
}

/// The journal lines for a pass: one per region that did or said anything.
pub fn report_lines(reports: &[RegionProbeReport]) -> Vec<String> {
    let mut out = Vec::new();
    for r in reports {
        let short = &r.region[..r.region.len().min(8)];
        if let Some(why) = &r.skipped {
            out.push(format!("pvfsd: probe: region {short} skipped: {why}"));
        }
        if r.measured + r.broken + r.errors > 0 || !r.refused.is_empty() {
            out.push(format!(
                "pvfsd: probe: region {short} for its holder: {} measured ({} by the same bytes), {} unreadable, {} could not run, {} left",
                r.measured, r.reused, r.broken, r.errors, r.pending
            ));
        }
        for line in &r.refused {
            out.push(format!("pvfsd: probe: region {short}: the holder refused {line}"));
        }
    }
    out
}
