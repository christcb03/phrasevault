//! D133 (doc 26 §7.3, the library side) — the mover on the new model. A box
//! that owns a *receiving* library region pulls, by content hash, every file
//! the merged view shows only on staging, and places it at the same relative
//! path; a staging winner replaces the library's losing copy (which goes to
//! the trash). The plan is `Engine::receive_plan`; this module moves the
//! bytes: this box's own copy when it has one, else the announced endpoints
//! in turn, 8 MiB ranges so a restart resumes and the D123 cancel flag is
//! honoured between ranges, a blake3 over the bytes as they land so the
//! whole-file check costs no second read, then sidecar, mtime, atomic rename.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use pvfs_core::media::Rules;
use pvfs_core::sync::{self, SWARM_CHUNK};
use pvfs_core::{Engine, PvfsError, ReceiveItem, ReplicaSource};

/// Free bytes a receiving root must keep after a placement.
pub const MIN_FREE_BYTES: u64 = 1 << 30;
const INCOMING: &str = ".pvfs-incoming";

/// What one pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReceiveReport {
    /// `(rel_path, hash, dest_region)` placed (or, dry-run, planned).
    pub received: Vec<(String, String, String)>,
    /// Paths whose library copy was replaced by the staging winner.
    pub replaced: Vec<String>,
    pub skipped_no_space: Vec<String>,
    pub failed: Vec<(String, String)>,
    /// What the plan would not act on, and why.
    pub reported: Vec<(String, String)>,
    pub cancelled: bool,
    pub dry_run: bool,
}

/// One pass: open the engine, plan, pull, place.
pub fn receive_pass(
    data_dir: &Path,
    rules: &Rules,
    dry_run: bool,
    min_free: u64,
    cancel: &AtomicBool,
) -> Result<ReceiveReport, PvfsError> {
    let engine = Engine::open(data_dir)?;
    let r = receive_pass_on(&engine, rules, dry_run, min_free, cancel);
    engine.close()?;
    r
}

/// [`receive_pass`] over an engine the caller holds (the CLI, tests).
pub fn receive_pass_on(
    engine: &Engine,
    rules: &Rules,
    dry_run: bool,
    min_free: u64,
    cancel: &AtomicBool,
) -> Result<ReceiveReport, PvfsError> {
    let mut report = ReceiveReport { dry_run, ..Default::default() };
    let (items, skips) = engine.receive_plan(rules)?;
    report.reported = skips.into_iter().map(|s| (s.rel_path, s.why)).collect();
    if dry_run {
        for it in &items {
            report.received.push((it.rel_path.clone(), it.hash.clone(), it.dest_region.clone()));
            if it.replaces {
                report.replaced.push(it.rel_path.clone());
            }
        }
        return Ok(report);
    }
    if items.is_empty() {
        return Ok(report);
    }
    let sources = announced_sources(engine);
    for it in items {
        if cancel.load(Ordering::SeqCst) {
            report.cancelled = true;
            break;
        }
        // Already placed by an earlier pass (or the job, racing a one-shot)
        // and not yet catalogued by this box's watch: the plan still names
        // it, and the right move is to wait, not to pull it again or call
        // it a failure. A planned replacement whose destination already holds
        // the winner is the same case: the old library row simply has not been
        // re-catalogued yet.
        let dest = it.dest_root.join(&it.rel_path);
        if dest.is_file() && sync::sidecar_whole_hash(&dest, it.size_bytes).as_deref() == Some(it.hash.as_str()) {
            report.reported.push((it.rel_path.clone(), "already placed here, awaiting the watch".into()));
            continue;
        }
        let free = pvfs_core::ingest::free_space_at(&it.dest_root).unwrap_or(0);
        if free < it.size_bytes.saturating_add(min_free) {
            report.skipped_no_space.push(it.rel_path.clone());
            continue;
        }
        let local = engine
            .local_path_for_hash(&it.hash)
            .ok()
            .flatten()
            .filter(|lb| lb.size == it.size_bytes)
            .map(|lb| lb.path);
        match pull_into_partial(&it, local.as_deref(), &sources, cancel) {
            Ok(Some(chunks)) => match place(&it, &chunks) {
                Ok(()) => {
                    report.received.push((it.rel_path.clone(), it.hash.clone(), it.dest_region.clone()));
                    if it.replaces {
                        report.replaced.push(it.rel_path.clone());
                    }
                }
                Err(e) => report.failed.push((it.rel_path.clone(), e)),
            },
            Ok(None) => {
                report.cancelled = true;
                break;
            }
            Err(e) => report.failed.push((it.rel_path.clone(), e)),
        }
    }
    Ok(report)
}

/// The announced endpoints minus this box, in pin order.
pub fn announced_sources(engine: &Engine) -> Vec<ReplicaSource> {
    let own = pvfs_core::storage::host_pin(engine.data_dir());
    let mut eps: Vec<(String, String)> = crate::fetch::catalog_endpoints(engine)
        .into_iter()
        .filter(|(pin, _)| own.as_deref() != Some(pin.as_str()))
        .collect();
    eps.sort();
    eps.into_iter()
        .map(|(pin, addr)| ReplicaSource {
            transport: "tcp".into(),
            target: addr,
            pin,
            region: String::new(),
        })
        .collect()
}

pub fn partial_path(it: &ReceiveItem) -> PathBuf {
    it.dest_root.join(INCOMING).join(format!("{}.partial", it.hash))
}

/// Bring `<dest_root>/.pvfs-incoming/<hash>.partial` to the item's full,
/// verified bytes: from `local` when this box holds them, else from
/// `sources` in turn, resuming from what an earlier attempt left. Returns
/// the per-chunk hashes for the sidecar, `None` when cancelled (the partial
/// is kept for the next pass), an error when no source could supply bytes
/// whose blake3 is the item's hash.
pub fn pull_into_partial(
    it: &ReceiveItem,
    local: Option<&Path>,
    sources: &[ReplicaSource],
    cancel: &AtomicBool,
) -> Result<Option<Vec<[u8; 32]>>, String> {
    let part = partial_path(it);
    std::fs::create_dir_all(part.parent().unwrap()).map_err(|e| format!("incoming dir: {e}"))?;
    if let Some(src) = local {
        std::fs::copy(src, &part).map_err(|e| format!("local copy: {e}"))?;
        let (whole, chunks) = hash_file(&part).map_err(|e| format!("hash local copy: {e}"))?;
        if whole != it.hash {
            let _ = std::fs::remove_file(&part);
            return Err(format!("this box's copy at {} no longer hashes to {}", src.display(), &it.hash[..12]));
        }
        return Ok(Some(chunks));
    }
    // Resume: keep the whole chunks an earlier attempt landed, re-hashed.
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(&part)
        .map_err(|e| format!("open partial: {e}"))?;
    let mut have = file.metadata().map(|m| m.len()).unwrap_or(0);
    if have > it.size_bytes || have % SWARM_CHUNK != 0 {
        have = (have.min(it.size_bytes) / SWARM_CHUNK) * SWARM_CHUNK;
        file.set_len(have).map_err(|e| format!("truncate partial: {e}"))?;
    }
    let mut whole = blake3::Hasher::new();
    let mut chunks: Vec<[u8; 32]> = Vec::new();
    if have > 0 {
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; SWARM_CHUNK as usize];
        let mut left = have;
        while left > 0 {
            let n = left.min(SWARM_CHUNK) as usize;
            file.read_exact(&mut buf[..n]).map_err(|e| format!("re-read partial: {e}"))?;
            whole.update(&buf[..n]);
            chunks.push(*blake3::hash(&buf[..n]).as_bytes());
            left -= n as u64;
        }
        file.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
    }
    let mut off = have;
    let mut last = String::from("no announced endpoint holds these bytes");
    'sources: for src in sources {
        if off >= it.size_bytes {
            break;
        }
        let mut client = match crate::follow::dial_source(src) {
            Ok(c) => c,
            Err(e) => {
                last = format!("{}: {e}", src.target);
                continue;
            }
        };
        while off < it.size_bytes {
            if cancel.load(Ordering::SeqCst) {
                return Ok(None);
            }
            let len = (it.size_bytes - off).min(SWARM_CHUNK);
            let mut buf: Vec<u8> = Vec::with_capacity(len as usize);
            match client.cat_hash_range(&it.hash, off, len, &mut buf) {
                Ok(n) if n == len && buf.len() as u64 == len => {
                    file.write_all(&buf).map_err(|e| format!("write partial: {e}"))?;
                    whole.update(&buf);
                    chunks.push(*blake3::hash(&buf).as_bytes());
                    off += len;
                }
                Ok(n) => {
                    last = format!("{}: short range, {n} of {len} bytes at {off}", src.target);
                    continue 'sources;
                }
                Err(crate::ClientError::Server { code, .. }) if code == "not_found" => {
                    continue 'sources;
                }
                Err(e) => {
                    last = format!("{}: {e}", src.target);
                    continue 'sources;
                }
            }
        }
    }
    if off < it.size_bytes {
        return Err(last); // the partial stays for the next pass
    }
    drop(file);
    let got = whole.finalize().to_hex().to_string();
    if got != it.hash {
        let _ = std::fs::remove_file(&part);
        return Err(format!(
            "served bytes whose hash is {}, not {} — refused",
            &got[..got.len().min(16)],
            &it.hash[..it.hash.len().min(16)]
        ));
    }
    Ok(Some(chunks))
}

/// The verified partial becomes the file: mtime from the row, the replaced
/// library copy to the trash, parents created, one atomic rename, then the
/// sidecar so the watch does not re-hash it.
fn place(it: &ReceiveItem, chunks: &[[u8; 32]]) -> Result<(), String> {
    let part = partial_path(it);
    let dest = it.dest_root.join(&it.rel_path);
    {
        let f = std::fs::File::options().write(true).open(&part).map_err(|e| e.to_string())?;
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_millis(it.mtime_ms);
        let _ = f.set_modified(t);
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    if dest.exists() {
        if !it.replaces {
            let _ = std::fs::remove_file(&part);
            return Err(format!("{} already exists and is not the planned replacement", dest.display()));
        }
        sync::move_to_trash(&it.dest_root, &dest).map_err(|e| format!("trash the old copy: {e}"))?;
    }
    std::fs::rename(&part, &dest).map_err(|e| format!("place {}: {e}", dest.display()))?;
    sync::write_manifest_sidecar(&dest, Some(&it.hash), chunks).map_err(|e| format!("sidecar: {e}"))?;
    Ok(())
}

/// Whole-file blake3 and the per-`SWARM_CHUNK` hashes, one read.
pub fn hash_file(path: &Path) -> std::io::Result<(String, Vec<[u8; 32]>)> {
    let mut f = std::fs::File::open(path)?;
    let mut whole = blake3::Hasher::new();
    let mut chunks = Vec::new();
    let mut buf = vec![0u8; SWARM_CHUNK as usize];
    loop {
        let mut n = 0usize;
        while n < buf.len() {
            let k = f.read(&mut buf[n..])?;
            if k == 0 {
                break;
            }
            n += k;
        }
        if n == 0 {
            break;
        }
        whole.update(&buf[..n]);
        chunks.push(*blake3::hash(&buf[..n]).as_bytes());
        if n < buf.len() {
            break;
        }
    }
    Ok((whole.finalize().to_hex().to_string(), chunks))
}
