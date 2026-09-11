//! D129 (doc 26 phase 5) — fetch the catalogue snapshots of the regions
//! this box does not catalogue itself, from whichever box holds them, and
//! install each only when it is exactly what the log attests.
//!
//! Who to ask: the fleet's announced endpoints (F5.7, `.fleet/endpoints`),
//! minus this box's own pin, in pin order. `region_not_held` or a dial
//! failure means the next box; nothing is special about the forest owner.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use pvfs_core::{identity, Engine, PvfsError, ReplicaSource};

use crate::ClientError;

/// What one pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CatalogueReport {
    /// `(region, head seq installed, rows)`.
    pub fetched: Vec<(String, u64, usize)>,
    /// Regions still behind after the pass: `(region, why)` — no endpoint
    /// held the manifest, or every dial failed.
    pub failed: Vec<(String, String)>,
    /// Endpoints tried (for the CLI's report).
    pub endpoints: usize,
    /// Catalogue regions that needed nothing: up to date, or this box's own.
    pub skipped: usize,
    pub cancelled: bool,
}

/// One pass over every stale, non-local catalogue region (doc 26 §8).
/// Opens the engine itself (the daemon's serve jobs each own their engine
/// for a pass); honours `cancel` between regions (D123).
pub fn fetch_pass(data_dir: &Path, cancel: &AtomicBool) -> Result<CatalogueReport, PvfsError> {
    let mut engine = Engine::open(data_dir)?;
    let r = fetch_pass_on(&mut engine, cancel, None);
    engine.close()?;
    r
}

/// [`fetch_pass`] over an engine the caller already holds (the CLI); `only`
/// narrows it to one region.
pub fn fetch_pass_on(
    engine: &mut Engine,
    cancel: &AtomicBool,
    only: Option<&str>,
) -> Result<CatalogueReport, PvfsError> {
    let mut report = CatalogueReport::default();
    let status = engine.catalogue_status()?;
    let wanted: Vec<(String, u64)> = status
        .iter()
        .filter(|s| only.is_none_or(|o| o == s.region))
        .filter(|s| s.stale && !s.local && s.head_seq > 0)
        .map(|s| (s.region.clone(), s.head_seq))
        .collect();
    report.skipped = status
        .iter()
        .filter(|s| only.is_none_or(|o| o == s.region))
        .count()
        - wanted.len();
    if wanted.is_empty() {
        return Ok(report);
    }
    // Endpoints: pin → address, minus ourselves, in a stable order.
    let own_pin = pvfs_core::storage::host_pin(engine.data_dir());
    let mut endpoints: Vec<(String, String)> = crate::fetch::catalog_endpoints(engine)
        .into_iter()
        .filter(|(pin, _)| own_pin.as_deref() != Some(pin.as_str()))
        .collect();
    endpoints.sort();
    report.endpoints = endpoints.len();
    if endpoints.is_empty() {
        for (region, _) in wanted {
            report.failed.push((region, "no announced endpoints to ask (fleet announce)".into()));
        }
        return Ok(report);
    }
    // The client identity dials; a member with read on the region is served.
    let mn = identity::client_identity_mnemonic()?;
    let key = identity::device_key(&mn, "", 0)?;
    let pubkey = pvfs_core::crypto::pubkey_bytes(&key);
    let sign = |d: &[u8; 32]| pvfs_core::crypto::sign_digest(&key, d).unwrap_or_default();
    for (region, seq) in wanted {
        if cancel.load(Ordering::SeqCst) {
            report.cancelled = true;
            break;
        }
        let mut last = String::from("no endpoint holds it");
        let mut done = false;
        for (pin, addr) in &endpoints {
            let src = ReplicaSource {
                transport: "tcp".into(),
                target: addr.clone(),
                pin: pin.clone(),
                region: String::new(),
            };
            let mut client = match crate::Client::connect_tcp_signed(&src.target, &src.pin, &pubkey, sign) {
                Ok(c) => c,
                Err(e) => {
                    last = format!("{addr}: {e}");
                    continue;
                }
            };
            match client.region_manifest(&region, seq) {
                Ok(bytes) => match engine.install_region_snapshot(&region, seq, &bytes, addr) {
                    Ok(n) => {
                        report.fetched.push((region.clone(), seq, n));
                        done = true;
                        break;
                    }
                    Err(e) => {
                        // A wrong manifest from one box is not a reason to
                        // stop asking the others.
                        last = format!("{addr}: refused: {e}");
                        continue;
                    }
                },
                Err(ClientError::Server { code, .. }) if code == "region_not_held" => continue,
                Err(e) => {
                    last = format!("{addr}: {e}");
                    continue;
                }
            }
        }
        if !done {
            report.failed.push((region, last));
        }
    }
    Ok(report)
}
