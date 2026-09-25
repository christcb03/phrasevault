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
    /// PVOS D183: claims taken as provisional heads — `(region, seq, from)`.
    pub claims_taken: Vec<(String, u64, String)>,
    /// PVOS D183: claims refused — `(from, why)`.
    pub claims_refused: Vec<(String, String)>,
    /// PVOS D183: this box's own pending heads committed through the owner.
    pub committed: usize,
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
    // PVOS D183 — first, this box's own heads published while the owner was
    // away: committed now if the owner answers (quietly left for the next
    // pass if it does not).
    if engine.is_replica() && !engine.pending_region_heads()?.is_empty() {
        if let Ok(Some((mut client, sign))) = crate::advertise::replica_route(engine.data_dir(), true) {
            let signer: &dyn Fn(&[u8; 32]) -> Vec<u8> = &*sign;
            let data_dir = engine.data_dir().to_path_buf();
            let committed = {
                let mut w = crate::advertise::RoutedScanWriter::new(&data_dir, &mut client, signer);
                crate::watch::commit_pending_heads(engine, &mut w)
            };
            match committed {
                Ok(n) => {
                    report.committed = n;
                    crate::advertise::catch_up(&data_dir, &mut client);
                }
                Err(e) => eprintln!("pvfs: catalogue: pending heads not committed yet: {e}"),
            }
        }
    }
    // PVOS D183 — then every peer's signed claims for the regions it owns,
    // taken as provisional heads on the fold's own rule; each remembered with
    // the box that made it, which is the box that holds the manifest.
    let claimed_by = collect_claims(engine, &mut report)?;
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
        // The box that claimed a provisional head holds its manifest: ask it first.
        let mut order: Vec<&(String, String)> = endpoints.iter().collect();
        if let Some(from) = claimed_by.get(&region) {
            order.sort_by_key(|(_, addr)| addr != from);
        }
        for (pin, addr) in order {
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

/// PVOS D183 — ask every announced endpoint (minus this box) for its signed
/// claims (`RegionClaims`, proto 12; an older daemon is skipped) and take each
/// the fold's rule accepts as the region's provisional head. Returns, per
/// region taken, the address that claimed it.
fn collect_claims(
    engine: &Engine,
    report: &mut CatalogueReport,
) -> Result<std::collections::HashMap<String, String>, PvfsError> {
    let mut claimed_by = std::collections::HashMap::new();
    let own_pin = pvfs_core::storage::host_pin(engine.data_dir());
    let mut endpoints: Vec<(String, String)> = crate::fetch::catalog_endpoints(engine)
        .into_iter()
        .filter(|(pin, _)| own_pin.as_deref() != Some(pin.as_str()))
        .collect();
    endpoints.sort();
    if endpoints.is_empty() {
        return Ok(claimed_by);
    }
    let mn = identity::client_identity_mnemonic()?;
    let key = identity::device_key(&mn, "", 0)?;
    let pubkey = pvfs_core::crypto::pubkey_bytes(&key);
    let sign = |d: &[u8; 32]| pvfs_core::crypto::sign_digest(&key, d).unwrap_or_default();
    for (pin, addr) in &endpoints {
        let Ok(mut client) = crate::Client::connect_tcp_signed(addr, pin, &pubkey, sign) else {
            continue; // down, or not ours: the manifest loop says so if it matters
        };
        if client.daemon_proto() < crate::REGION_CLAIMS_PROTO {
            continue;
        }
        let Ok(claims) = client.region_claims() else { continue };
        for c in claims {
            let Ok(body) = hex::decode(&c.body) else {
                report.claims_refused.push((addr.clone(), "claim body is not hex".into()));
                continue;
            };
            match engine.accept_region_claim(&body, addr)? {
                pvfs_core::ClaimOutcome::Accepted { region, seq } => {
                    claimed_by.insert(region.clone(), addr.clone());
                    report.claims_taken.push((region, seq, addr.clone()));
                }
                pvfs_core::ClaimOutcome::Known => {
                    claimed_by.entry(c.region.clone()).or_insert_with(|| addr.clone());
                }
                pvfs_core::ClaimOutcome::Refused(why) => {
                    eprintln!("pvfs: catalogue: a claim from {addr} for {} refused: {why}", &c.region[..c.region.len().min(8)]);
                    report.claims_refused.push((addr.clone(), why));
                }
            }
        }
    }
    Ok(claimed_by)
}
