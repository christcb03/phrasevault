//! D129 (doc 26 phase 5) — fetch the catalogue snapshots of the regions
//! this box does not catalogue itself, from whichever box holds them, and
//! install each only when it is exactly what the log attests.
//!
//! Who to ask: the fleet's announced endpoints (F5.7, `.fleet/endpoints`),
//! minus this box's own pin, in pin order. `region_not_held` or a dial
//! failure means the next box; nothing is special about the forest owner.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use pvfs_core::{identity, Db, Engine, OwnDb, PvfsError, ReplicaSource};

use crate::ClientError;

/// What one pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CatalogueReport {
    /// `(region, head seq installed, what the install wrote)` — the rows,
    /// and since PVOS D194 how many were added, changed and removed.
    pub fetched: Vec<(String, u64, pvfs_core::SnapshotInstall)>,
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
    /// PVOS D183: claims refused — `(from, why)`; since PVOS D206 `why`
    /// starts with the region's short id (`<region8>: <why>`).
    pub claims_refused: Vec<(String, String)>,
    /// PVOS D183: this box's own pending heads committed through the owner.
    pub committed: usize,
}

impl CatalogueReport {
    /// PVOS D206 — the refused claims as one note for the catalogue job's
    /// row (`last_error`, D156's attention): the owner's health probe reads
    /// it, the notifier says it once it has stood (D151) and when it clears
    /// (D161), and the page lists it. `None` when nothing was refused.
    pub fn claims_note(&self) -> Option<String> {
        if self.claims_refused.is_empty() {
            return None;
        }
        let each: Vec<String> =
            self.claims_refused.iter().map(|(from, why)| format!("refused a region claim from {from}: {why}")).collect();
        Some(each.join("; "))
    }
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
    fetch_pass_db(&OwnDb::new(engine), cancel, only)
}

/// PVOS D199 — one pass through `db`. The daemon's catalogue job hands it
/// its one writer and a read view: the claims asked of every box, the
/// manifests fetched, their hashes and the deltas computed with no lock
/// held; each accepted claim and each install's rows are steps of the
/// writer. It used to open an engine of its own every 60 s — and fold the
/// log to do it — beside the daemon's.
pub fn fetch_pass_db<D: Db>(db: &D, cancel: &AtomicBool, only: Option<&str>) -> Result<CatalogueReport, PvfsError> {
    let mut report = CatalogueReport::default();
    let (replica, data_dir) = db.read(|e| Ok((e.is_replica(), e.data_dir().to_path_buf())))?;
    // PVOS D183 — first, this box's own heads published while the owner was
    // away: committed now if the owner answers (quietly left for the next
    // pass if it does not).
    if replica && !db.read(|e| e.pending_region_heads())?.is_empty() {
        if let Ok(Some((mut client, sign))) = crate::advertise::replica_route(&data_dir, true) {
            let signer: &dyn Fn(&[u8; 32]) -> Vec<u8> = &*sign;
            let committed = {
                let mut w = crate::advertise::RoutedScanWriter::new(&data_dir, &mut client, signer);
                crate::watch::commit_pending_heads_db(db, &mut w)
            };
            match committed {
                Ok(n) => {
                    report.committed = n;
                    crate::advertise::catch_up_db(db, &mut client);
                }
                Err(e) => eprintln!("pvfs: catalogue: pending heads not committed yet: {e}"),
            }
        }
    }
    // PVOS D183 — then every peer's signed claims for the regions it owns,
    // taken as provisional heads on the fold's own rule; each remembered with
    // the box that made it, which is the box that holds the manifest.
    let claimed_by = collect_claims(db, &data_dir, &mut report)?;
    let status = db.read(|e| e.catalogue_status())?;
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
    let own_pin = pvfs_core::storage::host_pin(&data_dir);
    let mut endpoints: Vec<(String, String)> = db
        .read(|e| Ok(crate::fetch::catalog_endpoints(e)))?
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
                Ok(bytes) => match pvfs_core::fs::install_region_snapshot_db(db, &region, seq, &bytes, addr, || {}) {
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
fn collect_claims<D: Db>(
    db: &D,
    data_dir: &Path,
    report: &mut CatalogueReport,
) -> Result<std::collections::HashMap<String, String>, PvfsError> {
    let mut claimed_by = std::collections::HashMap::new();
    let own_pin = pvfs_core::storage::host_pin(data_dir);
    let mut endpoints: Vec<(String, String)> = db
        .read(|e| Ok(crate::fetch::catalog_endpoints(e)))?
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
                report.claims_refused.push((addr.clone(), format!("{}: claim body is not hex", short_region(&c.region))));
                continue;
            };
            match db.write("claim", |e| e.accept_region_claim(&body, addr))? {
                pvfs_core::ClaimOutcome::Accepted { region, seq } => {
                    claimed_by.insert(region.clone(), addr.clone());
                    report.claims_taken.push((region, seq, addr.clone()));
                }
                pvfs_core::ClaimOutcome::Known => {
                    claimed_by.entry(c.region.clone()).or_insert_with(|| addr.clone());
                }
                pvfs_core::ClaimOutcome::Refused(why) => {
                    eprintln!("pvfs: catalogue: a claim from {addr} for {} refused: {why}", short_region(&c.region));
                    report.claims_refused.push((addr.clone(), format!("{}: {why}", short_region(&c.region))));
                }
            }
        }
    }
    Ok(claimed_by)
}

/// A region's short id for a person (its first 8 characters).
fn short_region(region: &str) -> &str {
    region.get(..8).unwrap_or(region)
}

#[cfg(test)]
mod d206_tests {
    use super::*;

    // PVOS D206 — a refused claim is a note on the catalogue job's row: none
    // when nothing was refused, every refusal with its box and region.
    #[test]
    fn refused_claims_become_one_note() {
        let mut r = CatalogueReport::default();
        assert_eq!(r.claims_note(), None);
        r.claims_refused.push(("192.168.1.142:7433".into(), "a1b2c3d4: its signature does not verify (bad)".into()));
        assert_eq!(
            r.claims_note().unwrap(),
            "refused a region claim from 192.168.1.142:7433: a1b2c3d4: its signature does not verify (bad)"
        );
        r.claims_refused.push(("192.168.1.237:7433".into(), "e5f6a7b8: claim body is not hex".into()));
        let note = r.claims_note().unwrap();
        assert!(note.contains("; refused a region claim from 192.168.1.237:7433: e5f6a7b8"), "{note}");
        assert_eq!(short_region("abc"), "abc");
        assert_eq!(short_region("0123456789abcdef"), "01234567");
    }
}
