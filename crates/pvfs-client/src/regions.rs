//! P7.2b (doc 20 §2.4) — region-generation replication.
//!
//! Generations are discovered by scanning ingested logs for `RegionBaseline`
//! rows: the top log names the first-level generations, each pulled generation
//! names its nested ones, and every pulled chain is verified against the
//! genesis seed derived from its **committed** baseline (root, seq,
//! state_root) — so a shipped region log is checked against the enclosing
//! log's commitment before a single row lands. Shared by `replica add`/`sync`
//! and the follow loop's per-wake sweep.

use std::collections::HashSet;
use std::path::Path;

use pvfs_core::error::PvfsError;
use pvfs_core::{log_store, replica, ReplicaStore};

use crate::{Client, ClientError};

const BATCH: u32 = 512;

/// Pull region generations from the source, recursively, until caught up.
/// Returns the number of rows ingested. `scope` limits the pull to one region
/// root's generations (and everything nested inside them, discovered from the
/// pulled logs); `None` pulls every generation the store's logs name. A
/// `region_not_held` from the source (a partial replica serving us) skips
/// that generation — its rows stay attested-but-unfetched.
pub fn sync_generations(
    client: &mut Client,
    data_dir: &Path,
    scope: Option<&str>,
) -> Result<usize, PvfsError> {
    let store = ReplicaStore::open(data_dir)?;
    let (instance_id, forest_id) = match store.identity() {
        Ok(v) => v,
        // nothing ingested yet — nothing to discover
        Err(_) => return Ok(0),
    };
    let mut pulled = 0usize;
    let mut visited: HashSet<String> = HashSet::new();
    // (host log's rel file — None = top, host log id, host was in scope)
    let mut queue: Vec<(Option<String>, String, bool)> = vec![(None, String::new(), false)];
    let mut store = store;
    while let Some((host_rel, host_id, host_in_scope)) = queue.pop() {
        for (root, bseq, state_root) in store.scan_baselines(host_rel.as_deref())? {
            // in scope: everything (no filter), the target root itself, or
            // anything discovered inside an already-pulled scoped generation
            let in_scope = match scope {
                None => true,
                Some(target) => host_in_scope || root == target,
            };
            if !in_scope {
                continue;
            }
            let addr = replica::region_addr(&root, &host_id, bseq);
            if !visited.insert(addr.clone()) {
                continue;
            }
            let rel_file = format!("regions/{addr}");
            let genesis =
                log_store::region_genesis_seed(&instance_id, &forest_id, &root, bseq, &state_root);
            pulled += pull_generation(client, &mut store, &addr, &rel_file, &genesis)?;
            queue.push((Some(rel_file), root, true));
        }
    }
    Ok(pulled)
}

fn pull_generation(
    client: &mut Client,
    store: &mut ReplicaStore,
    addr: &str,
    rel_file: &str,
    genesis: &[u8; 32],
) -> Result<usize, PvfsError> {
    let mut pulled = 0usize;
    loop {
        let from = store.region_tip(rel_file)? + 1;
        let (tip, events) = match client.log_read(from, BATCH, addr) {
            Ok(v) => v,
            Err(ClientError::Server { code, .. }) if code == "region_not_held" => {
                return Ok(pulled); // partial source — stays attested-but-unfetched
            }
            Err(e) => {
                return Err(PvfsError::BadInput {
                    field: "replica".into(),
                    reason: format!("region ship failed ({e})"),
                })
            }
        };
        if events.is_empty() {
            return Ok(pulled);
        }
        let rows = crate::follow::wire_rows(&events)?;
        let got = rows.len();
        store.append_region(rel_file, genesis, &rows)?;
        pulled += got;
        if store.region_tip(rel_file)? >= tip {
            return Ok(pulled);
        }
    }
}
