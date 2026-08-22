//! D81 4c — an upgrade must find the copy it supersedes, on whichever volume.
//!
//! Unblocked by per-root staging marks: `BindKind` was derived per FOLDER, so
//! "feederbox drains, Data_ext keeps" was inexpressible. A root is now a
//! LIBRARY root unless marked staging (Chris: default to keeps; only
//! feederbox's /mnt/local/Media drains).

use pvfs_core::media::Rules;
use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

fn spec(dir: &std::path::Path) -> BindSpec {
    BindSpec {
        source_uri: format!("file://{}", dir.display()),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::Lazy,
    }
}

struct Rig {
    _tmp: tempfile::TempDir,
    engine: Engine,
    data_dir: std::path::PathBuf,
    warm: std::path::PathBuf,
    cold: std::path::PathBuf,
    media: String,
}

/// A cold title on `Data_ext`, and its upgrade waiting in staging.
fn rig(cold_bytes: usize, new_bytes: usize) -> Rig {
    let tmp = tempfile::tempdir().unwrap();
    let warm = tmp.path().join("Data");
    let cold = tmp.path().join("Data_ext");
    let staging = tmp.path().join("incoming");
    let rel = "Movies/Cold Title (1998)/cold.mkv";
    std::fs::create_dir_all(warm.join("Movies")).unwrap();
    std::fs::create_dir_all(cold.join("Movies/Cold Title (1998)")).unwrap();
    std::fs::create_dir_all(staging.join("Movies/Cold Title (1998)")).unwrap();
    std::fs::write(cold.join(rel), vec![1u8; cold_bytes]).unwrap();
    std::fs::write(staging.join(rel), vec![2u8; new_bytes]).unwrap();

    let (mut engine, _mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let media = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "Media".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    engine.bind_folder(&media, spec(&staging)).unwrap();
    engine.bind_folder(&media, spec(&cold)).unwrap();
    engine.scan_routed(Some(&media), None, 0).unwrap();

    let data_dir = engine.data_dir().to_path_buf();
    pvfs_core::sync::set_central(&data_dir, &media, &warm, false).unwrap();
    pvfs_core::sync::set_central_tree(&data_dir, &media, true).unwrap();
    // Chris's topology, now expressible: ONLY the ingest root drains. The cold
    // volume is a library root and keeps what it holds.
    pvfs_core::sync::set_staging_root(
        &data_dir,
        &media,
        &format!("file://{}", staging.display()),
        true,
    )
    .unwrap();
    Rig { _tmp: tmp, engine, data_dir, warm, cold, media }
}

fn cold_copy(r: &Rig) -> std::path::PathBuf {
    r.cold.join("Movies/Cold Title (1998)/cold.mkv")
}

/// WITHOUT `--rules`: refuse, and say where the other copy is.
///
/// The default has always been "I will not guess"; what changes is that it can
/// now SEE the thing it would have to guess about.
#[test]
fn a_copy_on_another_root_is_detected_and_refused_by_default() {
    let mut r = rig(3000, 9000);
    let mut fetcher = pvfs_client::fetch::Fetcher::new(&r.data_dir);
    let report = pvfs_client::fetch::tier_pass_ruled(&mut r.engine, &mut fetcher, true, None)
        .unwrap()
        .expect("a central placement exists");

    assert!(
        report.failed.iter().any(|(_, why)| why.contains("Data_ext")),
        "it must NAME the volume holding the other copy: {:?}",
        report.failed
    );
    assert!(
        report.failed.iter().any(|(_, why)| why.contains("--rules")),
        "and say what would let it decide: {:?}",
        report.failed
    );
    assert!(cold_copy(&r).exists(), "and touch nothing");
    r.engine.close().unwrap();
}

/// WITH `--rules`, and a dry run: plan the trash, on the cold volume.
#[test]
fn with_rules_the_dry_run_plans_to_trash_the_loser_where_it_lives() {
    let mut r = rig(3000, 9000);
    let mut fetcher = pvfs_client::fetch::Fetcher::new(&r.data_dir);
    let report = pvfs_client::fetch::tier_pass_ruled(
        &mut r.engine,
        &mut fetcher,
        true,
        Some(Rules::default()),
    )
    .unwrap()
    .expect("a central placement exists");

    assert!(
        report
            .planned
            .iter()
            .any(|p| p.contains("WOULD TRASH") && p.contains("Data_ext")),
        "the loser is on the cold volume and the plan must say so: {:?}",
        report.planned
    );
    assert!(
        cold_copy(&r).exists(),
        "a DRY run still changes nothing at all"
    );
    r.engine.close().unwrap();
}

/// For real: the new copy lands on the write target, the superseded one is
/// trashed on its OWN volume, and nothing is deleted.
#[test]
fn the_superseded_cold_copy_is_trashed_on_its_own_volume() {
    let mut r = rig(3000, 9000);
    let mut fetcher = pvfs_client::fetch::Fetcher::new(&r.data_dir);
    pvfs_client::fetch::tier_pass_ruled(
        &mut r.engine,
        &mut fetcher,
        false,
        Some(Rules::default()),
    )
    .unwrap()
    .expect("a central placement exists");

    assert!(
        !cold_copy(&r).exists(),
        "the superseded copy is gone from where it sat"
    );
    let trashed = walk_find(&r.cold, "cold.mkv");
    assert!(
        trashed.is_some(),
        "…but TRASHED, not deleted, and on the cold volume — never copied \
         across filesystems to reach the warm one's trash"
    );
    assert!(
        r.warm.join("Movies/Cold Title (1998)/cold.mkv").exists(),
        "and the upgrade landed at the write target"
    );
    r.engine.close().unwrap();
}

/// The occupant can WIN — bigger is not automatically newer-is-better.
#[test]
fn when_the_existing_copy_wins_the_incoming_one_does_not_land() {
    let mut r = rig(9000, 3000); // the cold copy is much larger
    let mut fetcher = pvfs_client::fetch::Fetcher::new(&r.data_dir);
    let report = pvfs_client::fetch::tier_pass_ruled(
        &mut r.engine,
        &mut fetcher,
        false,
        Some(Rules::default()),
    )
    .unwrap()
    .expect("a central placement exists");

    assert!(
        report.failed.iter().any(|(_, why)| why.contains("wins")),
        "a decision, reported as one: {:?}",
        report.failed
    );
    assert!(cold_copy(&r).exists(), "the winner stays put");
    assert!(
        !r.warm.join("Movies/Cold Title (1998)/cold.mkv").exists(),
        "and the loser is not placed"
    );
    r.engine.close().unwrap();
}

fn walk_find(dir: &std::path::Path, name: &str) -> Option<std::path::PathBuf> {
    let mut hit = None;
    fn walk(d: &std::path::Path, name: &str, hit: &mut Option<std::path::PathBuf>) {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, name, hit);
                } else if p.file_name().and_then(|s| s.to_str()) == Some(name) {
                    *hit = Some(p);
                }
            }
        }
    }
    walk(dir, name, &mut hit);
    hit
}


/// The loser leaves the tree, not just the disk (Chris's call).
///
/// The ladder trashing the bytes while leaving the node linked showed a phantom
/// duplicate of every upgraded title to anything browsing the library — and the
/// loser's LOCATION still named a path that, in the same-root case, the winner
/// was about to be written to. A stale claim pointing at someone else's bytes
/// is worse than a phantom.
#[test]
fn the_loser_leaves_the_tree_and_takes_its_location_with_it() {
    let mut r = rig(3000, 9000);
    let mut fetcher = pvfs_client::fetch::Fetcher::new(&r.data_dir);
    pvfs_client::fetch::tier_pass_ruled(
        &mut r.engine,
        &mut fetcher,
        false,
        Some(Rules::default()),
    )
    .unwrap()
    .expect("a central placement exists");

    // One live file at this tree path, not two.
    let live: Vec<String> = r
        .engine
        .walk(&r.media)
        .unwrap()
        .into_iter()
        .filter(|e| e.node.node_type == pvfs_core::TYPE_FILE && e.label == "cold.mkv")
        .map(|e| e.node.id)
        .collect();
    assert_eq!(
        live.len(),
        1,
        "the trashed loser must not still be shown in the tree: {live:?}"
    );

    // And nothing anywhere claims a path that does not hold its bytes.
    let mut stale = 0;
    for e in r.engine.walk(&r.media).unwrap() {
        if e.node.node_type != pvfs_core::TYPE_FILE {
            continue;
        }
        for u in r.engine.locations(&e.node.id).unwrap() {
            if let Some(p) = pvfs_core::storage::any_path_of(&u) {
                if !p.exists() {
                    stale += 1;
                }
            }
        }
    }
    assert_eq!(stale, 0, "no location may name a path its bytes have left");

    // The bytes are still recoverable — trashed, never deleted.
    assert!(
        walk_find(&r.cold, "cold.mkv").is_some(),
        "the loser's bytes must still be in the trash"
    );
    r.engine.close().unwrap();
}
