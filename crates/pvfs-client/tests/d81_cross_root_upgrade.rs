//! D81 4c — an upgrade must find the copy it supersedes, on whichever volume.
//!
//! ALL IGNORED, AND THE REASON IS THE POINT. The detection code is written and
//! correct; these cannot be exercised yet because the topology they describe is
//! currently INEXPRESSIBLE.
//!
//! `BindKind` is derived per FOLDER from its placement, not per binding:
//!
//! ```text
//! Some((_, dir, true))  => (BindKind::Mirror,  ..)   // the whole folder keeps
//! Some((_, dir, false)) => (BindKind::Migrate, ..)   // the whole folder drains
//! ```
//!
//! Chris's library needs both at once, under one folder: feederbox drains,
//! `Data` is the write target, `Data_ext` keeps. With `migrate` (what
//! production runs) every root counts as staging, so there are no library
//! roots and a title moved to `Data_ext` is fetched back. With `mirror`
//! nothing drains and nothing is ever placed. Neither end of the knob is his
//! topology, and there is no middle.
//!
//! Un-ignore these once drain-ness is per-ROOT. They are left here, failing-by-
//! ignore rather than deleted, because they are the specification for it.
//!
//! Chris: "if something gets upgraded from data_ext it would get written to
//! Data, but then the system has to remove the extra copy from data_ext. I'm
//! not sure how to manage that just yet."
//!
//! It was not that the system removed it badly — it never noticed. Collision
//! detection asked whether the DESTINATION PATH was occupied, so upgrading a
//! cold title found an empty destination on the warm volume, placed the new
//! copy, and left the old one live. Two copies of one tree path, on two
//! volumes, with nothing to reconcile them.

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
    Rig { _tmp: tmp, engine, data_dir, warm, cold }
}

fn cold_copy(r: &Rig) -> std::path::PathBuf {
    r.cold.join("Movies/Cold Title (1998)/cold.mkv")
}

/// WITHOUT `--rules`: refuse, and say where the other copy is.
///
/// The default has always been "I will not guess"; what changes is that it can
/// now SEE the thing it would have to guess about.
#[test]
#[ignore = "needs per-root drain semantics — see the module comment"]
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
#[ignore = "needs per-root drain semantics — see the module comment"]
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
#[ignore = "needs per-root drain semantics — see the module comment"]
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
#[ignore = "needs per-root drain semantics — see the module comment"]
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

