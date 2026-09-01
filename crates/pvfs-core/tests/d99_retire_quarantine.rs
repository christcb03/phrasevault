//! D99 §9b-ii — retire must not accept a quarantined copy as proof.
//!
//! `retire_locations_under` removes a location only while the same file keeps
//! another live one. That guard read `file_locations` alone, so a location PVFS
//! had already caught serving bytes the catalog does not name still counted as
//! "held elsewhere" — and retire would drop the record for the good copy,
//! leaving only the bad one behind.
//!
//! D99 fixed the same blind spot in `evict_pass` first, because evict deletes
//! bytes. Retire removes a catalog record, so a rescan repairs it; that is why
//! it was deferred rather than rushed into the same pass, not why it was safe.
//!
//! The guard is a pair of complementary queries — eligible is `EXISTS`, refused
//! is `NOT EXISTS` over the same condition. `every_location_lands_in_exactly_one_set`
//! is the test that matters most here: changing one side alone would produce a
//! location that is neither retired nor reported, which is worse than the bug.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, VerifyOutcome, TYPE_FILE, TYPE_FOLDER};

fn spec(dir: &std::path::Path) -> BindSpec {
    BindSpec {
        source_uri: format!("file://{}", dir.display()),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::OnAdd,
    }
}

fn library(root: &std::path::Path, n: usize) -> std::path::PathBuf {
    let media = root.join("Media");
    let season = media.join("TV").join("Show (2015)").join("Season 01");
    std::fs::create_dir_all(&season).unwrap();
    for i in 1..=n {
        std::fs::write(season.join(format!("ep{i:02}.mkv")), vec![b'a' + i as u8; 4096 + i]).unwrap();
    }
    media
}

fn files_under(engine: &Engine, folder: &str) -> Vec<String> {
    engine
        .walk(&folder.to_string())
        .unwrap()
        .into_iter()
        .filter(|e| e.node.node_type == TYPE_FILE)
        .map(|e| e.node.id)
        .collect()
}

/// Production's shape after the holder's scan: every file has the owner's NFS
/// view AND the holder's own path. Returns the engine, the folder, and the
/// prefix that is about to be retired.
fn migrated(dir: &std::path::Path, n: usize) -> (Engine, String, String) {
    let nfs = library(&dir.join("mnt-nas-media"), n);
    let nas = library(&dir.join("share-Data-Media"), n);

    let (mut engine, _mn) = Engine::init(dir.join("forest").as_path()).unwrap();
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

    let sp = spec(&nfs);
    let uri = sp.source_uri.clone();
    engine.scan_unbound(&media, &uri, &sp, &mut None, 0).unwrap();

    let sp2 = spec(&nas);
    let uri2 = sp2.source_uri.clone();
    let stats = engine.scan_unbound(&media, &uri2, &sp2, &mut None, 0).unwrap();
    assert_eq!(stats.added, 0, "the holder holds the same library");
    assert_eq!(stats.relocated as usize, n);

    let prefix = format!("file://{}/", nfs.display());
    (engine, media, prefix)
}

/// The holder's copy of `file` drifts, and verify catches it. This is the
/// production route into quarantine, not a hand-written row: `loc_verify`
/// hashes every location and quarantines the ones that no longer match.
fn quarantine_the_holders_copy(engine: &mut Engine, file: &str, prefix: &str) -> String {
    let holder_uri = engine
        .locations(&file.to_string())
        .unwrap()
        .into_iter()
        .find(|u| !u.starts_with(prefix))
        .expect("it has a holder location to corrupt");
    let path = pvfs_core::storage::any_path_of(&holder_uri).expect("a local path");
    std::fs::write(&path, b"these are not the bytes the catalog names").unwrap();

    let outcomes = engine.loc_verify(&file.to_string()).unwrap();
    let holder = outcomes.iter().find(|(u, _)| *u == holder_uri).unwrap();
    assert_eq!(holder.1, VerifyOutcome::Mismatch, "verify caught the drift");
    let good = outcomes.iter().find(|(u, _)| u.starts_with(prefix)).unwrap();
    assert_eq!(good.1, VerifyOutcome::Ok, "the copy under the prefix is fine");
    holder_uri
}

/// The bug, stated as the behaviour: a file whose only other location is
/// quarantined is held nowhere trustworthy, so retire must REFUSE it.
///
/// Before the fix this file was retired — its good copy's record removed on the
/// strength of a copy already known to be serving the wrong bytes.
#[test]
fn a_file_held_only_by_a_quarantined_copy_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, media, prefix) = migrated(dir.path(), 6);
    let files = files_under(&engine, &media);

    let drifted = files[2].clone();
    let bad_uri = quarantine_the_holders_copy(&mut engine, &drifted, &prefix);

    let report = engine.retire_locations_under(&prefix, false, 500).unwrap();

    assert_eq!(report.eligible, 5, "the other five are held by a copy we trust");
    assert_eq!(report.removed, 5);
    assert_eq!(report.refused.len(), 1, "a quarantined copy is not proof");
    assert_eq!(report.refused[0].0, drifted);
    assert!(report.refused[0].1.starts_with(&prefix));

    let locs = engine.locations(&drifted).unwrap();
    assert!(
        locs.iter().any(|u| u.starts_with(&prefix)),
        "the record for the GOOD copy survives — it is the only one left worth having"
    );
    assert!(locs.contains(&bad_uri), "and the quarantined one is untouched, for verify to lift");

    for f in files.iter().filter(|f| **f != drifted) {
        let locs = engine.locations(f).unwrap();
        assert!(!locs.is_empty(), "no file may be left held by nobody");
        assert!(
            locs.iter().all(|u| !u.starts_with(&prefix)),
            "the retired view is gone from every file with a trustworthy copy"
        );
    }
    engine.close().unwrap();
}

/// The invariant the fix had to preserve. `eligible` and `refused` come from
/// two queries that are complements of each other; editing one side alone
/// leaves locations in neither, which is a silent drop rather than a bug you
/// can see. Every live location under the prefix must be accounted for exactly
/// once, quarantines or no quarantines.
#[test]
fn every_location_lands_in_exactly_one_set() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, media, prefix) = migrated(dir.path(), 6);
    let files = files_under(&engine, &media);

    // Three shapes at once: one held only by a quarantined copy, one held
    // nowhere else at all, and four held by a copy we trust.
    quarantine_the_holders_copy(&mut engine, &files[1], &prefix);
    let holder_uri = engine
        .locations(&files[4])
        .unwrap()
        .into_iter()
        .find(|u| !u.starts_with(&prefix))
        .unwrap();
    engine.remove_location(&files[4], &holder_uri).unwrap();

    let under_prefix: Vec<(String, String)> = files
        .iter()
        .flat_map(|f| {
            engine
                .locations(f)
                .unwrap()
                .into_iter()
                .filter(|u| u.starts_with(&prefix))
                .map(move |u| (f.clone(), u))
        })
        .collect();
    assert_eq!(under_prefix.len(), 6, "every file still has its NFS view");

    let report = engine.retire_locations_under(&prefix, true, 500).unwrap();
    assert_eq!(
        report.eligible + report.refused.len(),
        under_prefix.len(),
        "a live location under the prefix is either eligible or refused — never neither"
    );
    assert_eq!(report.refused.len(), 2, "the quarantined one AND the unheld one");
    let refused: Vec<&String> = report.refused.iter().map(|(f, _)| f).collect();
    assert!(refused.contains(&&files[1]), "held only by a quarantined copy");
    assert!(refused.contains(&&files[4]), "held nowhere else at all");
    engine.close().unwrap();
}

/// The guard reads live quarantine state, not a permanent mark. Repair the
/// bytes, let verify lift the quarantine, and the location is eligible again —
/// which is also the rescan that repairs a retire refused for this reason.
#[test]
fn lifting_the_quarantine_makes_it_eligible_again() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, media, prefix) = migrated(dir.path(), 3);
    let files = files_under(&engine, &media);

    let drifted = files[0].clone();
    let bad_uri = quarantine_the_holders_copy(&mut engine, &drifted, &prefix);
    let refused = engine.retire_locations_under(&prefix, true, 500).unwrap();
    assert_eq!(refused.refused.len(), 1, "refused while the copy is suspect");

    // Restore the holder's copy from the one under the prefix and re-verify.
    let good_uri = engine
        .locations(&drifted)
        .unwrap()
        .into_iter()
        .find(|u| u.starts_with(&prefix))
        .unwrap();
    let good_path = pvfs_core::storage::any_path_of(&good_uri).unwrap();
    let bad_path = pvfs_core::storage::any_path_of(&bad_uri).unwrap();
    std::fs::copy(&good_path, &bad_path).unwrap();
    let outcomes = engine.loc_verify(&drifted).unwrap();
    assert!(
        outcomes.iter().all(|(_, o)| *o == VerifyOutcome::Ok),
        "both copies match the catalog again"
    );

    let report = engine.retire_locations_under(&prefix, false, 500).unwrap();
    assert_eq!(report.eligible, 3, "all three are held by a copy we trust now");
    assert!(report.refused.is_empty());
    engine.close().unwrap();
}
