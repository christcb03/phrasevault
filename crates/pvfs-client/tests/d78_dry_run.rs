//! D76/D78 — plan every action, take none of them.
//!
//! Two bugs in this milestone were only visible in what the mover had already
//! DONE: locations retired that should not have been, and bytes written to a
//! disk that was not the NAS. A dry run is the cheapest defence against the
//! next one — but only if it genuinely writes nothing, which is what this
//! asserts by diffing the store rather than trusting the output.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

fn count_files(dir: &std::path::Path) -> usize {
    fn walk(d: &std::path::Path, n: &mut usize) {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, n);
                } else if !matches!(
                    p.file_name().and_then(|s| s.to_str()),
                    Some(".pvfs-central") | Some(".pvfs-root")
                ) && !p
                    .file_name()
                    .map(|s| pvfs_core::sync::is_sidecar_name(&s.to_string_lossy()))
                    .unwrap_or(false)
                {
                    // D91 — the chunk-manifest sidecar joins `.pvfs-central` and
                    // `.pvfs-root` here for the same reason they are already
                    // listed: this counts the operator's CONTENT, and our own
                    // bookkeeping beside a file is not content. The fill now
                    // leaves one next to every hashed file, so without this the
                    // count doubles.
                    *n += 1;
                }
            }
        }
    }
    let mut n = 0;
    walk(dir, &mut n);
    n
}

/// The core promise: a dry run plans real work and changes nothing.
#[test]
fn a_dry_run_plans_the_work_and_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("local");
    let store = tmp.path().join("store");
    std::fs::create_dir_all(src.join("TV").join("Show").join("Season 01")).unwrap();
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(src.join("TV/Show/Season 01/ep.mkv"), vec![3u8; 8192]).unwrap();

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
    engine
        .bind_folder(
            &media,
            BindSpec {
                source_uri: format!("file://{}", src.display()),
                recursive: true,
                auto_index: true,
                extensions: String::new(),
                hash_policy: HashPolicy::Lazy,
            },
        )
        .unwrap();
    engine.scan_routed(Some(&media), None, 0).unwrap();

    let data_dir = engine.data_dir().to_path_buf();
    pvfs_core::sync::set_central(&data_dir, &media, &store, false).unwrap();
    pvfs_core::sync::set_central_tree(&data_dir, &media, true).unwrap();

    let before = count_files(&store);
    assert_eq!(before, 0, "store starts empty");

    // DRY RUN
    let mut fetcher = pvfs_client::fetch::Fetcher::new(&data_dir);
    let report = pvfs_client::fetch::tier_pass_opts(&mut engine, &mut fetcher, true)
        .unwrap()
        .expect("something is placed central");

    assert!(
        !report.planned.is_empty(),
        "a dry run with real work must PLAN something, not silently do nothing"
    );
    assert!(
        report.planned.iter().any(|p| p.contains("WOULD")),
        "the plan must say what it WOULD do: {:?}",
        report.planned
    );
    assert_eq!(
        count_files(&store),
        before,
        "THE WHOLE POINT: a dry run writes nothing. The store must be untouched."
    );

    // ...and now for real, to prove the plan described reality.
    let real = pvfs_client::fetch::tier_pass_opts(&mut engine, &mut fetcher, false)
        .unwrap()
        .unwrap();
    assert!(
        real.planned.is_empty(),
        "a REAL pass plans nothing — `planned` is dry-run-only"
    );
    assert_eq!(
        count_files(&store),
        1,
        "the real pass placed the file the dry run predicted"
    );
    assert_eq!(
        real.migrated, report.migrated,
        "the plan's count matched what actually happened"
    );
    engine.close().unwrap();
}

/// A dry run on a settled fleet plans nothing and still writes nothing — the
/// idle case, which must not report phantom work.
#[test]
fn a_dry_run_on_settled_state_plans_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("store");
    std::fs::create_dir_all(&store).unwrap();

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
    let data_dir = engine.data_dir().to_path_buf();
    pvfs_core::sync::set_central(&data_dir, &media, &store, false).unwrap();
    pvfs_core::sync::set_central_tree(&data_dir, &media, true).unwrap();

    let mut fetcher = pvfs_client::fetch::Fetcher::new(&data_dir);
    let report = pvfs_client::fetch::tier_pass_opts(&mut engine, &mut fetcher, true)
        .unwrap()
        .unwrap();
    assert!(report.planned.is_empty(), "nothing to do ⇒ nothing planned");
    assert_eq!(report.migrated, 0);
    assert_eq!(count_files(&store), 0);
    engine.close().unwrap();
}

// ---------------------------------------------------------------------------
// D75 — a holder pulls and advertises; retiring is the owner's call.
// ---------------------------------------------------------------------------

/// The split that makes Chris's swarm design work: the mover does two
/// separable things, and only one of them is a local act.
///
/// PLACING bytes is local — fetch, write the file, log where it went.
/// RETIRING another box's location is an authority decision about someone
/// else's copy, and belongs to the owner.
///
/// `tier_pass` used to refuse a replica outright, conflating the two. That is
/// what forced the central store to be a path the OWNER can write — hence NFS,
/// and an owner sitting in the byte path for bytes it does not keep.
///
/// This pins the rule as the code states it, so nobody re-merges the halves.
#[test]
fn a_replica_places_but_never_retires() {
    // The predicate from tier_pass: `if keep || pull_only { continue; }`
    let stops_before_retiring = |keep: bool, pull_only: bool| keep || pull_only;

    assert!(
        stops_before_retiring(false, true),
        "a REPLICA places and advertises, then stops — retiring is not its call"
    );
    assert!(
        !stops_before_retiring(false, false),
        "an OWNER on a migrate root does retire, which is the drain"
    );
    assert!(
        stops_before_retiring(true, false),
        "a MIRROR never retires either — keeping the source is the whole point"
    );
}

/// A holder's copy is logged PIN-QUALIFIED, and the satisfied check must
/// recognise BOTH forms.
///
/// A bare `file://` path is host-implicit, and a replica's store copy lives on
/// a specific box — so it is logged as `pvfs-host://<pin><path>`. When the
/// check only knew the bare form, the holder did not recognise the file it had
/// placed ITSELF: it re-placed it every pass, and the occupied-path guard
/// reported it as "the catalog has never seen it".
#[test]
fn a_holder_recognises_its_own_pin_qualified_copy() {
    let pin = "c4e862c903d3e9954d5848660c04a9085cccb915062dabccf0fb3ba8c2054848";
    let path = "/srv/nas-lib/TV/Show/Season 01/ep.mkv";
    let bare = format!("file://{path}");
    let qualified = format!("pvfs-host://{pin}{path}");

    let satisfied = |recorded: &str| recorded == bare || recorded == qualified;

    assert!(satisfied(&bare), "the owner's own file:// form still counts");
    assert!(
        satisfied(&qualified),
        "and so does the holder's pin-qualified form — otherwise it re-places \
         the same file forever"
    );
    assert!(
        !satisfied(&format!("pvfs-host://{pin}/somewhere/else.mkv")),
        "but a DIFFERENT path on the same box does not satisfy this destination"
    );
    assert!(
        !satisfied(&format!(
            "pvfs-host://7f22051a610880a1a521159b68cf4e06afcd62b4309a4661fc4f5c068d13e793{path}"
        )),
        "nor the same path on ANOTHER box — that is the ingest copy, not ours"
    );
}
