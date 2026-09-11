//! D81 — the mover must be TOLD the topology, because it cannot always see it.
//!
//! The mover runs on the owner. A replica's binding is machine-local by design
//! (D71 W1), so the owner cannot see feederbox's root or the NAS's — on Chris's
//! fleet it reports `no bound spaces`. Deriving library roots from bindings
//! therefore produced an EMPTY set on the one box the mover runs on, quietly
//! making "satisfied at any root" a no-op in production while passing every
//! test in the lab, where one box holds everything.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

/// D132 — a throwaway config dir for this binary, so no test here reads the
/// box's real instance registry (`XDG_CONFIG_HOME/pvfs/instances`). Set once
/// per process; every test in the file shares it, which is all the isolation
/// they need. The dir is deliberately leaked: the process is the lifetime.
fn isolate_config() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let dir = tempfile::tempdir().expect("config tempdir");
        std::env::set_var("XDG_CONFIG_HOME", dir.path());
        std::mem::forget(dir);
    });
}

fn spec(dir: &std::path::Path) -> BindSpec {
    BindSpec {
        source_uri: format!("file://{}", dir.display()),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::OnAdd,
    }
}

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

/// A root the mover cannot SEE, but has been TOLD about, still satisfies.
///
/// The staging root is bound (so the mover can find the incoming file); the
/// cold root is NOT bound at all — exactly the owner's view of the NAS — and is
/// declared instead. A title sitting there must not be fetched back.
#[test]
fn a_declared_root_satisfies_even_though_nothing_is_bound_to_it() {
    isolate_config();
    let tmp = tempfile::tempdir().unwrap();
    let warm = tmp.path().join("Data");
    let cold = tmp.path().join("Data_ext");
    let staging = tmp.path().join("incoming");
    let rel = "Movies/Cold Title (1998)/cold.mkv";
    std::fs::create_dir_all(warm.join("Movies")).unwrap();
    std::fs::create_dir_all(cold.join("Movies/Cold Title (1998)")).unwrap();
    std::fs::create_dir_all(staging.join("Movies/Cold Title (1998)")).unwrap();
    std::fs::write(staging.join(rel), vec![1u8; 4000]).unwrap();

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
    // ONLY staging is bound — the cold volume is somebody else's disk.
    engine.bind_folder(&media, spec(&staging)).unwrap();
    engine.scan_routed(Some(&media), None, 0).unwrap();

    let data_dir = engine.data_dir().to_path_buf();
    pvfs_core::sync::set_central(&data_dir, &media, &warm, false).unwrap();
    pvfs_core::sync::set_central_tree(&data_dir, &media, true).unwrap();
    let staging_uri = format!("file://{}", staging.display());
    let cold_uri = format!("file://{}", cold.display());
    pvfs_core::sync::set_staging_root(&data_dir, &media, &staging_uri, true).unwrap();
    pvfs_core::sync::set_library_root(&data_dir, &media, &cold_uri, true).unwrap();

    // Place it, then move it to the cold volume by hand and tell the catalog.
    let mut fetcher = pvfs_client::fetch::Fetcher::new(&data_dir);
    pvfs_client::fetch::tier_pass_opts(&mut engine, &mut fetcher, false)
        .unwrap()
        .expect("a central placement exists");
    assert_eq!(count_files(&warm), 1, "new content lands at the write target");

    std::fs::create_dir_all(cold.join("Movies/Cold Title (1998)")).unwrap();
    std::fs::rename(warm.join(rel), cold.join(rel)).unwrap();
    let id = engine
        .walk(&media)
        .unwrap()
        .into_iter()
        .find(|e| e.node.node_type == pvfs_core::TYPE_FILE)
        .unwrap()
        .node
        .id;
    let old = format!("file://{}", warm.join(rel).display());
    let new = format!("file://{}", cold.join(rel).display());
    engine.add_location(&id, &new).unwrap();
    engine.remove_location(&id, &old).unwrap();

    // THE POINT: the cold root is not bound, and must still satisfy.
    let report = pvfs_client::fetch::tier_pass_opts(&mut engine, &mut fetcher, true)
        .unwrap()
        .expect("a central placement exists");
    assert!(
        report.planned.is_empty(),
        "the title is at a DECLARED library root — the mover cannot see a \
         binding for it and must not need one: {:?}",
        report.planned
    );
    assert_eq!(count_files(&cold), 1);
    assert_eq!(count_files(&warm), 0, "and it is not dragged back");
    engine.close().unwrap();
}

/// Declaring nothing keeps the old behaviour exactly.
#[test]
fn declaring_nothing_falls_back_to_whatever_bindings_this_box_can_see() {
    isolate_config();
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("local");
    let store = tmp.path().join("store");
    std::fs::create_dir_all(src.join("TV/Show")).unwrap();
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(src.join("TV/Show/ep.mkv"), vec![2u8; 3000]).unwrap();

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
    engine.bind_folder(&media, spec(&src)).unwrap();
    engine.scan_routed(Some(&media), None, 0).unwrap();
    let data_dir = engine.data_dir().to_path_buf();
    pvfs_core::sync::set_central(&data_dir, &media, &store, false).unwrap();
    pvfs_core::sync::set_central_tree(&data_dir, &media, true).unwrap();

    let mut fetcher = pvfs_client::fetch::Fetcher::new(&data_dir);
    pvfs_client::fetch::tier_pass_opts(&mut engine, &mut fetcher, false)
        .unwrap()
        .expect("a central placement exists");
    assert_eq!(
        count_files(&store),
        1,
        "an undeclared fleet must behave exactly as it did before any of this"
    );
    engine.close().unwrap();
}
