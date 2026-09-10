//! D126 — the merged view (doc 26 phase 3): one logical entry per relative
//! path with every region's copy behind it, admitted only when the copies
//! agree on the bytes.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, ViewState, TYPE_FOLDER};

fn folder(e: &mut Engine, parent: &str, label: &str) -> String {
    e.add_node(
        &parent.to_string(),
        NodeSpec {
            node_type: TYPE_FOLDER.into(),
            label: label.into(),
            payload: Vec::new(),
            is_temp: false,
            creation_nonce: None,
        },
    )
    .unwrap()
}

/// A catalogue region bound to `dir`, scanned.
fn region(e: &mut Engine, label: &str, dir: &std::path::Path, policy: HashPolicy) -> String {
    let root = e.identity.root_node_id.clone();
    let r = folder(e, &root, label);
    e.region_mark_as(&r, "catalogue", None).unwrap();
    e.bind_folder(
        &r,
        BindSpec {
            source_uri: format!("file://{}", dir.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: policy,
        },
    )
    .unwrap();
    e.scan_routed(Some(&r), None, 0).unwrap();
    r
}

fn write(dir: &std::path::Path, rel: &str, bytes: &[u8]) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

#[test]
fn one_entry_per_path_admitted_only_when_the_bytes_agree() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    // Same bytes, different bytes, one-sided, an empty folder, a file/dir clash.
    write(&a, "Movies/Same (2001)/same.mkv", b"identical");
    write(&b, "Movies/Same (2001)/same.mkv", b"identical");
    write(&a, "Movies/Differs (2002)/differs.mkv", b"version-a");
    write(&b, "Movies/Differs (2002)/differs.mkv", b"version-b!");
    // A's copy is older by a minute, so "newest" is unambiguous.
    std::fs::File::options()
        .write(true)
        .open(a.join("Movies/Differs (2002)/differs.mkv"))
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(60))
        .unwrap();
    write(&a, "Movies/Only A (2003)/only.mkv", b"only-a");
    std::fs::create_dir_all(b.join("Movies/Empty (2004)")).unwrap();
    write(&a, "Movies/Clash", b"a file here");
    std::fs::create_dir_all(b.join("Movies/Clash")).unwrap();

    let (mut e, _mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let ra = region(&mut e, "A", &a, HashPolicy::OnAdd);
    let rb = region(&mut e, "B", &b, HashPolicy::OnAdd);

    // The root of every region, one level.
    let top = e.merged_view("").unwrap();
    assert_eq!(top.iter().map(|v| v.rel_path.as_str()).collect::<Vec<_>>(), vec!["Movies"]);
    assert_eq!(top[0].kind, "dir");
    assert_eq!(top[0].sources.len(), 2, "both regions hold Movies/");

    let movies = e.merged_view("Movies").unwrap();
    let names: Vec<&str> = movies.iter().map(|v| v.rel_path.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "Movies/Clash",
            "Movies/Differs (2002)",
            "Movies/Empty (2004)",
            "Movies/Only A (2003)",
            "Movies/Same (2001)"
        ],
        "bytewise order, one level"
    );
    let by = |p: &str| movies.iter().find(|v| v.rel_path == p).unwrap().clone();
    assert_eq!(by("Movies/Clash").state, ViewState::ConflictKind);
    assert_eq!(by("Movies/Empty (2004)").kind, "dir");
    assert_eq!(by("Movies/Empty (2004)").sources.len(), 1, "an empty folder in one region is a folder");

    let same = e.merged_view("Movies/Same (2001)").unwrap().remove(0);
    assert_eq!((same.state.clone(), same.copies), (ViewState::Admitted, 2), "identical bytes = redundancy");
    // Sources are ordered by region id (bytewise), not by creation: the same
    // on every box that holds these catalogues.
    let mut regions: Vec<&str> = same.sources.iter().map(|c| c.region.as_str()).collect();
    let mut expect = vec![ra.as_str(), rb.as_str()];
    expect.sort();
    assert_eq!(regions.clone(), expect, "both regions behind the path, in id order");
    regions.sort();
    assert_eq!(regions, expect);
    assert!(same.content_hash.is_some());

    let differs = e.merged_view("Movies/Differs (2002)").unwrap().remove(0);
    match &differs.state {
        ViewState::ConflictHashes(h) => assert_eq!(h.len(), 2, "both hashes reported"),
        other => panic!("expected a hash conflict, got {other:?}"),
    }
    assert_eq!(differs.copies, 0, "a conflict is not redundancy");
    assert_eq!(differs.content_hash, None);
    assert_eq!(differs.size_bytes, 10, "described by the newest copy until phase 4's ladder");

    let only = e.merged_view("Movies/Only A (2003)").unwrap().remove(0);
    assert_eq!((only.state.clone(), only.copies, only.sources.len()), (ViewState::Admitted, 1, 1));

    // The conflict list is exactly the two conflicts.
    let conflicts = e.view_conflicts().unwrap();
    assert_eq!(
        conflicts.iter().map(|v| v.rel_path.as_str()).collect::<Vec<_>>(),
        vec!["Movies/Clash", "Movies/Differs (2002)/differs.mkv"]
    );
}

#[test]
fn an_unhashed_copy_is_listed_but_not_counted() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    write(&a, "x.mkv", b"same-bytes");
    write(&b, "x.mkv", b"same-bytes");
    write(&b, "y.mkv", b"only-unhashed");
    let (mut e, _mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let _ra = region(&mut e, "A", &a, HashPolicy::OnAdd);
    let _rb = region(&mut e, "B", &b, HashPolicy::Never);

    let view = e.merged_view("").unwrap();
    let x = view.iter().find(|v| v.rel_path == "x.mkv").unwrap();
    assert_eq!((x.state.clone(), x.copies, x.sources.len()), (ViewState::Admitted, 1, 2), "listed twice, counted once");
    let y = view.iter().find(|v| v.rel_path == "y.mkv").unwrap();
    assert_eq!((y.state.clone(), y.copies), (ViewState::Unhashed, 0), "visible, not servable");
    assert!(e.view_conflicts().unwrap().is_empty(), "an unhashed copy is not a conflict");
}
