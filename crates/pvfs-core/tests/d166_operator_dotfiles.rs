//! D166 — a name with a dot in front is the operator's content like any other
//! (`.plexmatch` is how Plex is told which show a folder holds). What stays
//! out: PVFS's own bookkeeping, and the litter an OS or a NAS leaves behind.
//! Until D166 the walker skipped every dot-name — it kept our sidecars out of
//! the catalogue and took 153 `.plexmatch` files on the fleet with them.

use std::collections::BTreeSet;
use std::path::Path;

use pvfs_core::{sync, BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

fn write(root: &Path, rel: &str, bytes: &[u8]) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

fn region(e: &mut Engine, label: &str, dir: &Path) -> String {
    let root = e.identity.root_node_id.clone();
    let r = e
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: label.into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    e.region_mark_as(&r, "catalogue", None).unwrap();
    e.bind_folder(
        &r,
        BindSpec {
            source_uri: format!("file://{}", dir.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    r
}

fn manifests(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, root, out);
            } else if p.to_string_lossy().ends_with(".manifest") {
                out.push(p.strip_prefix(root).unwrap().to_string_lossy().into_owned());
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

#[test]
fn the_operators_dotfiles_are_content_and_ours_and_the_litter_are_not() {
    let tmp = tempfile::tempdir().unwrap();
    let lib = tmp.path().join("lib");
    // theirs
    write(&lib, "TV/Show (2020)/.plexmatch", b"tvdbid: 12345\n");
    write(&lib, "TV/Show (2020)/Season 01/Show - s01e01.mkv", b"episode bytes");
    write(&lib, ".htaccess", b"Deny from all\n");
    write(&lib, "TV/Show (2020)/.extras/behind-the-scenes.mkv", b"a dot-named folder is theirs too");
    // ours
    write(&lib, ".pvfs-root", b"marker");
    write(&lib, ".pvfs-central", b"marker");
    write(&lib, ".pvfs-trash/20710/TV/Old (1999)/old.mkv", b"trashed");
    write(&lib, ".pvfs-incoming/abc.partial", b"arriving");
    write(&lib, ".pvfs/index.db", b"a forest's own directory");
    write(&lib, "TV/Show (2020)/.0123abcd.tmp", b"a file still being published");
    // litter
    write(&lib, ".DS_Store", b"mac");
    write(&lib, "TV/Show (2020)/._Show - s01e01.mkv", b"resource fork");
    write(&lib, "TV/Show (2020)/Season 01/.@__thumb/default.jpg", b"qnap thumbnail");
    write(&lib, "TV/Show (2020)/Season 01/.@__thumb/.genSub/x", b"qnap");
    write(&lib, ".Trash-1001/files/gone.mkv", b"a desktop's trash");

    let (mut e, _) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let r = region(&mut e, "Library", &lib);
    e.scan_routed(Some(&r), None, 0).unwrap();

    let rows: BTreeSet<String> = e.region_entries(&r).unwrap().into_iter().map(|x| x.rel_path).collect();
    let want: BTreeSet<String> = [
        ".htaccess",
        "TV",
        "TV/Show (2020)",
        "TV/Show (2020)/.extras",
        "TV/Show (2020)/.extras/behind-the-scenes.mkv",
        "TV/Show (2020)/.plexmatch",
        "TV/Show (2020)/Season 01",
        "TV/Show (2020)/Season 01/Show - s01e01.mkv",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(rows, want, "theirs is catalogued; ours and the litter are not");

    // The view — what the mount lists — shows them, hashed like any file.
    let show: Vec<String> = e.merged_view("TV/Show (2020)").unwrap().into_iter().map(|v| v.rel_path).collect();
    assert!(show.contains(&"TV/Show (2020)/.plexmatch".to_string()), "{show:?}");
    let pm = e.view_entry("TV/Show (2020)/.plexmatch").unwrap().expect("a row");
    assert_eq!(pm.content_hash.as_deref(), Some(blake3::hash(b"tvdbid: 12345\n").to_hex().as_str()));

    // A dotfile gets a sidecar the way any file does (or does not), and that
    // sidecar is OURS: no pass adopts it, and the chain never grows (D87).
    let mkv = sync::manifest_sidecar_path(&lib.join("TV/Show (2020)/Season 01/Show - s01e01.mkv"));
    let dot = sync::manifest_sidecar_path(&lib.join("TV/Show (2020)/.plexmatch"));
    assert_eq!(dot.file_name().unwrap().to_string_lossy(), "..plexmatch.manifest");
    assert_eq!(dot.exists(), mkv.exists(), "a dotfile's sidecar is written exactly when any file's is");
    let after_one = manifests(&lib);
    for _ in 0..3 {
        let reports = e.scan_routed(Some(&r), None, 0).unwrap();
        assert!(reports.iter().all(|rep| rep.stats.added == 0), "a settled library adds nothing: {reports:?}");
    }
    assert_eq!(manifests(&lib), after_one, "no sidecar of a sidecar, however many passes");
    assert!(after_one.iter().all(|m| !m.ends_with(".manifest.manifest")), "{after_one:?}");
    let again: BTreeSet<String> = e.region_entries(&r).unwrap().into_iter().map(|x| x.rel_path).collect();
    assert_eq!(again, want);

    // A `.plexmatch` that goes away is a row that goes away — and its
    // sidecar, left alone beside nothing, is an orphan like any other (D149).
    std::fs::remove_file(lib.join("TV/Show (2020)/.plexmatch")).unwrap();
    e.scan_routed(Some(&r), None, 0).unwrap();
    assert!(e.view_entry("TV/Show (2020)/.plexmatch").unwrap().is_none());
}

#[test]
fn the_name_rules_say_whose_a_name_is() {
    for ours in [".pvfs", ".pvfs-root", ".pvfs-central", ".pvfs-trash", ".pvfs-incoming"] {
        assert!(sync::is_own_name(ours, true) && sync::is_own_name(ours, false), "{ours}");
    }
    for ours in [".a.mkv.manifest", "..plexmatch.manifest", "a.mkv.manifest", ".0123.tmp", ".x.mkv.partial"] {
        assert!(sync::is_own_name(ours, false), "{ours}");
    }
    // Every name PVFS writes into a content tree is held to the rule, by the
    // function that makes it — a dot alone no longer hides anything (doc 24 §2).
    let d = tempfile::tempdir().unwrap();
    let id = "ab".repeat(32);
    for made in [
        sync::swarm_part_path(d.path(), &id).unwrap(),
        pvfs_core::ingest::progress_path(d.path(), &id).unwrap(),
        sync::manifest_sidecar_path(Path::new("/lib/Show/.plexmatch")),
        sync::manifest_sidecar_path(Path::new("/lib/Show/a.mkv")),
        sync::legacy_manifest_sidecar_path(Path::new("/lib/Show/a.mkv")),
    ] {
        let name = made.file_name().unwrap().to_string_lossy().into_owned();
        assert!(sync::is_own_name(&name, false), "{name}");
    }
    assert!(sync::is_own_name(sync::ROOT_MARKER, false) && sync::is_own_name(sync::CENTRAL_MARKER, false));
    // a DIRECTORY someone named like a sidecar is theirs; so is every other dot-name
    assert!(!sync::is_own_name("backups.manifest", true));
    for theirs in [".plexmatch", ".plexignore", ".htaccess", ".extras", ".nomedia", "pvfs-notes.txt", ".pvfsrc"] {
        assert!(!sync::is_own_name(theirs, false) && !sync::is_litter_name(theirs), "{theirs}");
    }
    for litter in [".DS_Store", "._anything", ".AppleDouble", ".Trash-1000", ".Trash-1001", ".@__thumb", ".fuse_hidden0001", ".nfs00012"] {
        assert!(sync::is_litter_name(litter), "{litter}");
    }
    // litter is dot-names only: nothing catalogued before D166 stops being catalogued
    for kept in ["Thumbs.db", "@eaDir", "desktop.ini"] {
        assert!(!sync::is_litter_name(kept), "{kept}");
    }
}
