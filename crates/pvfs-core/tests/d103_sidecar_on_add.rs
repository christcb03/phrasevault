//! D103 — a fresh import must reuse the sidecar beside the file.
//!
//! `fill_hash_if_needed` reused sidecars and wrote them; the `on_add` paths —
//! the ones a re-import actually takes — called `hash_with_manifest` directly
//! and did neither. So the record that exists precisely to "let the library be
//! re-imported into a fresh forest without paying for the hashing again" was
//! ignored by the re-import, and a fresh forest re-read every byte.
//!
//! PROVING reuse took two wrong tries. Timing cannot do it: blake3 with rayon
//! hashes 600 MB in about a second on the build host, so cold and warm look
//! alike. Making the bytes unreadable cannot either — the scan marks a file it
//! cannot read as skipped BEFORE any hashing is attempted, so the file never
//! reaches the code under test.
//!
//! What does work: put a SENTINEL hash in the sidecar that the bytes could not
//! produce. If the forest records the sentinel, it read the sidecar; if it
//! records the real hash, it re-read the bytes. Nothing else explains either
//! outcome.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FILE, TYPE_FOLDER};

fn media(root: &std::path::Path) -> std::path::PathBuf {
    let lib = root.join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    // Over SWARM_CHUNK, so the whole-file hash and a single chunk hash differ.
    std::fs::write(lib.join("big.mkv"), vec![9u8; 9 * 1024 * 1024]).unwrap();
    lib
}

fn bind(engine: &mut Engine, lib: &std::path::Path) -> String {
    let root = engine.identity.root_node_id.clone();
    let folder = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "M".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    engine
        .bind_folder(
            &folder,
            BindSpec {
                source_uri: format!("file://{}", lib.display()),
                recursive: true,
                auto_index: true,
                extensions: String::new(),
                hash_policy: HashPolicy::OnAdd,
            },
        )
        .unwrap();
    folder
}

fn hash_of(engine: &Engine, folder: &str) -> String {
    let kids = engine.children(&folder.to_string()).unwrap();
    let desc: Vec<String> = kids
        .iter()
        .map(|c| format!("{}[{}]", c.node.label, c.node.node_type))
        .collect();
    kids.into_iter()
        .find(|c| c.node.node_type == TYPE_FILE)
        .map(|c| pvfs_core::FilePayload::decode(&c.node.payload).unwrap().content_hash)
        .unwrap_or_else(|| panic!("no TYPE_FILE child; children were {desc:?}"))
}

/// The whole point: a fresh forest must take the hash from the sidecar rather
/// than re-reading the file.
#[test]
fn a_fresh_import_takes_the_hash_from_the_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let lib = media(dir.path());
    let file = lib.join("big.mkv");

    // Forest A: cold. Reads the bytes, and must leave a sidecar behind — the
    // `on_add` path wrote nothing at all before D103.
    let (mut a, _mn) = Engine::init(&dir.path().join("fa")).unwrap();
    let fa = bind(&mut a, &lib);
    a.scan_routed(Some(&fa), None, 0).unwrap();
    let real = hash_of(&a, &fa);
    assert!(!real.is_empty(), "on_add must hash");
    a.close().unwrap();

    let sidecar = pvfs_core::sync::manifest_sidecar_path(&file);
    assert!(
        sidecar.exists(),
        "on_add must leave the record the next forest needs"
    );

    // Replace the recorded hash with one these bytes cannot produce. The size
    // stays honest, because that is what a sidecar is allowed to promise and
    // what the reader checks.
    // Line 3 of the v2 format is the whole-file hash (header / chunk size /
    // whole hash / exact size / chunk hashes). Rewriting that one line leaves
    // the size honest, which is what the reader validates.
    let sentinel = "5e0771e1".repeat(8);
    assert_ne!(sentinel, real);
    let text = std::fs::read_to_string(&sidecar).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    assert_eq!(lines[2], real, "line 3 should be the whole-file hash");
    lines[2] = sentinel.clone();
    std::fs::write(&sidecar, lines.join("\n") + "\n").unwrap();

    // Forest B: same bytes, sidecar now says something else.
    let (mut b, _mn) = Engine::init(&dir.path().join("fb")).unwrap();
    let fb = bind(&mut b, &lib);
    b.scan_routed(Some(&fb), None, 0).unwrap();
    let got = hash_of(&b, &fb);
    b.close().unwrap();

    assert_eq!(
        got, sentinel,
        "a fresh import re-read the bytes instead of reusing the sidecar \
         (got the real hash {real}), which on the production library is 40 TB \
         of reading for a record already on disk"
    );
}
