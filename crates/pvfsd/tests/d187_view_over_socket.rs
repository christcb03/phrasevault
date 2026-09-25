//! PVOS D187 — the merged view and `region ls` over the socket (protocol 13).
//!
//! An application (PVOS's Media app) reads a forest through its daemon,
//! under the forest's ACLs, instead of opening its store (which would hand
//! it the owner's device key and bypass every grant). Member-gated like
//! `ServeStatus`; every answer judged only over the regions the caller may
//! read — a path held only where it may not read is not there at all, and a
//! path held in two regions shows the copies it may read, re-judged.

use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Arc;

use pvfs_client::{Client, ClientError, VIEW_PROTO};
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

fn write(root: &Path, rel: &str, bytes: &[u8]) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

fn region(e: &mut Engine, root: &str, label: &str, dir: &Path) -> String {
    let r = e
        .add_node(
            &root.to_string(),
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
    e.scan_routed(Some(&r), None, 0).unwrap();
    r
}

fn key() -> (identity::SigningKey, Vec<u8>) {
    let k = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let p = crypto::pubkey_bytes(&k);
    (k, p)
}

fn connect(sock: &Path, k: &identity::SigningKey, p: &[u8]) -> Client {
    let k = k.clone();
    Client::connect_signed(sock, p, move |d| crypto::sign_digest(&k, d).unwrap()).unwrap()
}

fn names(entries: &[pvfs_proto::ViewEntryWire]) -> Vec<String> {
    let mut n: Vec<String> = entries.iter().map(|e| e.rel_path.clone()).collect();
    n.sort();
    n
}

#[test]
fn the_view_over_the_socket_shows_a_caller_only_what_it_may_read() {
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let (dir, shows_dir, movies_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    write(shows_dir.path(), "TV/Show/s01e01.mkv", b"episode-bytes");
    write(shows_dir.path(), "Both/shared.mkv", b"the-same-film");
    write(movies_dir.path(), "Films/film.mkv", b"a-film-only-in-movies");
    write(movies_dir.path(), "Both/shared.mkv", b"the-same-film");

    let (mut owner, mn) = Engine::init(dir.path()).unwrap();
    let root = owner.identity.root_node_id.clone();
    let shows = region(&mut owner, &root, "Shows", shows_dir.path());
    let movies = region(&mut owner, &root, "Movies", movies_dir.path());

    // A reader of the whole forest; a member who may read Shows only; a
    // member with no reads; a key the forest never admitted.
    let (all_k, all_p) = key();
    owner.authorize_member(&mn, &all_p).unwrap();
    owner.set_acl(&root, &Principal::Key(all_p.clone()), acl::ACL_R).unwrap();
    let (shows_k, shows_p) = key();
    owner.authorize_member(&mn, &shows_p).unwrap();
    owner.set_acl(&shows, &Principal::Key(shows_p.clone()), acl::ACL_R).unwrap();
    let (none_k, none_p) = key();
    owner.authorize_member(&mn, &none_p).unwrap();
    let (out_k, out_p) = key();

    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = Arc::new(Daemon::new(owner));
    std::thread::spawn(move || {
        let _ = serve(listener, daemon);
    });

    // ── the whole forest ────────────────────────────────────────────────
    let mut all = connect(&sock, &all_k, &all_p);
    assert!(all.daemon_proto() >= VIEW_PROTO);
    assert_eq!(names(&all.view_ls("").unwrap()), vec!["Both", "Films", "TV"]);
    let shared = all.view_entry("Both/shared.mkv").unwrap().expect("the shared film");
    assert_eq!((shared.sources.len(), shared.copies, shared.state.as_str()), (2, 2, "admitted"));
    assert_eq!(shared.content_hash.as_deref(), Some(blake3::hash(b"the-same-film").to_hex().as_str()));
    let film = all.view_entry("Films/film.mkv").unwrap().expect("the film");
    assert_eq!(film.size_bytes, b"a-film-only-in-movies".len() as u64);
    assert_eq!(names(&all.view_ls("TV/Show").unwrap()), vec!["TV/Show/s01e01.mkv"]);
    let mut labels: Vec<String> = all.catalogue_status().unwrap().into_iter().map(|r| r.label).collect();
    labels.sort();
    assert_eq!(labels, vec!["Movies", "Shows"]);

    // ── a member who may read Shows only ────────────────────────────────
    let mut some = connect(&sock, &shows_k, &shows_p);
    assert_eq!(names(&some.view_ls("").unwrap()), vec!["Both", "TV"], "Films lives only in Movies");
    assert!(some.view_entry("Films/film.mkv").unwrap().is_none(), "not a hint of a path it may not read");
    let shared = some.view_entry("Both/shared.mkv").unwrap().expect("its own copy");
    assert_eq!((shared.sources.len(), shared.copies), (1, 1), "re-judged over the copy it may read");
    assert_eq!(shared.sources[0].region, shows);
    let status = some.catalogue_status().unwrap();
    assert_eq!(status.len(), 1);
    assert_eq!((status[0].region.as_str(), status[0].label.as_str()), (shows.as_str(), "Shows"));
    assert!(status[0].head_seq >= 1 && status[0].local, "{:?}", status[0]);
    assert!(!status.iter().any(|r| r.region == movies));

    // ── a member with no reads sees an empty view, not an error ─────────
    let mut none = connect(&sock, &none_k, &none_p);
    assert!(none.view_ls("").unwrap().is_empty());
    assert!(none.catalogue_status().unwrap().is_empty());

    // ── a key the forest never admitted is refused ──────────────────────
    let mut out = connect(&sock, &out_k, &out_p);
    match out.view_ls("") {
        Err(ClientError::Server { code, .. }) => assert_eq!(code, "forbidden"),
        other => panic!("an unenrolled key must be refused, got {other:?}"),
    }
}
