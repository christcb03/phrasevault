//! P2 access-control foundation (doc 06 §3–§4): member authorization + ACLs.

use pvfs_core::{acl, crypto, identity, Engine, NodeSpec, PvfsError, TYPE_FOLDER};

/// A well-formed compressed secp256k1 pubkey the forest has never seen.
fn foreign_pubkey() -> Vec<u8> {
    let k = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    crypto::pubkey_bytes(&k)
}

fn folder(label: &str) -> NodeSpec {
    NodeSpec {
        node_type: TYPE_FOLDER.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    }
}

/// Sign each event of a prepared write with `sign` and commit it (the two-phase
/// member path). Lets a test act as a member/app signing with its own key.
fn commit_with(
    engine: &mut Engine,
    prep: pvfs_core::PreparedWrite,
    sign: impl Fn(&[u8; 32]) -> Vec<u8>,
) {
    let signed: Vec<_> = prep
        .events
        .into_iter()
        .map(|pe| {
            let mut ev = pe.event;
            ev.set_author_sig(sign(&pe.digest));
            ev
        })
        .collect();
    engine.commit_member_write(signed).unwrap();
}

#[test]
fn authorize_member_guards_and_survives_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, m) = Engine::init(dir.path()).unwrap();
    let member = foreign_pubkey();

    // malformed key → BadInput
    assert!(matches!(
        engine.authorize_member(&m, &[1u8, 2, 3]),
        Err(PvfsError::BadInput { .. })
    ));

    // wrong recovery phrase → Identity (only the identity root may authorize)
    let wrong = identity::generate_mnemonic().unwrap();
    assert!(matches!(
        engine.authorize_member(&wrong, &member),
        Err(PvfsError::Identity { .. })
    ));

    // happy path, then duplicate → AlreadyExists
    engine.authorize_member(&m, &member).unwrap();
    assert!(matches!(
        engine.authorize_member(&m, &member),
        Err(PvfsError::AlreadyExists { .. })
    ));
    engine.close().unwrap();

    // the grant is a root-signed log event: it survives a full projection rebuild
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    Engine::open(dir.path())
        .expect("authorized member survives rebuild")
        .close()
        .unwrap();
}

// doc 06 §4.2 — grant inheritance, the `any` wildcard, owner-always-full, rebuild
#[test]
fn acl_inheritance_wildcard_and_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, m) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let media = engine.add_node(&root, folder("media")).unwrap();
    let clip = engine.add_node(&media, folder("clip")).unwrap();
    let private = engine.add_node(&root, folder("private")).unwrap();

    let member = foreign_pubkey();
    engine.authorize_member(&m, &member).unwrap();
    let p = acl::Principal::Key(member.clone());

    // a bare member has no rights anywhere
    assert_eq!(engine.effective_rights(&p, &root).unwrap(), 0);

    // grant read on /media → inherited down to /media/clip, not up to root or sibling
    engine.set_acl(&media, &p, acl::ACL_R).unwrap();
    assert_eq!(engine.effective_rights(&p, &media).unwrap(), acl::ACL_R);
    assert_eq!(engine.effective_rights(&p, &clip).unwrap(), acl::ACL_R);
    assert_eq!(engine.effective_rights(&p, &root).unwrap(), 0);
    assert_eq!(engine.effective_rights(&p, &private).unwrap(), 0);

    // `any` write on root reaches every authorized member, everywhere (inherited down)
    engine.set_acl(&root, &acl::Principal::Any, acl::ACL_W).unwrap();
    assert_eq!(
        engine.effective_rights(&p, &clip).unwrap(),
        acl::ACL_R | acl::ACL_W
    );

    // the owner device is always full, with or without explicit grants
    let owner = acl::Principal::Key(engine.device_pubkey());
    assert_eq!(engine.effective_rights(&owner, &private).unwrap(), acl::ACL_RWA);

    // clearing the /media grant drops R there; the wildcard W remains
    engine.set_acl(&media, &p, 0).unwrap();
    assert_eq!(engine.effective_rights(&p, &clip).unwrap(), acl::ACL_W);
    assert!(engine.acl_entries(&media).unwrap().is_empty());

    // a re-grant shows up as a direct entry
    engine.set_acl(&media, &p, acl::ACL_R).unwrap();
    assert_eq!(engine.acl_entries(&media).unwrap().len(), 1);
    engine.close().unwrap();

    // ACLs are log events → survive a full rebuild
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let engine = Engine::open(dir.path()).unwrap();
    assert_eq!(
        engine.effective_rights(&p, &clip).unwrap(),
        acl::ACL_R | acl::ACL_W
    );
    engine.close().unwrap();
}

// doc 06 §4.2 / doc 07 §10 — enforcement primitives the daemon will call
#[test]
fn can_and_readable_children() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, m) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let public = engine.add_node(&root, folder("public")).unwrap();
    let _secret = engine.add_node(&root, folder("secret")).unwrap();

    let member = foreign_pubkey();
    engine.authorize_member(&m, &member).unwrap();
    let p = acl::Principal::Key(member);
    engine.set_acl(&public, &p, acl::ACL_R).unwrap(); // read on `public` only

    assert!(engine.can(&p, &public, acl::ACL_R).unwrap());
    assert!(!engine.can(&p, &_secret, acl::ACL_R).unwrap());
    assert!(!engine.can(&p, &public, acl::ACL_W).unwrap());

    let visible: Vec<String> = engine
        .readable_children(&p, &root)
        .unwrap()
        .into_iter()
        .map(|c| c.node.id)
        .collect();
    assert_eq!(visible, vec![public], "member sees only the granted child");

    // the owner device sees every child
    let owner = acl::Principal::Key(engine.device_pubkey());
    assert_eq!(engine.readable_children(&owner, &root).unwrap().len(), 2);
    engine.close().unwrap();
}

// doc 07 §5 — two-phase member write: prepare (daemon) → member signs → commit
#[test]
fn member_write_two_phase() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let dropbox = engine.add_node(&root, folder("dropbox")).unwrap();

    let member_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member_pub = crypto::pubkey_bytes(&member_key);
    engine.authorize_member(&owner_mn, &member_pub).unwrap();
    engine
        .set_acl(
            &dropbox,
            &acl::Principal::Key(member_pub.clone()),
            acl::ACL_R | acl::ACL_W,
        )
        .unwrap();

    // no write on root → prepare is refused
    assert!(matches!(
        engine.prepare_add_node(&member_pub, &root, folder("nope")),
        Err(PvfsError::Forbidden { .. })
    ));

    // prepare under dropbox (has w) → the member signs each digest → commit
    let prep = engine
        .prepare_add_node(&member_pub, &dropbox, folder("hello"))
        .unwrap();
    let signed: Vec<_> = prep
        .events
        .into_iter()
        .map(|pe| {
            let mut ev = pe.event;
            ev.set_author_sig(crypto::sign_digest(&member_key, &pe.digest).unwrap());
            ev
        })
        .collect();
    engine.commit_member_write(signed).unwrap();

    // the new node exists under dropbox and is authored by the member, not the owner
    let kids = engine.children(&dropbox).unwrap();
    let hello = kids
        .iter()
        .find(|c| c.node.label == "hello")
        .expect("member created the node");
    assert_eq!(hello.node.author, member_pub);
    let hello_id = hello.node.id.clone();
    engine.close().unwrap();

    // the member write replays through a full rebuild (member had w when created)
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let engine = Engine::open(dir.path()).unwrap();
    assert!(engine.node(&hello_id).unwrap().is_some());
    engine.close().unwrap();
}

// doc 09 §1 — tag-based sharing: a node grants `tag:X`; members holding X get it
#[test]
fn member_tags_grant_access() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, m) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let media = engine.add_node(&root, folder("media")).unwrap();

    let member = foreign_pubkey();
    engine.authorize_member(&m, &member).unwrap();
    let p = acl::Principal::Key(member.clone());

    // share /media with the `media_users` tag (read)
    engine
        .set_acl(&media, &acl::Principal::Tag("media_users".into()), acl::ACL_R)
        .unwrap();

    // a member without the tag sees nothing
    assert_eq!(engine.effective_rights(&p, &media).unwrap(), 0);

    // grant the tag → access (and it inherits down the tree)
    engine.set_member_tag(&member, "media_users", true).unwrap();
    assert!(engine
        .member_tags(&member)
        .unwrap()
        .iter()
        .any(|(_authority, t)| t == "media_users"));
    assert_eq!(engine.effective_rights(&p, &media).unwrap(), acl::ACL_R);
    let clip = engine.add_node(&media, folder("clip")).unwrap();
    assert_eq!(engine.effective_rights(&p, &clip).unwrap(), acl::ACL_R);
    // querying the tag principal reports the share grant itself
    assert_eq!(
        engine
            .effective_rights(&acl::Principal::Tag("media_users".into()), &media)
            .unwrap(),
        acl::ACL_R
    );
    engine.close().unwrap();

    // both the share grant and the member's tag survive a full rebuild
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let mut engine = Engine::open(dir.path()).unwrap();
    assert_eq!(engine.effective_rights(&p, &media).unwrap(), acl::ACL_R);

    // dropping the tag revokes access on the fly
    engine.set_member_tag(&member, "media_users", false).unwrap();
    assert_eq!(engine.effective_rights(&p, &media).unwrap(), 0);
    engine.close().unwrap();
}

// doc 09 §2.2 — an admin device admits a member with no recovery phrase
#[test]
fn admin_device_authorizes_member_without_phrase() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();

    // owner's device (admin) authorizes a member — no mnemonic
    let member_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member_pub = crypto::pubkey_bytes(&member_key);
    engine.authorize_member_by_device(&member_pub).unwrap();

    // grant write and let the member create a node signed with their own key
    let dropbox = engine.add_node(&root, folder("dropbox")).unwrap();
    engine
        .set_acl(
            &dropbox,
            &acl::Principal::Key(member_pub.clone()),
            acl::ACL_R | acl::ACL_W,
        )
        .unwrap();
    let prep = engine
        .prepare_add_node(&member_pub, &dropbox, folder("hi"))
        .unwrap();
    let signed: Vec<_> = prep
        .events
        .into_iter()
        .map(|pe| {
            let mut ev = pe.event;
            ev.set_author_sig(crypto::sign_digest(&member_key, &pe.digest).unwrap());
            ev
        })
        .collect();
    engine.commit_member_write(signed).unwrap();
    engine.close().unwrap();

    // the admin-device-signed cert AND the member write replay through a rebuild
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let engine = Engine::open(dir.path()).unwrap();
    assert_eq!(engine.children(&dropbox).unwrap().len(), 1);
    engine.close().unwrap();
}

// doc 07 §4 — the three tiers: `public` reaches everyone; `any` only members
#[test]
fn acl_public_vs_any_tiers() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, m) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let shared = engine.add_node(&root, folder("shared")).unwrap();
    let members_only = engine.add_node(&root, folder("members-only")).unwrap();

    let member = foreign_pubkey();
    engine.authorize_member(&m, &member).unwrap();
    let memberp = acl::Principal::Key(member);
    let stranger = acl::Principal::Key(foreign_pubkey()); // never authorized

    // `public` read on `shared` reaches everyone — even an unauthorized/unknown key
    engine.set_acl(&shared, &acl::Principal::Public, acl::ACL_R).unwrap();
    assert!(engine.can(&acl::Principal::Public, &shared, acl::ACL_R).unwrap());
    assert!(engine.can(&memberp, &shared, acl::ACL_R).unwrap());
    assert!(engine.can(&stranger, &shared, acl::ACL_R).unwrap());
    assert!(!engine.can(&acl::Principal::Public, &root, acl::ACL_R).unwrap());

    // `any` read on `members-only` reaches authorized members only
    engine
        .set_acl(&members_only, &acl::Principal::Any, acl::ACL_R)
        .unwrap();
    assert!(engine.can(&memberp, &members_only, acl::ACL_R).unwrap());
    assert!(!engine.can(&acl::Principal::Public, &members_only, acl::ACL_R).unwrap());
    assert!(
        !engine.can(&stranger, &members_only, acl::ACL_R).unwrap(),
        "an unauthorized key is not a member"
    );
    engine.close().unwrap();
}

// doc 10 §8 #1+#2 — per-key tags: two apps both use the name `friend`, but a tag
// only combines when the same key authored the grant and the membership. Also
// exercises self-service tagging: a non-root-admin app tags a member itself.
#[test]
fn per_key_tags_isolate_apps() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, m) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let node_a = engine.add_node(&root, folder("app-a")).unwrap();
    let node_b = engine.add_node(&root, folder("app-b")).unwrap();

    // two apps and a member, all authorized; each app gets admin only on its node
    let app_a = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let app_b = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let app_a_pub = crypto::pubkey_bytes(&app_a);
    let app_b_pub = crypto::pubkey_bytes(&app_b);
    let member = foreign_pubkey();
    for k in [&app_a_pub, &app_b_pub, &member] {
        engine.authorize_member(&m, k).unwrap();
    }
    engine
        .set_acl(&node_a, &acl::Principal::Key(app_a_pub.clone()), acl::ACL_A)
        .unwrap();
    engine
        .set_acl(&node_b, &acl::Principal::Key(app_b_pub.clone()), acl::ACL_A)
        .unwrap();

    // each app shares its node with `tag:friend` under its OWN authority
    let prep = engine
        .prepare_set_acl(&app_a_pub, &node_a, &acl::Principal::Tag("friend".into()), acl::ACL_R)
        .unwrap();
    commit_with(&mut engine, prep, |d| crypto::sign_digest(&app_a, d).unwrap());
    let prep = engine
        .prepare_set_acl(&app_b_pub, &node_b, &acl::Principal::Tag("friend".into()), acl::ACL_R)
        .unwrap();
    commit_with(&mut engine, prep, |d| crypto::sign_digest(&app_b, d).unwrap());

    // app A tags the member `friend` — self-service, no admin on the forest root
    let prep = engine
        .prepare_set_member_tag(&app_a_pub, &member, "friend", true)
        .unwrap();
    commit_with(&mut engine, prep, |d| crypto::sign_digest(&app_a, d).unwrap());

    // the member reads app A's node (same authority) but NOT app B's (different
    // authority granted B's node, even though the tag name is identical)
    let p = acl::Principal::Key(member.clone());
    assert_eq!(engine.effective_rights(&p, &node_a).unwrap(), acl::ACL_R);
    assert_eq!(
        engine.effective_rights(&p, &node_b).unwrap(),
        0,
        "app A's `friend` must not unlock app B's `friend`"
    );
    engine.close().unwrap();

    // the (authority, name) scoping survives a rebuild from the log
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let engine = Engine::open(dir.path()).unwrap();
    assert_eq!(engine.effective_rights(&p, &node_a).unwrap(), acl::ACL_R);
    assert_eq!(engine.effective_rights(&p, &node_b).unwrap(), 0);
    engine.close().unwrap();
}

// doc 10 §8 #4 / §9.2 — revoking the tag's authority denies access immediately:
// the membership is masked (no log write) and stays masked across a rebuild.
#[test]
fn revoking_tag_authority_denies_access() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, m) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let node = engine.add_node(&root, folder("shared")).unwrap();

    let app = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let app_pub = crypto::pubkey_bytes(&app);
    let member = foreign_pubkey();
    engine.authorize_member(&m, &app_pub).unwrap();
    engine.authorize_member(&m, &member).unwrap();
    engine
        .set_acl(&node, &acl::Principal::Key(app_pub.clone()), acl::ACL_A)
        .unwrap();

    // app shares the node by tag and tags the member, under the app's authority
    let prep = engine
        .prepare_set_acl(&app_pub, &node, &acl::Principal::Tag("crew".into()), acl::ACL_R)
        .unwrap();
    commit_with(&mut engine, prep, |d| crypto::sign_digest(&app, d).unwrap());
    let prep = engine
        .prepare_set_member_tag(&app_pub, &member, "crew", true)
        .unwrap();
    commit_with(&mut engine, prep, |d| crypto::sign_digest(&app, d).unwrap());

    let p = acl::Principal::Key(member.clone());
    assert_eq!(engine.effective_rights(&p, &node).unwrap(), acl::ACL_R);

    // revoke the app (the tag's authority) — access drops with no further events
    engine.revoke_by_device(&app_pub).unwrap();
    assert_eq!(
        engine.effective_rights(&p, &node).unwrap(),
        0,
        "a tag from a revoked authority must not grant access"
    );
    engine.close().unwrap();

    // and the masking is reproduced on a rebuild from the log
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let engine = Engine::open(dir.path()).unwrap();
    assert_eq!(engine.effective_rights(&p, &node).unwrap(), 0);
    engine.close().unwrap();
}
