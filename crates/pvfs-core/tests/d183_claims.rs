//! PVOS D183 — a region's head taken provisionally from the box that owns the
//! region: accepted on the fold's own rule, installable, and replaced by the
//! committed head when the owner is back.

use pvfs_core::acl::Principal;
use pvfs_core::event::{self, Event};
use pvfs_core::{crypto, identity, BindSpec, ClaimOutcome, Engine, HashPolicy, NodeSpec, RegionEntry, ReplicaSource, ReplicaStore, TYPE_FOLDER};

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

fn row(rel: &str, kind: &str, size: u64, hash: Option<&str>) -> RegionEntry {
    RegionEntry {
        rel_path: rel.into(),
        kind: kind.into(),
        size_bytes: size,
        mtime_ms: 1_700_000_000_000,
        changed_ms: 1_700_000_000_000,
        content_hash: hash.map(|h| h.into()),
        quality: None,
        seen_at: 0,
    }
}

/// What a region's own box hands its peers: its head, signed by it.
fn claim(key: &identity::SigningKey, region: &str, seq: u64, manifest_hash_hex: &str) -> Vec<u8> {
    let author = crypto::pubkey_bytes(key);
    let head_hash = hex::decode(manifest_hash_hex).unwrap();
    let at = 1_790_000_000_000 + seq;
    let sig = crypto::sign_digest(key, &event::msg_sub_region_head(region, seq, &head_hash, at, &author)).unwrap();
    Event::SubRegionHead { node_id: region.into(), head_seq: seq, head_hash, at, author, sig }.encode_body()
}

/// The forest owner commits `hash` at `seq` for the region, as the routed op does.
fn attest(e: &mut Engine, key: &identity::SigningKey, region: &str, seq: u64, hash: &str) {
    let pubkey = crypto::pubkey_bytes(key);
    let prep = e.prepare_commit_region_head(&pubkey, &region.to_string(), seq, hash).unwrap();
    let mut events = Vec::new();
    for pe in prep.events {
        let mut ev = pe.event;
        ev.set_author_sig(crypto::sign_digest(key, &pe.digest).unwrap());
        events.push(ev);
    }
    e.commit_member_write(events).unwrap();
}

struct Setup {
    _tmp: tempfile::TempDir,
    e: Engine,
    mn: pvfs_core::Mnemonic,
    far: String,
    local: String,
    holder: identity::SigningKey,
}

/// A forest with one region this box catalogues (`local`) and one another box
/// owns (`far`, granted to `holder`'s key).
fn setup() -> Setup {
    let tmp = tempfile::tempdir().unwrap();
    let mine = tmp.path().join("mine");
    std::fs::create_dir_all(mine.join("Shows")).unwrap();
    std::fs::write(mine.join("Shows/local.mkv"), b"local-bytes").unwrap();
    let (mut e, mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let local = folder(&mut e, &root, "Local");
    e.region_mark_as(&local, "catalogue", None).unwrap();
    e.bind_folder(
        &local,
        BindSpec {
            source_uri: format!("file://{}", mine.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    e.scan_routed(Some(&local), None, 0).unwrap();
    let holder = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let holder_pub = crypto::pubkey_bytes(&holder);
    e.authorize_member(&mn, &holder_pub).unwrap();
    let far = folder(&mut e, &root, "Far");
    e.region_mark_as(&far, "catalogue", Some(&Principal::Key(holder_pub))).unwrap();
    Setup { _tmp: tmp, e, mn, far, local, holder }
}

fn manifest(region: &str, seq: u64, extra: &str) -> (Vec<u8>, String) {
    let rows = vec![row("Shows", "dir", 0, None), row(&format!("Shows/{extra}.mkv"), "file", 9, Some(&"33".repeat(32)))];
    let bytes = Engine::region_manifest_bytes(region, seq, &rows);
    let hash = blake3::hash(&bytes).to_hex().to_string();
    (bytes, hash)
}

fn status(e: &Engine, region: &str) -> pvfs_core::CatalogueStatus {
    e.catalogue_status().unwrap().into_iter().find(|s| s.region == region).unwrap()
}

#[test]
fn a_signed_claim_is_taken_provisionally_and_its_manifest_installs() {
    let mut s = setup();
    let (bytes, hash) = manifest(&s.far, 1, "while-away");
    // Nothing in the log for `far`: before D183 this was not installable.
    assert!(s.e.install_region_snapshot(&s.far, 1, &bytes, "peer:7434").is_err());

    let got = s.e.accept_region_claim(&claim(&s.holder, &s.far, 1, &hash), "peer:7434").unwrap();
    assert_eq!(got, ClaimOutcome::Accepted { region: s.far.clone(), seq: 1 });
    let st = status(&s.e, &s.far);
    assert_eq!((st.head_seq, st.committed_seq, st.provisional, st.stale, st.held_seq), (1, 0, true, true, None));

    let mut e = s.e;
    assert_eq!(e.install_region_snapshot(&s.far, 1, &bytes, "peer:7434").unwrap(), 2);
    let st = status(&e, &s.far);
    assert_eq!((st.held_seq, st.stale), (Some(1), false), "installed at the provisional head");
    assert!(e.merged_view("Shows").unwrap().iter().any(|v| v.rel_path == "Shows/while-away.mkv"));
    // The same claim again is nothing new.
    assert_eq!(e.accept_region_claim(&claim(&s.holder, &s.far, 1, &hash), "peer:7434").unwrap(), ClaimOutcome::Known);
}

#[test]
fn claims_are_refused_on_the_folds_own_rule() {
    let mut s = setup();
    let (_, hash) = manifest(&s.far, 1, "a");
    // A signature that does not verify.
    let mut forged = claim(&s.holder, &s.far, 1, &hash);
    let n = forged.len();
    forged[n - 1] ^= 0x01;
    assert!(matches!(s.e.accept_region_claim(&forged, "p").unwrap(), ClaimOutcome::Refused(_)));
    // A key with no grant on the region (a member, but not this region's).
    let stranger = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    s.e.authorize_member(&s.mn, &crypto::pubkey_bytes(&stranger)).unwrap();
    match s.e.accept_region_claim(&claim(&stranger, &s.far, 1, &hash), "p").unwrap() {
        ClaimOutcome::Refused(why) => assert!(why.contains("may not publish"), "{why}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    // A claim for the region this box catalogues itself: its rows are the authority.
    let (_, lhash) = manifest(&s.local, 5, "x");
    assert_eq!(s.e.accept_region_claim(&claim(&s.holder, &s.local, 5, &lhash), "p").unwrap(), ClaimOutcome::Known);

    // Equivocation: two different heads at one seq.
    let (_, h3a) = manifest(&s.far, 3, "a");
    let (_, h3b) = manifest(&s.far, 3, "b");
    assert!(matches!(s.e.accept_region_claim(&claim(&s.holder, &s.far, 3, &h3a), "p").unwrap(), ClaimOutcome::Accepted { .. }));
    match s.e.accept_region_claim(&claim(&s.holder, &s.far, 3, &h3b), "q").unwrap() {
        ClaimOutcome::Refused(why) => assert!(why.contains("two different heads"), "{why}"),
        other => panic!("expected the second head at seq 3 refused, got {other:?}"),
    }
    assert_eq!(status(&s.e, &s.far).head_hash, h3a, "the first stands");
    // Older than what is held: nothing new.
    let (_, h2) = manifest(&s.far, 2, "old");
    assert_eq!(s.e.accept_region_claim(&claim(&s.holder, &s.far, 2, &h2), "p").unwrap(), ClaimOutcome::Known);

    // The log's head is the record: another hash at its seq is refused.
    let (_, h4) = manifest(&s.far, 4, "committed");
    attest(&mut s.e, &s.holder, &s.far, 4, &h4);
    let (_, h4x) = manifest(&s.far, 4, "other");
    assert!(matches!(s.e.accept_region_claim(&claim(&s.holder, &s.far, 4, &h4x), "p").unwrap(), ClaimOutcome::Refused(_)));

    // A revoked author: refused, whatever it signs (the posture: every read
    // verifies the signer is not revoked).
    let holder_pub = crypto::pubkey_bytes(&s.holder);
    s.e.revoke_device(&s.mn, &holder_pub).unwrap();
    let (_, h9) = manifest(&s.far, 9, "after-revocation");
    match s.e.accept_region_claim(&claim(&s.holder, &s.far, 9, &h9), "p").unwrap() {
        ClaimOutcome::Refused(why) => assert!(why.contains("may not publish"), "{why}"),
        other => panic!("expected a revoked author refused, got {other:?}"),
    }
}

#[test]
fn a_committed_head_clears_the_provisional_one() {
    let mut s = setup();
    let (_, h1) = manifest(&s.far, 1, "one");
    let (_, h3) = manifest(&s.far, 3, "three");
    assert!(matches!(s.e.accept_region_claim(&claim(&s.holder, &s.far, 3, &h3), "p").unwrap(), ClaimOutcome::Accepted { .. }));
    // The owner commits an OLDER head: the provisional one still leads.
    attest(&mut s.e, &s.holder, &s.far, 1, &h1);
    let st = status(&s.e, &s.far);
    assert_eq!((st.head_seq, st.committed_seq, st.provisional), (3, 1, true));
    // The owner commits the same head: it is the record; the provisional row goes.
    attest(&mut s.e, &s.holder, &s.far, 3, &h3);
    let st = status(&s.e, &s.far);
    assert_eq!((st.head_seq, st.committed_seq, st.provisional, st.head_hash.as_str()), (3, 3, false, h3.as_str()));
    // And it survives a reopen (the fold did it, not a flag in memory).
    let dir = s.e.data_dir().to_path_buf();
    s.e.close().unwrap();
    let e = Engine::open(&dir).unwrap();
    assert!(!status(&e, &s.far).provisional);
    e.close().unwrap();
}

#[test]
fn region_claims_sign_a_replicas_newest_published_heads() {
    let s = setup();
    let author = crypto::pubkey_bytes(&s.holder);
    // The forest owner offers none: it commits its heads straight into the log.
    assert!(s.e.region_claims(&author, |d| crypto::sign_digest(&s.holder, d)).unwrap().is_empty());

    // A replica that catalogues `far`, scanning with the owner away.
    let rows = s.e.log_events(1, s.e.log_tip().unwrap() as usize).unwrap();
    let rdir = s._tmp.path().join("replica");
    ReplicaStore::open(&rdir).unwrap().append(&rows).unwrap();
    ReplicaSource {
        transport: "socket".into(),
        target: s._tmp.path().join("owner.sock").display().to_string(),
        pin: String::new(),
        region: String::new(),
    }
    .save(&rdir)
    .unwrap();
    let media = s._tmp.path().join("far-media");
    std::fs::create_dir_all(media.join("Shows")).unwrap();
    std::fs::write(media.join("Shows/one.mkv"), b"one").unwrap();
    let mut r = Engine::open(&rdir).unwrap();
    r.bind_folder(
        &s.far,
        BindSpec {
            source_uri: format!("file://{}", media.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    assert!(r.catalogues_only().unwrap(), "every binding here is a catalogue region");
    let mut away = pvfs_core::OwnerAway;
    r.scan_routed(None, Some(&mut away), 0).unwrap();
    let claims = r.region_claims(&author, |d| crypto::sign_digest(&s.holder, d)).unwrap();
    assert_eq!(claims.iter().map(|c| (c.region.as_str(), c.seq)).collect::<Vec<_>>(), vec![(s.far.as_str(), 1)]);
    let ev = Event::decode(event::K_SUB_REGION_HEAD, &claims[0].body).unwrap();
    ev.verify_sig(&event::SigContext { forest_id: "any", bound: false }).unwrap(); // a region head: no forest authority
    match ev {
        Event::SubRegionHead { node_id, head_seq, head_hash, author: a, .. } => {
            assert_eq!((node_id.as_str(), head_seq, a.as_slice()), (s.far.as_str(), 1, author.as_slice()));
            assert_eq!(hex::encode(head_hash), claims[0].hash);
        }
        other => panic!("{other:?}"),
    }
    // Another scan while still away: the claim follows the newest, and one
    // head per region is pending — the newest, which is what commits.
    std::fs::write(media.join("Shows/two.mkv"), b"two").unwrap();
    r.scan_routed(None, Some(&mut away), 0).unwrap();
    let claims = r.region_claims(&author, |d| crypto::sign_digest(&s.holder, d)).unwrap();
    assert_eq!(claims.iter().map(|c| c.seq).collect::<Vec<_>>(), vec![2]);
    assert_eq!(r.pending_region_heads().unwrap().iter().map(|p| p.1).collect::<Vec<_>>(), vec![2]);
    r.close().unwrap();
}
