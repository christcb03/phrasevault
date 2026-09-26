//! PVOS D193 — a personal forest's genesis, signed by the person.
//!
//! Prepared from public keys, signed with the person's root and identity
//! keys, committed by the hosting box only after a full verifying replay.
//! The box's key is a member with no grant; the person's identity key is the
//! owner device (it certifies their session keys).

use pvfs_core::acl::{Principal, ACL_A, ACL_R, ACL_W};
use pvfs_core::personal::{
    init_signed_genesis, prepare_personal_genesis, prepare_personal_genesis_with, GenesisParams, GenesisSigner,
    PersonalGenesis,
};
use pvfs_core::{crypto, identity, Engine, NodeSpec};

struct Person {
    root: identity::SigningKey,
    ident: identity::SigningKey,
}

impl Person {
    fn new() -> Person {
        let mn = identity::generate_mnemonic().unwrap();
        Person {
            root: identity::root_key(&mn, "").unwrap(),
            ident: identity::identity_key(&mn, "", 0).unwrap(),
        }
    }

    fn genesis(&self, host: &identity::SigningKey) -> PersonalGenesis {
        PersonalGenesis {
            root_pub: crypto::pubkey_bytes(&self.root),
            identity_pub: crypto::pubkey_bytes(&self.ident),
            host_pub: crypto::pubkey_bytes(host),
        }
    }
}

#[test]
fn a_personal_forest_is_the_persons_and_its_host_holds_no_grant() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("people-alice");
    let person = Person::new();
    let host = identity::generate_device_key();
    let prep = prepare_personal_genesis(&person.genesis(&host)).unwrap();
    assert_eq!(prep.events.len(), 5);
    let forest_id = prep.params.forest_id.clone();
    let events = prep.sign(&person.root, &person.ident).unwrap();
    let mut engine = init_signed_genesis(&data, events, host.clone()).unwrap();

    assert_eq!(engine.identity.forest_id, forest_id);
    assert_eq!(engine.certificates_bound().unwrap().as_deref(), Some("genesis"), "born bound");
    assert_eq!(engine.current_root().unwrap(), crypto::pubkey_bytes(&person.root));
    let root = engine.identity.root_node_id.clone();
    let rights = |k: &identity::SigningKey| engine.effective_rights(&Principal::Key(crypto::pubkey_bytes(k)), &root).unwrap();
    assert_eq!(rights(&person.ident), ACL_R | ACL_W | ACL_A, "the identity is the owner device");
    assert_eq!(rights(&host), 0, "the host holds no grant");

    // the host cannot write on its own, nor admit anyone
    let spec = NodeSpec {
        node_type: "folder".into(),
        label: "mine".into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    };
    assert!(engine.add_node(&root, spec).is_err(), "the host's key writes nothing");
    let stranger = crypto::pubkey_bytes(&identity::generate_device_key());
    assert!(engine.prepare_authorize_member(&crypto::pubkey_bytes(&host), &stranger).is_err());

    // the person's identity certifies a session key (what a sign-in does)
    let session = crypto::pubkey_bytes(&identity::generate_device_key());
    let mut p = engine.prepare_authorize_member(&crypto::pubkey_bytes(&person.ident), &session).unwrap().events.remove(0);
    p.event.set_author_sig(crypto::sign_digest(&person.ident, &p.digest).unwrap());
    engine.commit_member_write(vec![p.event]).unwrap();
    assert!(engine.authority_active(&session).unwrap());
    engine.close().unwrap();

    Engine::open(&data).expect("the personal forest replays").close().unwrap();
}

#[test]
fn a_genesis_that_does_not_verify_leaves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("people-bob");
    let person = Person::new();
    let host = identity::generate_device_key();
    let prep = prepare_personal_genesis(&person.genesis(&host)).unwrap();
    // the identity's events signed by someone else
    let events = prep.sign(&person.root, &identity::generate_device_key()).unwrap(); // the identity's events by a stranger
    assert!(init_signed_genesis(&data, events, host).is_err());
    assert!(!data.exists(), "nothing is left behind");
}

#[test]
fn the_box_opens_it_only_with_the_key_the_genesis_admits() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("people-carol");
    let person = Person::new();
    let host = identity::generate_device_key();
    let events = prepare_personal_genesis(&person.genesis(&host)).unwrap().sign(&person.root, &person.ident).unwrap();
    assert!(init_signed_genesis(&data, events, identity::generate_device_key()).is_err());
    assert!(!data.exists());

    let mut same = person.genesis(&host);
    same.identity_pub = same.root_pub.clone();
    assert!(prepare_personal_genesis(&same).is_err(), "the four keys must differ");
}

/// BIP39's all-zero 256-bit vector.
const VECTOR: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

/// The keys a browser derives from a phrase must be the ones PVFS derives:
/// these vectors are pinned in the web page's tests too.
#[test]
fn the_phrase_keys_the_page_must_derive() {
    let mn = identity::parse_mnemonic(VECTOR).unwrap();
    let hex = |k: identity::SigningKey| hex::encode(crypto::pubkey_bytes(&k));
    let got = [
        ("root 0'", hex(identity::root_key(&mn, "").unwrap())),
        ("device 1'/0'", hex(identity::device_key(&mn, "", 0).unwrap())),
        ("encryption 2'/0'", hex(identity::encryption_key(&mn, "", 0).unwrap())),
        ("identity 3'/0'", hex(identity::identity_key(&mn, "", 0).unwrap())),
    ];
    let pinned = [
        ("root 0'", "036242fd83e40688fc2c61fa05061edc98fef9bf2e4c85c28718b9d5f4f6acd2ac"),
        ("device 1'/0'", "02c3a30e05b8c44bf16f0fcec80f481954acb45984d6ff6d6b0766385362092656"),
        ("encryption 2'/0'", "03d02843b4ffdfe3ae8a18feb3a9a2e6a4d5cc39150f2e8d9990da1b281355d744"),
        ("identity 3'/0'", "036435e78bcc147f4c92e0db70d4107d0c5bf04b169cf1b3d339212088df21a544"),
    ];
    for ((what, key), (_, want)) in got.iter().zip(pinned) {
        assert_eq!(key, want, "{what}");
    }
}

/// The genesis digests from fixed inputs — pinned in the web page's tests:
/// the page builds them itself from parameters it chose and the host's key
/// (so no server can slip itself in as the owner device, or aim a
/// certificate at another forest), and the box rebuilds the same events to
/// attach its signatures.
#[test]
fn the_genesis_digests_the_page_must_recompute() {
    use pvfs_core::{acl, event, link, node};
    let root = hex::decode("036242fd83e40688fc2c61fa05061edc98fef9bf2e4c85c28718b9d5f4f6acd2ac").unwrap();
    let ident = hex::decode("036435e78bcc147f4c92e0db70d4107d0c5bf04b169cf1b3d339212088df21a544").unwrap();
    let host = hex::decode("02c3a30e05b8c44bf16f0fcec80f481954acb45984d6ff6d6b0766385362092656").unwrap();
    let (instance, forest, t, nonce) = ("pvfs-00000001", "00000000-0000-4000-8000-000000000001", 1_700_000_000_000u64, 0x0123_4567_89ab_cdefu64);
    let node_id = hex::encode(node::compute_id_digest(node::TYPE_FOLDER, "root", node::VISIBILITY_PUBLIC, &[], false, nonce, t, &ident));
    let got = [
        ("root node", node_id.clone()),
        ("root link", hex::encode(link::compute_id_digest(None, &node_id, link::LINK_CONTAINS, 0))),
        ("forest created v2", hex::encode(event::msg_forest_created(instance, forest, &node_id, t, &root, true))),
        ("identity as owner device", hex::encode(event::msg_device_authorized(Some(forest), &ident, 0, t, &root))),
        ("host as member", hex::encode(event::msg_device_authorized(Some(forest), &host, acl::MEMBER_DEVICE_INDEX, t, &root))),
    ];
    let pinned = [
        "31071f80e0846ec198c1e2327480f4440fecc9a94af5bd92710b87c24331ff80",
        "5cc12ef8cdcfae7b6afda6cd6ec4893853c21de1eb0f5c921f796f6e185cc64c",
        "2ae3f1e6fcfb6c40784dc6c9f147fccfdc95e3dbb3e34f98a0aac13d5d4b7f68",
        "889c858d02e774d5f950f336eb5940eb034c20f8a9e43cada785eda4a1025b97",
        "7eaf631a33e329df0751ee57b42a0676215d6f96a580618f9fa04b11a7b634d3",
    ];
    for ((what, d), want) in got.iter().zip(pinned) {
        assert_eq!(d, want, "{what}");
    }

    // ... and they are exactly what the box prepares from those parameters,
    // in log order, each with its signer.
    let params = GenesisParams { forest_id: forest.into(), instance_id: instance.into(), created_at: t, root_nonce: nonce };
    let g = PersonalGenesis { root_pub: root, identity_pub: ident, host_pub: host };
    let prep = prepare_personal_genesis_with(&g, params).unwrap();
    let order = [(2, GenesisSigner::Root), (3, GenesisSigner::Root), (0, GenesisSigner::Identity), (1, GenesisSigner::Identity), (4, GenesisSigner::Root)];
    assert_eq!(prep.events.len(), order.len());
    for (p, (i, signer)) in prep.events.iter().zip(order) {
        assert_eq!(hex::encode(p.digest), pinned[i], "{}", got[i].0);
        assert_eq!(p.signer, signer, "{}", got[i].0);
    }

    // The signatures the vector phrase's keys make over them (RFC 6979 is
    // deterministic, so the page's must be these exact bytes) — and they
    // make a personal forest the box keeps.
    let mn = identity::parse_mnemonic(VECTOR).unwrap();
    let (root_key, ident_key) = (identity::root_key(&mn, "").unwrap(), identity::identity_key(&mn, "", 0).unwrap());
    let sigs: Vec<String> = prep
        .events
        .iter()
        .map(|p| {
            let key = if p.signer == GenesisSigner::Root { &root_key } else { &ident_key };
            hex::encode(crypto::sign_digest(key, &p.digest).unwrap())
        })
        .collect();
    let pinned_sigs = [
        "259a215ad3612da674e615d63b774aeb1fcfd74ced43919a473b66e66abe35dc02d668d64523b96ab5d45c162e3f737fdd9b61dd36d2375379332e02e08a26ac",
        "b3d4d50c9cbd5bd84588329b79e6c1325ec56f28fdad27135d53dae3e93bfd82765a0289ce20aadddf94f8b3b3daf5e488d698da2033790c449076b93c7718f6",
        "2c30841f2edfd13a9aabe25d5523cdba295c411fd81c2f06ff3009ed31bbb6ac7b2f6bd46722efff3f7ce5262c463ca96ae4925cf3237a932bebb794ff27a358",
        "9b6a53a7062df17120298fe76e5f60c746608ee6c5d2b1a5d6e375d5c8bee7aa198a481810a02d5fc70047de4cdc29e134aaaa7b58a3320b78d2d0dbe3347bc4",
        "ffe2f994b1fce79d9cbd6c9ae115977b83783091ef07eb3d3e866146ed1276a465dc69b57ba2ee371d0586224ef4d8e5f22368585c558021bcd48713689bf3e4",
    ];
    assert_eq!(sigs, pinned_sigs, "the genesis signatures");
    let dir = tempfile::tempdir().unwrap();
    let events = prep.attach(sigs.iter().map(|s| hex::decode(s).unwrap()).collect()).unwrap();
    let host_key = identity::device_key(&mn, "", 0).unwrap();
    let engine = init_signed_genesis(&dir.path().join("vector"), events, host_key).expect("the vector genesis replays");
    assert_eq!(engine.identity.forest_id, forest);
    engine.close().unwrap();
}

/// The signer's parameters name sockets and directories on the box: only
/// the one canonical form is accepted.
#[test]
fn genesis_parameters_are_checked() {
    let person = Person::new();
    let host = identity::generate_device_key();
    let ok = GenesisParams::fresh();
    assert!(prepare_personal_genesis_with(&person.genesis(&host), ok.clone()).is_ok());
    let with = |f: &dyn Fn(&mut GenesisParams)| {
        let mut p = ok.clone();
        f(&mut p);
        prepare_personal_genesis_with(&person.genesis(&host), p)
    };
    assert!(with(&|p| p.forest_id = "../../run/pvfs/x".into()).is_err(), "a path");
    assert!(with(&|p| p.forest_id = "0A0B0C0D-0000-4000-8000-00000000000E".into()).is_err(), "uppercase");
    assert!(with(&|p| p.forest_id = "0a0b0c0d-0000-4000-8000-00000000000e".into()).is_ok(), "its lowercase form");
    assert!(with(&|p| p.forest_id = p.forest_id.replace('-', "")).is_err(), "unhyphenated");
    assert!(with(&|p| p.forest_id = "00000000-0000-1000-8000-000000000001".into()).is_err(), "not random (v1)");
    assert!(with(&|p| p.instance_id = "pvfs-0000000G".into()).is_err(), "instance not hex");
    assert!(with(&|p| p.instance_id = "pvfs-000000001".into()).is_err(), "instance too long");
    assert!(with(&|p| p.created_at = 0).is_err(), "no time");
}
