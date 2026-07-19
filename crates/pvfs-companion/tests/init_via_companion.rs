//! Forest genesis via an external root signer (doc 14): the companion's root
//! key signs `ForestCreated` + `DeviceAuthorized`; a fresh local device key is
//! cached — no new recovery phrase.

use pvfs_companion::{KeyRole, KdfParams, RequestType, UnlockedSigner, Vault};
use pvfs_core::{crypto, identity, mount, Engine, HashPolicy};

fn fast() -> KdfParams {
    KdfParams {
        m_cost: 32,
        t_cost: 1,
        p_cost: 1,
    }
}

#[test]
fn forest_init_with_companion_root_no_new_phrase() {
    let phrase = identity::generate_mnemonic().unwrap();
    let root_pub = crypto::pubkey_bytes(&identity::root_key(&phrase, "").unwrap());

    let vdir = tempfile::tempdir().unwrap();
    let vpath = vdir.path().join("vault.json");
    Vault::create_with(&vpath, phrase.to_string().as_bytes(), b"pw", fast()).unwrap();
    let secret = Vault::open(&vpath).unwrap().unseal(b"pw").unwrap();
    let signer = UnlockedSigner::from_phrase(std::str::from_utf8(&secret).unwrap()).unwrap();
    assert_eq!(signer.pubkey(KeyRole::Root).unwrap(), root_pub);

    let mount = tempfile::tempdir().unwrap();
    let (engine, report) = mount::init_forest_with_root_signer(
        mount.path(),
        false,
        HashPolicy::Lazy,
        &root_pub,
        |digest| {
            Ok(signer
                .sign(RequestType::RootDeviceCert, digest)
                .expect("sign"))
        },
    )
    .expect("init via companion root");

    assert!(report.is_none());
    assert_eq!(engine.identity.root_pubkey, root_pub);

    let state = mount.path().join(".pvfs");
    let local_device = identity::DeviceKeyCache::load(&state).unwrap().pubkey();
    // Local device key is authorized and distinct from the mnemonic's device 0.
    let device0 = crypto::pubkey_bytes(&identity::device_key(&phrase, "", 0).unwrap());
    assert_ne!(local_device, device0);
    assert!(engine.authority_active(&local_device).unwrap());

    // Re-open with the cached device key works.
    engine.close().unwrap();
    let reopened = Engine::open(&state).unwrap();
    assert_eq!(reopened.identity.root_pubkey, root_pub);
    reopened.close().unwrap();
}
