//! PVOS D219 — a holder's catalogue head committed to the owner wakes the
//! owner's catalogue job: the manifest is fetched now, not at the next minute
//! (mediabox learned the NAS's heads 53–58 s late, and a read through its view
//! of a file deleted meanwhile was an I/O error). Any other commit does not.

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::Client;
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, Engine, NodeSpec, TYPE_FOLDER};
use pvfsd::jobs::JobsState;
use pvfsd::{serve, Daemon};

#[test]
fn a_committed_region_head_nudges_the_catalogue_job_and_another_commit_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let (mut owner, mn) = Engine::init(dir.path()).unwrap();
    let root = owner.identity.root_node_id.clone();
    let library = owner
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "Library".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    let holder_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let holder_pub = crypto::pubkey_bytes(&holder_key);
    let writer_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let writer_pub = crypto::pubkey_bytes(&writer_key);
    owner.authorize_member(&mn, &holder_pub).unwrap();
    owner.authorize_member(&mn, &writer_pub).unwrap();
    owner.set_acl(&root, &Principal::Key(writer_pub.clone()), acl::ACL_R | acl::ACL_W).unwrap();
    owner
        .region_mark_as(&library, "catalogue", Some(&Principal::Key(holder_pub.clone())))
        .unwrap();

    let jobs = Arc::new(JobsState::load(dir.path().to_path_buf()).unwrap());
    let daemon = Arc::new(Daemon::new(owner));
    daemon.attach_jobs(Arc::clone(&jobs));
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }
    let sign_holder = |d: &[u8; 32]| crypto::sign_digest(&holder_key, d).unwrap();
    let sign_writer = |d: &[u8; 32]| crypto::sign_digest(&writer_key, d).unwrap();
    let mut holder = Client::connect_signed(&sock, &holder_pub, sign_holder).unwrap();
    let mut writer = Client::connect_signed(&sock, &writer_pub, sign_writer).unwrap();
    assert!(!jobs.catalogue_nudged(), "nothing committed yet");

    // An ordinary write commits and wakes nothing of the catalogue's.
    writer.mkdir(&root, "Downloads", sign_writer).unwrap();
    assert!(!jobs.catalogue_nudged(), "a folder is not a head");

    // A refused head commits nothing and wakes nothing.
    assert!(writer.commit_region_head(&library, 1, &"cd".repeat(32), sign_writer).is_err());
    assert!(!jobs.catalogue_nudged(), "a refused head is no head");

    // The holder's head lands: the catalogue job is to run now.
    holder.commit_region_head(&library, 1, &"ab".repeat(32), sign_holder).unwrap();
    assert!(jobs.catalogue_nudged(), "a committed head nudges the catalogue job");
}
