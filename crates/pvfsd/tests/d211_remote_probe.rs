//! PVOS D211 — a box with ffprobe measures the video files of a region
//! another box holds (mediabox for the NAS), reading the bytes from the
//! holder's daemon in ranges, and the holder writes its own rows.
//!
//! The forest is made once and copied: the copy is the HOLDER (its region
//! bound to the files, served over a Unix socket); the original unbinds the
//! region and installs the holder's head as fetched from that socket — the
//! shape mediabox has of a NAS region. The prober is a shell stand-in that
//! reads its URL with `curl` ranges, as ffprobe reads a file over HTTP.
//!
//! 1. Nothing listed in `probe-remote`: nothing is probed.
//! 2. A pass: a good file is measured on the holder; a broken one is only a
//!    suspect there; one whose probe errs records nothing; a file whose
//!    bytes this box has measured elsewhere is sent without a read; a region
//!    where this box has no `w` is refused.
//! 3. A second pass leaves what it sent alone; a fresh one sends the broken
//!    file again and the holder does not confirm it inside 30 minutes.
//! 4. The holder's checks over the wire: conflict, bad_input, not_found.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use pvfs_client::remote_probe::{remote_probe_pass, remote_probe_regions, RemoteProbe};
use pvfs_client::ClientError;
use pvfs_core::acl::{self, Principal};
use pvfs_core::media::{MediaQuality, Observed};
use pvfs_core::probe::Prober;
use pvfs_core::{crypto, identity, BindSpec, Engine, HashPolicy, NodeSpec, ReplicaSource, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

/// ffprobe as far as these tests need: it reads the head (and the tail) of
/// its URL with ranges, and answers by what the bytes say.
const FAKE: &str = r#"#!/bin/sh
for a; do u="$a"; done
d="$(dirname "$0")"
head="$(curl -s -f -r 0-15 "$u")" || { echo "$u: Input/output error" >&2; exit 1; }
tail="$(curl -s -f -r -4 "$u")" || { echo "$u: Input/output error" >&2; exit 1; }
echo "$head|$tail" >> "$d/probed.log"
case "$head" in
  BROKEN*) echo "$u: Invalid data found when processing input" >&2; exit 1 ;;
  IOERR*) echo "$u: Input/output error" >&2; exit 1 ;;
esac
echo "codec_name=h264"
echo "width=1280"
echo "height=720"
echo "duration=1300.0"
echo "size=1000"
"#;

fn folder(e: &mut Engine, label: &str) -> String {
    let root = e.identity.root_node_id.clone();
    e.add_node(
        &root,
        NodeSpec { node_type: TYPE_FOLDER.into(), label: label.into(), payload: Vec::new(), is_temp: false, creation_nonce: None },
    )
    .unwrap()
}

fn bind(e: &mut Engine, region: &str, dir: &Path) {
    e.region_mark_as(&region.to_string(), "catalogue", None).unwrap();
    e.bind_folder(
        &region.to_string(),
        BindSpec {
            source_uri: format!("file://{}", dir.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    e.scan_routed(Some(&region.to_string()), None, 0).unwrap();
}

fn holder_quality(holder_dir: &Path, region: &str, rel: &str) -> Option<MediaQuality> {
    let v = Engine::open_read_view(holder_dir).unwrap();
    v.region_row_quality(&region.to_string(), rel).unwrap().map(|q| MediaQuality::decode(&q).unwrap())
}

fn copy_dir(from: &Path, to: &Path) {
    assert!(std::process::Command::new("cp").arg("-a").arg(from).arg(to).status().unwrap().success());
}

#[test]
fn mediabox_measures_the_nas_files_over_the_wire_and_the_holder_writes_them() {
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let tmp = tempfile::tempdir().unwrap();
    let files = tmp.path().join("nas-files");
    let files2 = tmp.path().join("nas-files2");
    let own = tmp.path().join("own-files");
    for d in [&files, &files2, &own] {
        std::fs::create_dir_all(d).unwrap();
    }
    let big: Vec<u8> = b"GOOD-big-header.".iter().copied().chain((0..3_000_000u32).map(|i| (i % 251) as u8)).collect();
    std::fs::write(files.join("good.mkv"), &big).unwrap();
    std::fs::write(files.join("bad.mkv"), b"BROKEN-bytes-of-a-file-that-never-was").unwrap();
    std::fs::write(files.join("ioerr.mkv"), b"IOERR-a-disk-that-would-not-read").unwrap();
    std::fs::write(files.join("reuse.mkv"), b"GOOD-the-same-bytes-on-two-boxes").unwrap();
    std::fs::write(files.join("notes.nfo"), b"not video").unwrap();
    std::fs::write(files2.join("other.mkv"), b"GOOD-in-a-region-this-box-may-not-write").unwrap();
    std::fs::write(own.join("reuse-here.mkv"), b"GOOD-the-same-bytes-on-two-boxes").unwrap();

    // ---- one forest, two regions the NAS will hold; the prober's own region
    let fdir = tmp.path().join("mediabox");
    let (mut f, mn) = Engine::init(fdir.as_path()).unwrap();
    let root = f.identity.root_node_id.clone();
    let nas = folder(&mut f, "Data");
    let nas2 = folder(&mut f, "Data_ext");
    let mine = folder(&mut f, "Local");
    // a region the NAS knows but does not catalogue from its own disk
    let away = folder(&mut f, "Elsewhere");
    f.region_mark_as(&away, "catalogue", None).unwrap();
    bind(&mut f, &nas, &files);
    bind(&mut f, &nas2, &files2);
    // what the prober dials as: this box's client identity — w on Data only
    let me = identity::device_key(&identity::client_identity_mnemonic().unwrap(), "", 0).unwrap();
    let me_pub = crypto::pubkey_bytes(&me);
    f.authorize_member(&mn, &me_pub).unwrap();
    f.set_acl(&root, &Principal::Key(me_pub.clone()), acl::ACL_R).unwrap();
    f.set_acl(&nas, &Principal::Key(me_pub.clone()), acl::ACL_R | acl::ACL_W).unwrap();
    f.set_acl(&away, &Principal::Key(me_pub), acl::ACL_R | acl::ACL_W).unwrap();
    f.close().unwrap();

    // ---- the NAS: a copy of the forest that keeps both regions bound
    let hdir = tmp.path().join("nas");
    copy_dir(&fdir, &hdir);
    let holder = Engine::open(&hdir).unwrap();
    let sock = tmp.path().join("nas.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = Arc::new(Daemon::new(holder));
    std::thread::spawn(move || {
        let _ = serve(listener, daemon);
    });
    let src = ReplicaSource {
        transport: "socket".into(),
        target: sock.to_string_lossy().into_owned(),
        pin: String::new(),
        region: String::new(),
    };

    // ---- mediabox: the NAS regions as fetched from the NAS; its own region
    let mut f = Engine::open(&fdir).unwrap();
    let mut heads = Vec::new();
    for r in [&nas, &nas2] {
        f.unbind_folder(r, None).unwrap();
        heads.push(f.region_snapshots(r).unwrap().pop().unwrap().seq);
    }
    f.close().unwrap();
    {
        // what this box published for them is the NAS's record, not its own
        let db = rusqlite::Connection::open(fdir.join("index.db")).unwrap();
        for r in [&nas, &nas2] {
            db.execute("DELETE FROM region_snapshots WHERE region_id = ?1", [r]).unwrap();
        }
    }
    let mut f = Engine::open(&fdir).unwrap();
    for (r, seq) in [&nas, &nas2].into_iter().zip(heads) {
        let bytes = std::fs::read(fdir.join("regions").join(r).join(format!("manifest.{seq}"))).unwrap();
        f.install_region_snapshot(r, seq, &bytes, &src.target).unwrap();
    }
    bind(&mut f, &mine, &own);
    let (rel, size, mtime) = f.quality_candidates(&mine).unwrap().remove(0);
    let reuse_q = MediaQuality { width: 3840, height: 2160, video_codec: "hevc".into(), duration_s: 50, ..Default::default() };
    f.write_region_quality(&mine, &[(rel, size, mtime, Observed::Measured(reuse_q.clone()))]).unwrap();
    assert_eq!(f.region_holders().unwrap().get(&nas), Some(&src.target), "premise: the NAS is Data's holder");
    assert_eq!(f.quality_candidates(&nas).unwrap().len(), 4, "premise: four unmeasured videos");

    let bin = tmp.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let script = bin.join("ffprobe");
    std::fs::write(&script, FAKE).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let probed = || std::fs::read_to_string(bin.join("probed.log")).unwrap_or_default();
    let fresh = || {
        let mut rp = RemoteProbe::new(Prober { program: script.clone() });
        rp.lan_max_connect = None; // a Unix socket has no LAN to test
        rp.timeout = Duration::from_secs(20);
        rp
    };
    let cancel = AtomicBool::new(false);
    let sources = vec![src.clone()];

    // ---- 1. nothing listed: nothing probed
    let rp = fresh();
    assert!(remote_probe_pass(&f, &sources, &rp, &cancel).unwrap().is_empty());
    assert!(probed().is_empty());

    // ---- 2. a pass over both NAS regions (and this box's own, skipped)
    for r in [&nas, &nas2, &mine] {
        pvfs_core::sync::set_probe_remote(&fdir, r, true).unwrap();
    }
    let reps = remote_probe_pass(&f, &sources, &rp, &cancel).unwrap();
    let rep = reps.iter().find(|r| r.region == nas).unwrap();
    assert_eq!((rep.measured, rep.reused, rep.broken, rep.errors), (2, 1, 1, 1), "{rep:?}");
    assert!(rep.refused.is_empty(), "{rep:?}");
    let log = probed();
    assert!(log.contains("GOOD-big-header.|"), "the head of the 3 MB file came over the wire: {log}");
    assert!(!log.contains("the-same-bytes"), "the file measured elsewhere was not read: {log}");
    assert!(log.contains("BROKEN-bytes-of-"));
    let good = holder_quality(&hdir, &nas, "good.mkv").expect("the NAS wrote its own row");
    assert_eq!((good.width, good.height), (1280, 720));
    assert!(holder_quality(&hdir, &nas, "bad.mkv").unwrap().suspect(), "a first failure is a suspect");
    assert_eq!(holder_quality(&hdir, &nas, "ioerr.mkv"), None, "an error records nothing");
    assert_eq!(holder_quality(&hdir, &nas, "reuse.mkv").unwrap(), reuse_q, "the same bytes, the same quality");
    assert_eq!(holder_quality(&hdir, &nas, "notes.nfo"), None);
    let rep2 = reps.iter().find(|r| r.region == nas2).unwrap();
    assert_eq!(rep2.measured, 0);
    assert!(rep2.refused.iter().any(|l| l.contains("forbidden")), "no w on Data_ext: {rep2:?}");
    assert_eq!(holder_quality(&hdir, &nas2, "other.mkv"), None);
    let rep3 = reps.iter().find(|r| r.region == mine).unwrap();
    assert!(rep3.skipped.as_deref().is_some_and(|s| s.contains("holds it")), "{rep3:?}");

    // ---- 3. the same probe again: left alone; a fresh one cannot confirm
    let reps = remote_probe_regions(&f, std::slice::from_ref(&nas), &sources, &rp, &cancel).unwrap();
    assert_eq!((reps[0].measured, reps[0].broken, reps[0].errors), (0, 0, 0), "{:?}", reps[0]);
    let rp2 = fresh();
    let reps = remote_probe_regions(&f, std::slice::from_ref(&nas), &sources, &rp2, &cancel).unwrap();
    assert_eq!(reps[0].broken, 1, "{:?}", reps[0]);
    let still = holder_quality(&hdir, &nas, "bad.mkv").unwrap();
    assert!(still.suspect() && !still.unreadable(), "not confirmed inside 30 minutes");

    // ---- 4. the holder's checks, straight over the wire
    let mut c = pvfs_client::follow::dial_source(&src).unwrap();
    let row = f.region_entries(&nas).unwrap().into_iter().find(|r| r.rel_path == "ioerr.mkv").unwrap();
    let hash = row.content_hash.clone().unwrap();
    let m = Observed::Measured(MediaQuality { width: 640, height: 480, ..Default::default() }).encode();
    let code = |r: Result<(bool, Option<String>), ClientError>| match r {
        Err(ClientError::Server { code, .. }) => code,
        other => format!("{other:?}"),
    };
    assert_eq!(code(c.set_region_quality(&nas, "ioerr.mkv", &hash, row.size_bytes + 1, row.mtime_ms, &m)), "conflict");
    assert_eq!(code(c.set_region_quality(&nas, "ioerr.mkv", &"0".repeat(64), row.size_bytes, row.mtime_ms, &m)), "conflict");
    assert_eq!(code(c.set_region_quality(&nas, "ioerr.mkv", &hash, row.size_bytes, row.mtime_ms + 1, &m)), "conflict");
    let suspect = MediaQuality { probe_suspect_ms: 1, ..Default::default() }.encode();
    assert_eq!(code(c.set_region_quality(&nas, "ioerr.mkv", &hash, row.size_bytes, row.mtime_ms, &suspect)), "bad_input");
    assert_eq!(code(c.set_region_quality(&away, "ioerr.mkv", &hash, row.size_bytes, row.mtime_ms, &m)), "not_found");
    assert_eq!(
        code(c.set_region_quality(&"ab".repeat(32), "ioerr.mkv", &hash, row.size_bytes, row.mtime_ms, &m)),
        "forbidden",
        "a region nobody granted: default deny"
    );
    assert_eq!(code(c.set_region_quality(&nas, "../x.mkv", &hash, row.size_bytes, row.mtime_ms, &m)), "bad_input");
    let (written, now) = c.set_region_quality(&nas, "ioerr.mkv", &hash, row.size_bytes, row.mtime_ms, &m).unwrap();
    assert!(written);
    assert_eq!(now.as_deref(), Some(m.as_str()));
    let (written, _) = c.set_region_quality(&nas, "ioerr.mkv", &hash, row.size_bytes, row.mtime_ms, &Observed::Broken.encode()).unwrap();
    assert!(!written, "a measurement is never overwritten");
    let _ = std::fs::remove_file(bin.join("probed.log"));
}
