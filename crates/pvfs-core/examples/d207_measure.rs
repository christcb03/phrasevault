//! PVOS D207 — the measurement: what a quiet catalogue pass writes, on a
//! library of fleet shape (shows / seasons / episodes). A manual run, not a
//! test (PVOS D221: nothing in the suite is ignored); run it in release on
//! presubuntu's disk:
//!
//!   PVFS_D207_FILES=29500 cargo run --release -p pvfs-core --example d207_measure
//!
//! It uses only the engine API PVFS had before D199, so the same file runs
//! on the commit before D199 for the "before".

use std::time::Instant;

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

fn count(c: &rusqlite::Connection) -> (i64, i64) {
    let n = |op: &str| c.query_row("SELECT COUNT(*) FROM d207_w WHERE op = ?1", [op], |r| r.get(0)).unwrap();
    let got = (n("put"), n("del"));
    c.execute("DELETE FROM d207_w", []).unwrap();
    got
}

fn main() {
    let files: usize = std::env::var("PVFS_D207_FILES").ok().and_then(|v| v.parse().ok()).unwrap_or(2_000);
    let base = std::env::var("PVFS_D207_DIR").map(std::path::PathBuf::from).unwrap_or_else(|_| std::env::temp_dir());
    let tmp = tempfile::tempdir_in(base).unwrap();
    let media = tmp.path().join("media");
    let t = Instant::now();
    for i in 0..files {
        let d = media.join(format!("Show {:03}/Season {:02}", i / 100, (i / 10) % 10));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(format!("e{i:05}.mkv")), format!("episode {i} of a library of fleet shape")).unwrap();
    }
    let planted = t.elapsed();
    let (mut e, _) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let local = e
        .add_node(
            &root,
            NodeSpec { node_type: TYPE_FOLDER.into(), label: "Local".into(), payload: Vec::new(), is_temp: false, creation_nonce: None },
        )
        .unwrap();
    e.region_mark_as(&local, "catalogue", None).unwrap();
    e.bind_folder(
        &local,
        BindSpec {
            source_uri: format!("file://{}", media.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    let c = rusqlite::Connection::open(e.data_dir().join("index.db")).unwrap();
    c.busy_timeout(std::time::Duration::from_secs(15)).unwrap();
    c.execute_batch(
        "CREATE TABLE d207_w (op TEXT NOT NULL);
         CREATE TRIGGER d207_wi AFTER INSERT ON region_entries BEGIN INSERT INTO d207_w VALUES ('put'); END;
         CREATE TRIGGER d207_wu AFTER UPDATE ON region_entries BEGIN INSERT INTO d207_w VALUES ('put'); END;
         CREATE TRIGGER d207_wd AFTER DELETE ON region_entries BEGIN INSERT INTO d207_w VALUES ('del'); END;",
    )
    .unwrap();

    let t = Instant::now();
    e.scan(None).unwrap();
    let first = (t.elapsed(), count(&c));
    let mut quiet = Vec::new();
    for _ in 0..3 {
        let t = Instant::now();
        e.scan(None).unwrap();
        quiet.push((t.elapsed(), count(&c)));
    }
    // One new file, one changed: what a pass after a download writes.
    std::fs::write(media.join("Show 000/Season 00/e99999.mkv"), "a new episode").unwrap();
    std::fs::write(media.join("Show 000/Season 00/e00001.mkv"), "episode 1, a better copy").unwrap();
    let t = Instant::now();
    e.scan(None).unwrap();
    let bump = (t.elapsed(), count(&c));
    let rows: i64 = c.query_row("SELECT COUNT(*) FROM region_entries", [], |r| r.get(0)).unwrap();
    println!(
        "D207 measure: {files} files ({rows} rows) planted in {:.1} s on {}",
        planted.as_secs_f64(),
        tmp.path().display()
    );
    println!("D207 measure: first pass {:.2} s, writes {:?} (put, del)", first.0.as_secs_f64(), first.1);
    for (i, (d, w)) in quiet.iter().enumerate() {
        println!("D207 measure: quiet pass {} {:.2} s, writes {:?}", i + 1, d.as_secs_f64(), w);
    }
    println!("D207 measure: one new + one changed {:.2} s, writes {:?}", bump.0.as_secs_f64(), bump.1);
}
