//! PVOS D245 — the instance pins are the owner's alone: `pvfs instance add`
//! writes `instances` 0600 in a 0700 config dir, and narrows a dir something
//! widened.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

/// A scratch directory, removed when dropped (this crate has no tempfile).
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new() -> Scratch {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let p = std::env::temp_dir().join(format!("pvfs-d245-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn mode(p: &std::path::Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn instance(cfg: &std::path::Path, args: &[&str]) {
    let out = Command::new(env!("CARGO_BIN_EXE_pvfs"))
        .arg("instance")
        .args(args)
        .env("XDG_CONFIG_HOME", cfg)
        .env_remove("PVFS_DATA_DIR")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn instance_add_keeps_the_pins_private() {
    let s = Scratch::new();
    let cfg = s.0.join("config");
    instance(&cfg, &["add", "nas", "192.0.2.7:7433", "aa11"]);
    let dir = cfg.join("pvfs");
    assert_eq!(mode(&dir), 0o700, "the config dir is made 0700");
    assert_eq!(mode(&dir.join("instances")), 0o600, "the pins are written 0600");

    // the mediabox shape: something opened the dir and the file to everyone
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    std::fs::set_permissions(dir.join("instances"), std::fs::Permissions::from_mode(0o666)).unwrap();
    instance(&cfg, &["add", "box2", "192.0.2.8:7433", "bb22"]);
    assert_eq!(mode(&dir), 0o700, "the widened dir is narrowed");
    assert_eq!(mode(&dir.join("instances")), 0o600, "the rewritten pins are 0600");
    let text = std::fs::read_to_string(dir.join("instances")).unwrap();
    assert!(text.contains("nas 192.0.2.7:7433 aa11") && text.contains("box2 192.0.2.8:7433 bb22"), "{text}");
}
