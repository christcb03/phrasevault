//! pvfs — thin CLI over pvfs-core (spec §13.4).
//!
//! Exit codes (scriptable): 0 ok · 1 internal/io/db · 2 bad input ·
//! 3 not found · 4 conflict (exists/contained/not-orphan/cycle) ·
//! 5 integrity/identity · 6 corruption (recovery ladder).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use pvfs_core::{
    acl, identity, mount, BindSpec, ByteRange, Engine, FilePayload, HashPolicy, NodeSpec, OrderKey,
    PvfsError, Registry, ResolveAction, VerifyOutcome, TYPE_FILE, TYPE_FOLDER,
};

#[derive(Parser)]
#[command(name = "pvfs", version, about = "PVFS — PhraseVault File System")]
struct Cli {
    /// Low-level state-dir override for tests/scripts (or $PVFS_DATA_DIR).
    /// Interactive use: run inside a mount or pass --forest.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    /// Forest context: registered alias or mount path
    #[arg(long, global = true)]
    forest: Option<String>,

    /// Emit machine-readable JSON
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Forest lifecycle: init, register, unregister, info
    #[command(subcommand)]
    Forest(ForestCmd),
    /// Low-level: initialize a forest at the raw state dir (prefer `pvfs forest init`)
    Init,
    /// Recover onto this machine from a recovery phrase
    Recover {
        #[arg(long)]
        mnemonic: String,
        #[arg(long, default_value_t = 0)]
        device_index: u64,
    },
    /// Show forest identity
    Info,
    /// Tree operations
    #[command(subcommand)]
    Tree(TreeCmd),
    /// Add a node under a parent
    Add {
        parent: String,
        #[arg(long, value_parser = ["folder", "file"])]
        kind: String,
        #[arg(long)]
        label: String,
        #[arg(long)]
        temp: bool,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 0)]
        size: u64,
        #[arg(long, default_value = "application/octet-stream")]
        mime: String,
        #[arg(long, default_value = "")]
        content_hash: String,
    },
    /// Create an explicit link (default type: ref)
    Link {
        parent: String,
        child: String,
        #[arg(long = "type", default_value = "ref")]
        link_type: String,
        #[arg(long, default_value_t = 0)]
        nonce: u64,
    },
    /// Soft-remove a link (triggers temp purge check)
    Unlink { link_id: String },
    /// Change a link's sibling order key
    Reorder {
        link_id: String,
        #[arg(long)]
        key: String,
    },
    /// No target: list registered forests. With target (pvfs:// URI, absolute
    /// path under a mount, or node id): list that location's children.
    Ls { target: Option<String> },
    /// Pre-order walk of a tree (target: URI / path / node id)
    Walk { target: String },
    /// Show one node (target: URI / path / node id)
    Node { target: String },
    /// File location operations
    #[command(subcommand)]
    Loc(LocCmd),
    /// Recompute id + check signature
    Verify { id: String },
    /// List orphaned durable nodes
    Orphans,
    /// Hard-delete orphaned nodes (explicit)
    Purge { ids: Vec<String> },
    /// Device certificate operations
    #[command(subcommand)]
    Device(DeviceCmd),
    /// Access-control list operations (doc 06 §4)
    #[command(subcommand)]
    Acl(AclCmd),
    /// Bind a folder node to a real directory (P1)
    Bind {
        folder: String,
        dir: PathBuf,
        #[arg(long)]
        no_recursive: bool,
        #[arg(long)]
        no_auto_index: bool,
        #[arg(long, default_value = "")]
        extensions: String,
        #[arg(long, default_value = "lazy", value_parser = ["lazy", "on_add", "never"])]
        hash_policy: String,
    },
    /// Remove a folder's directory binding
    Unbind { folder: String },
    /// Scan bound folders against their directories
    Scan { folder: Option<String> },
    /// Node + per-location availability (target: URI / path / node id)
    Stat { target: String },
    /// Stream a file node's bytes (verifies full reads)
    Cat {
        target: String,
        /// byte range START-END (END exclusive; END optional)
        #[arg(long)]
        range: Option<String>,
        /// write to FILE instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Fill a lazy content hash (creates a successor node — prints new id)
    Hash { target: String },
    /// List nodes flagged invalid: changed-on-disk
    Changes,
    /// Resolve a flagged node: accept the new contents or remove the node
    Resolve {
        id: String,
        #[arg(long, conflicts_with = "delete")]
        replace: bool,
        #[arg(long)]
        delete: bool,
        /// with --delete: hard-delete instead of leaving an orphan
        #[arg(long, requires = "delete")]
        purge: bool,
    },
    /// Run the watcher daemon (live indexing + scheduled reconciliation)
    Serve {
        #[arg(long, default_value_t = 3600)]
        reconcile_secs: u64,
        #[arg(long, default_value_t = 2000)]
        debounce_ms: u64,
    },
}

#[derive(Subcommand)]
enum TreeCmd {
    /// Create a new tree (root folder node)
    Create { label: String },
}

#[derive(Subcommand)]
enum ForestCmd {
    /// Create a forest at a mount directory (state in <mount>/.pvfs/);
    /// imports the directory's existing tree unless --no-import
    Init {
        /// Mount directory (default: current directory)
        #[arg(long)]
        mount: Option<PathBuf>,
        /// Skip binding + scanning the mount's own tree
        #[arg(long)]
        no_import: bool,
        /// Suggested alias for a later `pvfs forest register --alias` (does not register)
        #[arg(long)]
        alias: Option<String>,
        #[arg(long, default_value = "lazy", value_parser = ["lazy", "on_add", "never"])]
        hash_policy: String,
    },
    /// Add an existing mount to this host's registry
    Register {
        mount: PathBuf,
        #[arg(long)]
        alias: Option<String>,
    },
    /// Remove a forest from the registry (never deletes .pvfs/)
    Unregister { name: String },
    /// Fix `.pvfs/` ownership after a mistaken `sudo forest init` (or run via sudo register)
    FixPermissions {
        /// Mount directory (default: current directory if it is a mount)
        #[arg(long)]
        mount: Option<PathBuf>,
    },
    /// Show a forest's identity (default: current context)
    Info { target: Option<String> },
}

#[derive(Subcommand)]
enum LocCmd {
    Add { file: String, uri: String },
    Rm { file: String, uri: String },
    Ls { file: String },
    /// Re-hash locations; lift quarantine where bytes match again
    Verify { file: String },
}

#[derive(Subcommand)]
enum DeviceCmd {
    /// Authorize a new device key (requires the recovery phrase)
    Authorize {
        #[arg(long)]
        mnemonic: String,
        #[arg(long)]
        index: u64,
    },
    /// Authorize an external member's device key by public key (doc 06 §3;
    /// requires the recovery phrase). The member signs their own writes.
    AuthorizeMember {
        #[arg(long)]
        mnemonic: String,
        /// The member's compressed secp256k1 public key, hex (33-byte SEC1)
        #[arg(long)]
        pubkey: String,
    },
    /// Revoke a device or member key for new appends (requires the recovery
    /// phrase). Its already-signed history stays valid.
    Revoke {
        #[arg(long)]
        mnemonic: String,
        #[arg(long)]
        pubkey: String,
    },
}

#[derive(Subcommand)]
enum AclCmd {
    /// Set (or clear) a principal's rights on a node
    Set {
        /// Node id (64-hex)
        node: String,
        /// Principal: `any` or `key:<hex>`
        principal: String,
        /// Rights: letters from r,w,a (e.g. `rw`), or `-`/`none` to clear
        rights: String,
    },
    /// List the direct ACL grants on a node
    Ls {
        /// Node id (64-hex)
        node: String,
    },
    /// Show a principal's effective rights on a node (incl. inheritance)
    Check {
        /// Node id (64-hex)
        node: String,
        /// Principal: `any` or `key:<hex>`
        principal: String,
    },
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn exit_code_for(e: &PvfsError) -> u8 {
    match e {
        PvfsError::BadInput { .. } | PvfsError::Encoding { .. } => 2,
        PvfsError::NotFound { .. } => 3,
        PvfsError::AlreadyExists { .. }
        | PvfsError::AlreadyContained { .. }
        | PvfsError::NotOrphan { .. }
        | PvfsError::CycleDetected { .. } => 4,
        PvfsError::Integrity { .. }
        | PvfsError::Identity { .. }
        | PvfsError::SchemaVersion { .. } => 5,
        PvfsError::Corruption { .. } | PvfsError::LogChainBroken { .. } => 6,
        _ => 1,
    }
}

fn variant_name(e: &PvfsError) -> &'static str {
    match e {
        PvfsError::Io { .. } => "Io",
        PvfsError::Db { .. } => "Db",
        PvfsError::Busy { .. } => "Busy",
        PvfsError::Encoding { .. } => "Encoding",
        PvfsError::NotFound { .. } => "NotFound",
        PvfsError::Integrity { .. } => "Integrity",
        PvfsError::LogChainBroken { .. } => "LogChainBroken",
        PvfsError::Corruption { .. } => "Corruption",
        PvfsError::CycleDetected { .. } => "CycleDetected",
        PvfsError::Identity { .. } => "Identity",
        PvfsError::BadInput { .. } => "BadInput",
        PvfsError::AlreadyExists { .. } => "AlreadyExists",
        PvfsError::NotOrphan { .. } => "NotOrphan",
        PvfsError::AlreadyContained { .. } => "AlreadyContained",
        PvfsError::SchemaVersion { .. } => "SchemaVersion",
    }
}

fn print_error(e: &PvfsError, json: bool) {
    if json {
        eprintln!(
            "{{\"error\":\"{}\",\"message\":\"{}\"}}",
            variant_name(e),
            json_escape(&e.to_string())
        );
    } else {
        eprintln!("error: {e}");
        // print the cause chain (spec §13.4)
        let mut src = std::error::Error::source(e);
        while let Some(s) = src {
            eprintln!("  caused by: {s}");
            src = s.source();
        }
    }
}

/// Old-style state dir for the low-level `init` / `recover` commands.
fn legacy_state_dir(cli: &Cli) -> PathBuf {
    cli.data_dir.clone().unwrap_or_else(|| {
        std::env::var("PVFS_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(".pvfs"))
    })
}

/// Forest context for node-id commands (doc 05 §6.4):
/// --data-dir > --forest (alias or mount path) > $PVFS_DATA_DIR > enclosing mount of CWD.
fn context_state_dir(cli: &Cli) -> Result<PathBuf, PvfsError> {
    if let Some(d) = &cli.data_dir {
        return Ok(d.clone());
    }
    if let Some(f) = &cli.forest {
        if let Some(reg) = Registry::system().find(f)? {
            return Ok(mount::state_dir(&reg.mount));
        }
        let p = PathBuf::from(f);
        if mount::is_mount(&p) {
            return Ok(mount::state_dir(&p));
        }
        return Err(PvfsError::NotFound {
            kind: "forest",
            id: f.clone(),
        });
    }
    if let Ok(d) = std::env::var("PVFS_DATA_DIR") {
        return Ok(PathBuf::from(d));
    }
    let cwd = std::env::current_dir().map_err(|e| PvfsError::io("getcwd", e))?;
    if let Some(m) = mount::enclosing_mount(&cwd) {
        return Ok(mount::state_dir(&m));
    }
    Err(PvfsError::BadInput {
        field: "forest".into(),
        reason: "no forest context — run inside a mount, pass --forest <alias|mount>, or set PVFS_DATA_DIR"
            .into(),
    })
}

fn is_node_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())
}

/// Resolve a command target: bare node id (uses forest context) or a
/// pvfs:// URI / absolute path under a mount (doc 05 §4).
fn engine_and_node(
    ctx: Result<PathBuf, PvfsError>,
    target: &str,
) -> Result<(Engine, String), PvfsError> {
    if is_node_id(target) {
        let dir = ctx?;
        Ok((Engine::open(&dir)?, target.to_string()))
    } else {
        let t = mount::resolve_target(&Registry::system(), target)?;
        let engine = mount::open_mount(&t.mount)?;
        let node = mount::node_at_path(&engine, &t.segments)?;
        Ok((engine, node))
    }
}

fn run(cli: Cli) -> Result<(), PvfsError> {
    let legacy = legacy_state_dir(&cli);
    let ctx = context_state_dir(&cli);
    let json = cli.json;
    match cli.cmd {
        Cmd::Init => {
            let (engine, mnemonic) = Engine::init(&legacy)?;
            if json {
                println!(
                    "{{\"instance_id\":\"{}\",\"forest_id\":\"{}\",\"root_node_id\":\"{}\",\"mnemonic\":\"{}\"}}",
                    json_escape(&engine.identity.instance_id),
                    json_escape(&engine.identity.forest_id),
                    json_escape(&engine.identity.root_node_id),
                    json_escape(&mnemonic.to_string()),
                );
            } else {
                println!("Forest initialized in {}", legacy.display());
                println!("  instance_id : {}", engine.identity.instance_id);
                println!("  forest_id   : {}", engine.identity.forest_id);
                println!("  root node   : {}", engine.identity.root_node_id);
                println!();
                println!("RECOVERY PHRASE — write this down now; it is shown ONCE and never stored:");
                println!();
                println!("  {mnemonic}");
                println!();
            }
            engine.close()
        }
        Cmd::Recover {
            mnemonic,
            device_index,
        } => {
            let m = identity::parse_mnemonic(&mnemonic)?;
            let engine = Engine::recover(&legacy, &m, device_index)?;
            if json {
                println!(
                    "{{\"recovered\":true,\"device_index\":{},\"device_pubkey\":\"{}\"}}",
                    device_index,
                    hex::encode(engine.device_pubkey())
                );
            } else {
                println!(
                    "Recovered as device {} ({})",
                    device_index,
                    hex::encode(engine.device_pubkey())
                );
            }
            engine.close()
        }
        Cmd::Info => {
            let engine = Engine::open(&ctx?)?;
            if json {
                println!(
                    "{{\"instance_id\":\"{}\",\"forest_id\":\"{}\",\"root_node_id\":\"{}\",\"device_pubkey\":\"{}\"}}",
                    json_escape(&engine.identity.instance_id),
                    json_escape(&engine.identity.forest_id),
                    json_escape(&engine.identity.root_node_id),
                    hex::encode(engine.device_pubkey()),
                );
            } else {
                println!("instance_id : {}", engine.identity.instance_id);
                println!("forest_id   : {}", engine.identity.forest_id);
                println!("root node   : {}", engine.identity.root_node_id);
                println!("device key  : {}", hex::encode(engine.device_pubkey()));
            }
            engine.close()
        }
        Cmd::Tree(TreeCmd::Create { label }) => {
            let mut engine = Engine::open(&ctx?)?;
            let id = engine.create_tree(&label)?;
            emit_id(json, "root_node_id", &id);
            engine.close()
        }
        Cmd::Add {
            parent,
            kind,
            label,
            temp,
            nonce,
            size,
            mime,
            content_hash,
        } => {
            let mut engine = Engine::open(&ctx?)?;
            let (node_type, payload) = if kind == "file" {
                (
                    TYPE_FILE.to_string(),
                    FilePayload {
                        content_hash,
                        size_bytes: size,
                        mime_type: mime,
                        original_name: label.clone(),
                    }
                    .encode(),
                )
            } else {
                (TYPE_FOLDER.to_string(), Vec::new())
            };
            let id = engine.add_node(
                &parent,
                NodeSpec {
                    node_type,
                    label,
                    payload,
                    is_temp: temp,
                    creation_nonce: nonce,
                },
            )?;
            emit_id(json, "node_id", &id);
            engine.close()
        }
        Cmd::Link {
            parent,
            child,
            link_type,
            nonce,
        } => {
            let mut engine = Engine::open(&ctx?)?;
            let id = engine.link(&parent, &child, &link_type, None, nonce)?;
            emit_id(json, "link_id", &id);
            engine.close()
        }
        Cmd::Unlink { link_id } => {
            let mut engine = Engine::open(&ctx?)?;
            engine.remove_link(&link_id)?;
            if json {
                println!("{{\"removed\":true}}");
            } else {
                println!("removed {link_id}");
            }
            engine.close()
        }
        Cmd::Reorder { link_id, key } => {
            let mut engine = Engine::open(&ctx?)?;
            let key = OrderKey::parse(&key)?;
            engine.reorder_link(&link_id, &key)?;
            if json {
                println!("{{\"reordered\":true}}");
            } else {
                println!("reordered {link_id}");
            }
            engine.close()
        }
        Cmd::Ls { target: None } => {
            // forest inventory (doc 05 §6.1)
            let forests = Registry::system().list()?;
            if json {
                let items: Vec<String> = forests
                    .iter()
                    .map(|f| {
                        let identity = mount::peek_identity(&f.mount).ok();
                        format!(
                            "{{\"alias\":{},\"mount\":\"{}\",\"enabled\":{},\"instance_id\":{},\"forest_id\":{}}}",
                            f.alias
                                .as_ref()
                                .map(|a| format!("\"{}\"", json_escape(a)))
                                .unwrap_or_else(|| "null".into()),
                            json_escape(&f.mount.to_string_lossy()),
                            f.enabled,
                            identity
                                .as_ref()
                                .map(|i| format!("\"{}\"", json_escape(&i.instance_id)))
                                .unwrap_or_else(|| "null".into()),
                            identity
                                .as_ref()
                                .map(|i| format!("\"{}\"", json_escape(&i.forest_id)))
                                .unwrap_or_else(|| "null".into()),
                        )
                    })
                    .collect();
                println!("[{}]", items.join(","));
            } else if forests.is_empty() {
                println!("no registered forests (see `pvfs forest init` / `pvfs forest register`)");
            } else {
                for f in forests {
                    let identity = mount::peek_identity(&f.mount);
                    println!(
                        "{:<16} {}  {}{}",
                        f.alias.as_deref().unwrap_or("-"),
                        f.mount.display(),
                        identity
                            .map(|i| format!("{} / {}", i.instance_id, i.forest_id))
                            .unwrap_or_else(|_| "(unreadable)".into()),
                        if f.enabled { "" } else { "  [disabled]" }
                    );
                }
            }
            Ok(())
        }
        Cmd::Ls { target: Some(target) } => {
            let (engine, node) = engine_and_node(ctx, &target)?;
            let kids = engine.children(&node)?;
            if json {
                let items: Vec<String> = kids
                    .iter()
                    .map(|k| {
                        format!(
                            "{{\"id\":\"{}\",\"label\":\"{}\",\"type\":\"{}\",\"link_type\":\"{}\",\"temp\":{},\"link_id\":\"{}\"}}",
                            k.node.id,
                            json_escape(&k.node.label),
                            json_escape(&k.node.node_type),
                            json_escape(&k.link_type),
                            k.node.is_temp,
                            k.link_id,
                        )
                    })
                    .collect();
                println!("[{}]", items.join(","));
            } else {
                for k in kids {
                    println!(
                        "{}  {:<8} {:<8} {}{}",
                        k.node.id,
                        k.node.node_type,
                        k.link_type,
                        k.node.label,
                        if k.node.is_temp { "  [temp]" } else { "" }
                    );
                }
            }
            engine.close()
        }
        Cmd::Walk { target } => {
            let (engine, root) = engine_and_node(ctx, &target)?;
            let walk = engine.walk(&root)?;
            if json {
                let items: Vec<String> = walk
                    .iter()
                    .map(|e| {
                        format!(
                            "{{\"id\":\"{}\",\"label\":\"{}\",\"depth\":{},\"link_type\":\"{}\"}}",
                            e.node.id,
                            json_escape(&e.node.label),
                            e.depth,
                            json_escape(&e.link_type),
                        )
                    })
                    .collect();
                println!("[{}]", items.join(","));
            } else {
                for e in walk.iter() {
                    println!(
                        "{}{} {}{}",
                        "  ".repeat(e.depth),
                        e.node.label,
                        if e.link_type == "ref" { "→ " } else { "" },
                        if e.node.is_temp { "[temp]" } else { "" }
                    );
                }
            }
            engine.close()
        }
        Cmd::Node { target } => {
            let (engine, id) = engine_and_node(ctx, &target)?;
            match engine.get_node(&id)? {
                None => {
                    engine.close()?;
                    return Err(PvfsError::NotFound { kind: "node", id });
                }
                Some(n) => {
                    if json {
                        println!(
                            "{{\"id\":\"{}\",\"type\":\"{}\",\"label\":\"{}\",\"temp\":{},\"created_at\":{},\"author\":\"{}\"}}",
                            n.id,
                            json_escape(&n.node_type),
                            json_escape(&n.label),
                            n.is_temp,
                            n.created_at,
                            hex::encode(&n.author),
                        );
                    } else {
                        println!("id         : {}", n.id);
                        println!("type       : {}", n.node_type);
                        println!("label      : {}", n.label);
                        println!("temp       : {}", n.is_temp);
                        println!("created_at : {}", n.created_at);
                        println!("author     : {}", hex::encode(&n.author));
                    }
                }
            }
            engine.close()
        }
        Cmd::Loc(loc) => {
            let mut engine = Engine::open(&ctx?)?;
            match loc {
                LocCmd::Add { file, uri } => {
                    engine.add_location(&file, &uri)?;
                    if json {
                        println!("{{\"added\":true}}");
                    } else {
                        println!("added");
                    }
                }
                LocCmd::Rm { file, uri } => {
                    engine.remove_location(&file, &uri)?;
                    if json {
                        println!("{{\"removed\":true}}");
                    } else {
                        println!("removed");
                    }
                }
                LocCmd::Ls { file } => {
                    let uris = engine.locations(&file)?;
                    if json {
                        let items: Vec<String> =
                            uris.iter().map(|u| format!("\"{}\"", json_escape(u))).collect();
                        println!("[{}]", items.join(","));
                    } else {
                        for u in uris {
                            println!("{u}");
                        }
                    }
                }
                LocCmd::Verify { file } => {
                    let results = engine.loc_verify(&file)?;
                    let mut bad = 0;
                    for (uri, outcome) in &results {
                        let s = match outcome {
                            VerifyOutcome::Ok => "ok",
                            VerifyOutcome::Mismatch => {
                                bad += 1;
                                "MISMATCH (quarantined)"
                            }
                            VerifyOutcome::Missing => "missing",
                        };
                        if json {
                            println!(
                                "{{\"uri\":\"{}\",\"outcome\":\"{}\"}}",
                                json_escape(uri),
                                s
                            );
                        } else {
                            println!("{s:<24} {uri}");
                        }
                    }
                    if bad > 0 {
                        engine.close()?;
                        return Err(PvfsError::Integrity {
                            kind: "location",
                            id: file,
                            reason: pvfs_core::IntegrityReason::IdMismatch {
                                expected: "recorded content hash".into(),
                                actual: format!("{bad} location(s) mismatched"),
                            },
                        });
                    }
                }
            }
            engine.close()
        }
        Cmd::Verify { id } => {
            let engine = Engine::open(&ctx?)?;
            let ok = engine.verify(&id)?;
            if json {
                println!("{{\"valid\":{ok}}}");
            } else {
                println!("valid");
            }
            engine.close()
        }
        Cmd::Orphans => {
            let engine = Engine::open(&ctx?)?;
            let orphans = engine.list_orphans()?;
            if json {
                let items: Vec<String> = orphans
                    .iter()
                    .map(|n| {
                        format!(
                            "{{\"id\":\"{}\",\"label\":\"{}\",\"type\":\"{}\"}}",
                            n.id,
                            json_escape(&n.label),
                            json_escape(&n.node_type)
                        )
                    })
                    .collect();
                println!("[{}]", items.join(","));
            } else {
                for n in orphans {
                    println!("{}  {:<8} {}", n.id, n.node_type, n.label);
                }
            }
            engine.close()
        }
        Cmd::Purge { ids } => {
            if ids.is_empty() {
                return Err(PvfsError::BadInput {
                    field: "ids".into(),
                    reason: "at least one node id required".into(),
                });
            }
            let mut engine = Engine::open(&ctx?)?;
            engine.purge(&ids)?;
            if json {
                println!("{{\"purged\":{}}}", ids.len());
            } else {
                println!("purged {} node(s)", ids.len());
            }
            engine.close()
        }
        Cmd::Device(dev) => {
            let mut engine = Engine::open(&ctx?)?;
            match dev {
                DeviceCmd::Authorize { mnemonic, index } => {
                    let m = identity::parse_mnemonic(&mnemonic)?;
                    let pk = engine.authorize_device(&m, index)?;
                    if json {
                        println!(
                            "{{\"authorized\":true,\"device_index\":{index},\"device_pubkey\":\"{}\"}}",
                            hex::encode(pk)
                        );
                    } else {
                        println!("authorized device {index}: {}", hex::encode(pk));
                    }
                }
                DeviceCmd::AuthorizeMember { mnemonic, pubkey } => {
                    let m = identity::parse_mnemonic(&mnemonic)?;
                    let pk = hex::decode(&pubkey).map_err(|_| PvfsError::BadInput {
                        field: "pubkey".into(),
                        reason: "must be hex".into(),
                    })?;
                    engine.authorize_member(&m, &pk)?;
                    if json {
                        println!("{{\"authorized\":true,\"member_pubkey\":\"{pubkey}\"}}");
                    } else {
                        println!("authorized member {pubkey}");
                    }
                }
                DeviceCmd::Revoke { mnemonic, pubkey } => {
                    let m = identity::parse_mnemonic(&mnemonic)?;
                    let pk = hex::decode(&pubkey).map_err(|_| PvfsError::BadInput {
                        field: "pubkey".into(),
                        reason: "must be hex".into(),
                    })?;
                    engine.revoke_device(&m, &pk)?;
                    if json {
                        println!("{{\"revoked\":true}}");
                    } else {
                        println!("revoked {pubkey}");
                    }
                }
            }
            engine.close()
        }
        Cmd::Acl(a) => {
            let mut engine = Engine::open(&ctx?)?;
            match a {
                AclCmd::Set {
                    node,
                    principal,
                    rights,
                } => {
                    let p = acl::Principal::parse(&principal)?;
                    let r = acl::parse_rights(&rights)?;
                    engine.set_acl(&node, &p, r)?;
                    if json {
                        println!(
                            "{{\"node\":\"{}\",\"principal\":\"{}\",\"rights\":\"{}\"}}",
                            json_escape(&node),
                            json_escape(&p.display()),
                            acl::rights_to_str(r)
                        );
                    } else {
                        println!("set {} on {} = {}", p.display(), node, acl::rights_to_str(r));
                    }
                }
                AclCmd::Ls { node } => {
                    let entries = engine.acl_entries(&node)?;
                    if json {
                        let items: Vec<String> = entries
                            .iter()
                            .map(|(p, r)| {
                                format!(
                                    "{{\"principal\":\"{}\",\"rights\":\"{}\"}}",
                                    json_escape(&p.display()),
                                    acl::rights_to_str(*r)
                                )
                            })
                            .collect();
                        println!("[{}]", items.join(","));
                    } else if entries.is_empty() {
                        println!("(no direct grants on {node})");
                    } else {
                        for (p, r) in entries {
                            println!("{:>3}  {}", acl::rights_to_str(r), p.display());
                        }
                    }
                }
                AclCmd::Check { node, principal } => {
                    let p = acl::Principal::parse(&principal)?;
                    let r = engine.effective_rights(&p, &node)?;
                    if json {
                        println!(
                            "{{\"node\":\"{}\",\"principal\":\"{}\",\"effective\":\"{}\"}}",
                            json_escape(&node),
                            json_escape(&p.display()),
                            acl::rights_to_str(r)
                        );
                    } else {
                        println!(
                            "{} effective on {} = {}",
                            p.display(),
                            node,
                            acl::rights_to_str(r)
                        );
                    }
                }
            }
            engine.close()
        }
        Cmd::Bind {
            folder,
            dir: bind_dir,
            no_recursive,
            no_auto_index,
            extensions,
            hash_policy,
        } => {
            let mut engine = Engine::open(&ctx?)?;
            let abs = std::fs::canonicalize(&bind_dir)
                .map_err(|e| PvfsError::io("canonicalize dir", e))?;
            let source_uri = pvfs_core::storage::path_to_uri(&abs)?;
            engine.bind_folder(
                &folder,
                BindSpec {
                    source_uri: source_uri.clone(),
                    recursive: !no_recursive,
                    auto_index: !no_auto_index,
                    extensions,
                    hash_policy: HashPolicy::parse(&hash_policy)?,
                },
            )?;
            if json {
                println!("{{\"bound\":true,\"source_uri\":\"{}\"}}", json_escape(&source_uri));
            } else {
                println!("bound {folder} -> {source_uri}");
            }
            engine.close()
        }
        Cmd::Unbind { folder } => {
            let mut engine = Engine::open(&ctx?)?;
            engine.unbind_folder(&folder)?;
            if json {
                println!("{{\"unbound\":true}}");
            } else {
                println!("unbound {folder}");
            }
            engine.close()
        }
        Cmd::Scan { folder } => {
            let mut engine = Engine::open(&ctx?)?;
            let reports = engine.scan(folder.as_ref())?;
            if json {
                let items: Vec<String> = reports
                    .iter()
                    .map(|r| {
                        format!(
                            "{{\"folder_id\":\"{}\",\"added\":{},\"unchanged\":{},\"changed\":{},\"removed\":{},\"skipped\":{},\"unreadable\":{}}}",
                            r.folder_id,
                            r.stats.added,
                            r.stats.unchanged,
                            r.stats.changed,
                            r.stats.removed,
                            r.stats.skipped,
                            r.stats.unreadable
                        )
                    })
                    .collect();
                println!("[{}]", items.join(","));
            } else {
                for r in &reports {
                    println!(
                        "{}: +{} added, {} unchanged, {} changed, -{} removed, {} skipped, {} unreadable",
                        r.folder_id,
                        r.stats.added,
                        r.stats.unchanged,
                        r.stats.changed,
                        r.stats.removed,
                        r.stats.skipped,
                        r.stats.unreadable
                    );
                }
                let changed: u64 = reports.iter().map(|r| r.stats.changed).sum();
                if changed > 0 {
                    eprintln!("note: {changed} file(s) flagged changed — review with `pvfs changes`");
                }
                let unreadable: u64 = reports.iter().map(|r| r.stats.unreadable).sum();
                if unreadable > 0 {
                    eprintln!("note: {unreadable} path(s) skipped — not readable by your user");
                }
            }
            engine.close()
        }
        Cmd::Stat { target } => {
            let (mut engine, id) = engine_and_node(ctx, &target)?;
            let st = engine.stat_node(&id)?;
            if json {
                let locs: Vec<String> = st
                    .locations
                    .iter()
                    .map(|l| {
                        format!(
                            "{{\"uri\":\"{}\",\"exists\":{},\"size\":{},\"quarantined\":{},\"pending_change\":{}}}",
                            json_escape(&l.uri),
                            l.exists,
                            l.size,
                            l.quarantined
                                .as_ref()
                                .map(|q| format!("\"{}\"", json_escape(q)))
                                .unwrap_or_else(|| "null".into()),
                            l.pending_change
                        )
                    })
                    .collect();
                println!(
                    "{{\"id\":\"{}\",\"label\":\"{}\",\"type\":\"{}\",\"unavailable\":{},\"locations\":[{}]}}",
                    st.node.id,
                    json_escape(&st.node.label),
                    json_escape(&st.node.node_type),
                    st.unavailable,
                    locs.join(",")
                );
            } else {
                println!("id    : {}", st.node.id);
                println!("label : {}", st.node.label);
                println!("type  : {}", st.node.node_type);
                if st.unavailable {
                    println!("state : UNAVAILABLE (no readable, trusted location)");
                }
                for l in &st.locations {
                    let mut flags = Vec::new();
                    if !l.exists {
                        flags.push("missing".to_string());
                    }
                    if let Some(q) = &l.quarantined {
                        flags.push(format!("quarantined: {q}"));
                    }
                    if l.pending_change {
                        flags.push("changed-on-disk (pvfs resolve)".to_string());
                    }
                    println!(
                        "loc   : {} ({} bytes){}",
                        l.uri,
                        l.size,
                        if flags.is_empty() {
                            String::new()
                        } else {
                            format!("  [{}]", flags.join("; "))
                        }
                    );
                }
            }
            engine.close()
        }
        Cmd::Cat { target, range, output } => {
            let (mut engine, id) = engine_and_node(ctx, &target)?;
            let range = match range {
                None => None,
                Some(r) => Some(parse_range(&r)?),
            };
            let written = match output {
                Some(path) => {
                    let mut f = std::fs::File::create(&path)
                        .map_err(|e| PvfsError::io("create output", e))?;
                    engine.cat(&id, range, &mut f)?
                }
                None => {
                    let stdout = std::io::stdout();
                    let mut lock = stdout.lock();
                    engine.cat(&id, range, &mut lock)?
                }
            };
            if json {
                eprintln!("{{\"bytes\":{written}}}");
            }
            engine.close()
        }
        Cmd::Hash { target } => {
            let (mut engine, id) = engine_and_node(ctx, &target)?;
            let new_id = engine.hash_node(&id)?;
            if json {
                println!(
                    "{{\"node_id\":\"{new_id}\",\"re_identified\":{}}}",
                    new_id != id
                );
            } else if new_id != id {
                println!("{new_id}");
                eprintln!("note: hashing re-identified the node (successor created; old id orphaned)");
            } else {
                println!("{new_id}");
            }
            engine.close()
        }
        Cmd::Changes => {
            let engine = Engine::open(&ctx?)?;
            let changes = engine.changes()?;
            if json {
                let items: Vec<String> = changes
                    .iter()
                    .map(|c| {
                        format!(
                            "{{\"id\":\"{}\",\"label\":\"{}\",\"uri\":\"{}\",\"old_size\":{},\"new_size\":{}}}",
                            c.file_id,
                            json_escape(&c.label),
                            json_escape(&c.uri),
                            c.old_size,
                            c.new_size
                        )
                    })
                    .collect();
                println!("[{}]", items.join(","));
            } else {
                for c in &changes {
                    println!(
                        "{}  {}  {} -> {} bytes  {}",
                        c.file_id, c.label, c.old_size, c.new_size, c.uri
                    );
                }
                if !changes.is_empty() {
                    eprintln!(
                        "resolve with: pvfs resolve <id> --replace   (accept new contents)");
                    eprintln!(
                        "          or: pvfs resolve <id> --delete [--purge]   (treat as untrusted)");
                }
            }
            engine.close()
        }
        Cmd::Resolve {
            id,
            replace,
            delete,
            purge,
        } => {
            if replace == delete {
                return Err(PvfsError::BadInput {
                    field: "action".into(),
                    reason: "pass exactly one of --replace / --delete".into(),
                });
            }
            let mut engine = Engine::open(&ctx?)?;
            let action = if replace {
                ResolveAction::Replace
            } else {
                ResolveAction::Delete { purge }
            };
            let result = engine.resolve(&id, action)?;
            if json {
                println!("{{\"resolved\":\"{result}\"}}");
            } else if replace {
                println!("{result}");
                eprintln!("replaced — new node id above; old node kept as reviewable orphan");
            } else {
                println!("resolved (deleted{})", if purge { ", purged" } else { "" });
            }
            engine.close()
        }
        Cmd::Serve {
            reconcile_secs,
            debounce_ms,
        } => serve(&ctx?, json, reconcile_secs, debounce_ms),
        Cmd::Forest(cmd) => forest_cmd(cmd, ctx, json),
    }
}

fn forest_cmd(
    cmd: ForestCmd,
    ctx: Result<PathBuf, PvfsError>,
    json: bool,
) -> Result<(), PvfsError> {
    match cmd {
        ForestCmd::Init {
            mount: mount_arg,
            no_import,
            alias,
            hash_policy,
        } => {
            mount::mount_owner_credentials()?; // fail before creating state as raw root
            let target = match mount_arg {
                Some(m) => m,
                None => std::env::current_dir().map_err(|e| PvfsError::io("getcwd", e))?,
            };
            if let Some(a) = &alias {
                Registry::validate_alias(a)?;
            }
            let (engine, mnemonic, report) =
                mount::init_forest(&target, !no_import, HashPolicy::parse(&hash_policy)?)?;
            let mount = std::fs::canonicalize(&target)
                .map_err(|e| PvfsError::io("canonicalize mount", e))?;
            if json {
                println!(
                    "{{\"mount\":\"{}\",\"instance_id\":\"{}\",\"forest_id\":\"{}\",\"root_node_id\":\"{}\",\"imported\":{},\"registered\":false,\"suggested_alias\":{},\"mnemonic\":\"{}\"}}",
                    json_escape(&mount.to_string_lossy()),
                    json_escape(&engine.identity.instance_id),
                    json_escape(&engine.identity.forest_id),
                    json_escape(&engine.identity.root_node_id),
                    report.is_some(),
                    alias
                        .as_ref()
                        .map(|a| format!("\"{}\"", json_escape(a)))
                        .unwrap_or_else(|| "null".into()),
                    json_escape(&mnemonic.to_string()),
                );
            } else {
                println!("Forest created at {}", mount.display());
                println!("  instance_id : {}", engine.identity.instance_id);
                println!("  forest_id   : {}", engine.identity.forest_id);
                println!("  root node   : {}", engine.identity.root_node_id);
                if let Some(r) = &report {
                    println!(
                        "  imported    : {} file(s) from the mount tree",
                        r.stats.added
                    );
                    if r.stats.unreadable > 0 {
                        println!(
                            "  skipped     : {} path(s) you cannot read (not imported)",
                            r.stats.unreadable
                        );
                    }
                }
                println!("  portable    : register for system-wide listing:");
                if let Some(a) = &alias {
                    println!(
                        "    sudo pvfs forest register {} --alias {}",
                        mount.display(),
                        a
                    );
                } else {
                    println!("    sudo pvfs forest register {}", mount.display());
                }
                println!();
                println!("RECOVERY PHRASE — write this down now; it is shown ONCE and never stored:");
                println!();
                println!("  {mnemonic}");
                println!();
            }
            engine.close()
        }
        ForestCmd::Register { mount: m, alias } => {
            if let Some(a) = &alias {
                Registry::validate_alias(a)?;
            }
            let m = std::fs::canonicalize(&m).map_err(|e| PvfsError::io("canonicalize mount", e))?;
            mount::ensure_mount_owned_by_operator(&m)?;
            let f = Registry::system().register(&m, alias.as_deref())?;
            if json {
                println!(
                    "{{\"registered\":true,\"mount\":\"{}\",\"alias\":{}}}",
                    json_escape(&f.mount.to_string_lossy()),
                    f.alias
                        .as_ref()
                        .map(|a| format!("\"{}\"", json_escape(a)))
                        .unwrap_or_else(|| "null".into()),
                );
            } else {
                println!(
                    "registered {} ({})",
                    f.mount.display(),
                    f.alias.as_deref().unwrap_or("no alias")
                );
            }
            Ok(())
        }
        ForestCmd::Unregister { name } => {
            Registry::system().unregister(&name)?;
            if json {
                println!("{{\"unregistered\":true}}");
            } else {
                println!("unregistered {name} (mount and .pvfs/ untouched)");
            }
            Ok(())
        }
        ForestCmd::FixPermissions { mount: m } => {
            let target = match m {
                Some(p) => p,
                None => std::env::current_dir().map_err(|e| PvfsError::io("getcwd", e))?,
            };
            mount::ensure_mount_owned_by_operator(&target)?;
            if json {
                println!(
                    "{{\"fixed\":true,\"mount\":\"{}\"}}",
                    json_escape(&target.to_string_lossy())
                );
            } else {
                let canon = std::fs::canonicalize(&target)
                    .map_err(|e| PvfsError::io("canonicalize mount", e))?;
                println!(
                    "fixed ownership of {} (and .pvfs/) for your user",
                    canon.display()
                );
            }
            Ok(())
        }
        ForestCmd::Info { target } => {
            let (mount_path, state) = match target {
                Some(t) => {
                    let r = mount::resolve_target(&Registry::system(), &t)?;
                    (Some(r.mount.clone()), mount::state_dir(&r.mount))
                }
                None => (None, ctx?),
            };
            let engine = Engine::open(&state)?;
            if json {
                println!(
                    "{{\"mount\":{},\"instance_id\":\"{}\",\"forest_id\":\"{}\",\"root_node_id\":\"{}\",\"device_pubkey\":\"{}\"}}",
                    mount_path
                        .as_ref()
                        .map(|m| format!("\"{}\"", json_escape(&m.to_string_lossy())))
                        .unwrap_or_else(|| "null".into()),
                    json_escape(&engine.identity.instance_id),
                    json_escape(&engine.identity.forest_id),
                    json_escape(&engine.identity.root_node_id),
                    hex::encode(engine.device_pubkey()),
                );
            } else {
                if let Some(m) = &mount_path {
                    println!("mount       : {}", m.display());
                }
                println!("instance_id : {}", engine.identity.instance_id);
                println!("forest_id   : {}", engine.identity.forest_id);
                println!("root node   : {}", engine.identity.root_node_id);
                println!("device key  : {}", hex::encode(engine.device_pubkey()));
            }
            engine.close()
        }
    }
}

fn parse_range(s: &str) -> Result<ByteRange, PvfsError> {
    let (a, b) = s.split_once('-').ok_or_else(|| PvfsError::BadInput {
        field: "range".into(),
        reason: "expected START-END".into(),
    })?;
    let start: u64 = a.parse().map_err(|_| PvfsError::BadInput {
        field: "range".into(),
        reason: "bad start".into(),
    })?;
    let end = if b.is_empty() {
        None
    } else {
        Some(b.parse().map_err(|_| PvfsError::BadInput {
            field: "range".into(),
            reason: "bad end".into(),
        })?)
    };
    Ok(ByteRange { start, end })
}

/// Minimal P1 daemon: live watcher + scheduled reconciliation (doc 04 §6).
fn serve(dir: &PathBuf, json: bool, reconcile_secs: u64, debounce_ms: u64) -> Result<(), PvfsError> {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let lock_path = dir.join("serve.lock");
    let _lock = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .map_err(|e| PvfsError::BadInput {
            field: "serve".into(),
            reason: format!(
                "another daemon may be running ({}): {e} — delete the file if stale",
                lock_path.display()
            ),
        })?;

    let result = (|| {
        let mut engine = Engine::open(dir)?;
        // initial reconciliation
        let reports = engine.scan(None)?;
        if !json {
            for r in &reports {
                println!(
                    "reconciled {}: +{} ~{} !{} -{}",
                    r.folder_id, r.stats.added, r.stats.unchanged, r.stats.changed, r.stats.removed
                );
            }
        }

        let (tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();
        let mut watcher = notify::recommended_watcher(tx).map_err(|e| PvfsError::BadInput {
            field: "watcher".into(),
            reason: e.to_string(),
        })?;
        let mut watching = 0usize;
        for b in engine.bindings()? {
            if !b.auto_index {
                continue;
            }
            let path = pvfs_core::storage::uri_to_path(&b.source_uri)?;
            notify::Watcher::watch(
                &mut watcher,
                &path,
                if b.recursive {
                    notify::RecursiveMode::Recursive
                } else {
                    notify::RecursiveMode::NonRecursive
                },
            )
            .map_err(|e| PvfsError::BadInput {
                field: "watcher".into(),
                reason: format!("{}: {e}", path.display()),
            })?;
            watching += 1;
        }
        if !json {
            println!("serving: watching {watching} bound folder(s); reconcile every {reconcile_secs}s; Ctrl-C to stop");
        }

        let debounce = Duration::from_millis(debounce_ms);
        let reconcile_every = Duration::from_secs(reconcile_secs.max(1));
        let mut dirty_since: Option<Instant> = None;
        let mut last_reconcile = Instant::now();

        loop {
            match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(Ok(_event)) => dirty_since = Some(Instant::now()),
                Ok(Err(_)) => dirty_since = Some(Instant::now()),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            let due_debounce = dirty_since
                .map(|t| t.elapsed() >= debounce)
                .unwrap_or(false);
            let due_reconcile = last_reconcile.elapsed() >= reconcile_every;
            if due_debounce || due_reconcile {
                dirty_since = None;
                last_reconcile = Instant::now();
                match engine.scan(None) {
                    Ok(reports) => {
                        if !json {
                            for r in reports.iter().filter(|r| {
                                r.stats.added + r.stats.changed + r.stats.removed > 0
                            }) {
                                println!(
                                    "ingested {}: +{} !{} -{}",
                                    r.folder_id, r.stats.added, r.stats.changed, r.stats.removed
                                );
                            }
                        }
                    }
                    Err(e) => eprintln!("scan error: {e}"),
                }
            }
        }
        engine.close()
    })();
    let _ = std::fs::remove_file(&lock_path);
    result
}

fn emit_id(json: bool, key: &str, id: &str) {
    if json {
        println!("{{\"{key}\":\"{id}\"}}");
    } else {
        println!("{id}");
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            print_error(&e, json);
            ExitCode::from(exit_code_for(&e))
        }
    }
}
