//! pvfs — thin CLI over pvfs-core (spec §13.4).
//!
//! Exit codes (scriptable): 0 ok · 1 internal/io/db · 2 bad input ·
//! 3 not found · 4 conflict (exists/contained/not-orphan/cycle) ·
//! 5 integrity/identity · 6 corruption (recovery ladder).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use pvfs_core::{
    identity, Engine, FilePayload, NodeSpec, OrderKey, PvfsError, TYPE_FILE, TYPE_FOLDER,
};

#[derive(Parser)]
#[command(name = "pvfs", version, about = "PVFS — PhraseVault File System (P0 core)")]
struct Cli {
    /// Data directory (default: $PVFS_DATA_DIR or ./.pvfs)
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    /// Emit machine-readable JSON
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Initialize a new forest (prints the recovery phrase ONCE)
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
    /// List a node's children in order
    Ls { node: String },
    /// Pre-order walk of a tree
    Walk { root: String },
    /// Show one node
    Node { id: String },
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
}

#[derive(Subcommand)]
enum TreeCmd {
    /// Create a new tree (root folder node)
    Create { label: String },
}

#[derive(Subcommand)]
enum LocCmd {
    Add { file: String, uri: String },
    Rm { file: String, uri: String },
    Ls { file: String },
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
    /// Revoke a device key for new appends (requires the recovery phrase)
    Revoke {
        #[arg(long)]
        mnemonic: String,
        #[arg(long)]
        pubkey: String,
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

fn data_dir(cli: &Cli) -> PathBuf {
    cli.data_dir.clone().unwrap_or_else(|| {
        std::env::var("PVFS_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(".pvfs"))
    })
}

fn run(cli: Cli) -> Result<(), PvfsError> {
    let dir = data_dir(&cli);
    let json = cli.json;
    match cli.cmd {
        Cmd::Init => {
            let (engine, mnemonic) = Engine::init(&dir)?;
            if json {
                println!(
                    "{{\"instance_id\":\"{}\",\"forest_id\":\"{}\",\"root_node_id\":\"{}\",\"mnemonic\":\"{}\"}}",
                    json_escape(&engine.identity.instance_id),
                    json_escape(&engine.identity.forest_id),
                    json_escape(&engine.identity.root_node_id),
                    json_escape(&mnemonic.to_string()),
                );
            } else {
                println!("Forest initialized in {}", dir.display());
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
            let engine = Engine::recover(&dir, &m, device_index)?;
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
            let engine = Engine::open(&dir)?;
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
            let mut engine = Engine::open(&dir)?;
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
            let mut engine = Engine::open(&dir)?;
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
            let mut engine = Engine::open(&dir)?;
            let id = engine.link(&parent, &child, &link_type, None, nonce)?;
            emit_id(json, "link_id", &id);
            engine.close()
        }
        Cmd::Unlink { link_id } => {
            let mut engine = Engine::open(&dir)?;
            engine.remove_link(&link_id)?;
            if json {
                println!("{{\"removed\":true}}");
            } else {
                println!("removed {link_id}");
            }
            engine.close()
        }
        Cmd::Reorder { link_id, key } => {
            let mut engine = Engine::open(&dir)?;
            let key = OrderKey::parse(&key)?;
            engine.reorder_link(&link_id, &key)?;
            if json {
                println!("{{\"reordered\":true}}");
            } else {
                println!("reordered {link_id}");
            }
            engine.close()
        }
        Cmd::Ls { node } => {
            let engine = Engine::open(&dir)?;
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
        Cmd::Walk { root } => {
            let engine = Engine::open(&dir)?;
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
        Cmd::Node { id } => {
            let engine = Engine::open(&dir)?;
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
            let mut engine = Engine::open(&dir)?;
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
            }
            engine.close()
        }
        Cmd::Verify { id } => {
            let engine = Engine::open(&dir)?;
            let ok = engine.verify(&id)?;
            if json {
                println!("{{\"valid\":{ok}}}");
            } else {
                println!("valid");
            }
            engine.close()
        }
        Cmd::Orphans => {
            let engine = Engine::open(&dir)?;
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
            let mut engine = Engine::open(&dir)?;
            engine.purge(&ids)?;
            if json {
                println!("{{\"purged\":{}}}", ids.len());
            } else {
                println!("purged {} node(s)", ids.len());
            }
            engine.close()
        }
        Cmd::Device(dev) => {
            let mut engine = Engine::open(&dir)?;
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
    }
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
