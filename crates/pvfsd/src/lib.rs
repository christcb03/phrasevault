//! PVFS per-user daemon (doc 07): serves one forest over a Unix socket with
//! challenge-response auth (§2) and per-node ACL enforcement (§4).
//!
//! Control plane only in this slice — handshake + `Info`/`Ls`/`Stat`. The engine
//! is shared behind a `Mutex`, so ops serialize; a read-only connection pool and
//! the data plane (`Cat`, two-phase writes) land in later slices.

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, Engine, NodeId, PvfsError};
use pvfs_proto::{
    auth_digest, read_msg, write_msg, ChildInfo, ClientMsg, NodeInfo, ServerMsg, PROTO_VERSION,
};
use rand::RngCore;

/// How long a challenge stays valid.
const CHALLENGE_TTL_MS: u64 = 30_000;

/// One forest served by the daemon: the engine plus its forest id (for the
/// challenge binding).
pub struct Daemon {
    engine: Mutex<Engine>,
    forest_id: String,
}

impl Daemon {
    pub fn new(engine: Engine) -> Daemon {
        let forest_id = engine.identity.forest_id.clone();
        Daemon {
            engine: Mutex::new(engine),
            forest_id,
        }
    }
}

/// Accept connections until the listener closes — one thread per connection.
pub fn serve(listener: UnixListener, daemon: Arc<Daemon>) -> io::Result<()> {
    for stream in listener.incoming() {
        let stream = stream?;
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            // A broken connection is not fatal to the daemon.
            let _ = serve_connection(&d, stream);
        });
    }
    Ok(())
}

/// Handshake then request loop for one connection.
pub fn serve_connection(daemon: &Daemon, mut stream: UnixStream) -> io::Result<()> {
    // 1. challenge
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let expiry_ms = now_ms() + CHALLENGE_TTL_MS;
    write_msg(
        &mut stream,
        &ServerMsg::Challenge {
            nonce: hex::encode(nonce),
            forest_id: daemon.forest_id.clone(),
            expiry_ms,
            version: PROTO_VERSION,
        },
    )?;

    // 2. resolve the principal from the client's response
    let principal = match read_msg::<_, ClientMsg>(&mut stream)? {
        None => return Ok(()), // client hung up
        Some(ClientMsg::Anonymous) => Principal::Public,
        Some(ClientMsg::Auth { pubkey, sig }) => {
            match resolve_auth(&nonce, &daemon.forest_id, expiry_ms, &pubkey, &sig) {
                Ok(p) => p,
                Err(msg) => {
                    write_msg(&mut stream, &msg)?;
                    return Ok(());
                }
            }
        }
        Some(_) => {
            write_msg(&mut stream, &err("bad_input", "expected auth or anonymous"))?;
            return Ok(());
        }
    };
    write_msg(
        &mut stream,
        &ServerMsg::Ready {
            principal: principal.display(),
        },
    )?;

    // 3. request loop
    while let Some(req) = read_msg::<_, ClientMsg>(&mut stream)? {
        let resp = handle(daemon, &principal, req);
        write_msg(&mut stream, &resp)?;
    }
    Ok(())
}

/// Verify a client's signature over the challenge → the proven key is the principal.
fn resolve_auth(
    nonce: &[u8],
    forest_id: &str,
    expiry_ms: u64,
    pubkey: &str,
    sig: &str,
) -> Result<Principal, ServerMsg> {
    if now_ms() > expiry_ms {
        return Err(err("bad_input", "challenge expired"));
    }
    let pk = hex::decode(pubkey).map_err(|_| err("bad_input", "pubkey not hex"))?;
    let sigb = hex::decode(sig).map_err(|_| err("bad_input", "sig not hex"))?;
    let digest = auth_digest(nonce, forest_id, expiry_ms);
    crypto::verify_digest(&pk, &digest, &sigb).map_err(|_| err("forbidden", "bad signature"))?;
    Ok(Principal::Key(pk))
}

fn handle(daemon: &Daemon, principal: &Principal, req: ClientMsg) -> ServerMsg {
    match req {
        ClientMsg::Info => {
            let e = daemon.engine.lock().unwrap();
            ServerMsg::Info {
                instance_id: e.identity.instance_id.clone(),
                forest_id: e.identity.forest_id.clone(),
                root: e.identity.root_node_id.clone(),
            }
        }
        ClientMsg::Ls { node } => match do_ls(daemon, principal, &node) {
            Ok(children) => ServerMsg::Ls { children },
            Err(msg) => msg,
        },
        ClientMsg::Stat { node } => match do_stat(daemon, principal, &node) {
            Ok(node) => ServerMsg::Stat { node },
            Err(msg) => msg,
        },
        ClientMsg::Auth { .. } | ClientMsg::Anonymous => {
            err("bad_input", "already past handshake")
        }
    }
}

fn do_ls(daemon: &Daemon, principal: &Principal, node: &str) -> Result<Vec<ChildInfo>, ServerMsg> {
    let e = daemon.engine.lock().unwrap();
    let id: NodeId = node.to_string();
    if !e.can(principal, &id, acl::ACL_R).map_err(err_from)? {
        return Err(forbidden());
    }
    let kids = e.readable_children(principal, &id).map_err(err_from)?;
    Ok(kids
        .into_iter()
        .map(|c| ChildInfo {
            id: c.node.id,
            label: c.node.label,
            node_type: c.node.node_type,
        })
        .collect())
}

fn do_stat(daemon: &Daemon, principal: &Principal, node: &str) -> Result<NodeInfo, ServerMsg> {
    let e = daemon.engine.lock().unwrap();
    let id: NodeId = node.to_string();
    let rights = e.effective_rights(principal, &id).map_err(err_from)?;
    if rights & acl::ACL_R == 0 {
        return Err(forbidden());
    }
    let n = e
        .node(&id)
        .map_err(err_from)?
        .ok_or_else(|| err("not_found", "no such node"))?;
    Ok(NodeInfo {
        id: n.id,
        label: n.label,
        node_type: n.node_type,
        rights: acl::rights_to_str(rights),
    })
}

fn err(code: &str, message: &str) -> ServerMsg {
    ServerMsg::Error {
        code: code.into(),
        message: message.into(),
    }
}

fn forbidden() -> ServerMsg {
    err("forbidden", "access denied")
}

fn err_from(e: PvfsError) -> ServerMsg {
    let code = match &e {
        PvfsError::NotFound { .. } => "not_found",
        PvfsError::BadInput { .. } => "bad_input",
        PvfsError::Integrity { .. } => "integrity",
        _ => "internal",
    };
    err(code, &e.to_string())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
