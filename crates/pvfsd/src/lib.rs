//! PVFS per-user daemon (doc 07): serves one forest over a Unix socket with
//! challenge-response auth (§2) and per-node ACL enforcement (§4).
//!
//! Control plane only in this slice — handshake + `Info`/`Ls`/`Stat`. The engine
//! is shared behind a `Mutex`, so ops serialize; a read-only connection pool and
//! the data plane (`Cat`, two-phase writes) land in later slices.

use std::collections::HashMap;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use pvfs_core::acl::{self, Principal};
use pvfs_core::{
    crypto, Engine, FilePayload, NodeId, NodeSpec, PreparedEvent, PvfsError, TYPE_FILE, TYPE_FOLDER,
};
use pvfs_proto::{
    auth_digest, read_msg, write_msg, ChildInfo, ClientMsg, NodeInfo, ServerMsg, WriteOp,
    PROTO_VERSION,
};
use rand::RngCore;

/// How long a challenge stays valid.
const CHALLENGE_TTL_MS: u64 = 30_000;
/// How long a prepared (phase-1) write awaits its signatures.
const PREPARE_TTL_MS: u64 = 30_000;

/// A phase-1 write held server-side until the member sends signatures.
struct PreparedState {
    author_pub: Vec<u8>,
    events: Vec<PreparedEvent>,
    result_id: String,
    expiry_ms: u64,
}

/// One forest served by the daemon: the engine, its forest id (challenge
/// binding), and in-flight prepared writes.
pub struct Daemon {
    engine: Mutex<Engine>,
    forest_id: String,
    prepared: Mutex<HashMap<String, PreparedState>>,
}

impl Daemon {
    pub fn new(engine: Engine) -> Daemon {
        let forest_id = engine.identity.forest_id.clone();
        Daemon {
            engine: Mutex::new(engine),
            forest_id,
            prepared: Mutex::new(HashMap::new()),
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
        ClientMsg::Cat {
            node,
            offset,
            len,
        } => do_cat(daemon, principal, &node, offset, len),
        ClientMsg::PrepareWrite { op } => do_prepare_write(daemon, principal, op),
        ClientMsg::Commit { prepared_id, sigs } => do_commit(daemon, principal, &prepared_id, sigs),
        ClientMsg::Auth { .. } | ClientMsg::Anonymous => {
            err("bad_input", "already past handshake")
        }
    }
}

/// Stream one chunk of a file's bytes (ACL-checked). The engine lock is held only
/// for this chunk, so concurrent requests interleave between chunks.
fn do_cat(daemon: &Daemon, principal: &Principal, node: &str, offset: u64, len: u64) -> ServerMsg {
    let id: NodeId = node.to_string();
    let mut e = daemon.engine.lock().unwrap();
    match e.effective_rights(principal, &id) {
        Ok(r) if r & acl::ACL_R != 0 => {}
        Ok(_) => return forbidden(),
        Err(err) => return err_from(err),
    }
    let range = pvfs_core::ByteRange {
        start: offset,
        end: Some(offset.saturating_add(len)),
    };
    let mut buf: Vec<u8> = Vec::new();
    if let Err(err) = e.cat(&id, Some(range), &mut buf) {
        return err_from(err);
    }
    let eof = (buf.len() as u64) < len;
    ServerMsg::CatData {
        data: hex::encode(&buf),
        eof,
    }
}

/// Phase 1: build the signable events for `op` and stash them under a fresh id.
fn do_prepare_write(daemon: &Daemon, principal: &Principal, op: WriteOp) -> ServerMsg {
    let author = match principal {
        Principal::Key(pk) => pk.clone(),
        _ => return err("forbidden", "writes require an authenticated identity"),
    };
    let prepared = {
        let e = daemon.engine.lock().unwrap();
        match op {
            WriteOp::Mkdir { parent, label } => e.prepare_add_node(
                &author,
                &parent,
                NodeSpec {
                    node_type: TYPE_FOLDER.into(),
                    label,
                    payload: Vec::new(),
                    is_temp: false,
                    creation_nonce: None,
                },
            ),
            WriteOp::AddFile {
                parent,
                label,
                size,
                mime,
            } => {
                let payload = FilePayload {
                    content_hash: String::new(),
                    size_bytes: size,
                    mime_type: mime,
                    original_name: label.clone(),
                }
                .encode();
                e.prepare_add_node(
                    &author,
                    &parent,
                    NodeSpec {
                        node_type: TYPE_FILE.into(),
                        label,
                        payload,
                        is_temp: false,
                        creation_nonce: None,
                    },
                )
            }
            WriteOp::Rm { node } => e.prepare_remove_node(&author, &node),
        }
    };
    let prepared = match prepared {
        Ok(p) => p,
        Err(e) => return err_from(e),
    };
    let preimages = prepared.events.iter().map(|pe| hex::encode(pe.digest)).collect();
    let result_id = prepared.result_id.clone();
    let prepared_id = random_id();
    daemon.prepared.lock().unwrap().insert(
        prepared_id.clone(),
        PreparedState {
            author_pub: author,
            events: prepared.events,
            result_id: result_id.clone(),
            expiry_ms: now_ms() + PREPARE_TTL_MS,
        },
    );
    ServerMsg::Prepared {
        prepared_id,
        preimages,
        result_id,
    }
}

/// Phase 2: attach the member's signatures to the stashed events and append.
fn do_commit(daemon: &Daemon, principal: &Principal, prepared_id: &str, sigs: Vec<String>) -> ServerMsg {
    let author = match principal {
        Principal::Key(pk) => pk,
        _ => return err("forbidden", "writes require an authenticated identity"),
    };
    let state = match daemon.prepared.lock().unwrap().remove(prepared_id) {
        Some(s) => s,
        None => return err("not_found", "no such prepared write (expired?)"),
    };
    if now_ms() > state.expiry_ms {
        return err("bad_input", "prepared write expired");
    }
    if &state.author_pub != author {
        return err("forbidden", "prepared write belongs to another principal");
    }
    if sigs.len() != state.events.len() {
        return err("bad_input", "wrong number of signatures");
    }
    let mut events = Vec::with_capacity(state.events.len());
    for (pe, sig_hex) in state.events.into_iter().zip(sigs) {
        let sig = match hex::decode(&sig_hex) {
            Ok(s) => s,
            Err(_) => return err("bad_input", "signature not hex"),
        };
        let mut ev = pe.event;
        ev.set_author_sig(sig);
        events.push(ev);
    }
    let mut e = daemon.engine.lock().unwrap();
    match e.commit_member_write(events) {
        Ok(()) => ServerMsg::Committed { id: state.result_id },
        Err(e) => err_from(e),
    }
}

fn random_id() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
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
        PvfsError::Forbidden { .. } => "forbidden",
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
