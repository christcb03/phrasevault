//! Minimal client for talking to a running companion agent (doc 14 §3) — used by
//! the CLI to get the root/identity pubkey and to request signatures.

use std::os::unix::net::UnixStream;
use std::path::Path;

use pvfs_proto::{read_msg, write_msg};

use crate::proto::{AgentRequest, AgentResponse, KEY_FIELD};

/// Send one request to the companion at `socket` and read its reply.
pub fn request(socket: &Path, req: &AgentRequest) -> std::io::Result<AgentResponse> {
    request_for_key(socket, req, None)
}

/// PVOS D189 — [`request`] for the phrase that holds `key` (any of its
/// public keys; a forest's current root for its root signatures). A
/// companion before protocol v4 ignores the field and answers with its one
/// phrase, which the caller's own check then accepts or refuses.
pub fn request_for_key(socket: &Path, req: &AgentRequest, key: Option<&[u8]>) -> std::io::Result<AgentResponse> {
    let mut frame = serde_json::to_value(req).map_err(std::io::Error::other)?;
    if let (Some(k), Some(obj)) = (key, frame.as_object_mut()) {
        obj.insert(KEY_FIELD.into(), serde_json::Value::String(hex::encode(k)));
    }
    let mut stream = UnixStream::connect(socket)?;
    write_msg(&mut stream, &frame)?;
    read_msg::<_, AgentResponse>(&mut stream)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "companion closed the connection",
        )
    })
}
