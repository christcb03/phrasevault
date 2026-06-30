//! Minimal client for talking to a running companion agent (doc 14 §3) — used by
//! the CLI to get the root/identity pubkey and to request signatures.

use std::os::unix::net::UnixStream;
use std::path::Path;

use pvfs_proto::{read_msg, write_msg};

use crate::proto::{AgentRequest, AgentResponse};

/// Send one request to the companion at `socket` and read its reply.
pub fn request(socket: &Path, req: &AgentRequest) -> std::io::Result<AgentResponse> {
    let mut stream = UnixStream::connect(socket)?;
    write_msg(&mut stream, req)?;
    read_msg::<_, AgentResponse>(&mut stream)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "companion closed the connection",
        )
    })
}
