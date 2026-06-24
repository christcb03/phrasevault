//! PVFS daemon client (doc 07): connect to a forest's `pvfsd`, perform the
//! challenge-response handshake, and issue read requests.
//!
//! Signing is injected as a closure so this crate needs no key library — the
//! caller (CLI/app) holds the identity key and provides how to sign the 32-byte
//! challenge digest.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;

use pvfs_proto::{auth_digest, read_data_frame, read_msg, write_msg, ClientMsg, ServerMsg, WriteOp};

pub use pvfs_proto::{ChildInfo, NodeInfo};

/// Identity + root of the forest behind the socket.
#[derive(Debug, Clone)]
pub struct ForestInfo {
    pub instance_id: String,
    pub forest_id: String,
    pub root: String,
}

#[derive(Debug)]
pub enum ClientError {
    Io(io::Error),
    /// The peer sent something unexpected for the protocol.
    Protocol(String),
    /// A typed error returned by the daemon.
    Server { code: String, message: String },
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "io: {e}"),
            ClientError::Protocol(m) => write!(f, "protocol: {m}"),
            ClientError::Server { code, message } => write!(f, "{code}: {message}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        ClientError::Io(e)
    }
}

type Result<T> = std::result::Result<T, ClientError>;

/// The server's parsed challenge: a nonce bound to the forest, with an expiry.
struct Challenge {
    nonce: Vec<u8>,
    forest_id: String,
    expiry_ms: u64,
}

/// A connected, authenticated session with a forest's daemon.
pub struct Client {
    stream: UnixStream,
    /// The principal the daemon resolved us to ("public" or "key:<hex>").
    pub principal: String,
}

impl Client {
    /// Connect and authenticate as `public` (no key proven).
    pub fn connect_public(path: &Path) -> Result<Client> {
        let (mut stream, _challenge) = Self::open(path)?;
        write_msg(&mut stream, &ClientMsg::Anonymous)?;
        Self::finish(stream)
    }

    /// Connect and prove possession of `pubkey` by signing the challenge digest
    /// with `sign` (e.g. `|d| crypto::sign_digest(&key, d).unwrap()`).
    pub fn connect_signed<F>(path: &Path, pubkey: &[u8], sign: F) -> Result<Client>
    where
        F: FnOnce(&[u8; 32]) -> Vec<u8>,
    {
        let (mut stream, ch) = Self::open(path)?;
        let digest = auth_digest(&ch.nonce, &ch.forest_id, ch.expiry_ms);
        write_msg(
            &mut stream,
            &ClientMsg::Auth {
                pubkey: hex::encode(pubkey),
                sig: hex::encode(sign(&digest)),
            },
        )?;
        Self::finish(stream)
    }

    /// Connect and read the server's challenge.
    fn open(path: &Path) -> Result<(UnixStream, Challenge)> {
        let mut stream = UnixStream::connect(path)?;
        match read_msg::<_, ServerMsg>(&mut stream)? {
            Some(ServerMsg::Challenge {
                nonce,
                forest_id,
                expiry_ms,
                ..
            }) => {
                let nonce = hex::decode(&nonce)
                    .map_err(|_| ClientError::Protocol("challenge nonce not hex".into()))?;
                Ok((
                    stream,
                    Challenge {
                        nonce,
                        forest_id,
                        expiry_ms,
                    },
                ))
            }
            Some(other) => Err(unexpected("Challenge", &other)),
            None => Err(ClientError::Protocol("closed before challenge".into())),
        }
    }

    /// Read the `Ready` (or error) that completes the handshake.
    fn finish(mut stream: UnixStream) -> Result<Client> {
        match read_msg::<_, ServerMsg>(&mut stream)? {
            Some(ServerMsg::Ready { principal }) => Ok(Client { stream, principal }),
            Some(ServerMsg::Error { code, message }) => Err(ClientError::Server { code, message }),
            Some(other) => Err(unexpected("Ready", &other)),
            None => Err(ClientError::Protocol("closed during handshake".into())),
        }
    }

    fn request(&mut self, req: ClientMsg) -> Result<ServerMsg> {
        write_msg(&mut self.stream, &req)?;
        match read_msg::<_, ServerMsg>(&mut self.stream)? {
            Some(ServerMsg::Error { code, message }) => Err(ClientError::Server { code, message }),
            Some(msg) => Ok(msg),
            None => Err(ClientError::Protocol("connection closed".into())),
        }
    }

    pub fn info(&mut self) -> Result<ForestInfo> {
        match self.request(ClientMsg::Info)? {
            ServerMsg::Info {
                instance_id,
                forest_id,
                root,
            } => Ok(ForestInfo {
                instance_id,
                forest_id,
                root,
            }),
            other => Err(unexpected("Info", &other)),
        }
    }

    pub fn ls(&mut self, node: &str) -> Result<Vec<ChildInfo>> {
        match self.request(ClientMsg::Ls { node: node.into() })? {
            ServerMsg::Ls { children } => Ok(children),
            other => Err(unexpected("Ls", &other)),
        }
    }

    pub fn stat(&mut self, node: &str) -> Result<NodeInfo> {
        match self.request(ClientMsg::Stat { node: node.into() })? {
            ServerMsg::Stat { node } => Ok(node),
            other => Err(unexpected("Stat", &other)),
        }
    }

    /// Stream a file node's bytes to `out` using the raw binary data plane
    /// (doc 07 §6, PROTO_VERSION 2). Returns the total number of bytes written.
    pub fn cat(&mut self, node: &str, out: &mut dyn std::io::Write) -> Result<u64> {
        write_msg(&mut self.stream, &ClientMsg::Cat { node: node.into() })?;
        // Server responds: CatStart (JSON) → binary data frames → CatDone (JSON).
        let size = match read_msg::<_, ServerMsg>(&mut self.stream)? {
            Some(ServerMsg::CatStart { size }) => size,
            Some(ServerMsg::Error { code, message }) => return Err(ClientError::Server { code, message }),
            Some(other) => return Err(unexpected("CatStart", &other)),
            None => return Err(ClientError::Protocol("connection closed before CatStart".into())),
        };
        let mut written: u64 = 0;
        while written < size {
            match read_data_frame(&mut self.stream)? {
                Some(chunk) if chunk.is_empty() => break, // abort signal
                Some(chunk) => {
                    out.write_all(&chunk).map_err(ClientError::Io)?;
                    written += chunk.len() as u64;
                }
                None => break,
            }
        }
        // Read CatDone (JSON) to return the stream to control-plane state.
        match read_msg::<_, ServerMsg>(&mut self.stream)? {
            Some(ServerMsg::CatDone { written: w }) => Ok(w),
            Some(ServerMsg::Error { code, message }) => Err(ClientError::Server { code, message }),
            Some(other) => Err(unexpected("CatDone", &other)),
            None => Ok(written), // server closed cleanly after data
        }
    }

    /// Create a folder named `label` under `parent`. Returns the new node id.
    pub fn mkdir<F>(&mut self, parent: &str, label: &str, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(
            WriteOp::Mkdir {
                parent: parent.into(),
                label: label.into(),
            },
            sign,
        )
    }

    /// Create a file node named `label` under `parent` (metadata). Returns its id.
    pub fn add_file<F>(
        &mut self,
        parent: &str,
        label: &str,
        size: u64,
        mime: &str,
        sign: F,
    ) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(
            WriteOp::AddFile {
                parent: parent.into(),
                label: label.into(),
                size,
                mime: mime.into(),
            },
            sign,
        )
    }

    /// Unlink `node` from its home parent. Returns the removed link id.
    pub fn rm<F>(&mut self, node: &str, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(WriteOp::Rm { node: node.into() }, sign)
    }

    /// Record where a file node's bytes live. Returns the file id.
    pub fn add_location<F>(&mut self, file: &str, uri: &str, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(
            WriteOp::AddLocation {
                file: file.into(),
                uri: uri.into(),
            },
            sign,
        )
    }

    /// Re-home `node` under `new_parent`. Returns the node id.
    pub fn mv<F>(&mut self, node: &str, new_parent: &str, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(
            WriteOp::Mv {
                node: node.into(),
                new_parent: new_parent.into(),
            },
            sign,
        )
    }

    /// Set a principal's rights on a node (admin op, doc 09 §3c). `principal` =
    /// `public`|`any`|`tag:<name>`|`key:<hex>`; `rights` = `rwa` letters or `-`.
    pub fn set_acl<F>(&mut self, node: &str, principal: &str, rights: &str, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(
            WriteOp::SetAcl {
                node: node.into(),
                principal: principal.into(),
                rights: rights.into(),
            },
            sign,
        )
    }

    /// Grant (`granted`) or remove a membership tag from a member key (hex).
    pub fn tag_member<F>(&mut self, member: &str, tag: &str, granted: bool, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(
            WriteOp::TagMember {
                member: member.into(),
                tag: tag.into(),
                granted,
            },
            sign,
        )
    }

    /// Admit a member's key (hex). Signed by an admin device.
    pub fn authorize_member<F>(&mut self, pubkey: &str, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(WriteOp::AuthorizeMember { pubkey: pubkey.into() }, sign)
    }

    /// Revoke a device/member key (hex). Signed by an admin device.
    pub fn revoke<F>(&mut self, pubkey: &str, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(WriteOp::Revoke { pubkey: pubkey.into() }, sign)
    }

    /// The two-phase write flow (doc 07 §5): prepare → sign each preimage → commit.
    /// `sign` produces a signature over each 32-byte preimage with the member's key.
    fn write_op<F>(&mut self, op: WriteOp, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        let (prepared_id, preimages) = match self.request(ClientMsg::PrepareWrite { op })? {
            ServerMsg::Prepared {
                prepared_id,
                preimages,
                ..
            } => (prepared_id, preimages),
            other => return Err(unexpected("Prepared", &other)),
        };
        let mut sigs = Vec::with_capacity(preimages.len());
        for preimage in &preimages {
            let bytes = hex::decode(preimage)
                .map_err(|_| ClientError::Protocol("preimage not hex".into()))?;
            let digest: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| ClientError::Protocol("preimage not 32 bytes".into()))?;
            sigs.push(hex::encode(sign(&digest)));
        }
        match self.request(ClientMsg::Commit { prepared_id, sigs })? {
            ServerMsg::Committed { id } => Ok(id),
            other => Err(unexpected("Committed", &other)),
        }
    }
}

fn unexpected(want: &str, got: &ServerMsg) -> ClientError {
    ClientError::Protocol(format!("expected {want}, got {got:?}"))
}
