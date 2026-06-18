//! PVFS daemon client (doc 07): connect to a forest's `pvfsd`, perform the
//! challenge-response handshake, and issue read requests.
//!
//! Signing is injected as a closure so this crate needs no key library — the
//! caller (CLI/app) holds the identity key and provides how to sign the 32-byte
//! challenge digest.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;

use pvfs_proto::{auth_digest, read_msg, write_msg, ClientMsg, ServerMsg, WriteOp};

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

    /// Stream a file node's bytes to `out`, chunk by chunk. Returns the total
    /// number of bytes written.
    pub fn cat(&mut self, node: &str, out: &mut dyn std::io::Write) -> Result<u64> {
        const CHUNK: u64 = 1 << 20; // 1 MiB per request
        let mut offset = 0u64;
        loop {
            match self.request(ClientMsg::Cat {
                node: node.into(),
                offset,
                len: CHUNK,
            })? {
                ServerMsg::CatData { data, eof } => {
                    let bytes = hex::decode(&data)
                        .map_err(|_| ClientError::Protocol("cat data not hex".into()))?;
                    out.write_all(&bytes).map_err(ClientError::Io)?;
                    offset += bytes.len() as u64;
                    if eof || bytes.is_empty() {
                        break;
                    }
                }
                other => return Err(unexpected("CatData", &other)),
            }
        }
        Ok(offset)
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
