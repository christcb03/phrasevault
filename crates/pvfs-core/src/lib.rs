//! pvfs-core — the PVFS P0 core engine (kernel).
//!
//! Spec: `docs/02-p0-core-engine-spec.md`. Design: `docs/01-core-engine-design.md`.
//!
//! - Append-only event log (`log.db`) is the source of truth; SQLite
//!   projection (`index.db`) is rebuildable (design doc §2).
//! - Nodes are immutable, content-addressed (BLAKE3), signed (secp256k1).
//! - Links carry a mutable state band outside the id preimage; one active
//!   `contains` home per node.
//! - Temp data lives only in the projection — never logged, never replicated.
//! - Identity: generated BIP39 mnemonic → BIP32 hardened HD keys with
//!   per-device signing keys and device certificates in the log.

pub mod crypto;
pub mod encoding;
pub mod engine;
pub mod error;
pub mod event;
pub mod fs;
pub mod identity;
pub mod link;
pub mod log_store;
pub mod mount;
pub mod node;
pub mod orderkey;
pub mod projection;
pub mod storage;
pub mod walk;

pub use engine::{ChildEntry, Engine, NodeSpec};
pub use error::{IntegrityReason, PvfsError, Result};
pub use fs::{
    BindSpec, Binding, HashPolicy, NodeStat, PendingChange, ResolveAction, ScanReport, ScanStats,
    VerifyOutcome,
};
pub use identity::Mnemonic;
pub use link::{Link, LinkId, LINK_CONTAINS, LINK_REF};
pub use mount::{RegisteredForest, Registry, ResolvedTarget};
pub use node::{FilePayload, Node, NodeId, TYPE_FILE, TYPE_FOLDER};
pub use orderkey::OrderKey;
pub use storage::ByteRange;
pub use walk::{TreeWalk, WalkEntry};
