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

/// D181 — the view mount's compatibility level. On a box that restarts its
/// mount only when nothing is open through it (PVOS D181 §8: mediabox, under
/// Plex), a roll leaves the running mount on the OLDER build until an idle
/// minute. That is safe only while this number is unchanged between the two
/// builds. Bump it with any change a RUNNING older mount cannot follow:
///
/// * a request a mount sends other boxes (`CatHash`, `TrashPath`,
///   `RenamePath`, `RmdirPath`, …) changed so the older form fails, or
/// * a projection change an older mount's catalogue reads cannot run on that
///   the migration ladder applies IN PLACE (a dropped or renamed column).
///
/// A schema move that rebuilds, or a schema newer than the mount reads, needs
/// no bump: `projection::projection_plan` sees those for itself.
pub const MOUNT_COMPAT: u32 = 1;

pub mod acl;
pub mod crypto;
pub mod encoding;
pub mod engine;
pub mod envelope;
pub mod error;
pub mod event;
pub mod export;
pub mod fence;
pub mod fs;
pub mod identity;
pub mod ingest;
pub mod link;
pub mod arr;
pub mod media;
pub mod probe;
pub mod log_store;
pub mod mount;
pub mod node;
pub mod orderkey;
pub mod projection;
pub mod replica;
pub mod serve;
pub mod storage;
pub mod sync;
pub mod walk;

pub use acl::{Principal, ACL_A, ACL_R, ACL_RWA, ACL_W};
pub use engine::{
    DeviceCert,
    ChildEntry, DuplicateGroup, DuplicateReport, Engine, Island, IslandReport, NodeSpec,
    PreparedEvent, PreparedWrite, RegionInfo, SubtreeSize,
};
pub use error::{IntegrityReason, PvfsError, Result};
pub use export::{ExportMode, ExportReport, ExportSkip, ExportSpec};
pub use fs::{
    BackfillReport,
    Binding,
    BindingRow,
    BindKind,
    BindSpec,
    CatalogueStatus,
    StoreFs,
    CATALOGUE_BATCH_MS,
    CATALOGUE_BATCH_ROWS,
    DrainCheck,
    HashPolicy,
    LocalBytes,
    NodeStat,
    PendingChange,
    ReceiveItem,
    ReceiveSkip,
    RegionEntry,
    RegionTrashList,
    TrashedHere,
    LOCAL_PATH_FOR_HASH_SQL,
    MERGED_VIEW_SQL,
    VIEW_ENTRY_SQL,
    RenameExpect,
    RenamedHere,
    DirRemovedHere,
    RegionSnapshot,
    ResolveAction,
    ResolveReport,
    ScanReport,
    ScanStats,
    ScanWriter,
    ORPHAN_SIDECAR_GRACE_MS,
    UNLINK_GRACE_MS,
    UpgradeReport,
    VerifyOutcome,
    ViewCopy,
    ViewEntry,
    ViewState,
    WATCH_SETTLE_MS,
};
pub use identity::Mnemonic;
pub use link::{Link, LinkId, LINK_CONTAINS, LINK_REF};
pub use mount::{RegisteredForest, Registry, ResolvedTarget};
pub use replica::{ReplicaSource, ReplicaStore};
pub use node::{FilePayload, Node, NodeId, TYPE_FILE, TYPE_FOLDER, TYPE_SECURE};
pub use orderkey::OrderKey;
pub use storage::ByteRange;
pub use sync::SyncSink;
pub use walk::{TreeWalk, WalkEntry};
