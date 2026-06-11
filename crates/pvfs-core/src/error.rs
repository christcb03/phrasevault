//! PvfsError — spec §13. Typed, structured, cause-preserving; no panics on
//! recoverable conditions anywhere in the kernel.

#[derive(Debug)]
pub enum IntegrityReason {
    IdMismatch { expected: String, actual: String },
    SignatureInvalid,
    UnknownAuthor,
}

impl std::fmt::Display for IntegrityReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntegrityReason::IdMismatch { expected, actual } => {
                write!(f, "id mismatch: expected {expected}, recomputed {actual}")
            }
            IntegrityReason::SignatureInvalid => write!(f, "signature invalid"),
            IntegrityReason::UnknownAuthor => write!(f, "author not authorized"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PvfsError {
    #[error("I/O error during {op}: {source}")]
    Io {
        op: String,
        #[source]
        source: std::io::Error,
    },

    #[error("database error during {op}: {source}")]
    Db {
        op: String,
        #[source]
        source: rusqlite::Error,
    },

    #[error("SQLite is busy/locked during {op} (retried {retries}x)")]
    Busy { op: String, retries: u32 },

    #[error("canonical-encoding error in {what} at byte {offset}: {detail}")]
    Encoding {
        what: String,
        offset: usize,
        detail: String,
    },

    #[error("{kind} not found: {id}")]
    NotFound { kind: &'static str, id: String },

    #[error("integrity violation on {kind} {id}: {reason}")]
    Integrity {
        kind: &'static str,
        id: String,
        reason: IntegrityReason,
    },

    #[error("log chain broken at seq {seq}: expected {expected}, got {actual}")]
    LogChainBroken {
        seq: u64,
        expected: String,
        actual: String,
    },

    #[error(
        "corruption in {db}: {detail} — see recovery options \
         (backup, replica, salvage, filesystem rebuild)"
    )]
    Corruption {
        db: String,
        detail: String,
        seq: Option<u64>,
    },

    #[error("cycle detected: linking {child} under {parent} would create a loop via {path}")]
    CycleDetected {
        parent: String,
        child: String,
        path: String,
    },

    #[error("identity derivation failed: {detail}")]
    Identity { detail: String },

    #[error("invalid input for {field}: {reason}")]
    BadInput { field: String, reason: String },

    #[error("{kind} already exists: {id}")]
    AlreadyExists { kind: &'static str, id: String },

    #[error("cannot purge {id}: {active_inbound} active inbound link(s) still reference it")]
    NotOrphan { id: String, active_inbound: u64 },

    #[error("{child} already has a home under {existing_parent}; use a ref link or move it")]
    AlreadyContained {
        child: String,
        existing_parent: String,
    },

    #[error("schema version mismatch: store is v{found}, engine supports v{supported}")]
    SchemaVersion { found: u32, supported: u32 },
}

impl PvfsError {
    pub fn db(op: &str, source: rusqlite::Error) -> Self {
        PvfsError::Db {
            op: op.to_string(),
            source,
        }
    }
    pub fn io(op: &str, source: std::io::Error) -> Self {
        PvfsError::Io {
            op: op.to_string(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, PvfsError>;

/// Map a rusqlite error in context `op`, surfacing BUSY distinctly (§13.3).
pub fn map_db(op: &str) -> impl Fn(rusqlite::Error) -> PvfsError + '_ {
    move |e| match e {
        rusqlite::Error::SqliteFailure(f, _)
            if f.code == rusqlite::ErrorCode::DatabaseBusy
                || f.code == rusqlite::ErrorCode::DatabaseLocked =>
        {
            PvfsError::Busy {
                op: op.to_string(),
                retries: 0,
            }
        }
        other => PvfsError::db(op, other),
    }
}
