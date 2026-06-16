//! Access-control primitives — principals and rights (doc 06 §4).
//!
//! ACLs are stored as `AclSet` events and projected into the `acl` table; the
//! evaluation that walks the tree lives in `projection::effective_rights`. This
//! module is just the value types shared by the engine, projection, and CLI.

use crate::error::{PvfsError, Result};

/// Read a node (its metadata/payload) and see it when listing a parent.
pub const ACL_R: u8 = 0b001;
/// Create/modify/remove children of a node and modify its payload.
pub const ACL_W: u8 = 0b010;
/// Set ACLs on a node and its subtree (grant/revoke access).
pub const ACL_A: u8 = 0b100;
/// Full rights.
pub const ACL_RWA: u8 = ACL_R | ACL_W | ACL_A;

/// `device_index` sentinel marking an externally-authorized **member** key (one
/// admitted by `authorize_member`, not HD-derived from this forest's seed).
/// Owner devices use real indices `< 2^31`, so this cleanly distinguishes the
/// two without a new event field. Owner devices have implicit full rights.
pub const MEMBER_DEVICE_INDEX: u64 = u64::MAX;

/// Who an ACL entry is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// Any authorized member of the forest (filesystem "other-but-authenticated").
    Any,
    /// A specific device/member public key (33-byte compressed secp256k1).
    Key(Vec<u8>),
}

impl Principal {
    /// Wire/table discriminant: 0 = Any, 1 = Key.
    pub fn kind(&self) -> u64 {
        match self {
            Principal::Any => 0,
            Principal::Key(_) => 1,
        }
    }

    /// Wire/table identity bytes (pubkey for `Key`, empty for `Any`).
    pub fn id(&self) -> &[u8] {
        match self {
            Principal::Any => &[],
            Principal::Key(k) => k,
        }
    }

    /// Reconstruct from the on-wire `(kind, id)` pair.
    pub fn from_wire(kind: u64, id: Vec<u8>) -> Result<Principal> {
        match kind {
            0 => Ok(Principal::Any),
            1 => {
                crate::crypto::validate_pubkey(&id)?;
                Ok(Principal::Key(id))
            }
            other => Err(PvfsError::BadInput {
                field: "principal_kind".into(),
                reason: format!("unknown principal kind {other}"),
            }),
        }
    }

    /// Parse the CLI form: `any` or `key:<hex>`.
    pub fn parse(s: &str) -> Result<Principal> {
        if s == "any" {
            return Ok(Principal::Any);
        }
        if let Some(hexstr) = s.strip_prefix("key:") {
            let bytes = hex::decode(hexstr).map_err(|_| PvfsError::BadInput {
                field: "principal".into(),
                reason: "key:<hex> — pubkey is not valid hex".into(),
            })?;
            crate::crypto::validate_pubkey(&bytes)?;
            return Ok(Principal::Key(bytes));
        }
        Err(PvfsError::BadInput {
            field: "principal".into(),
            reason: format!("{s:?} — expected `any` or `key:<hex>`"),
        })
    }

    /// CLI/display form, the inverse of [`Principal::parse`].
    pub fn display(&self) -> String {
        match self {
            Principal::Any => "any".into(),
            Principal::Key(k) => format!("key:{}", hex::encode(k)),
        }
    }
}

/// Parse a rights string (`r`, `rw`, `rwa`, … or `-`/`none`/empty for clear).
pub fn parse_rights(s: &str) -> Result<u8> {
    if s == "-" || s == "none" || s.is_empty() {
        return Ok(0);
    }
    let mut r = 0u8;
    for c in s.chars() {
        match c {
            'r' => r |= ACL_R,
            'w' => r |= ACL_W,
            'a' => r |= ACL_A,
            _ => {
                return Err(PvfsError::BadInput {
                    field: "rights".into(),
                    reason: format!("{s:?} — use letters from r,w,a (or '-' to clear)"),
                })
            }
        }
    }
    Ok(r)
}

/// Render a rights bitmask as `rwa`-style letters (`-` when empty).
pub fn rights_to_str(r: u8) -> String {
    if r & ACL_RWA == 0 {
        return "-".into();
    }
    let mut s = String::new();
    if r & ACL_R != 0 {
        s.push('r');
    }
    if r & ACL_W != 0 {
        s.push('w');
    }
    if r & ACL_A != 0 {
        s.push('a');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_roundtrip() {
        for s in ["r", "rw", "rwa", "-"] {
            assert_eq!(rights_to_str(parse_rights(s).unwrap()), s);
        }
        assert_eq!(parse_rights("none").unwrap(), 0);
        assert_eq!(parse_rights("").unwrap(), 0);
        assert!(parse_rights("x").is_err());
        assert_eq!(parse_rights("war").unwrap(), ACL_RWA);
    }

    #[test]
    fn principal_parse() {
        assert_eq!(Principal::parse("any").unwrap(), Principal::Any);
        assert!(Principal::parse("key:zz").is_err());
        assert!(Principal::parse("bogus").is_err());
    }
}
