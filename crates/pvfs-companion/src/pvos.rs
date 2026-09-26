//! PVOS D193 — the PVOS statements this companion BUILDS before it signs.
//!
//! A relayed request names what it wants signed as structured fields; the
//! companion computes the digest itself from them, so a server that could
//! hand it any 32 bytes as "a sign-in" gets nothing it did not ask the human
//! for. Each digest must byte-match its pvos-core twin — the vectors below
//! are pinned in pvos-core's tests (`members::tests::the_digests_the_page_builds`,
//! `members::tests::the_confirm_digest`) and the web page's.

use sha2::{Digest, Sha256};

fn length_prefixed(h: &mut Sha256, fields: &[&[u8]]) {
    for f in fields {
        h.update((f.len() as u64).to_le_bytes());
        h.update(f);
    }
}

/// pvos-core `login_digest` (v2): the domain, the length-prefixed nonce,
/// instance id and session key, then the expiry as u64 LE.
pub fn login_digest(nonce: &[u8], instance_id: &str, expiry_ms: u64, session_pubkey: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"pvos:login:v2:");
    length_prefixed(&mut h, &[nonce, instance_id.as_bytes(), session_pubkey]);
    h.update(expiry_ms.to_le_bytes());
    h.finalize().into()
}

/// pvos-core `personal_binding_digest`: "this is my personal forest on this
/// site", signed by the person's owner (device) key at join.
pub fn personal_binding_digest(rp_id: &str, member: &str, forest_id: &str, root_node_id: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"pvos:personal-forest:v1:");
    length_prefixed(&mut h, &[rp_id.as_bytes(), member.as_bytes(), forest_id.as_bytes(), root_node_id.as_bytes()]);
    h.finalize().into()
}

/// pvos-core `confirm_digest`: a delete or a grant a human confirmed — the
/// paired server, the PVOS instance, the operation and what it acts on, a
/// fresh nonce and its expiry.
pub fn confirm_digest(
    server_pubkey_hex: &str,
    instance_id: &str,
    op: &str,
    subject: &str,
    detail: &str,
    nonce_hex: &str,
    expiry_ms: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"pvos:confirm:v1:");
    length_prefixed(
        &mut h,
        &[
            server_pubkey_hex.as_bytes(),
            instance_id.as_bytes(),
            op.as_bytes(),
            subject.as_bytes(),
            detail.as_bytes(),
            nonce_hex.as_bytes(),
        ],
    );
    h.update(expiry_ms.to_le_bytes());
    h.finalize().into()
}

/// The host of an Origin — what a page's `location.hostname` is, and the
/// site a personal forest is bound to. Empty when there is none.
pub fn origin_host(origin: &str) -> String {
    let rest = origin.split_once("://").map_or(origin, |(_, r)| r);
    let hostport = rest.split('/').next().unwrap_or("");
    if hostport.starts_with('[') {
        return hostport.split(']').next().map(|h| format!("{h}]")).unwrap_or_default();
    }
    hostport.split(':').next().unwrap_or("").to_ascii_lowercase()
}

/// The words a confirmation prompt shows, written HERE from the structured
/// operation — never a server's sentence. `None` for an operation this
/// companion does not know: it is refused, not signed blind.
pub fn describe_confirm(op: &str, subject: &str, detail: &str, server: &str, origin: &str) -> Option<String> {
    let what = match op {
        "member_remove" => format!("REMOVE member \"{subject}\" — they lose access; their data is kept, moved aside"),
        "member_set_role" => format!("change member \"{subject}\"'s role to {detail}"),
        "member_rekey" => format!("RE-KEY member \"{subject}\" — their keys and sessions stop working until they redeem a new invite"),
        "invite_revoke" => format!("revoke the pending invite {subject} ({detail})"),
        "session_revoke" => format!("sign out session {subject} ({detail})"),
        "share" => format!("SHARE the app \"{subject}\" with the {detail} role"),
        "unshare" => format!("stop sharing the app \"{subject}\" with the {detail} role"),
        "mount_unbind" => format!("unbind the folder {detail} from the forest at {subject}"),
        "forest_unregister" => format!("unregister the forest \"{subject}\""),
        "instance_remove" => format!("remove the PVFS instance \"{subject}\""),
        "replica_remove" => format!("remove the replica \"{subject}\""),
        _ => return None,
    };
    Some(format!("pvfs-companion: on \"{server}\", {what}? Asked from {origin}."))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FOREST: &str = "00000000-0000-4000-8000-000000000001";

    #[test]
    fn digests_match_pvos_core() {
        let nonce: Vec<u8> = (0u8..16).collect();
        let session = hex::decode("03d02843b4ffdfe3ae8a18feb3a9a2e6a4d5cc39150f2e8d9990da1b281355d744").unwrap();
        assert_eq!(
            hex::encode(login_digest(&nonce, FOREST, 1_700_000_030_000, &session)),
            "2a10892d7d3286c44a1442f6e4446c7522cf06b41962e65a18250fc1fb1196fc",
            "login v2"
        );
        assert_eq!(
            hex::encode(personal_binding_digest(
                "pvos.example",
                "kim",
                FOREST,
                "31071f80e0846ec198c1e2327480f4440fecc9a94af5bd92710b87c24331ff80"
            )),
            "53464f326f270c5f5c677be2c1583a0b93e27b2df0b3c11f584c1e488be49e46",
            "binding"
        );
        assert_eq!(
            hex::encode(confirm_digest("02aa", FOREST, "member_remove", "kim", "", "00112233", 1_700_000_060_000)),
            "39aec65af13a4935b8ec81123be6ef871242478b9572e3c4cbda65fb6ffdf8b1",
            "confirm"
        );
    }

    #[test]
    fn origin_hosts() {
        assert_eq!(origin_host("https://PVOS.example:7443"), "pvos.example");
        assert_eq!(origin_host("http://localhost:7420"), "localhost");
        assert_eq!(origin_host("http://[::1]:7420"), "[::1]");
        assert_eq!(origin_host(""), "");
    }

    #[test]
    fn unknown_operations_are_not_described() {
        assert!(describe_confirm("member_remove", "kim", "", "pvos", "https://pvos.example").is_some());
        assert!(describe_confirm("format_disk", "/", "", "pvos", "https://pvos.example").is_none());
    }
}
