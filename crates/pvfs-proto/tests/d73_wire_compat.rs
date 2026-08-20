//! D73 — forward compatibility for the WIRE.
//!
//! D72 Part A made the LOG tolerant: a box replaying a log survives an event it
//! cannot read. The wire got nothing, so a newer peer sending an op an older
//! daemon had never heard of simply lost its connection — indistinguishable
//! from a network fault, and the reason no additive wire change could roll.
//!
//! What makes refusing safe is the FRAMING: frames are length-prefixed, so a
//! frame we cannot interpret has still been consumed exactly and the stream
//! stays aligned.

use pvfs_proto::{read_frame, ClientMsg, Frame, WriteOp, PROTO_COMPATIBLE_WITH};

fn framed(json: &str) -> Vec<u8> {
    let mut out = (json.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(json.as_bytes());
    out
}

/// The core claim: an unknown op is a REFUSAL, and the stream survives it.
#[test]
fn an_unknown_op_is_refusable_and_the_stream_stays_aligned() {
    let mut buf = Vec::new();
    buf.extend(framed(r#"{"t":"something_from_the_future","wat":1}"#));
    buf.extend(framed(r#"{"t":"info"}"#));
    let mut cur = std::io::Cursor::new(buf);

    match read_frame::<_, ClientMsg>(&mut cur).unwrap() {
        Some(Frame::Unknown { tag }) => assert_eq!(tag, "something_from_the_future"),
        other => panic!("expected Unknown, got {other:?}"),
    }
    // ...and the NEXT frame still reads. This is the whole point: one
    // unreadable request must not cost the connection.
    match read_frame::<_, ClientMsg>(&mut cur).unwrap() {
        Some(Frame::Msg(ClientMsg::Info)) => {}
        other => panic!("the stream must stay aligned, got {other:?}"),
    }
}

/// A write op is named by `op`, not `t` — the refusal must say which one, or a
/// client cannot tell which of its requests was too new to fall back on.
#[test]
fn an_unknown_write_op_is_named() {
    let mut cur = std::io::Cursor::new(framed(r#"{"op":"teleport","link_id":"x"}"#));
    match read_frame::<_, WriteOp>(&mut cur).unwrap() {
        Some(Frame::Unknown { tag }) => assert_eq!(tag, "teleport"),
        other => panic!("expected Unknown, got {other:?}"),
    }
}

/// Tolerance is NOT unconditional. Bytes that are not a JSON object mean the
/// peer is not speaking this protocol, and reading on would be guessing.
#[test]
fn garbage_is_still_fatal() {
    let mut cur = std::io::Cursor::new(framed("not json at all"));
    assert!(
        read_frame::<_, ClientMsg>(&mut cur).is_err(),
        "a frame that is not even JSON must not be treated as a polite unknown"
    );
}

/// Relabel is the op D73 adds, and it must round-trip on the wire.
#[test]
fn the_relabel_op_round_trips() {
    let op = WriteOp::Relabel {
        link_id: "abc".into(),
        label: "Show Name (2019)".into(),
    };
    let json = serde_json::to_string(&op).unwrap();
    assert!(json.contains(r#""op":"relabel""#), "tagged as relabel: {json}");
    assert_eq!(serde_json::from_str::<WriteOp>(&json).unwrap(), op);
}

/// The two numbers that let a playbook tell an additive bump from a breaking
/// one. `PROTO_VERSION` is what we speak; `PROTO_COMPATIBLE_WITH` is how far
/// back we degrade. Moving the FLOOR is the fleet-wide event — moving the
/// version alone is not.
#[test]
fn the_compatibility_floor_is_not_above_what_we_speak() {
    // (`COMPATIBLE_WITH <= VERSION` is a compile-time assertion in the crate —
    // it cannot be violated, so there is nothing for a runtime test to catch.)
    assert_eq!(
        PROTO_COMPATIBLE_WITH, 3,
        "D73 is additive: proto 4 still talks to 3. Changing this is a \
         fleet-wide event and should be a deliberate edit, not a surprise."
    );
}
