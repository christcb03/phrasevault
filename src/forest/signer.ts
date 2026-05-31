import { blake3 } from '@noble/hashes/blake3'
import * as secp from '@noble/secp256k1'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import type { TruthNode, TruthLink, NewNode, NewLink } from './types.js'

// ─── ID derivation ────────────────────────────────────────────────────────────

// Node ID = BLAKE3(type + "\0" + label + "\0" + visibility + "\0" + payload_str + "\0" + created_at + "\0" + author)
// visibility is part of the preimage: changing visibility creates a new node.
// payload_str is the stored value (plaintext JSON for public, base64 ciphertext for private/community).
export function deriveNodeId(node: NewNode): string {
  const payloadStr = typeof node.payload === 'string'
    ? node.payload   // already serialized (private/community ciphertext)
    : JSON.stringify(node.payload)
  const content = `${node.type}\0${node.label}\0${node.visibility}\0${payloadStr}\0${node.created_at}\0${node.author}`
  return bytesToHex(blake3(content))
}

// Link ID = BLAKE3(parent_id + "\0" + child_id + "\0" + link_type + "\0" + created_at)
export function deriveLinkId(link: NewLink): string {
  const content = `${link.parent_id ?? ''}\0${link.child_id}\0${link.link_type}\0${link.created_at}`
  return bytesToHex(blake3(content))
}

// ─── Signing ─────────────────────────────────────────────────────────────────

// Signs the content-addressed ID. The ID already commits to all fields,
// so signing the ID is equivalent to signing the full content.
export async function signId(id: string, privKeyHex: string): Promise<string> {
  const msgHash = blake3(hexToBytes(id))
  const sig = await secp.sign(msgHash, privKeyHex, { lowS: true })
  return sig.toCompactHex()
}

// ─── Verification ─────────────────────────────────────────────────────────────

export async function verifyNodeSig(node: TruthNode): Promise<boolean> {
  try {
    const expectedId = deriveNodeId(node)
    if (expectedId !== node.id) return false
    const msgHash = blake3(hexToBytes(node.id))
    const sig = secp.Signature.fromCompact(node.sig)
    return secp.verify(sig, msgHash, node.author, { lowS: true })
  } catch {
    return false
  }
}

export async function verifyLinkSig(link: TruthLink, authorPubKey: string): Promise<boolean> {
  try {
    const msgHash = blake3(hexToBytes(link.id))
    const sig = secp.Signature.fromCompact(link.sig)
    return secp.verify(sig, msgHash, authorPubKey, { lowS: true })
  } catch {
    return false
  }
}

// ─── Node / link creation helpers ────────────────────────────────────────────

export async function createNode(
  input: NewNode,
  privKeyHex: string,
): Promise<TruthNode> {
  const id = deriveNodeId(input)
  const sig = await signId(id, privKeyHex)
  return { ...input, id, sig } as TruthNode
}

export async function createLink(
  input: NewLink,
  privKeyHex: string,
): Promise<TruthLink> {
  const id = deriveLinkId(input)
  const sig = await signId(id, privKeyHex)
  return {
    ...input,
    id,
    sig,
    removed_at:    null,
    removed_by:    null,
    removal_sig:   null,
    superseded_by: null,
    suspended_at:  null,
  }
}
