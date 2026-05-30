/**
 * PhraseVault node schema — base fields only (platform layer).
 * Application-layer fields live in the payload; the platform doesn't validate them.
 */

export interface PVNode {
  id: string;           // BLAKE3 content hash of the canonical JSON (hex)
  type: string;         // application-defined (e.g. "full_solution", "leaf", "media")
  author: string;       // secp256k1 compressed public key (hex)
  signature: string;    // 64-byte compact ECDSA signature over canonical JSON (hex)
  timestamp: number;    // unix ms
  links: string[];      // ids of nodes this node references/depends on
  score: number;        // falsehood probability: 0.0 = certain, approaching 1.0 = impossible
  payload: Record<string, unknown>; // application-defined content
}

/** Fields present before signing — id and signature not yet set */
export type UnsignedNode = Omit<PVNode, "id" | "signature">;

/** Canonical JSON for hashing/signing — deterministic key order */
export function canonicalize(node: UnsignedNode): string {
  return JSON.stringify({
    type: node.type,
    author: node.author,
    timestamp: node.timestamp,
    links: [...node.links].sort(),
    score: node.score,
    payload: node.payload,
  });
}
