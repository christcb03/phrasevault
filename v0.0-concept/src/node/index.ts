/**
 * Node creation and verification.
 * Wires together crypto (content addressing) and identity (signing).
 */

import { nodeId } from "../crypto/index.js";
import { identityFromPrivKey, signWithKey, verify } from "../identity/index.js";
import { PVNode, UnsignedNode, canonicalize } from "./types.js";

/**
 * Create and sign a new PhraseVault node using a raw secp256k1 private key.
 */
export async function createNode(
  privKeyHex: string,
  partial: Omit<UnsignedNode, "author">,
): Promise<PVNode> {
  const identity = identityFromPrivKey(privKeyHex);
  const author = Buffer.from(identity.publicKey).toString("hex");

  const unsigned: UnsignedNode = { ...partial, author };
  const canonical = canonicalize(unsigned);
  const id = nodeId(canonical);

  const sigBytes = await signWithKey(privKeyHex, new TextEncoder().encode(canonical));
  const signature = Buffer.from(sigBytes).toString("hex");

  return { id, ...unsigned, signature };
}

/**
 * Verify a node's signature and content hash.
 * Returns true only if both checks pass.
 */
export function verifyNode(node: PVNode): boolean {
  const { id, signature, ...unsigned } = node;
  const canonical = canonicalize(unsigned as UnsignedNode);

  const expectedId = nodeId(canonical);
  if (id !== expectedId) return false;

  const pubKey = Buffer.from(node.author, "hex");
  const sig = Buffer.from(signature, "hex");
  return verify(pubKey, new TextEncoder().encode(canonical), sig);
}

export { PVNode, UnsignedNode, canonicalize } from "./types.js";
