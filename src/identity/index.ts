/**
 * secp256k1 identity — keypairs, signing, verification.
 * Ported from phrasevault/identity.py.
 *
 * One keypair per user, derived deterministically from passphrase.
 * Same passphrase → same identity on every device.
 * Private key is NEVER stored — always re-derived when needed.
 */

import * as secp from "@noble/secp256k1";
import { blake3 } from "@noble/hashes/blake3";
import argon2 from "argon2";

const TAG_IDENTITY = new TextEncoder().encode("phrasevault:identity:v1:");

const ARGON2_OPTS = {
  type: argon2.argon2id,
  timeCost: 3,
  memoryCost: 65536,
  parallelism: 4,
  hashLength: 32,
  raw: true,
} as const;

export interface Identity {
  publicKey: Uint8Array;   // 33-byte compressed secp256k1 public key
  did: string;             // did:key identifier derived from public key
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
}

/**
 * Derive the identity salt for a passphrase.
 * Domain-separated from the address/key derivation in crypto.ts.
 */
function identitySalt(passphrase: string): Uint8Array {
  return blake3(concat(TAG_IDENTITY, new TextEncoder().encode(passphrase)));
}

/**
 * Derive a secp256k1 private key from passphrase via Argon2id.
 * The resulting 32-byte seed is used directly as the private key scalar.
 */
async function derivePrivateKey(passphrase: string): Promise<Uint8Array> {
  const salt = identitySalt(passphrase);
  const seed = await argon2.hash(passphrase, {
    ...ARGON2_OPTS,
    salt: Buffer.from(salt),
  }) as unknown as Uint8Array;

  // Ensure the seed is a valid secp256k1 scalar (non-zero, < curve order)
  if (!secp.utils.isValidPrivateKey(seed)) {
    // Extremely unlikely — hash once more with a counter if it happens
    return blake3(concat(seed, new Uint8Array([1])));
  }
  return seed;
}

/**
 * Derive the full identity (public key + DID) from passphrase.
 * Call this when you need to display or store the user's identity.
 */
export async function deriveIdentity(passphrase: string): Promise<Identity> {
  const privKey = await derivePrivateKey(passphrase);
  const pubKey = secp.getPublicKey(privKey, true); // compressed, 33 bytes
  const did = `did:key:z${Buffer.from(pubKey).toString("base64url")}`;
  return { publicKey: pubKey, did };
}

/**
 * Sign a message (typically a node's canonical JSON) with the identity key.
 * Returns a 64-byte compact signature.
 */
export async function sign(passphrase: string, message: Uint8Array): Promise<Uint8Array> {
  const privKey = await derivePrivateKey(passphrase);
  const msgHash = blake3(message);
  const sig = await secp.signAsync(msgHash, privKey);
  return sig.toCompactRawBytes();
}

/**
 * Verify a signature against a public key.
 */
export function verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    const msgHash = blake3(message);
    return secp.verify(signature, msgHash, publicKey);
  } catch {
    return false;
  }
}
