/**
 * Pure cryptographic primitives — zero I/O, zero side effects.
 * Ported from phrasevault/crypto.py.
 *
 * Stack:
 *   BLAKE3 (via @noble/hashes)  — content addressing, chain hashing
 *   Argon2id                     — memory-hard key derivation
 *   XSalsa20-Poly1305 (tweetnacl) — authenticated encryption
 */

import { blake3 } from "@noble/hashes/blake3";
import argon2 from "argon2";
import nacl from "tweetnacl";

// Domain-separation tags (must match Python implementation)
const TAG_ADDRESS = new TextEncoder().encode("phrasevault:address:v1:");
const TAG_SALT    = new TextEncoder().encode("phrasevault:salt:v1:");
const TAG_CHAIN   = new TextEncoder().encode("phrasevault:chain:v1:");
const TAG_NODE_ID = new TextEncoder().encode("phrasevault:node:v1:");

// Argon2id parameters (OWASP minimums, matching Python)
const ARGON2_OPTS = {
  type: argon2.argon2id,
  timeCost: 3,
  memoryCost: 65536, // 64 MB
  parallelism: 4,
  hashLength: 32,
  raw: true,
} as const;

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
}

function positionBytes(n: number): Uint8Array {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  // Write as big-endian uint64 (position fits in 32 bits in practice)
  view.setUint32(0, 0, false);
  view.setUint32(4, n, false);
  return new Uint8Array(buf);
}

/**
 * Derive a content address from passphrase + chain position.
 * BLAKE3(TAG_ADDRESS | passphrase | position) → 32 bytes
 */
export function deriveAddress(passphrase: string, chainPosition: number): Uint8Array {
  const input = concat(
    TAG_ADDRESS,
    new TextEncoder().encode(passphrase),
    positionBytes(chainPosition),
  );
  return blake3(input);
}

/**
 * Derive the Argon2id salt for a passphrase.
 * BLAKE3(TAG_SALT | passphrase) → 32 bytes
 */
export function deriveSalt(passphrase: string): Uint8Array {
  return blake3(concat(TAG_SALT, new TextEncoder().encode(passphrase)));
}

/**
 * Derive a 32-byte symmetric key from passphrase via Argon2id.
 * Same passphrase + same salt → same key, always.
 */
export async function deriveKey(passphrase: string): Promise<Uint8Array> {
  const salt = deriveSalt(passphrase);
  const hash = await argon2.hash(passphrase, { ...ARGON2_OPTS, salt: Buffer.from(salt) });
  return hash as unknown as Uint8Array;
}

/**
 * Encrypt plaintext with XSalsa20-Poly1305.
 * Returns nonce (24 bytes) + ciphertext concatenated.
 */
export function encrypt(key: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const box = nacl.secretbox(plaintext, nonce, key);
  return concat(nonce, box);
}

/**
 * Decrypt nonce+ciphertext produced by encrypt().
 * Returns plaintext or throws if authentication fails.
 */
export function decrypt(key: Uint8Array, payload: Uint8Array): Uint8Array {
  const nonce = payload.slice(0, nacl.secretbox.nonceLength);
  const box = payload.slice(nacl.secretbox.nonceLength);
  const plain = nacl.secretbox.open(box, nonce, key);
  if (!plain) throw new Error("Decryption failed — bad key or corrupted data");
  return plain;
}

/**
 * Content-address a PhraseVault node payload.
 * BLAKE3(TAG_NODE_ID | canonical_json) → 32-byte hex string
 */
export function nodeId(canonicalJson: string): string {
  const hash = blake3(concat(TAG_NODE_ID, new TextEncoder().encode(canonicalJson)));
  return Buffer.from(hash).toString("hex");
}

/**
 * Chain two addresses together.
 * BLAKE3(TAG_CHAIN | prev_address | passphrase | position) → 32 bytes
 */
export function chainAddress(
  prevAddress: Uint8Array,
  passphrase: string,
  chainPosition: number,
): Uint8Array {
  return blake3(concat(
    TAG_CHAIN,
    prevAddress,
    new TextEncoder().encode(passphrase),
    positionBytes(chainPosition),
  ));
}
