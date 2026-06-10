/**
 * API authentication — challenge-response using a secp256k1 auth keypair
 * derived from the passphrase via BLAKE3 only (no argon2), so it can be
 * re-derived client-side in the browser without native dependencies.
 *
 * Domain separation:
 *   Identity keypair  → "phrasevault:identity:v1:"  + argon2id (server-only)
 *   Auth keypair      → "phrasevault:api-auth-v1:"  + BLAKE3   (browser-safe)
 *
 * Auth flow:
 *   1. Client: GET /auth/challenge → nonce
 *   2. Client: derive auth privkey client-side (BLAKE3, no argon2)
 *   3. Client: sign BLAKE3(domain + nonce) with auth privkey
 *   4. Client: POST /auth/verify { challenge, signature }
 *   5. Server: verify sig against known auth pubkey, issue session token
 */

import * as secp from "@noble/secp256k1";
import { blake3 } from "@noble/hashes/blake3";
import { randomBytes } from "crypto";

const DOMAIN_AUTH      = new TextEncoder().encode("phrasevault:api-auth-v1:");
const DOMAIN_CHALLENGE = new TextEncoder().encode("phrasevault:auth-challenge:v1:");

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** Derive the 32-byte auth private key from passphrase (browser-compatible). */
export function deriveAuthPrivKey(passphrase: string): Uint8Array {
  const key = blake3(concat(DOMAIN_AUTH, new TextEncoder().encode(passphrase)));
  if (!secp.utils.isValidPrivateKey(key)) {
    return blake3(new Uint8Array([...key, 1]));
  }
  return key;
}

/** Derive the compressed (33-byte) auth public key from passphrase. */
export function deriveAuthPubKey(passphrase: string): Uint8Array {
  return secp.getPublicKey(deriveAuthPrivKey(passphrase), true);
}

/** Hash a challenge nonce for signing (domain-separated). */
export function hashChallenge(nonce: string): Uint8Array {
  return blake3(concat(DOMAIN_CHALLENGE, new TextEncoder().encode(nonce)));
}

// ── Challenge store ────────────────────────────────────────────────────────

const CHALLENGE_TTL_MS = 5 * 60 * 1000;

/** Create a one-time challenge nonce (5-min TTL). Prunes expired entries. */
export function createChallenge(store: Map<string, number>): string {
  const now = Date.now();
  for (const [nonce, expiry] of store) {
    if (expiry < now) store.delete(nonce);
  }
  const nonce = randomBytes(32).toString("hex");
  store.set(nonce, now + CHALLENGE_TTL_MS);
  return nonce;
}

/** Consume a challenge — returns false if unknown or expired. */
export function consumeChallenge(store: Map<string, number>, nonce: string): boolean {
  const expiry = store.get(nonce);
  if (!expiry || expiry < Date.now()) return false;
  store.delete(nonce);
  return true;
}

/** Verify a compact secp256k1 signature of a challenge nonce. */
export function verifyAuthSignature(
  authPubKey: Uint8Array,
  nonce: string,
  signatureHex: string,
): boolean {
  try {
    const sig = Buffer.from(signatureHex, "hex");
    return secp.verify(sig, hashChallenge(nonce), authPubKey);
  } catch {
    return false;
  }
}

// ── Session store ──────────────────────────────────────────────────────────

const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

/** Issue a new 24-hour session token. Prunes expired tokens. */
export function createSession(store: Map<string, number>): string {
  const now = Date.now();
  for (const [token, expiry] of store) {
    if (expiry < now) store.delete(token);
  }
  const token = randomBytes(32).toString("hex");
  store.set(token, now + SESSION_TTL_MS);
  return token;
}

/** Check whether a session token is valid and not expired. */
export function verifySession(store: Map<string, number>, token: string): boolean {
  const expiry = store.get(token);
  return !!expiry && expiry >= Date.now();
}
