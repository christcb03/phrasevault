/**
 * Browser-side auth crypto — secp256k1 challenge-response.
 *
 * Auth private key = BLAKE3("phrasevault:api-auth-v1:" + passphrase)
 * This is intentionally simpler than the identity keypair (no argon2) so it
 * can be derived in the browser. Same domain tag as the server's auth module.
 */

import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { blake3 } from "@noble/hashes/blake3.js";
import * as secp from "@noble/secp256k1";

// Noble secp256k1 v3 requires HMAC and SHA256 to be wired up explicitly.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
secp.hashes.sha256 = sha256 as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
secp.hashes.hmacSha256 = ((key: Uint8Array, msg: Uint8Array) => hmac(sha256 as any, key, msg)) as any;

const DOMAIN_AUTH      = new TextEncoder().encode("phrasevault:api-auth-v1:");
const DOMAIN_CHALLENGE = new TextEncoder().encode("phrasevault:auth-challenge:v1:");

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function deriveAuthPrivKey(passphrase: string): Uint8Array {
  return blake3(concat(DOMAIN_AUTH, new TextEncoder().encode(passphrase)));
}

/**
 * Sign a server-issued challenge nonce. Returns a compact 64-byte hex signature.
 * The passphrase is used only to derive the private key locally — it never leaves
 * the browser.
 */
export async function signChallenge(passphrase: string, challenge: string): Promise<string> {
  const privKey = deriveAuthPrivKey(passphrase);
  const msgHash = blake3(concat(DOMAIN_CHALLENGE, new TextEncoder().encode(challenge)));
  // prehash:false — msgHash is already a BLAKE3 digest; skip secp256k1's default SHA256 step
  const sig = await secp.signAsync(msgHash, privKey, { prehash: false });
  return toHex(sig as Uint8Array);
}
