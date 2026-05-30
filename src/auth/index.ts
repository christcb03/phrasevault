/**
 * API authentication — derives a deterministic bearer token from the
 * passphrase using domain-separated BLAKE3. The token is distinct from
 * the node-signing keypair: same passphrase, different domain tag.
 *
 * Upgrade path to challenge-response (when multi-user is needed):
 *   1. Add GET /auth/challenge → server returns random nonce
 *   2. Client signs nonce with secp256k1 private key (from passphrase)
 *   3. POST /auth/verify → server checks signature, issues short-lived JWT
 *   4. Swap the Bearer check here for JWT verification
 * The middleware interface (FastifyRequest → 401 or pass) stays the same.
 */

import { blake3 } from "@noble/hashes/blake3";
import { timingSafeEqual } from "crypto";

const DOMAIN = new TextEncoder().encode("phrasevault:api-auth-v1:");

export function deriveApiToken(passphrase: string): string {
  const passphraseBytes = new TextEncoder().encode(passphrase);
  const input = new Uint8Array(DOMAIN.length + passphraseBytes.length);
  input.set(DOMAIN, 0);
  input.set(passphraseBytes, DOMAIN.length);
  return Buffer.from(blake3(input)).toString("hex");
}

export function verifyBearer(token: string, validToken: string): boolean {
  if (token.length !== validToken.length) return false;
  return timingSafeEqual(Buffer.from(token), Buffer.from(validToken));
}
