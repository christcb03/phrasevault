/**
 * Payload encryption for private and community forest nodes.
 *
 * Private nodes:   AES-256-GCM, key = BLAKE3("phrasevault:forest-enc-v1:" + passphrase)
 * Community nodes: AES-256-GCM, key = community shared key (managed externally)
 *
 * Wire format: base64( iv[12] || ciphertext || authTag[16] )
 * The 12-byte IV is random per encryption; never reused.
 */

import { blake3 } from '@noble/hashes/blake3'
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto'

const DOMAIN_ENC = Buffer.from('phrasevault:forest-enc-v1:')

export type Visibility = 'public' | 'private' | `community:${string}`

/**
 * Derive the forest encryption key from a passphrase.
 * Returns a 32-byte Uint8Array suitable for AES-256-GCM.
 */
export function deriveForestEncKey(passphrase: string): Uint8Array {
  return blake3(Buffer.concat([DOMAIN_ENC, Buffer.from(passphrase)]))
}

/**
 * Encrypt a payload object. Returns a base64 string: iv + ciphertext + authTag.
 */
export function encryptPayload(payload: unknown, encKey: Uint8Array): string {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(encKey), iv)
  const plaintext = Buffer.from(JSON.stringify(payload))
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const authTag = cipher.getAuthTag()
  return Buffer.concat([iv, ciphertext, authTag]).toString('base64')
}

/**
 * Decrypt a payload that was encrypted with encryptPayload.
 * Throws if the key is wrong or the ciphertext is tampered.
 */
export function decryptPayload(ciphertext: string, encKey: Uint8Array): unknown {
  const buf = Buffer.from(ciphertext, 'base64')
  if (buf.length < 28) throw new Error('ciphertext too short')
  const iv      = buf.subarray(0, 12)
  const tag     = buf.subarray(buf.length - 16)
  const body    = buf.subarray(12, buf.length - 16)
  const decipher = createDecipheriv('aes-256-gcm', Buffer.from(encKey), iv)
  decipher.setAuthTag(tag)
  const plaintext = Buffer.concat([decipher.update(body), decipher.final()])
  return JSON.parse(plaintext.toString())
}

/**
 * Determine whether a node type should default to private visibility.
 * Callers can always override — this is just the default.
 */
export function defaultVisibility(type: string): Visibility {
  if (
    type.startsWith('user.') ||
    type.startsWith('config.') ||
    type === 'pvfs.integrity_failure' ||
    type.startsWith('event.')
  ) {
    return 'private'
  }
  return 'public'
}

/**
 * Return the stored payload string for a node: plaintext JSON if public,
 * encrypted base64 if private/community.
 */
export function serializePayload(
  payload: unknown,
  visibility: Visibility,
  encKey: Uint8Array | null,
): string {
  if (visibility === 'public') return JSON.stringify(payload)
  if (!encKey) throw new Error(`encKey required for visibility "${visibility}"`)
  return encryptPayload(payload, encKey)
}

/**
 * Parse the stored payload string back to an object, decrypting if needed.
 * Returns null for private/community nodes when no key is supplied —
 * caller must handle the opaque case.
 */
export function deserializePayload(
  raw: string,
  visibility: Visibility,
  encKey: Uint8Array | null,
): unknown {
  if (visibility === 'public') return JSON.parse(raw)
  if (!encKey) return null   // opaque to this caller
  return decryptPayload(raw, encKey)
}
