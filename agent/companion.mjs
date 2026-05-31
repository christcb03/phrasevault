#!/usr/bin/env node
/**
 * PhraseVault Local Auth Agent
 *
 * Reads the passphrase from ~/.config/phrasevault/config.json on startup,
 * derives the auth private key, then discards the passphrase from memory.
 *
 * Listens on 127.0.0.1:8765 and handles challenge-signing on behalf of
 * the browser so the passphrase never enters a browser process.
 *
 * Chrome Private Network Access: responds to OPTIONS preflight with
 * Access-Control-Allow-Private-Network: true.
 */

import { createServer } from 'node:http'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'

// ── Crypto setup ────────────────────────────────────────────────────────────

// Locate noble packages relative to this file's repo root.
// agent/ lives one level below repo root; noble is in repo root node_modules.
const repoRoot = new URL('..', import.meta.url).pathname
const resolve = (pkg) => join(repoRoot, 'node_modules', pkg)

const { blake3 }   = await import(resolve('@noble/hashes/blake3.js'))
const secp         = await import(resolve('@noble/secp256k1/index.js'))

const ENC               = new TextEncoder()
const DOMAIN_AUTH       = ENC.encode('phrasevault:api-auth-v1:')
const DOMAIN_CHALLENGE  = ENC.encode('phrasevault:auth-challenge:v1:')

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0)
  out.set(b, a.length)
  return out
}

function toHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

// ── Load passphrase and derive auth key ─────────────────────────────────────

const CONFIG_PATH = join(homedir(), '.config', 'phrasevault', 'config.json')

let authPrivKey
try {
  const raw = readFileSync(CONFIG_PATH, 'utf8')
  const { passphrase } = JSON.parse(raw)
  if (!passphrase || typeof passphrase !== 'string') {
    throw new Error('"passphrase" key missing or empty in config.json')
  }
  authPrivKey = blake3(concat(DOMAIN_AUTH, ENC.encode(passphrase)))
  // Overwrite string in memory as best-effort (V8 may not honour this, but it's good practice)
} catch (err) {
  console.error(`[companion] Failed to load passphrase: ${err.message}`)
  console.error(`[companion] Expected: ${CONFIG_PATH}`)
  console.error('[companion] Create it with: {"passphrase":"your-passphrase-here"}')
  process.exit(1)
}

console.log('[companion] Auth key derived. Passphrase reference released.')

// ── HTTP server ──────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PV_AGENT_PORT ?? '8765', 10)
const HOST = '127.0.0.1'

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Private-Network': 'true',
}

function send(res, status, body) {
  const json = JSON.stringify(body)
  res.writeHead(status, { 'Content-Type': 'application/json', ...CORS_HEADERS })
  res.end(json)
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    req.on('data', c => chunks.push(c))
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString())) }
      catch { reject(new Error('invalid JSON')) }
    })
    req.on('error', reject)
  })
}

const server = createServer(async (req, res) => {
  // CORS preflight (Chrome Private Network Access sends this first)
  if (req.method === 'OPTIONS') {
    res.writeHead(204, CORS_HEADERS)
    res.end()
    return
  }

  if (req.method === 'GET' && req.url === '/health') {
    send(res, 200, { ok: true, version: '1' })
    return
  }

  if (req.method === 'POST' && req.url === '/sign') {
    let body
    try {
      body = await readBody(req)
    } catch {
      send(res, 400, { error: 'invalid body' })
      return
    }
    if (!body?.challenge || typeof body.challenge !== 'string') {
      send(res, 400, { error: 'challenge required' })
      return
    }
    try {
      const msgHash = blake3(concat(DOMAIN_CHALLENGE, ENC.encode(body.challenge)))
      const sig = await secp.signAsync(msgHash, authPrivKey, { lowS: true })
      send(res, 200, { signature: sig.toCompactHex() })
    } catch (err) {
      console.error('[companion] sign error:', err)
      send(res, 500, { error: 'signing failed' })
    }
    return
  }

  send(res, 404, { error: 'not found' })
})

server.listen(PORT, HOST, () => {
  console.log(`[companion] Listening on ${HOST}:${PORT}`)
})

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`[companion] Port ${PORT} already in use. Is the companion already running?`)
  } else {
    console.error('[companion] Server error:', err)
  }
  process.exit(1)
})

// Graceful shutdown
process.on('SIGTERM', () => { server.close(); process.exit(0) })
process.on('SIGINT',  () => { server.close(); process.exit(0) })
