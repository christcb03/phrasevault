#!/usr/bin/env node
/**
 * PhraseVault / MediaForest Companion Agent
 *
 * Signs server challenges on behalf of the browser so your passphrase never
 * enters a browser process. Listens only on 127.0.0.1:8765.
 *
 * Normal usage:
 *   node companion.mjs       — first run: setup wizard then start in background
 *                              subsequent runs: show config, offer to start
 *
 * Maintenance flags:
 *   node companion.mjs --setup    — re-run setup wizard, then start
 *   node companion.mjs --status   — check if companion is running
 *   node companion.mjs --stop     — stop a running companion
 */

import { createServer }                         from 'node:http'
import { readFileSync, writeFileSync,
         existsSync, mkdirSync, openSync,
         closeSync }                            from 'node:fs'
import { join }                                 from 'node:path'
import { homedir }                              from 'node:os'
import { createInterface }                      from 'node:readline'
import { fileURLToPath }                        from 'node:url'

// ── Paths ────────────────────────────────────────────────────────────────────

const CONFIG_DIR  = join(homedir(), '.config', 'phrasevault')
const CONFIG_PATH = join(CONFIG_DIR, 'config.json')
const PID_PATH    = join(CONFIG_DIR, 'companion.pid')
const LOG_PATH    = join(CONFIG_DIR, 'companion.log')

// ── Crypto setup ─────────────────────────────────────────────────────────────

const repoRoot = new URL('..', import.meta.url).pathname
const resolve  = (pkg) => join(repoRoot, 'node_modules', pkg)

const { blake3 } = await import(resolve('@noble/hashes/blake3.js'))
const secp       = await import(resolve('@noble/secp256k1/index.js'))

const ENC              = new TextEncoder()
const DOMAIN_AUTH      = ENC.encode('phrasevault:api-auth-v1:')
const DOMAIN_CHALLENGE = ENC.encode('phrasevault:auth-challenge:v1:')

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0); out.set(b, a.length)
  return out
}

function deriveAuthKey(passphrase) {
  return blake3(concat(DOMAIN_AUTH, ENC.encode(passphrase)))
}

function pubKeyHex(authKey) {
  const bytes = secp.getPublicKey(authKey, true)
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

async function signChallenge(authKey, challenge) {
  const msgHash = blake3(concat(DOMAIN_CHALLENGE, ENC.encode(challenge)))
  const sig = await secp.signAsync(msgHash, authKey, { lowS: true })
  return sig.toCompactHex()
}

// ── Config ───────────────────────────────────────────────────────────────────

function loadConfig() {
  if (!existsSync(CONFIG_PATH)) return null
  try {
    return JSON.parse(readFileSync(CONFIG_PATH, 'utf8'))
  } catch {
    return null
  }
}

function saveConfig(cfg) {
  mkdirSync(CONFIG_DIR, { recursive: true })
  writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2), { mode: 0o600 })
}

// ── Interactive prompts ───────────────────────────────────────────────────────

function readLine(prompt) {
  return new Promise(resolve => {
    const rl = createInterface({ input: process.stdin, output: process.stdout })
    rl.question(prompt, answer => { rl.close(); resolve(answer.trim()) })
  })
}

function readSecret(prompt) {
  return new Promise(resolve => {
    if (!process.stdin.isTTY) {
      const rl = createInterface({ input: process.stdin })
      rl.once('line', line => { rl.close(); resolve(line.trim()) })
      return
    }
    process.stdout.write(prompt)
    process.stdin.setRawMode(true)
    process.stdin.resume()
    process.stdin.setEncoding('utf8')
    let input = ''
    function handler(ch) {
      if (ch === '\r' || ch === '\n' || ch === '') {
        process.stdin.setRawMode(false)
        process.stdin.pause()
        process.stdin.removeListener('data', handler)
        process.stdout.write('\n')
        resolve(input)
      } else if (ch === '') {
        process.stdout.write('\n')
        process.exit(0)
      } else if (ch === '' || ch === '\b') {
        if (input.length > 0) { input = input.slice(0, -1); process.stdout.write('\b \b') }
      } else {
        input += ch
        process.stdout.write('*')
      }
    }
    process.stdin.on('data', handler)
  })
}

// ── Server communication ──────────────────────────────────────────────────────

/**
 * Test auth against a server.
 * Returns:
 *   { ok: true }
 *   { ok: false, reason, notRegistered: true }   — server reachable but key unknown
 *   { ok: false, reason, noOwner: true }          — server has no users yet (owner setup)
 *   { ok: false, reason }                         — connection or other error
 */
async function testServerAuth(serverUrl, authKey, timeoutMs = 5000) {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const challengeRes = await fetch(`${serverUrl}/auth/challenge`, { signal: ctrl.signal })
    if (!challengeRes.ok) {
      clearTimeout(timer)
      return { ok: false, reason: `challenge endpoint returned ${challengeRes.status}` }
    }
    const { challenge } = await challengeRes.json()

    const signature = await signChallenge(authKey, challenge)

    const verifyRes = await fetch(`${serverUrl}/auth/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challenge, signature }),
      signal: ctrl.signal,
    })
    clearTimeout(timer)

    if (verifyRes.ok) return { ok: true }

    const errBody = await verifyRes.json().catch(() => ({}))
    const errMsg = errBody?.error ?? ''

    if (verifyRes.status === 401) {
      if (errMsg.includes('server not configured') || errMsg.includes('register an owner')) {
        return { ok: false, reason: 'Server has no users yet (owner setup needed)', noOwner: true }
      }
      return { ok: false, reason: 'Passphrase not registered on this server', notRegistered: true }
    }
    return { ok: false, reason: `server returned ${verifyRes.status}` }
  } catch (err) {
    clearTimeout(timer)
    if (err.name === 'AbortError') return { ok: false, reason: 'connection timed out' }
    return { ok: false, reason: err.message }
  }
}

/**
 * Register this key with a server.
 * Returns { ok: true } or { ok: false, reason, needsInvite: true }
 */
async function registerWithServer(serverUrl, authKey, { inviteToken, name, password } = {}) {
  const pubKey = pubKeyHex(authKey)
  const body = { pubKey }
  if (inviteToken) body.inviteToken = inviteToken
  if (name)        body.name = name
  if (password)    body.recoveryPassword = password

  try {
    const res = await fetch(`${serverUrl}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    if (res.ok) return { ok: true }
    const errBody = await res.json().catch(() => ({}))
    const errMsg = errBody?.error ?? `server returned ${res.status}`
    if (res.status === 403 && errMsg.includes('invite')) {
      return { ok: false, reason: errMsg, needsInvite: true }
    }
    return { ok: false, reason: errMsg }
  } catch (err) {
    return { ok: false, reason: err.message }
  }
}

// ── Setup wizard ──────────────────────────────────────────────────────────────

async function runSetupWizard(existingConfig) {
  console.log('\n╔══════════════════════════════════════════╗')
  console.log('║   MediaForest Companion Setup            ║')
  console.log('╚══════════════════════════════════════════╝\n')
  console.log('The companion stores your identity key and signs logins automatically.')
  console.log('Your passphrase never leaves this machine.\n')

  if (existingConfig) {
    console.log('Existing config found. This will update it.\n')
  }

  // ── Passphrase ──
  let passphrase
  while (true) {
    passphrase = await readSecret('Passphrase: ')
    if (passphrase.length < 8) {
      console.log('Passphrase must be at least 8 characters. Try again.')
      continue
    }
    const confirm = await readSecret('Confirm passphrase: ')
    if (passphrase !== confirm) {
      console.log('Passphrases do not match. Try again.\n')
      continue
    }
    break
  }

  const authKey = deriveAuthKey(passphrase)
  console.log('\n✓ Key derived.\n')

  // ── Servers ──
  const servers = existingConfig?.servers ?? []
  console.log('Add your MediaForest server URL(s). Leave blank when done.\n')
  if (servers.length > 0) {
    console.log(`Currently configured: ${servers.map(s => s.url).join(', ')}`)
    const keep = await readLine('Keep existing servers? [Y/n]: ')
    if (keep.toLowerCase() === 'n') servers.length = 0
  }

  while (true) {
    const url = await readLine(`Server URL (e.g. https://mymediaforest.example.com): `)
    if (!url) break

    const cleanUrl = url.replace(/\/$/, '')
    process.stdout.write(`  Connecting to ${cleanUrl}... `)
    const result = await testServerAuth(cleanUrl, authKey)

    if (result.ok) {
      console.log('✓ Signed in successfully!')
      const name = await readLine('  Friendly name for this server (optional): ')
      servers.push({ url: cleanUrl, name: name || null, registered: true })
    } else if (result.notRegistered || result.noOwner) {
      console.log(result.noOwner ? '(new server, no accounts yet)' : '(not registered)')
      const reg = await readLine('  Register a new account on this server? [Y/n]: ')
      if (reg.toLowerCase() !== 'n') {
        await runRegistrationFlow(cleanUrl, authKey, servers, result.noOwner)
      } else {
        const add = await readLine('  Add server without registering? [y/N]: ')
        if (add.toLowerCase() === 'y') {
          const name = await readLine('  Friendly name: ')
          servers.push({ url: cleanUrl, name: name || null, registered: false })
        }
      }
    } else {
      console.log(`✗ ${result.reason}`)
      const add = await readLine('  Add it anyway? [y/N]: ')
      if (add.toLowerCase() === 'y') {
        const name = await readLine('  Friendly name: ')
        servers.push({ url: cleanUrl, name: name || null, registered: false })
      }
    }

    const more = await readLine('Add another server? [y/N]: ')
    if (more.toLowerCase() !== 'y') break
  }

  if (servers.length === 0) {
    console.log('\nNo servers configured. Run --setup later to add one.')
  }

  const cfg = { passphrase, servers }
  saveConfig(cfg)
  console.log(`\n✓ Config saved to ${CONFIG_PATH}`)
  console.log('  (chmod 600 — readable only by you)\n')

  return cfg
}

async function runRegistrationFlow(serverUrl, authKey, servers, isOwnerSetup) {
  console.log()
  if (isOwnerSetup) {
    console.log('  This will create the owner (admin) account on the server.')
  } else {
    console.log('  You can register without an invite if the server is in open mode.')
    console.log('  If registration fails, ask the server owner for an invite token.\n')
  }

  const name = await readLine('  Your display name (optional): ')
  const password = await readSecret('  Account password (lets you log in from any device — recommended): ')
  if (password && password.length < 8) {
    console.log('  Password must be at least 8 characters. Skipping password.')
  }
  const validPassword = password && password.length >= 8 ? password : null
  let inviteToken = null

  while (true) {
    process.stdout.write('  Registering...')
    const result = await registerWithServer(serverUrl, authKey, {
      inviteToken: inviteToken || undefined,
      name: name || undefined,
      password: validPassword || undefined,
    })

    if (result.ok) {
      console.log(' ✓ Registered!')
      // Verify auth now works
      process.stdout.write('  Verifying login... ')
      const authResult = await testServerAuth(serverUrl, authKey)
      if (authResult.ok) {
        console.log('✓ Signed in successfully!')
        const srvName = await readLine('  Friendly name for this server (optional): ')
        servers.push({ url: serverUrl, name: srvName || null, registered: true })
      } else {
        console.log(`✗ ${authResult.reason}`)
        console.log('  Registration succeeded but login failed. Check server logs.')
        servers.push({ url: serverUrl, name: null, registered: false })
      }
      return
    } else if (result.needsInvite) {
      console.log(` ✗ ${result.reason}`)
      inviteToken = await readLine('  Enter invite token (or leave blank to skip): ')
      if (!inviteToken) {
        console.log('  Skipping registration for this server.')
        return
      }
    } else {
      console.log(` ✗ ${result.reason}`)
      const retry = await readLine('  Try again? [y/N]: ')
      if (retry.toLowerCase() !== 'y') return
    }
  }
}

// ── Startup self-test ─────────────────────────────────────────────────────────

async function runSelfTests(authKey, servers) {
  if (!servers || servers.length === 0) {
    console.log('[companion] No servers configured — skipping self-test')
    return
  }
  for (const srv of servers) {
    process.stdout.write(`[companion] Testing ${srv.url}... `)
    const result = await testServerAuth(srv.url, authKey, 5000)
    if (result.ok) {
      console.log('✓ OK')
    } else {
      console.log(`✗ ${result.reason}`)
      if (result.notRegistered) {
        console.error('[companion] WARNING: Not registered on this server — run --setup to register')
      } else if (result.noOwner) {
        console.error('[companion] WARNING: Server has no accounts yet — run --setup to register as owner')
      }
    }
  }
}

// ── Daemon control ────────────────────────────────────────────────────────────

function writePid() {
  mkdirSync(CONFIG_DIR, { recursive: true })
  writeFileSync(PID_PATH, String(process.pid))
}

function readPid() {
  if (!existsSync(PID_PATH)) return null
  try { return parseInt(readFileSync(PID_PATH, 'utf8').trim(), 10) } catch { return null }
}

function isRunning(pid) {
  try { process.kill(pid, 0); return true } catch { return false }
}

async function handleStatusCommand() {
  const pid = readPid()
  if (!pid || !isRunning(pid)) {
    console.log('companion: not running')
    process.exit(1)
  }
  console.log(`companion: running (PID ${pid})`)
  process.exit(0)
}

async function handleStopCommand() {
  const pid = readPid()
  if (!pid || !isRunning(pid)) {
    console.log('companion: not running')
    process.exit(0)
  }
  process.kill(pid, 'SIGTERM')
  console.log(`companion: stopped (PID ${pid})`)
  process.exit(0)
}

async function handleDetachCommand(originalArgs) {
  const { spawn } = await import('node:child_process')
  mkdirSync(CONFIG_DIR, { recursive: true })
  const logFd = openSync(LOG_PATH, 'a')
  const child = spawn(
    process.execPath,
    [fileURLToPath(import.meta.url), ...originalArgs.filter(a => a !== '--detach')],
    { detached: true, stdio: ['ignore', logFd, logFd], env: process.env },
  )
  child.unref()
  closeSync(logFd)
  console.log(`[companion] Started in background (PID ${child.pid})`)
  console.log(`[companion] Logs: ${LOG_PATH}`)
  console.log('[companion] Run with --status to confirm, --stop to stop.')
  process.exit(0)
}

// ── HTTP server ───────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PV_AGENT_PORT ?? '8765', 10)
const HOST = process.env.PV_AGENT_BIND ?? '127.0.0.1'

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Private-Network': 'true',
}

function sendJson(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...CORS_HEADERS })
  res.end(JSON.stringify(body))
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

function startHttpServer(authKey, config) {
  const httpServer = createServer(async (req, res) => {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, CORS_HEADERS); res.end(); return
    }

    if (req.method === 'GET' && req.url === '/health') {
      sendJson(res, 200, {
        ok: true,
        version: '2',
        servers: (config.servers ?? []).map(s => ({ url: s.url, name: s.name, registered: s.registered })),
      })
      return
    }

    if (req.method === 'GET' && req.url === '/pubkey') {
      sendJson(res, 200, { pubKey: pubKeyHex(authKey) })
      return
    }

    if (req.method === 'POST' && req.url === '/sign') {
      let body
      try { body = await readBody(req) }
      catch { sendJson(res, 400, { error: 'invalid body' }); return }

      if (!body?.challenge || typeof body.challenge !== 'string') {
        sendJson(res, 400, { error: 'challenge required' }); return
      }
      try {
        const signature = await signChallenge(authKey, body.challenge)
        sendJson(res, 200, { signature })
      } catch (err) {
        console.error('[companion] sign error:', err)
        sendJson(res, 500, { error: 'signing failed' })
      }
      return
    }

    sendJson(res, 404, { error: 'not found' })
  })

  httpServer.listen(PORT, HOST, () => {
    const serverList = (config.servers ?? []).map(s => s.url).join(', ') || '(none)'
    console.log(`[companion] Listening on ${HOST}:${PORT}`)
    console.log(`[companion] Servers: ${serverList}`)
  })

  httpServer.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`[companion] Port ${PORT} in use — already running? Try --status`)
    } else {
      console.error('[companion] Server error:', err)
    }
    process.exit(1)
  })

  process.on('SIGTERM', () => { httpServer.close(); process.exit(0) })
  process.on('SIGINT',  () => { httpServer.close(); process.exit(0) })
}

// ── Main ──────────────────────────────────────────────────────────────────────

const args = process.argv.slice(2)

if (args.includes('--status')) { await handleStatusCommand() }
if (args.includes('--stop'))   { await handleStopCommand() }
if (args.includes('--detach')) { await handleDetachCommand(args) }

const forceSetup = args.includes('--setup')
let config = loadConfig()

if (!config || forceSetup) {
  config = await runSetupWizard(config)
} else {
  console.log(`\nConfig:  ${CONFIG_PATH}`)
  const serverList = (config.servers ?? []).map(s => s.name ? `${s.name} (${s.url})` : s.url).join('\n         ') || '(none configured)'
  console.log(`Servers: ${serverList}`)
}

if (!config?.passphrase) {
  console.error('[companion] No passphrase in config. Run again to set it up.')
  process.exit(1)
}

const existingPid = readPid()
if (existingPid && isRunning(existingPid)) {
  console.log(`\n[companion] Already running (PID ${existingPid}) — nothing to do.`)
  console.log(`[companion] Use --stop to stop it, --setup to reconfigure.`)
  process.exit(0)
}

const authKey = deriveAuthKey(config.passphrase)
const runConfig = { ...config, passphrase: undefined }

if (process.stdin.isTTY) {
  const answer = await readLine('\nStart agent in background? [Y/n]: ')
  if (answer.toLowerCase() !== 'n') {
    await handleDetachCommand(args.filter(a => a !== '--setup'))
  }
  console.log('[companion] Starting in foreground. Ctrl+C to stop.')
}

console.log('[companion] Key derived. Passphrase reference released.')
await runSelfTests(authKey, runConfig.servers)
writePid()
startHttpServer(authKey, runConfig)
