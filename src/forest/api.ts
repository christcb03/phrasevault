import { createReadStream, existsSync } from 'node:fs'
import { extname } from 'node:path'
import path from 'node:path'
import { scanVideoFilesAsync } from './scan.js'
import { scoreCandidates } from './matcher.js'
import { randomUUID } from 'node:crypto'
import type { FastifyInstance } from 'fastify'
import type { ForestDB } from './db.js'
import type { ForestWalker } from './walker.js'
import type { PVFSVerifier } from './pvfs.js'
import type { Pruner } from './pruner.js'
import { createNode, createLink } from './signer.js'
import { defaultVisibility, serializePayload, deserializePayload } from './cipher.js'
import type { NewNode, NewLink, TruthNode, PvfsFilePayload, PvfsLocationPayload, MediaMoviePayload, MediaSeriesPayload, MediaSeasonPayload } from './types.js'
import type { Visibility } from './cipher.js'

export function registerForestRoutes(
  app: FastifyInstance,
  db: ForestDB,
  walker: ForestWalker,
  pvfs: PVFSVerifier,
  pruner: Pruner,
  authorPubKey: string,
  privKeyHex: string,
  encKey: Uint8Array,
  pvfsStoreDir: string,
  getTmdbToken?: () => string,
): void {

  const TMDB_BASE = 'https://api.themoviedb.org/3'
  function tmdbHeaders(token: string) {
    return { Authorization: `Bearer ${token}`, Accept: 'application/json' }
  }

  // Decrypt a node's payload in API responses. Returns plaintext payload for owner.
  function decryptNode(node: TruthNode): TruthNode {
    if (node.visibility === 'public') return node
    const payload = deserializePayload(node.payload as string, node.visibility as Visibility, encKey)
    return { ...node, payload }
  }

  // Resolve (decrypt if needed) a node's payload to a typed object.
  function resolvePayload<T>(node: TruthNode): T {
    if (node.visibility === 'public') return node.payload as T
    return deserializePayload(node.payload as string, node.visibility as Visibility, encKey) as T
  }

  // Create a node with correct visibility and encrypted payload.
  async function makeNode(
    type: TruthNode['type'],
    label: string,
    rawPayload: unknown,
    now: number,
  ): Promise<TruthNode> {
    const vis = defaultVisibility(type)
    const payload = serializePayload(rawPayload, vis, vis === 'public' ? null : encKey)
    return createNode({ type, label, visibility: vis, payload, created_at: now, author: authorPubKey }, privKeyHex)
  }

  // ─── Forest ────────────────────────────────────────────────────────────────

  app.get('/forest/roots', async (_req, reply) => {
    return reply.send(walker.roots())
  })

  app.get<{ Params: { nodeId: string }; Querystring: { depth?: string } }>(
    '/forest/walk/:nodeId',
    async (req, reply) => {
      const depth = req.query.depth ? parseInt(req.query.depth, 10) : Infinity
      const result = walker.walk(req.params.nodeId, depth)
      if (!result) return reply.status(404).send({ error: 'node not found' })
      return reply.send(result)
    },
  )

  app.get<{ Params: { nodeId: string } }>(
    '/forest/node/:nodeId',
    async (req, reply) => {
      const node = db.getNode(req.params.nodeId)
      if (!node) return reply.status(404).send({ error: 'node not found' })
      return reply.send(decryptNode(node))
    },
  )

  app.post<{ Body: Omit<NewNode, 'author' | 'visibility'> & { visibility?: Visibility } }>(
    '/forest/node',
    async (req, reply) => {
      const vis: Visibility = req.body.visibility ?? defaultVisibility(req.body.type)
      const payload = serializePayload(req.body.payload, vis, vis === 'public' ? null : encKey)
      const input: NewNode = { ...req.body, author: authorPubKey, visibility: vis, payload }
      const node = await createNode(input, privKeyHex)
      db.insertNode(node)
      return reply.status(201).send(decryptNode(node))
    },
  )

  app.post<{ Body: Omit<NewLink, 'author'> }>(
    '/forest/link',
    async (req, reply) => {
      const input: NewLink = { ...req.body, author: authorPubKey }
      const link = await createLink(input, privKeyHex)
      db.insertLink(link)
      return reply.status(201).send(link)
    },
  )

  app.delete<{ Params: { linkId: string }; Body: { removal_sig?: string } }>(
    '/forest/link/:linkId',
    async (req, reply) => {
      const link = db.getLink(req.params.linkId)
      if (!link) return reply.status(404).send({ error: 'link not found' })
      db.softRemoveLink(req.params.linkId, authorPubKey, req.body.removal_sig ?? '')
      return reply.send({ removed: true })
    },
  )

  app.get<{ Params: { nodeId: string } }>(
    '/forest/verify/:nodeId',
    async (req, reply) => {
      return reply.send(walker.verify(req.params.nodeId))
    },
  )

  app.get('/forest/orphans', async (_req, reply) => {
    return reply.send(walker.orphans())
  })

  // ─── Config ────────────────────────────────────────────────────────────────

  // Walk the configuration tree.
  app.get('/config', async (_req, reply) => {
    const configRoot = db.getNodesByType('tree.root').find(n => n.label === 'Configuration')
      ?? db.getNodesByType('forest.root')[0]
    if (!configRoot) return reply.send({ sections: [] })
    return reply.send(walker.walk(configRoot.id))
  })

  // Set a config value (creates config.value node and links it under the section).
  // Supersedes any existing node for the same key under the same section.
  app.put<{
    Params: { section: string; key: string }
    Body: { value: string | number | boolean | null; score_method?: string }
  }>(
    '/config/:section/:key',
    async (req, reply) => {
      const now = Date.now()
      const { section, key } = req.params

      // Ensure section node exists.
      let sectionNode = db.getNodesByType('config.section').find(n => n.label === section)
      if (!sectionNode) {
        sectionNode = await makeNode('config.section', section, {}, now)
        db.insertNode(sectionNode)

        // Link section under config root.
        const configRoot = db.getNodesByType('tree.root').find(n => n.label === 'Configuration')
        if (configRoot) {
          db.insertLink(await createLink({
            parent_id: configRoot.id, child_id: sectionNode.id,
            link_type: 'branch', truth_score: 1.0, sort_key: section,
            score_method: null, created_at: now, author: authorPubKey,
          }, privKeyHex))
        }
      }

      // Create new config.value node (private).
      const valueNode = await makeNode('config.value', key, { key, value: req.body.value }, now)
      db.insertNode(valueNode)

      // Find and supersede any existing link for this key under this section.
      const existing = walker.children(sectionNode.id, 'branch')
        .find(c => c.node.type === 'config.value' && resolvePayload<{ key: string }>(c.node).key === key)

      const newLink = await createLink({
        parent_id: sectionNode.id, child_id: valueNode.id,
        link_type: 'branch', truth_score: 1.0, sort_key: key,
        score_method: req.body.score_method ?? null,
        created_at: now, author: authorPubKey,
      }, privKeyHex)
      db.insertLink(newLink)

      if (existing) {
        db.softRemoveLink(existing.link.id, authorPubKey, '')
        db.supersedeLink(existing.link.id, newLink.id)
      }

      return reply.send(decryptNode(valueNode))
    },
  )

  app.delete<{ Params: { section: string; key: string } }>(
    '/config/:section/:key',
    async (req, reply) => {
      const sectionNode = db.getNodesByType('config.section').find(n => n.label === req.params.section)
      if (!sectionNode) return reply.status(404).send({ error: 'section not found' })

      const existing = walker.children(sectionNode.id, 'branch')
        .find(c => c.node.type === 'config.value' && (c.node.payload as { key: string }).key === req.params.key)
      if (!existing) return reply.status(404).send({ error: 'key not found' })

      db.softRemoveLink(existing.link.id, authorPubKey, '')
      return reply.send({ removed: true })
    },
  )

  // ─── PVFS ──────────────────────────────────────────────────────────────────

  app.get<{ Params: { nodeId: string } }>(
    '/pvfs/file/:nodeId',
    async (req, reply) => {
      const node = db.getNode(req.params.nodeId)
      if (!node || node.type !== 'pvfs.file') return reply.status(404).send({ error: 'file node not found' })
      const locations = walker.children(req.params.nodeId, 'member')
        .filter(c => c.node.type === 'pvfs.location')
      const streamUrl = `${req.protocol}://${req.hostname}/pvfs/file/${req.params.nodeId}/stream`
      return reply.send({ node, locations: locations.map(l => l.node), stream_url: streamUrl })
    },
  )

  app.get<{ Params: { nodeId: string } }>(
    '/pvfs/file/:nodeId/stream',
    async (req, reply) => {
      const node = db.getNode(req.params.nodeId)
      if (!node || node.type !== 'pvfs.file') return reply.status(404).send({ error: 'file node not found' })

      const payload = node.payload as PvfsFilePayload

      // Resolve the best local file path from pvfs.location nodes.
      // Supports: file:///path (NAS pointer) and pvfs-local:<hash> (copied to store).
      const locations = walker.children(req.params.nodeId, 'member')
        .filter(c => c.node.type === 'pvfs.location')
      const locPayload = locations.map(l => l.node.payload as import('./types.js').PvfsLocationPayload)
        .find(p => p.type === 'local')

      let filePath: string | null = null
      if (locPayload) {
        if (locPayload.uri.startsWith('file://')) {
          filePath = locPayload.uri.slice('file://'.length)
        } else if (locPayload.uri.startsWith('pvfs-local:')) {
          filePath = path.join(pvfsStoreDir, locPayload.uri.slice('pvfs-local:'.length))
        }
      }
      if (!filePath || !existsSync(filePath)) return reply.status(404).send({ error: 'file not found at stored location' })

      const mimeType = payload.mime_type || 'application/octet-stream'
      const totalSize = payload.size_bytes
      const rangeHeader = req.headers['range'] as string | undefined

      reply.header('Accept-Ranges', 'bytes')
      reply.header('Content-Type', mimeType)

      if (rangeHeader) {
        const match = rangeHeader.match(/^bytes=(\d+)-(\d*)$/)
        if (!match) return reply.status(416).send({ error: 'invalid range' })

        const start = parseInt(match[1], 10)
        const end = match[2] ? parseInt(match[2], 10) : totalSize - 1

        if (start >= totalSize || end >= totalSize || start > end) {
          reply.header('Content-Range', `bytes */${totalSize}`)
          return reply.status(416).send({ error: 'range not satisfiable' })
        }

        reply.status(206)
        reply.header('Content-Range', `bytes ${start}-${end}/${totalSize}`)
        reply.header('Content-Length', end - start + 1)
        return reply.send(createReadStream(filePath, { start, end }))
      }

      reply.header('Content-Length', totalSize)
      return reply.send(createReadStream(filePath))
    },
  )

  app.post<{
    Body: { path: string; media_node_id?: string; mime_type?: string; label?: string }
  }>(
    '/pvfs/ingest',
    async (req, reply) => {
      const { path: localPath, media_node_id, mime_type, label } = req.body
      if (!localPath) return reply.status(400).send({ error: 'path is required' })
      if (!existsSync(localPath)) return reply.status(400).send({ error: `file not found: ${localPath}` })

      try {
        const result = await pvfs.ingest(localPath, { mediaNodeId: media_node_id, mimeType: mime_type, label })
        const streamUrl = `${req.protocol}://${req.hostname}/pvfs/file/${result.fileNode.id}/stream`
        return reply.status(201).send({
          fileNodeId: result.fileNode.id,
          contentHash: result.contentHash,
          streamUrl,
        })
      } catch (err) {
        return reply.status(500).send({ error: err instanceof Error ? err.message : 'ingest failed' })
      }
    },
  )

  app.get<{ Params: { nodeId: string }; Querystring: { uri: string } }>(
    '/pvfs/file/:nodeId/verify',
    async (req, reply) => {
      const result = await pvfs.verify(req.params.nodeId, req.query.uri)
      if (!result.passed && result.actual_hash) {
        const locationNode = db.getNodesByType('pvfs.location')
          .find(n => (n.payload as { uri: string }).uri === req.query.uri)
        await pvfs.recordFailure(
          req.params.nodeId,
          locationNode?.id ?? '',
          result.expected_hash,
          result.actual_hash,
        )
      }
      return reply.send(result)
    },
  )

  app.post<{ Body: Omit<NewNode, 'author' | 'type'> & { payload: import('./types.js').PvfsFilePayload } }>(
    '/pvfs/file',
    async (req, reply) => {
      const node = await makeNode('pvfs.file', req.body.label, req.body.payload, Date.now())
      db.insertNode(node)
      return reply.status(201).send(node)
    },
  )

  app.post<{
    Params: { nodeId: string }
    Body: { payload: import('./types.js').PvfsLocationPayload; sort_key?: string }
  }>(
    '/pvfs/file/:nodeId/location',
    async (req, reply) => {
      const fileNode = db.getNode(req.params.nodeId)
      if (!fileNode) return reply.status(404).send({ error: 'file node not found' })

      const now = Date.now()
      const locNode = await makeNode(
        'pvfs.location',
        req.body.payload.uri,
        { ...req.body.payload, last_verified: null, last_seen: now },
        now,
      )
      db.insertNode(locNode)

      const link = await createLink({
        parent_id: fileNode.id, child_id: locNode.id,
        link_type: 'member', truth_score: 1.0,
        sort_key: req.body.sort_key ?? null, score_method: null,
        created_at: now, author: authorPubKey,
      }, privKeyHex)
      db.insertLink(link)

      return reply.status(201).send({ node: locNode, link })
    },
  )

  // Build a Set of all file:// URIs already indexed in pvfs.location nodes.
  function buildIngestedUriSet(): Set<string> {
    const uriSet = new Set<string>()
    for (const node of db.getNodesByType('pvfs.location')) {
      const payload = node.payload as PvfsLocationPayload
      if (payload?.uri) uriSet.add(payload.uri)
    }
    return uriSet
  }

  // Background scan jobs — keyed by UUID, cleaned up after 2h
  interface ScanJob {
    status: 'running' | 'done' | 'error'
    startedAt: number
    dry_run: boolean
    found: number
    new_count?: number
    already_ingested_count?: number
    files: unknown[]
    ingested?: number
    failed?: number
    failures?: Array<{ path: string; error: string }>
    error?: string
  }
  const scanJobs = new Map<string, ScanJob>()

  function cleanOldJobs() {
    const cutoff = Date.now() - 2 * 60 * 60 * 1000
    for (const [id, job] of scanJobs) {
      if (job.startedAt < cutoff && job.status !== 'running') scanJobs.delete(id)
    }
  }

  app.post<{
    Body: { path: string; dry_run?: boolean; extensions?: string[]; limit?: number }
  }>(
    '/pvfs/scan',
    async (req, reply) => {
      const { path: dirPath, dry_run = true, extensions, limit } = req.body
      if (!dirPath) return reply.status(400).send({ error: 'path is required' })
      if (!existsSync(dirPath)) return reply.status(400).send({ error: `directory not found: ${dirPath}` })

      cleanOldJobs()
      const jobId = randomUUID()
      const job: ScanJob = { status: 'running', startedAt: Date.now(), dry_run, found: 0, files: [] }
      scanJobs.set(jobId, job)

      const extSet = extensions
        ? new Set(extensions.map(e => e.startsWith('.') ? e.toLowerCase() : '.' + e.toLowerCase()))
        : undefined

      const baseUrl = `${req.protocol}://${req.hostname}`

      // Run async — returns job ID immediately so the HTTP request doesn't time out
      ;(async () => {
        try {
          const ingestedUris = buildIngestedUriSet()

          if (dry_run) {
            // Stream files into job.files as they're discovered so the client
            // can start matching before the scan is finished.
            let fileCount = 0
            await scanVideoFilesAsync(dirPath, extSet, undefined, (file) => {
              if (limit && fileCount >= limit) return
              file.already_ingested = ingestedUris.has(`file://${file.path}`)
              ;(job.files as import('./scan.js').ScannedFile[]).push(file)
              fileCount++
              job.found = fileCount
              job.new_count = (job.files as import('./scan.js').ScannedFile[]).filter(f => !f.already_ingested).length
              job.already_ingested_count = fileCount - (job.new_count ?? 0)
            })
            job.status = 'done'
            return
          }

          // Live ingest: collect all first, then process new-only.
          const files = await scanVideoFilesAsync(dirPath, extSet, n => { job.found = n })
          const batch = limit ? files.slice(0, limit) : files
          job.found = batch.length

          for (const file of batch) {
            file.already_ingested = ingestedUris.has(`file://${file.path}`)
          }
          const newFiles = batch.filter(f => !f.already_ingested)
          job.new_count = newFiles.length
          job.already_ingested_count = batch.length - newFiles.length

          const ingested: Array<{ path: string; fileNodeId: string; contentHash: string; streamUrl: string }> = []
          const failures: Array<{ path: string; error: string }> = []

          for (const file of newFiles) {
            try {
              const result = await pvfs.ingest(file.path, { label: file.parsed.title || path.basename(file.path) })
              const streamUrl = `${baseUrl}/pvfs/file/${result.fileNode.id}/stream`
              ingested.push({ path: file.path, fileNodeId: result.fileNode.id, contentHash: result.contentHash, streamUrl })
            } catch (err) {
              failures.push({ path: file.path, error: err instanceof Error ? err.message : 'ingest failed' })
            }
            job.found = ingested.length + failures.length
          }

          job.files = ingested
          job.ingested = ingested.length
          job.failed = failures.length
          job.failures = failures
          job.status = 'done'
        } catch (err) {
          job.error = err instanceof Error ? err.message : 'scan failed'
          job.status = 'error'
        }
      })()

      return reply.status(202).send({ jobId })
    },
  )

  app.get<{ Params: { jobId: string } }>(
    '/pvfs/scan/job/:jobId',
    async (req, reply) => {
      const job = scanJobs.get(req.params.jobId)
      if (!job) return reply.status(404).send({ error: 'job not found' })
      return reply.send(job)
    },
  )

  app.post<{
    Params: { nodeId: string }
    Body: { content_hash: string; size_bytes: number; mime_type: string; original_filename?: string }
  }>(
    '/pvfs/file/:nodeId/replace',
    async (req, reply) => {
      const newNode = await pvfs.acceptReplacement(
        req.params.nodeId,
        req.body.content_hash,
        req.body.size_bytes,
        req.body.mime_type,
        req.body.original_filename ?? null,
      )
      return reply.send(newNode)
    },
  )

  // ─── Provider management ───────────────────────────────────────────────────

  // List all providers with their current config.
  app.get('/config/providers', async (_req, reply) => {
    const configRoot = db.getNodesByType('tree.root').find(n => n.label === 'Configuration')
      ?? db.getNodesByType('forest.root')[0]
    if (!configRoot) return reply.send([])

    const sections = walker.children(configRoot.id, 'branch')
    const providerSection = sections.find(c => c.node.label === 'Metadata Providers')
    if (!providerSection) return reply.send([])

    const providers = walker.children(providerSection.node.id, 'branch')
      .filter(c => c.node.type === 'config.provider')
      .map(c => {
        const pp = resolvePayload<{ provider_id: string; name: string; enabled: boolean }>(c.node)
        const configVals: Record<string, unknown> = {}
        for (const val of walker.children(c.node.id, 'branch')) {
          const vp = resolvePayload<{ key?: string; value?: unknown }>(val.node)
          if (vp?.key) configVals[vp.key as string] = vp.value
        }
        return { node_id: c.node.id, provider_id: pp.provider_id, name: pp.name, enabled: pp.enabled, config: configVals }
      })
    return reply.send(providers)
  })

  // Upsert a provider's config (read_access_token, enabled). Creates the provider node if needed.
  app.put<{
    Params: { providerId: string }
    Body: { read_access_token?: string; api_key?: string; enabled?: boolean; name?: string }
  }>(
    '/config/providers/:providerId',
    async (req, reply) => {
      const now = Date.now()
      const { providerId } = req.params

      const configRoot = db.getNodesByType('tree.root').find(n => n.label === 'Configuration')
      if (!configRoot) return reply.status(503).send({ error: 'forest not bootstrapped' })

      const sections = walker.children(configRoot.id, 'branch')
      const providerSection = sections.find(c => c.node.label === 'Metadata Providers')
      if (!providerSection) return reply.status(503).send({ error: 'providers section not found' })

      // Find or create the provider node.
      let providerEntry = walker.children(providerSection.node.id, 'branch')
        .find(c => c.node.type === 'config.provider' &&
          resolvePayload<{ provider_id: string }>(c.node).provider_id === providerId)

      const enabled = req.body.enabled ?? (providerEntry
        ? resolvePayload<{ enabled: boolean }>(providerEntry.node).enabled
        : false)
      const name = req.body.name ?? (providerEntry
        ? resolvePayload<{ name: string }>(providerEntry.node).name
        : providerId.toUpperCase())

      if (!providerEntry) {
        // Create provider node and link it under Metadata Providers.
        const provNode = await makeNode('config.provider', name, { provider_id: providerId, name, enabled }, now)
        db.insertNode(provNode)
        db.insertLink(await createLink({
          parent_id: providerSection.node.id, child_id: provNode.id,
          link_type: 'branch', truth_score: 1.0, sort_key: providerId,
          score_method: null, created_at: now, author: authorPubKey,
        }, privKeyHex))
        // Re-fetch so we can add children below.
        providerEntry = walker.children(providerSection.node.id, 'branch')
          .find(c => resolvePayload<{ provider_id: string }>(c.node).provider_id === providerId)!
      } else if (enabled !== resolvePayload<{ enabled: boolean }>(providerEntry.node).enabled) {
        // Provider node is immutable — create a new one superseding the old.
        const newProvNode = await makeNode('config.provider', name, { provider_id: providerId, name, enabled }, now)
        db.insertNode(newProvNode)
        const newProvLink = await createLink({
          parent_id: providerSection.node.id, child_id: newProvNode.id,
          link_type: 'branch', truth_score: 1.0, sort_key: providerId,
          score_method: null, created_at: now, author: authorPubKey,
        }, privKeyHex)
        db.insertLink(newProvLink)
        db.softRemoveLink(providerEntry.link.id, authorPubKey, '')
        db.supersedeLink(providerEntry.link.id, newProvLink.id)
        providerEntry = walker.children(providerSection.node.id, 'branch')
          .find(c => resolvePayload<{ provider_id: string }>(c.node).provider_id === providerId)!
      }

      if (!providerEntry) return reply.status(500).send({ error: 'provider entry not found after upsert' })

      // Upsert read_access_token config.value if provided (also accepts legacy api_key field).
      const tokenValue = req.body.read_access_token ?? req.body.api_key
      if (tokenValue !== undefined) {
        const existingKey = walker.children(providerEntry.node.id, 'branch')
          .find(c => c.node.type === 'config.value' &&
            ['read_access_token', 'api_key'].includes(resolvePayload<{ key: string }>(c.node).key as string))

        const keyNode = await makeNode('config.value', 'read_access_token', { key: 'read_access_token', value: tokenValue }, now)
        db.insertNode(keyNode)
        const keyLink = await createLink({
          parent_id: providerEntry.node.id, child_id: keyNode.id,
          link_type: 'branch', truth_score: 1.0, sort_key: 'read_access_token',
          score_method: null, created_at: now, author: authorPubKey,
        }, privKeyHex)
        db.insertLink(keyLink)
        if (existingKey) {
          db.softRemoveLink(existingKey.link.id, authorPubKey, '')
          db.supersedeLink(existingKey.link.id, keyLink.id)
        }
      }

      return reply.send({ provider_id: providerId, enabled, updated: true })
    },
  )

  // ─── Local artwork proxy ───────────────────────────────────────────────────

  const ALLOWED_IMAGE_EXTS = new Set(['.jpg', '.jpeg', '.png', '.webp'])

  app.get<{ Querystring: { path: string } }>(
    '/pvfs/artwork',
    async (req, reply) => {
      const filePath = req.query.path
      if (!filePath) return reply.status(400).send({ error: 'path is required' })
      const ext = extname(filePath).toLowerCase()
      if (!ALLOWED_IMAGE_EXTS.has(ext)) return reply.status(400).send({ error: 'not an image path' })
      if (!existsSync(filePath)) return reply.status(404).send({ error: 'not found' })
      const mimeMap: Record<string, string> = {
        '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
        '.png': 'image/png', '.webp': 'image/webp',
      }
      reply.header('Content-Type', mimeMap[ext] ?? 'image/jpeg')
      reply.header('Cache-Control', 'public, max-age=86400')
      return reply.send(createReadStream(filePath))
    },
  )

  // ─── Media match (batch TMDB search with confidence scoring) ──────────────

  interface MatchQuery {
    title: string
    year: number | null
    kind: 'movie' | 'series' | 'unknown'
  }

  app.post<{
    Body: { items: MatchQuery[]; threshold?: number }
  }>(
    '/media/match/search',
    async (req, reply) => {
      const token = getTmdbToken?.()
      if (!token) return reply.status(503).send({ error: 'TMDB not configured' })

      const { items, threshold = 0.8 } = req.body
      if (!Array.isArray(items) || items.length === 0) {
        return reply.status(400).send({ error: 'items array is required' })
      }

      const results = []
      for (const item of items) {
        try {
          const mediaType = item.kind === 'movie' ? 'movie' : item.kind === 'series' ? 'tv' : 'multi'
          const endpoint = mediaType === 'multi'
            ? `${TMDB_BASE}/search/multi?query=${encodeURIComponent(item.title)}&include_adult=false`
            : `${TMDB_BASE}/search/${mediaType}?query=${encodeURIComponent(item.title)}&include_adult=false`
          const res = await fetch(endpoint, { headers: tmdbHeaders(token) })
          const data = await res.json() as { results?: Record<string, unknown>[] }

          const raw = (data.results ?? [])
            .filter(r => r.media_type === 'movie' || r.media_type === 'tv' || mediaType !== 'multi')
            .slice(0, 10)
            .map(r => {
              const isTv = mediaType === 'tv' || r.media_type === 'tv'
              return {
                tmdb_id: String(r.id),
                media_type: (isTv ? 'tv' : 'movie') as 'movie' | 'tv',
                title: (isTv ? r.name : r.title) as string ?? '',
                year: ((isTv ? r.first_air_date : r.release_date) as string ?? '').slice(0, 4),
                poster_path: (r.poster_path as string | null) ?? null,
                overview: (r.overview as string | null) ?? null,
              }
            })

          results.push(scoreCandidates(item, raw, threshold))
        } catch {
          results.push({
            query: item,
            candidates: [],
            best: null,
            needs_review: true,
          })
        }
        // ~10 req/sec to stay well under TMDB's 50/sec limit
        await new Promise(r => setTimeout(r, 100))
      }

      return reply.send({ results, threshold })
    },
  )

  // ─── Media import (batch: match + ingest atomically) ──────────────────────

  interface TmdbMatchSource {
    source: 'tmdb'
    tmdb_id: string
    media_type: 'movie' | 'tv'
    title: string
    year: string
    poster_path: string | null
    overview: string | null
  }
  interface ManualMatchSource {
    source: 'manual'
    title: string
    year: number | null
    kind: 'movie' | 'series'
  }
  interface ImportItem {
    kind: 'movie' | 'series'
    files: import('./scan.js').ScannedFile[]
    selected_seasons?: number[] | null
    match: TmdbMatchSource | ManualMatchSource
  }

  app.post<{ Body: { items: ImportItem[] } }>(
    '/media/import/batch',
    async (req, reply) => {
      const token = getTmdbToken?.()
      const { items } = req.body
      if (!Array.isArray(items) || items.length === 0) {
        return reply.status(400).send({ error: 'items array is required' })
      }

      const imported: Array<{ mediaNodeId: string; title: string; fileCount: number }> = []
      const failures: Array<{ title: string; error: string }> = []
      const now = Date.now()

      for (const item of items) {
        try {
          const { match, files, kind, selected_seasons } = item

          // ── Fetch TMDB details (genres, imdb_id) if needed ──────────────
          let tmdbDetails: Record<string, unknown> | null = null
          if (match.source === 'tmdb' && token) {
            try {
              const segment = match.media_type === 'tv' ? 'tv' : 'movie'
              const res = await fetch(
                `${TMDB_BASE}/${segment}/${match.tmdb_id}?append_to_response=external_ids`,
                { headers: tmdbHeaders(token) },
              )
              tmdbDetails = await res.json() as Record<string, unknown>
              await new Promise(r => setTimeout(r, 100))
            } catch { /* proceed without full details */ }
          }

          const matchTitle = match.title
          const matchYear = match.source === 'tmdb'
            ? (parseInt(match.year, 10) || null)
            : match.year
          const tmdbId = match.source === 'tmdb' ? match.tmdb_id : null
          const genres = (tmdbDetails?.genres as { name: string }[] | undefined)?.map(g => g.name) ?? []
          const imdbId = (tmdbDetails?.imdb_id ?? (tmdbDetails?.external_ids as Record<string,unknown>)?.imdb_id ?? null) as string | null
          const overview = match.source === 'tmdb' ? match.overview : null

          if (kind === 'movie') {
            // ── Check if media.movie with this tmdb_id already exists ──────
            let mediaNode: TruthNode | undefined
            if (tmdbId) {
              mediaNode = db.getNodesByType('media.movie').find(n => {
                const p = n.payload as MediaMoviePayload
                return p.tmdb_id === tmdbId
              })
            }
            if (!mediaNode) {
              const payload: MediaMoviePayload = {
                title: matchTitle, year: matchYear, genres,
                imdb_id: imdbId, tmdb_id: tmdbId, overview: overview ?? null,
              }
              mediaNode = await createNode({
                type: 'media.movie', label: matchTitle, visibility: 'public',
                payload, created_at: now, author: authorPubKey,
              }, privKeyHex)
              db.insertNode(mediaNode)
            }

            // Link pvfs.file nodes under the movie
            let fileCount = 0
            for (const file of files) {
              const { fileNode } = await pvfs.ingest(file.path, {
                mediaNodeId: mediaNode!.id,
                label: file.parsed.title || path.basename(file.path),
              })
              fileCount++
              app.log.info(`imported movie file: ${file.path} → ${fileNode.id}`)
            }
            imported.push({ mediaNodeId: mediaNode!.id, title: matchTitle, fileCount })

          } else {
            // ── Series ────────────────────────────────────────────────────
            let seriesNode: TruthNode | undefined
            if (tmdbId) {
              seriesNode = db.getNodesByType('media.series').find(n => {
                const p = n.payload as MediaSeriesPayload
                return p.tmdb_id === tmdbId
              })
            }
            if (!seriesNode) {
              const payload: MediaSeriesPayload = {
                title: matchTitle, year: matchYear, genres,
                imdb_id: imdbId, tmdb_id: tmdbId, overview: overview ?? null,
                status: (tmdbDetails?.status as string | null) ?? null,
              }
              seriesNode = await createNode({
                type: 'media.series', label: matchTitle, visibility: 'public',
                payload, created_at: now, author: authorPubKey,
              }, privKeyHex)
              db.insertNode(seriesNode)
            }

            // Group files by season
            const byseason = new Map<number, typeof files>()
            for (const file of files) {
              const sn = file.parsed.season ?? 0
              if (!byseason.has(sn)) byseason.set(sn, [])
              byseason.get(sn)!.push(file)
            }

            let fileCount = 0
            for (const [seasonNum, episodeFiles] of byseason) {
              // Skip seasons not in the selection (null = all)
              if (selected_seasons && !selected_seasons.includes(seasonNum)) continue

              // Find or create the season node
              const existingSeasons = walker.children(seriesNode!.id, 'member')
                .filter(c => c.node.type === 'media.season')
              let seasonNode = existingSeasons.find(c => {
                const p = c.node.payload as MediaSeasonPayload
                return p.season_number === seasonNum
              })?.node

              if (!seasonNode) {
                const seasonPayload: MediaSeasonPayload = {
                  season_number: seasonNum,
                  title: seasonNum === 0 ? 'Specials' : `Season ${seasonNum}`,
                  year: null,
                  episode_count: episodeFiles.length,
                }
                seasonNode = await createNode({
                  type: 'media.season',
                  label: seasonNum === 0 ? `${matchTitle} - Specials` : `${matchTitle} - Season ${seasonNum}`,
                  visibility: 'public',
                  payload: seasonPayload,
                  created_at: now, author: authorPubKey,
                }, privKeyHex)
                db.insertNode(seasonNode)
                db.insertLink(await createLink({
                  parent_id: seriesNode!.id, child_id: seasonNode.id,
                  link_type: 'member', truth_score: 1.0,
                  sort_key: String(seasonNum).padStart(4, '0'),
                  score_method: null, created_at: now, author: authorPubKey,
                }, privKeyHex))
              }

              for (const file of episodeFiles) {
                const epLabel = file.parsed.episode != null
                  ? `S${String(seasonNum).padStart(2,'0')}E${String(file.parsed.episode).padStart(2,'0')}`
                  : path.basename(file.path)
                const { fileNode } = await pvfs.ingest(file.path, {
                  mediaNodeId: seasonNode!.id,
                  label: epLabel,
                })
                fileCount++
                app.log.info(`imported episode: ${file.path} → ${fileNode.id}`)
              }
            }

            imported.push({ mediaNodeId: seriesNode!.id, title: matchTitle, fileCount })
          }
        } catch (err) {
          failures.push({
            title: item.match.title,
            error: err instanceof Error ? err.message : 'import failed',
          })
        }
      }

      return reply.send({
        imported: imported.length,
        failed: failures.length,
        results: imported,
        failures,
      })
    },
  )

  // ─── Unmatched media (ingested pvfs.file nodes not linked to any media node) ─

  app.get('/media/unmatched', async (_req, reply) => {
    const allFileNodes = db.getNodesByType('pvfs.file')
    const unmatched = allFileNodes.filter(n => {
      const parentLinks = db.getParentLinks(n.id)
      return !parentLinks.some(l => {
        if (l.removed_at || l.link_type !== 'file') return false
        const parent = db.getNode(l.parent_id ?? '')
        return parent?.type === 'media.movie' || parent?.type === 'media.series' || parent?.type === 'media.season'
      })
    })
    return reply.send({ count: unmatched.length, nodes: unmatched })
  })

  // ─── Prune ─────────────────────────────────────────────────────────────────

  app.get('/forest/prune/preview', async (_req, reply) => {
    return reply.send(pruner.preview())
  })

  app.post('/forest/prune', async (_req, reply) => {
    const result = await pruner.execute(false)
    return reply.send(result)
  })
}
