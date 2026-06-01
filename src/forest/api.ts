import type { FastifyInstance } from 'fastify'
import type { ForestDB } from './db.js'
import type { ForestWalker } from './walker.js'
import type { PVFSVerifier } from './pvfs.js'
import type { Pruner } from './pruner.js'
import { createNode, createLink } from './signer.js'
import { defaultVisibility, serializePayload, deserializePayload } from './cipher.js'
import type { NewNode, NewLink, TruthNode } from './types.js'
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
): void {

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
      return reply.send({ node, locations: locations.map(l => l.node) })
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

  // ─── Prune ─────────────────────────────────────────────────────────────────

  app.get('/forest/prune/preview', async (_req, reply) => {
    return reply.send(pruner.preview())
  })

  app.post('/forest/prune', async (_req, reply) => {
    const result = await pruner.execute(false)
    return reply.send(result)
  })
}
