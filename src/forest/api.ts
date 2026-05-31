import type { FastifyInstance } from 'fastify'
import type { ForestDB } from './db.js'
import type { ForestWalker } from './walker.js'
import type { PVFSVerifier } from './pvfs.js'
import type { Pruner } from './pruner.js'
import { createNode, createLink } from './signer.js'
import type { NewNode, NewLink } from './types.js'

export function registerForestRoutes(
  app: FastifyInstance,
  db: ForestDB,
  walker: ForestWalker,
  pvfs: PVFSVerifier,
  pruner: Pruner,
  authorPubKey: string,
  privKeyHex: string,
): void {

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
      return reply.send(node)
    },
  )

  app.post<{ Body: Omit<NewNode, 'author'> }>(
    '/forest/node',
    async (req, reply) => {
      const input: NewNode = { ...req.body, author: authorPubKey }
      const node = await createNode(input, privKeyHex)
      db.insertNode(node)
      return reply.status(201).send(node)
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
        sectionNode = await createNode({
          type: 'config.section', label: section,
          payload: {}, created_at: now, author: authorPubKey,
        }, privKeyHex)
        db.insertNode(sectionNode)

        // Link section under config root.
        const configRoot = db.getNodesByType('tree.root').find(n => n.label === 'Configuration')
        if (configRoot) {
          const sectionLink = await createLink({
            parent_id: configRoot.id, child_id: sectionNode.id,
            link_type: 'branch', truth_score: 1.0, sort_key: section,
            score_method: null, created_at: now, author: authorPubKey,
          }, privKeyHex)
          db.insertLink(sectionLink)
        }
      }

      // Create new config.value node.
      const valueNode = await createNode({
        type: 'config.value', label: key,
        payload: { key, value: req.body.value },
        created_at: now, author: authorPubKey,
      }, privKeyHex)
      db.insertNode(valueNode)

      // Find and supersede any existing link for this key under this section.
      const existing = walker.children(sectionNode.id, 'branch')
        .find(c => c.node.type === 'config.value' && (c.node.payload as { key: string }).key === key)

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

      return reply.send(valueNode)
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
      const node = await createNode({
        type: 'pvfs.file',
        label: req.body.label,
        payload: req.body.payload,
        created_at: Date.now(),
        author: authorPubKey,
      }, privKeyHex)
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
      const locNode = await createNode({
        type: 'pvfs.location',
        label: req.body.payload.uri,
        payload: { ...req.body.payload, last_verified: null, last_seen: now },
        created_at: now,
        author: authorPubKey,
      }, privKeyHex)
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

  // ─── Prune ─────────────────────────────────────────────────────────────────

  app.get('/forest/prune/preview', async (_req, reply) => {
    return reply.send(pruner.preview())
  })

  app.post('/forest/prune', async (_req, reply) => {
    const result = await pruner.execute(false)
    return reply.send(result)
  })
}
