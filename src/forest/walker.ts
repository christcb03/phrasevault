import type { ForestDB } from './db.js'
import type {
  TruthNode, TruthLink, LinkedChild, WalkResult, VerificationResult,
} from './types.js'

export class ForestWalker {
  constructor(private db: ForestDB) {}

  // ─── Root enumeration ───────────────────────────────────────────────────────

  // Root nodes = nodes whose only incoming links are null-parent links (explicit roots).
  roots(): TruthNode[] {
    const rootLinks = this.db.getChildren('__forest_root__')  // won't match anything
    // True roots: nodes that have a link with parent_id = null pointing to them.
    const rows = (this.db as any).db?.prepare(`
      SELECT n.* FROM truth_nodes n
      INNER JOIN truth_links l ON l.child_id = n.id
      WHERE l.parent_id IS NULL AND l.removed_at IS NULL
    `).all() ?? []
    // Fallback: use getNodesByType for tree.root and forest.root
    return this.db.getNodesByType('forest.root').concat(this.db.getNodesByType('tree.root'))
  }

  findRoot(label: string): TruthNode | null {
    const all = this.roots()
    return all.find(n => n.label === label) ?? null
  }

  // ─── Tree walking ───────────────────────────────────────────────────────────

  // Walk the tree rooted at nodeId up to maxDepth levels (default: unlimited).
  // Uses sibling-order linked list for large child sets.
  walk(nodeId: string, maxDepth = Infinity, depth = 0): WalkResult | null {
    const node = this.db.getNode(nodeId)
    if (!node) return null

    const children: WalkResult[] = []
    if (depth < maxDepth) {
      // Use sibling-order linked list when available, fall back to sorted query.
      const childLinks = this.db.walkSiblings(nodeId).length > 0
        ? this.db.walkSiblings(nodeId)
        : this.db.getChildren(nodeId)

      for (const link of childLinks) {
        const child = this.walk(link.child_id, maxDepth, depth + 1)
        if (child) {
          children.push({ ...child, link })
        }
      }
    }

    return { node, link: null, children }
  }

  // ─── Children ───────────────────────────────────────────────────────────────

  children(nodeId: string, linkType?: string): LinkedChild[] {
    const links = this.db.getChildren(nodeId, linkType)
    return links.flatMap(link => {
      const node = this.db.getNode(link.child_id)
      return node ? [{ node, link, truth_score: link.truth_score }] : []
    })
  }

  // ─── Parents ────────────────────────────────────────────────────────────────

  parents(nodeId: string): TruthNode[] {
    const parentLinks = this.db.getParentLinks(nodeId)
    return parentLinks.flatMap(link => {
      if (!link.parent_id) return []
      const node = this.db.getNode(link.parent_id)
      return node ? [node] : []
    })
  }

  // ─── Validity verification ──────────────────────────────────────────────────

  // A node is valid if there is an unbroken signed link chain from it to a root.
  // A root is a node with a null-parent link or a forest.root / tree.root node.
  verify(nodeId: string, visited = new Set<string>()): VerificationResult {
    if (visited.has(nodeId)) {
      return { valid: false, chain: [], reason: 'cycle detected' }
    }
    visited.add(nodeId)

    const node = this.db.getNode(nodeId)
    if (!node) return { valid: false, chain: [], reason: 'node not found' }

    // A root node with a null-parent link is valid by definition.
    const incomingLinks = this.db.getParentLinks(nodeId)
    const nullParentLink = incomingLinks.find(l => l.parent_id === null)
    if (nullParentLink || node.type === 'forest.root') {
      return { valid: true, chain: nullParentLink ? [nullParentLink] : [], reason: null }
    }

    if (incomingLinks.length === 0) {
      return { valid: false, chain: [], reason: 'no incoming links — node is orphaned' }
    }

    // Walk upward; valid if ANY incoming chain reaches a root.
    for (const link of incomingLinks) {
      if (!link.parent_id) continue
      const parentResult = this.verify(link.parent_id, new Set(visited))
      if (parentResult.valid) {
        return { valid: true, chain: [link, ...parentResult.chain], reason: null }
      }
    }

    return { valid: false, chain: [], reason: 'no valid chain to any root' }
  }

  // ─── Orphans ────────────────────────────────────────────────────────────────

  orphans(): TruthNode[] {
    return this.db.getOrphanedNodes()
  }

  isOrphaned(nodeId: string): boolean {
    const result = this.verify(nodeId)
    return !result.valid
  }

  // ─── Config tree helpers ─────────────────────────────────────────────────────

  // Get a config value by walking config.root → section → key.
  getConfigValue(section: string, key: string): unknown | null {
    const configRoot = this.db.getNodesByType('forest.root')[0]
      ?? this.db.getNodesByType('tree.root').find(n => n.label === 'Configuration')
    if (!configRoot) return null

    const sections = this.children(configRoot.id, 'branch')
    const sectionNode = sections.find(c => c.node.label === section)
    if (!sectionNode) return null

    const values = this.children(sectionNode.node.id, 'branch')
    const valueNode = values.find(c => {
      const p = c.node.payload as { key?: string }
      return p?.key === key
    })
    if (!valueNode) return null

    const p = valueNode.node.payload as { value: unknown }
    return p?.value ?? null
  }

  // Get all config values under a section as a flat key→value map.
  getConfigSection(section: string): Record<string, unknown> {
    const configRoot = this.db.getNodesByType('tree.root').find(n => n.label === 'Configuration')
      ?? this.db.getNodesByType('forest.root')[0]
    if (!configRoot) return {}

    const sections = this.children(configRoot.id, 'branch')
    const sectionNode = sections.find(c => c.node.label === section)
    if (!sectionNode) return {}

    const result: Record<string, unknown> = {}
    for (const child of this.children(sectionNode.node.id, 'branch')) {
      const p = child.node.payload as { key?: string; value?: unknown }
      if (p?.key !== undefined) result[p.key as string] = p.value ?? null
    }
    return result
  }

  // Get config map for a specific provider (regardless of enabled state).
  getProviderConfig(providerId: string): Record<string, unknown> | null {
    const configRoot = this.db.getNodesByType('tree.root').find(n => n.label === 'Configuration')
      ?? this.db.getNodesByType('forest.root')[0]
    if (!configRoot) return null

    const sections = this.children(configRoot.id, 'branch')
    const providerSection = sections.find(c => c.node.label === 'Metadata Providers')
    if (!providerSection) return null

    const providerNode = this.children(providerSection.node.id, 'branch')
      .find(c => c.node.type === 'config.provider' &&
        (c.node.payload as { provider_id: string }).provider_id === providerId)
    if (!providerNode) return null

    const config: Record<string, unknown> = {}
    for (const val of this.children(providerNode.node.id, 'branch')) {
      const vp = val.node.payload as { key?: string; value?: unknown }
      if (vp?.key) config[vp.key as string] = vp.value
    }
    // Include top-level provider fields
    const pp = providerNode.node.payload as { provider_id: string; name: string; enabled: boolean }
    config['_provider_id'] = pp.provider_id
    config['_name'] = pp.name
    config['_enabled'] = pp.enabled
    config['_node_id'] = providerNode.node.id
    return config
  }

  // Get all enabled metadata providers from the config tree.
  getEnabledProviders(): Array<{ provider_id: string; name: string; config: Record<string, unknown> }> {
    const configRoot = this.db.getNodesByType('tree.root').find(n => n.label === 'Configuration')
      ?? this.db.getNodesByType('forest.root')[0]
    if (!configRoot) return []

    const sections = this.children(configRoot.id, 'branch')
    const providerSection = sections.find(c => c.node.label === 'Metadata Providers')
    if (!providerSection) return []

    const result = []
    for (const child of this.children(providerSection.node.id, 'branch')) {
      if (child.node.type !== 'config.provider') continue
      const p = child.node.payload as { provider_id: string; name: string; enabled: boolean }
      if (!p.enabled) continue

      const configMap: Record<string, unknown> = {}
      for (const val of this.children(child.node.id, 'branch')) {
        const vp = val.node.payload as { key?: string; value?: unknown }
        if (vp?.key) configMap[vp.key as string] = vp.value
      }
      result.push({ provider_id: p.provider_id, name: p.name, config: configMap })
    }
    return result
  }
}
