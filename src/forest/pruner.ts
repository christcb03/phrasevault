import type { ForestDB } from './db.js'
import type { ForestWalker } from './walker.js'
import { createNode } from './signer.js'
import { serializePayload } from './cipher.js'
import type { PruneCandidate, PrunePreview, PruneResult, PrunePolicyPayload } from './types.js'

export class Pruner {
  constructor(
    private db: ForestDB,
    private walker: ForestWalker,
    private authorPubKey: string,
    private privKeyHex: string,
    private encKey: Uint8Array,
  ) {}

  // ─── Policy resolution ───────────────────────────────────────────────────────

  // Resolve the effective prune policy. Node-level > tree-level > forest default.
  private resolvePolicy(nodeId?: string): PrunePolicyPayload {
    const defaults: PrunePolicyPayload = {
      target_id:          null,
      retain_orphan_days: 30,
      warn_before_days:   7,
      auto:               false,
    }

    // Look up policy nodes from config tree.
    const policyNodes = this.db.getNodesByType('config.prune_policy')
    if (policyNodes.length === 0) return defaults

    // Most specific: node-level policy.
    if (nodeId) {
      const nodePolicy = policyNodes.find(n => (n.payload as PrunePolicyPayload).target_id === nodeId)
      if (nodePolicy) return { ...defaults, ...(nodePolicy.payload as PrunePolicyPayload) }
    }

    // Forest default.
    const forestPolicy = policyNodes.find(n => (n.payload as PrunePolicyPayload).target_id === null)
    if (forestPolicy) return { ...defaults, ...(forestPolicy.payload as PrunePolicyPayload) }

    return defaults
  }

  // ─── Candidate collection ────────────────────────────────────────────────────

  private buildCandidates(policy: PrunePolicyPayload): PruneCandidate[] {
    const orphans = this.walker.orphans()
    const now = Date.now()
    const cutoffMs = policy.retain_orphan_days !== null
      ? policy.retain_orphan_days * 24 * 60 * 60 * 1000
      : null

    return orphans.flatMap(node => {
      // Skip nodes that have individual no-prune policies.
      const nodePolicy = this.resolvePolicy(node.id)
      if (nodePolicy.retain_orphan_days === null) return []

      const age = now - node.created_at
      const effectiveCutoff = nodePolicy.retain_orphan_days * 24 * 60 * 60 * 1000
      if (age < effectiveCutoff) return []

      return [{
        node,
        orphaned_at: node.created_at,
        reason: `orphaned, age ${Math.floor(age / 86400000)}d > retain ${nodePolicy.retain_orphan_days}d`,
      }]
    })
  }

  // ─── Preview ─────────────────────────────────────────────────────────────────

  preview(): PrunePreview {
    const policy = this.resolvePolicy()
    const candidates = this.buildCandidates(policy)
    const linkCount = candidates.reduce((acc, c) => {
      const incoming = this.db.getParentLinks(c.node.id).filter(l => l.removed_at !== null)
      return acc + incoming.length
    }, 0)
    return { candidates, node_count: candidates.length, link_count: linkCount }
  }

  // ─── Execute ─────────────────────────────────────────────────────────────────

  async execute(dryRun = false): Promise<PruneResult> {
    const preview = this.preview()
    const now = Date.now()

    if (!dryRun && preview.candidates.length > 0) {
      this.db.transaction(() => {
        for (const candidate of preview.candidates) {
          this.db.deleteInactiveLinksForNode(candidate.node.id)
          this.db.deleteNode(candidate.node.id)
        }
      })
    }

    const rawRecord = {
      pruned_at:   now,
      dry_run:     dryRun,
      node_count:  preview.node_count,
      link_count:  preview.link_count,
      node_ids:    preview.candidates.map(c => c.node.id),
      policy_id:   null,
    }
    const recordNode = await createNode({
      type: 'event.prune_record',
      label: `Prune ${dryRun ? 'preview' : 'run'} at ${new Date(now).toISOString()}`,
      visibility: 'private',
      payload: serializePayload(rawRecord, 'private', this.encKey),
      created_at: now,
      author: this.authorPubKey,
    }, this.privKeyHex)

    if (!dryRun) {
      this.db.insertNode(recordNode)
    }

    return { ...preview, executed_at: now, record_id: recordNode.id }
  }
}
