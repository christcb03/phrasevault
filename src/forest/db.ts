import Database from 'better-sqlite3'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import type {
  TruthNode, TruthLink, SiblingOrderEntry, NewNode, NewLink,
} from './types.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

// ─── Schema migrations ────────────────────────────────────────────────────────
// Add new SQL strings at the END of this array. Never modify existing entries.
// Each string is executed exactly once, in order, tracked by index in schema_version.

const MIGRATIONS: string[] = [
  readFileSync(join(__dirname, 'schema.sql'), 'utf8'),
]

// ─── ForestDB ─────────────────────────────────────────────────────────────────

export class ForestDB {
  private db: Database.Database

  constructor(dbPath: string) {
    this.db = new Database(dbPath)
    this.db.pragma('journal_mode = WAL')
    this.db.pragma('foreign_keys = ON')
    this.migrate()
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY,
        applied_at INTEGER NOT NULL
      )
    `)
    const applied = (this.db.prepare('SELECT MAX(version) as v FROM schema_version').get() as { v: number | null }).v ?? -1
    for (let i = applied + 1; i < MIGRATIONS.length; i++) {
      this.db.exec(MIGRATIONS[i])
      this.db.prepare('INSERT INTO schema_version (version, applied_at) VALUES (?, ?)').run(i, Date.now())
    }
  }

  close(): void {
    this.db.close()
  }

  // ─── Nodes ──────────────────────────────────────────────────────────────────

  insertNode(node: TruthNode): void {
    // For public nodes, payload is an object — serialize to JSON.
    // For private/community nodes, payload is already a base64 ciphertext string.
    const payloadStr = typeof node.payload === 'string'
      ? node.payload
      : JSON.stringify(node.payload)
    this.db.prepare(`
      INSERT OR IGNORE INTO truth_nodes (id, type, label, visibility, payload, created_at, author, sig)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(node.id, node.type, node.label, node.visibility, payloadStr, node.created_at, node.author, node.sig)
  }

  getNode(id: string): TruthNode | null {
    const row = this.db.prepare('SELECT * FROM truth_nodes WHERE id = ?').get(id) as RawNode | undefined
    return row ? deserializeNode(row) : null
  }

  getNodesByType(type: string): TruthNode[] {
    return (this.db.prepare('SELECT * FROM truth_nodes WHERE type = ?').all(type) as RawNode[]).map(deserializeNode)
  }

  // ─── Links ──────────────────────────────────────────────────────────────────

  insertLink(link: TruthLink): void {
    this.db.transaction(() => {
      this.db.prepare(`
        INSERT OR IGNORE INTO truth_links
          (id, parent_id, child_id, link_type, truth_score, sort_key, score_method,
           created_at, author, sig,
           removed_at, removed_by, removal_sig, superseded_by, suspended_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        link.id, link.parent_id, link.child_id, link.link_type,
        link.truth_score, link.sort_key, link.score_method,
        link.created_at, link.author, link.sig,
        link.removed_at, link.removed_by, link.removal_sig,
        link.superseded_by, link.suspended_at,
      )
      if (link.parent_id && !link.removed_at) {
        this.updateSiblingOrder(link.parent_id, link.id, true)
      }
    })()
  }

  getLink(id: string): TruthLink | null {
    const row = this.db.prepare('SELECT * FROM truth_links WHERE id = ?').get(id) as RawLink | undefined
    return row ? deserializeLink(row) : null
  }

  // Active (non-removed, non-suspended) children of a node, sorted by truth_score desc then sort_key.
  getChildren(parentId: string, linkType?: string): TruthLink[] {
    const base = `
      SELECT * FROM truth_links
      WHERE parent_id = ? AND removed_at IS NULL AND suspended_at IS NULL
      ${linkType ? 'AND link_type = ?' : ''}
      ORDER BY truth_score DESC, sort_key ASC
    `
    const rows = linkType
      ? this.db.prepare(base).all(parentId, linkType) as RawLink[]
      : this.db.prepare(base).all(parentId) as RawLink[]
    return rows.map(deserializeLink)
  }

  // All active links pointing TO a node (for upward traversal / validity check).
  getParentLinks(childId: string): TruthLink[] {
    return (this.db.prepare(`
      SELECT * FROM truth_links
      WHERE child_id = ? AND removed_at IS NULL
    `).all(childId) as RawLink[]).map(deserializeLink)
  }

  softRemoveLink(linkId: string, removedBy: string, removalSig: string): void {
    this.db.transaction(() => {
      const link = this.getLink(linkId)
      if (!link) return
      this.db.prepare(`
        UPDATE truth_links SET removed_at = ?, removed_by = ?, removal_sig = ? WHERE id = ?
      `).run(Date.now(), removedBy, removalSig, linkId)
      if (link.parent_id) {
        this.updateSiblingOrder(link.parent_id, linkId, false)
      }
    })()
  }

  supersedeLink(oldLinkId: string, newLinkId: string): void {
    this.db.prepare('UPDATE truth_links SET superseded_by = ? WHERE id = ?').run(newLinkId, oldLinkId)
  }

  suspendLink(linkId: string): void {
    this.db.prepare('UPDATE truth_links SET suspended_at = ? WHERE id = ?').run(Date.now(), linkId)
  }

  unsuspendLink(linkId: string): void {
    this.db.prepare('UPDATE truth_links SET suspended_at = NULL WHERE id = ?').run(linkId)
  }

  // ─── Sibling order ──────────────────────────────────────────────────────────

  private updateSiblingOrder(parentId: string, linkId: string, insert: boolean): void {
    if (insert) {
      // Find the link's truth_score to insert at the right position.
      const link = this.getLink(linkId)
      if (!link) return
      const siblings = this.getChildren(parentId)  // already sorted desc by score
      const idx = siblings.findIndex(s => s.id === linkId)

      // Rebuild the affected portion of the list.
      const prev = idx > 0 ? siblings[idx - 1] : null
      const next = idx < siblings.length - 1 ? siblings[idx + 1] : null

      this.db.prepare('INSERT OR REPLACE INTO link_sibling_order (parent_id, link_id, next_link_id) VALUES (?, ?, ?)')
        .run(parentId, linkId, next?.id ?? null)

      if (prev) {
        this.db.prepare('UPDATE link_sibling_order SET next_link_id = ? WHERE parent_id = ? AND link_id = ?')
          .run(linkId, parentId, prev.id)
      }
    } else {
      // Remove from list: re-wire prev → next.
      const entry = this.db.prepare(
        'SELECT * FROM link_sibling_order WHERE parent_id = ? AND link_id = ?',
      ).get(parentId, linkId) as SiblingOrderEntry | undefined
      if (!entry) return

      // Find who points to this link and re-wire to skip it.
      this.db.prepare(
        'UPDATE link_sibling_order SET next_link_id = ? WHERE parent_id = ? AND next_link_id = ?',
      ).run(entry.next_link_id, parentId, linkId)

      this.db.prepare('DELETE FROM link_sibling_order WHERE parent_id = ? AND link_id = ?')
        .run(parentId, linkId)
    }
  }

  // Walk sorted siblings via linked list (O(1) per step). Returns links in order.
  walkSiblings(parentId: string): TruthLink[] {
    // Find the head: the link in the parent's sibling list with no predecessor.
    const allEntries = this.db.prepare(
      'SELECT * FROM link_sibling_order WHERE parent_id = ?',
    ).all(parentId) as SiblingOrderEntry[]

    if (allEntries.length === 0) return []

    const pointed = new Set(allEntries.map(e => e.next_link_id).filter(Boolean))
    const head = allEntries.find(e => !pointed.has(e.link_id))
    if (!head) return []

    const result: TruthLink[] = []
    let current: SiblingOrderEntry | undefined = head
    while (current) {
      const link = this.getLink(current.link_id)
      if (link) result.push(link)
      current = current.next_link_id
        ? (this.db.prepare('SELECT * FROM link_sibling_order WHERE parent_id = ? AND link_id = ?')
            .get(parentId, current.next_link_id) as SiblingOrderEntry | undefined)
        : undefined
    }
    return result
  }

  // ─── Orphan detection ───────────────────────────────────────────────────────

  // Returns nodes that have no active incoming branch or cross links from any valid chain.
  getOrphanedNodes(): TruthNode[] {
    return (this.db.prepare(`
      SELECT n.* FROM truth_nodes n
      WHERE NOT EXISTS (
        SELECT 1 FROM truth_links l
        WHERE l.child_id = n.id
          AND l.removed_at IS NULL
          AND l.link_type IN ('branch', 'cross', 'member', 'file', 'metadata')
      )
      AND NOT EXISTS (
        SELECT 1 FROM truth_links l2
        WHERE l2.parent_id IS NULL AND l2.child_id = n.id AND l2.removed_at IS NULL
      )
    `).all() as RawNode[]).map(deserializeNode)
  }

  // ─── Batch / transaction ────────────────────────────────────────────────────

  transaction<T>(fn: () => T): T {
    return this.db.transaction(fn)()
  }

  // ─── Raw access for pruner ──────────────────────────────────────────────────

  deleteNode(id: string): void {
    this.db.prepare('DELETE FROM truth_nodes WHERE id = ?').run(id)
  }

  deleteInactiveLinksForNode(nodeId: string): void {
    this.db.prepare(`
      DELETE FROM truth_links WHERE child_id = ? AND removed_at IS NOT NULL
    `).run(nodeId)
    this.db.prepare(`
      DELETE FROM truth_links WHERE parent_id = ? AND removed_at IS NOT NULL
    `).run(nodeId)
  }
}

// ─── Row deserialization ──────────────────────────────────────────────────────

interface RawNode {
  id: string; type: string; label: string; visibility: string; payload: string
  created_at: number; author: string; sig: string
}

interface RawLink {
  id: string; parent_id: string | null; child_id: string; link_type: string
  truth_score: number; sort_key: string | null; score_method: string | null
  created_at: number; author: string; sig: string
  removed_at: number | null; removed_by: string | null; removal_sig: string | null
  superseded_by: string | null; suspended_at: number | null
}

function deserializeNode(row: RawNode): TruthNode {
  // For public nodes, parse JSON payload back to object.
  // For private/community nodes, leave payload as the raw ciphertext string —
  // decryption happens in the application layer with the user's enc key.
  const payload = row.visibility === 'public'
    ? JSON.parse(row.payload)
    : row.payload   // opaque base64 ciphertext
  return { ...row, payload } as TruthNode
}

function deserializeLink(row: RawLink): TruthLink {
  return row as TruthLink
}
