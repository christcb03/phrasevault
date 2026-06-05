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
  `
    CREATE TABLE IF NOT EXISTS pvfs_scan_jobs (
      id TEXT PRIMARY KEY,
      status TEXT NOT NULL,
      started_at INTEGER NOT NULL,
      finished_at INTEGER,
      dry_run INTEGER NOT NULL,
      root_path TEXT NOT NULL,
      found INTEGER NOT NULL DEFAULT 0,
      new_count INTEGER,
      already_ingested_count INTEGER,
      ingested INTEGER,
      failed INTEGER,
      files_json TEXT,
      failures_json TEXT,
      error TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_pvfs_scan_jobs_started ON pvfs_scan_jobs(started_at DESC);
  `,
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

  hardDeleteLink(linkId: string): void {
    this.db.transaction(() => {
      const link = this.getLink(linkId)
      if (link?.parent_id) {
        this.updateSiblingOrder(link.parent_id, linkId, false)
      }
      this.db.prepare('DELETE FROM truth_links WHERE id = ?').run(linkId)
    })()
  }

  hardDeleteAllLinksForNode(nodeId: string): void {
    const ids = (this.db.prepare(
      'SELECT id FROM truth_links WHERE child_id = ? OR parent_id = ?',
    ).all(nodeId, nodeId) as { id: string }[]).map(r => r.id)
    for (const id of ids) this.hardDeleteLink(id)
  }

  // ─── PVFS scan jobs (persistent) ────────────────────────────────────────────

  insertScanJob(row: PvfsScanJobRow): void {
    this.db.prepare(`
      INSERT INTO pvfs_scan_jobs (
        id, status, started_at, finished_at, dry_run, root_path, found,
        new_count, already_ingested_count, ingested, failed,
        files_json, failures_json, error
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      row.id, row.status, row.started_at, row.finished_at ?? null,
      row.dry_run ? 1 : 0, row.root_path, row.found,
      row.new_count ?? null, row.already_ingested_count ?? null,
      row.ingested ?? null, row.failed ?? null,
      row.files_json ?? null, row.failures_json ?? null, row.error ?? null,
    )
  }

  updateScanJob(id: string, patch: Partial<PvfsScanJobRow>): void {
    const fields: string[] = []
    const values: unknown[] = []
    const set = (col: string, val: unknown) => { fields.push(`${col} = ?`); values.push(val) }

    if (patch.status !== undefined) set('status', patch.status)
    if (patch.finished_at !== undefined) set('finished_at', patch.finished_at)
    if (patch.found !== undefined) set('found', patch.found)
    if (patch.new_count !== undefined) set('new_count', patch.new_count)
    if (patch.already_ingested_count !== undefined) set('already_ingested_count', patch.already_ingested_count)
    if (patch.ingested !== undefined) set('ingested', patch.ingested)
    if (patch.failed !== undefined) set('failed', patch.failed)
    if (patch.files_json !== undefined) set('files_json', patch.files_json)
    if (patch.failures_json !== undefined) set('failures_json', patch.failures_json)
    if (patch.error !== undefined) set('error', patch.error)

    if (fields.length === 0) return
    values.push(id)
    this.db.prepare(`UPDATE pvfs_scan_jobs SET ${fields.join(', ')} WHERE id = ?`).run(...values)
  }

  getScanJob(id: string): PvfsScanJobRow | null {
    const row = this.db.prepare('SELECT * FROM pvfs_scan_jobs WHERE id = ?').get(id) as RawScanJob | undefined
    return row ? deserializeScanJob(row) : null
  }

  listScanJobs(limit = 50): PvfsScanJobRow[] {
    return (this.db.prepare(
      'SELECT * FROM pvfs_scan_jobs ORDER BY started_at DESC LIMIT ?',
    ).all(limit) as RawScanJob[]).map(deserializeScanJob)
  }
}

export interface PvfsScanJobRow {
  id: string
  status: 'running' | 'done' | 'error'
  started_at: number
  finished_at?: number | null
  dry_run: boolean
  root_path: string
  found: number
  new_count?: number | null
  already_ingested_count?: number | null
  ingested?: number | null
  failed?: number | null
  files_json?: string | null
  failures_json?: string | null
  error?: string | null
}

interface RawScanJob {
  id: string
  status: string
  started_at: number
  finished_at: number | null
  dry_run: number
  root_path: string
  found: number
  new_count: number | null
  already_ingested_count: number | null
  ingested: number | null
  failed: number | null
  files_json: string | null
  failures_json: string | null
  error: string | null
}

function deserializeScanJob(row: RawScanJob): PvfsScanJobRow {
  return {
    id: row.id,
    status: row.status as PvfsScanJobRow['status'],
    started_at: row.started_at,
    finished_at: row.finished_at,
    dry_run: row.dry_run === 1,
    root_path: row.root_path,
    found: row.found,
    new_count: row.new_count,
    already_ingested_count: row.already_ingested_count,
    ingested: row.ingested,
    failed: row.failed,
    files_json: row.files_json,
    failures_json: row.failures_json,
    error: row.error,
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
