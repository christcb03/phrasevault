/**
 * PVFS file orphan detection and explicit purge (app-initiated only).
 */

import type { ForestDB } from './db.js'
import type { ForestWalker } from './walker.js'
import type { PvfsFilePayload, PvfsLocationPayload } from './types.js'

export interface PvfsOrphanEntry {
  file_node_id: string
  label: string
  content_hash: string
  size_bytes: number
  mime_type: string
  original_filename: string | null
  uris: string[]
  created_at: number
}

export function listPvfsFileOrphans(db: ForestDB, walker: ForestWalker): PvfsOrphanEntry[] {
  const orphans: PvfsOrphanEntry[] = []

  for (const node of db.getNodesByType('pvfs.file')) {
    if (db.getParentLinks(node.id).length > 0) continue

    const fp = node.payload as PvfsFilePayload
    const uris = walker.children(node.id, 'member')
      .filter(c => c.node.type === 'pvfs.location')
      .map(c => (c.node.payload as PvfsLocationPayload).uri)

    orphans.push({
      file_node_id: node.id,
      label: node.label,
      content_hash: fp.content_hash,
      size_bytes: fp.size_bytes,
      mime_type: fp.mime_type,
      original_filename: fp.original_filename,
      uris,
      created_at: node.created_at,
    })
  }

  return orphans.sort((a, b) => b.created_at - a.created_at)
}

export interface PurgeOrphansResult {
  requested: number
  purged: string[]
  skipped: Array<{ file_node_id: string; reason: string }>
}

/** Hard-delete orphan pvfs.file nodes and their location children. App must call explicitly. */
export function purgePvfsOrphans(
  db: ForestDB,
  walker: ForestWalker,
  fileNodeIds?: string[],
): PurgeOrphansResult {
  const candidates = fileNodeIds?.length
    ? fileNodeIds
    : listPvfsFileOrphans(db, walker).map(o => o.file_node_id)

  const purged: string[] = []
  const skipped: Array<{ file_node_id: string; reason: string }> = []

  for (const fileNodeId of candidates) {
    const node = db.getNode(fileNodeId)
    if (!node || node.type !== 'pvfs.file') {
      skipped.push({ file_node_id: fileNodeId, reason: 'not a pvfs.file node' })
      continue
    }
    if (db.getParentLinks(fileNodeId).length > 0) {
      skipped.push({ file_node_id: fileNodeId, reason: 'still has active inbound links' })
      continue
    }

    db.transaction(() => {
      for (const child of walker.children(fileNodeId, 'member')) {
        if (child.node.type === 'pvfs.location') {
          db.hardDeleteAllLinksForNode(child.node.id)
          db.deleteNode(child.node.id)
        }
      }
      db.hardDeleteAllLinksForNode(fileNodeId)
      db.deleteInactiveLinksForNode(fileNodeId)
      db.deleteNode(fileNodeId)
    })

    purged.push(fileNodeId)
  }

  return { requested: candidates.length, purged, skipped }
}