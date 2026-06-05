/**
 * Remove a file from the primary tree with cascade soft-delete of all inbound links.
 * Local file:// bytes are deleted only when confirm_local_delete is true.
 */

import { unlink } from 'node:fs/promises'
import type { ForestDB } from './db.js'
import type { ForestWalker } from './walker.js'
import { PVFS_PRIMARY_LABEL } from './pvfs-trees.js'
import type { PvfsLocationPayload } from './types.js'

export interface LocalDeletePreview {
  required_confirmation: boolean
  paths: string[]
  warning: string
}

export interface RemoveFromPrimaryResult {
  file_node_id: string
  removed_link_ids: string[]
  orphaned: boolean
  local_delete?: LocalDeletePreview | {
    deleted: string[]
    skipped: string[]
    failed: Array<{ path: string; error: string }>
  }
}

export function localFilePathsForNode(walker: ForestWalker, fileNodeId: string): string[] {
  const paths: string[] = []
  for (const child of walker.children(fileNodeId, 'member')) {
    if (child.node.type !== 'pvfs.location') continue
    const payload = child.node.payload as PvfsLocationPayload
    if (payload.uri.startsWith('file://')) {
      paths.push(payload.uri.slice('file://'.length))
    }
  }
  return paths
}

export function previewRemoveFromPrimary(
  db: ForestDB,
  walker: ForestWalker,
  fileNodeId: string,
): RemoveFromPrimaryResult | { error: string } {
  const fileNode = db.getNode(fileNodeId)
  if (!fileNode || fileNode.type !== 'pvfs.file') {
    return { error: 'file node not found' }
  }

  const primary = walker.findRoot(PVFS_PRIMARY_LABEL)
  if (!primary) return { error: 'primary tree not found' }

  const inbound = db.getParentLinks(fileNodeId)
  const localPaths = localFilePathsForNode(walker, fileNodeId)

  return {
    file_node_id: fileNodeId,
    removed_link_ids: inbound.map(l => l.id),
    orphaned: inbound.length > 0,
    ...(localPaths.length > 0 ? {
      local_delete: {
        required_confirmation: true,
        paths: localPaths,
        warning: `${localPaths.length} local file(s) on disk can be deleted after links are removed. `
          + 'Re-send the request with confirm_local_delete: true to delete them from disk.',
      } satisfies LocalDeletePreview,
    } : {}),
  }
}

export async function removeFromPrimary(
  db: ForestDB,
  walker: ForestWalker,
  fileNodeId: string,
  removedBy: string,
  opts: { confirmLocalDelete?: boolean } = {},
): Promise<RemoveFromPrimaryResult | { error: string }> {
  const fileNode = db.getNode(fileNodeId)
  if (!fileNode || fileNode.type !== 'pvfs.file') {
    return { error: 'file node not found' }
  }

  const primary = walker.findRoot(PVFS_PRIMARY_LABEL)
  if (!primary) return { error: 'primary tree not found' }

  const hasPrimaryLink = db.getChildren(primary.id, 'branch')
    .some(l => l.child_id === fileNodeId)
  if (!hasPrimaryLink) {
    return { error: 'file is not linked under the primary tree' }
  }

  const inbound = db.getParentLinks(fileNodeId)
  const removedIds: string[] = []

  db.transaction(() => {
    for (const link of inbound) {
      db.softRemoveLink(link.id, removedBy, '')
      removedIds.push(link.id)
    }
  })

  const stillLinked = db.getParentLinks(fileNodeId).length > 0
  const localPaths = localFilePathsForNode(walker, fileNodeId)
  const result: RemoveFromPrimaryResult = {
    file_node_id: fileNodeId,
    removed_link_ids: removedIds,
    orphaned: !stillLinked,
  }

  if (localPaths.length === 0) return result

  if (!opts.confirmLocalDelete) {
    result.local_delete = {
      required_confirmation: true,
      paths: localPaths,
      warning: `${localPaths.length} local file(s) remain on disk. `
        + 'Set confirm_local_delete: true in the request body to delete them.',
    }
    return result
  }

  const deleted: string[] = []
  const skipped: string[] = []
  const failed: Array<{ path: string; error: string }> = []

  for (const p of localPaths) {
    try {
      await unlink(p)
      deleted.push(p)
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code
      if (code === 'ENOENT') {
        skipped.push(p)
      } else {
        failed.push({ path: p, error: err instanceof Error ? err.message : String(err) })
      }
    }
  }

  result.local_delete = { deleted, skipped, failed }
  return result
}