/**
 * PVFS tree roots — primary (server) inventory and per-user trees.
 */

import type { ForestDB } from './db.js'
import type { ForestWalker } from './walker.js'
import { createNode, createLink } from './signer.js'
import { serializePayload, defaultVisibility } from './cipher.js'
import type { TruthNode, PvfsFilePayload, PvfsLocationPayload } from './types.js'

export const PVFS_PRIMARY_LABEL = 'pvfs:primary'
export const PVFS_USER_LABEL_PREFIX = 'pvfs:user:'

export function userPvfsLabel(pubKeyHex: string): string {
  return `${PVFS_USER_LABEL_PREFIX}${pubKeyHex}`
}

async function makeNode(
  db: ForestDB,
  authorPubKey: string,
  privKeyHex: string,
  encKey: Uint8Array | null,
  type: TruthNode['type'],
  label: string,
  rawPayload: unknown,
  now: number,
): Promise<TruthNode> {
  const vis = defaultVisibility(type)
  const payload = serializePayload(rawPayload, vis, vis === 'public' ? null : encKey)
  const node = await createNode({ type, label, visibility: vis, payload, created_at: now, author: authorPubKey }, privKeyHex)
  db.insertNode(node)
  return node
}

/** Ensure forest.root exists and return it (create minimal forest if empty). */
export async function ensureForestRoot(
  db: ForestDB,
  walker: ForestWalker,
  authorPubKey: string,
  privKeyHex: string,
  encKey: Uint8Array | null,
): Promise<TruthNode> {
  const existing = db.getNodesByType('forest.root')[0]
  if (existing) return existing

  const now = Date.now()
  const forestRoot = await makeNode(db, authorPubKey, privKeyHex, encKey, 'forest.root', 'PhraseVault', { version: 1 }, now)
  db.insertLink(await createLink({
    parent_id: null, child_id: forestRoot.id,
    link_type: 'branch', truth_score: 1.0, sort_key: null,
    score_method: null, created_at: now, author: authorPubKey,
  }, privKeyHex))
  return forestRoot
}

/** Create or return the primary PVFS tree root (ordered file inventory). */
export async function ensurePrimaryRoot(
  db: ForestDB,
  walker: ForestWalker,
  authorPubKey: string,
  privKeyHex: string,
  encKey: Uint8Array | null,
): Promise<TruthNode> {
  const found = walker.findRoot(PVFS_PRIMARY_LABEL)
  if (found) return found

  const now = Date.now()
  const forestRoot = await ensureForestRoot(db, walker, authorPubKey, privKeyHex, encKey)
  const primaryRoot = await makeNode(db, authorPubKey, privKeyHex, encKey, 'tree.root', PVFS_PRIMARY_LABEL, {
    role: 'pvfs_primary',
    description: 'Canonical ordered inventory of files on this server',
  }, now)

  db.insertLink(await createLink({
    parent_id: forestRoot.id, child_id: primaryRoot.id,
    link_type: 'branch', truth_score: 1.0, sort_key: 'pvfs_primary',
    score_method: null, created_at: now, author: authorPubKey,
  }, privKeyHex))

  db.insertLink(await createLink({
    parent_id: null, child_id: primaryRoot.id,
    link_type: 'branch', truth_score: 1.0, sort_key: PVFS_PRIMARY_LABEL,
    score_method: null, created_at: now, author: authorPubKey,
  }, privKeyHex))

  return primaryRoot
}

/** Link a pvfs.file node under the primary tree (branch + sibling ordering). */
export async function linkFileToPrimary(
  db: ForestDB,
  walker: ForestWalker,
  authorPubKey: string,
  privKeyHex: string,
  encKey: Uint8Array | null,
  fileNodeId: string,
  sortKey?: string | null,
): Promise<void> {
  const primary = await ensurePrimaryRoot(db, walker, authorPubKey, privKeyHex, encKey)
  const already = db.getChildren(primary.id, 'branch').some(l => l.child_id === fileNodeId)
  if (already) return

  const now = Date.now()
  db.insertLink(await createLink({
    parent_id: primary.id,
    child_id: fileNodeId,
    link_type: 'branch',
    truth_score: 1.0,
    sort_key: sortKey ?? null,
    score_method: null,
    created_at: now,
    author: authorPubKey,
  }, privKeyHex))
}

/** Per-user PVFS tree root (references + owned files). */
export async function ensureUserRoot(
  db: ForestDB,
  walker: ForestWalker,
  authorPubKey: string,
  privKeyHex: string,
  encKey: Uint8Array | null,
  userPubKeyHex: string,
): Promise<TruthNode> {
  const label = userPvfsLabel(userPubKeyHex)
  const found = walker.findRoot(label)
  if (found) return found

  const now = Date.now()
  const forestRoot = await ensureForestRoot(db, walker, authorPubKey, privKeyHex, encKey)
  const userRoot = await makeNode(db, authorPubKey, privKeyHex, encKey, 'tree.root', label, {
    role: 'pvfs_user',
    user_pub_key: userPubKeyHex,
  }, now)

  db.insertLink(await createLink({
    parent_id: forestRoot.id, child_id: userRoot.id,
    link_type: 'branch', truth_score: 1.0, sort_key: label,
    score_method: null, created_at: now, author: authorPubKey,
  }, privKeyHex))

  db.insertLink(await createLink({
    parent_id: null, child_id: userRoot.id,
    link_type: 'branch', truth_score: 1.0, sort_key: label,
    score_method: null, created_at: now, author: authorPubKey,
  }, privKeyHex))

  return userRoot
}

/** Reference a primary-tree file from a user's tree (no duplicate file node). */
export async function linkUserRefToPrimaryFile(
  db: ForestDB,
  walker: ForestWalker,
  authorPubKey: string,
  privKeyHex: string,
  encKey: Uint8Array | null,
  userPubKeyHex: string,
  primaryFileNodeId: string,
): Promise<{ userRootId: string; linkId: string }> {
  const fileNode = db.getNode(primaryFileNodeId)
  if (!fileNode || fileNode.type !== 'pvfs.file') {
    throw new Error('primary file node not found')
  }

  const userRoot = await ensureUserRoot(db, walker, authorPubKey, privKeyHex, encKey, userPubKeyHex)
  const dup = db.getChildren(userRoot.id, 'pvfs_ref').some(l => l.child_id === primaryFileNodeId)
  if (dup) {
    const link = db.getChildren(userRoot.id, 'pvfs_ref').find(l => l.child_id === primaryFileNodeId)!
    return { userRootId: userRoot.id, linkId: link.id }
  }

  const now = Date.now()
  const link = await createLink({
    parent_id: userRoot.id,
    child_id: primaryFileNodeId,
    link_type: 'pvfs_ref',
    truth_score: 1.0,
    sort_key: null,
    score_method: null,
    created_at: now,
    author: authorPubKey,
  }, privKeyHex)
  db.insertLink(link)
  return { userRootId: userRoot.id, linkId: link.id }
}

export interface PrimaryFileEntry {
  file_node_id: string
  sort_key: string | null
  content_hash: string
  size_bytes: number
  mime_type: string
  original_filename: string | null
  label: string
  uri: string | null
  link_id: string
}

/** Walk primary tree in sibling order; only direct pvfs.file children. */
export function listPrimaryFiles(
  db: ForestDB,
  walker: ForestWalker,
  opts: { offset?: number; limit?: number } = {},
): { root: TruthNode; files: PrimaryFileEntry[]; total: number } | null {
  const root = walker.findRoot(PVFS_PRIMARY_LABEL)
  if (!root) return null

  const offset = Math.max(0, opts.offset ?? 0)
  const limit = Math.min(500, Math.max(1, opts.limit ?? 100))

  const childLinks = db.walkSiblings(root.id).length > 0
    ? db.walkSiblings(root.id)
    : db.getChildren(root.id, 'branch')

  const all: PrimaryFileEntry[] = []
  for (const link of childLinks) {
    const node = db.getNode(link.child_id)
    if (!node || node.type !== 'pvfs.file') continue
    const fp = node.payload as PvfsFilePayload
    const locs = walker.children(node.id, 'member').filter(c => c.node.type === 'pvfs.location')
    const uri = locs.length > 0
      ? (locs[0].node.payload as PvfsLocationPayload).uri
      : null
    all.push({
      file_node_id: node.id,
      sort_key: link.sort_key,
      content_hash: fp.content_hash,
      size_bytes: fp.size_bytes,
      mime_type: fp.mime_type,
      original_filename: fp.original_filename,
      label: node.label,
      uri,
      link_id: link.id,
    })
  }

  return {
    root,
    files: all.slice(offset, offset + limit),
    total: all.length,
  }
}

/** Link every pvfs.file not yet under primary (migration after upgrade). */
export async function backfillPrimaryTree(
  db: ForestDB,
  walker: ForestWalker,
  authorPubKey: string,
  privKeyHex: string,
  encKey: Uint8Array | null,
): Promise<{ linked: number; skipped: number }> {
  const primary = await ensurePrimaryRoot(db, walker, authorPubKey, privKeyHex, encKey)
  const existing = new Set(db.getChildren(primary.id, 'branch').map(l => l.child_id))
  let linked = 0
  let skipped = 0
  for (const node of db.getNodesByType('pvfs.file')) {
    if (existing.has(node.id)) {
      skipped++
      continue
    }
    await linkFileToPrimary(db, walker, authorPubKey, privKeyHex, encKey, node.id, node.label)
    linked++
  }
  return { linked, skipped }
}

/** Flat index for MediaForest compatibility (`GET /pvfs/locations`). */
export function listAllFileLocations(
  db: ForestDB,
  walker: ForestWalker,
): Array<{
  id: string
  payload: PvfsFilePayload & { uri: string | null }
}> {
  const fileNodes = db.getNodesByType('pvfs.file')
  return fileNodes.map(node => {
    const fp = node.payload as PvfsFilePayload
    const locs = walker.children(node.id, 'member').filter(c => c.node.type === 'pvfs.location')
    const uri = locs.length > 0 ? (locs[0].node.payload as PvfsLocationPayload).uri : null
    return { id: node.id, payload: { ...fp, uri } }
  })
}