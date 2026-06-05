import { createReadStream, existsSync } from 'node:fs'
import { stat } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import path from 'node:path'
import { blake3 } from '@noble/hashes/blake3'
import { bytesToHex } from '@noble/hashes/utils'
import type { ForestDB } from './db.js'
import type { ForestWalker } from './walker.js'
import { linkFileToPrimary } from './pvfs-trees.js'
import { createNode, createLink } from './signer.js'
import { serializePayload } from './cipher.js'
import type {
  TruthNode, PvfsFilePayload, PvfsLocationPayload, PvfsIntegrityFailurePayload,
} from './types.js'

export interface VerifyResult {
  passed:        boolean
  expected_hash: string
  actual_hash:   string | null
  error:         string | null
}

export interface IntegrityFailureRecord {
  failureNode: TruthNode
  fileNodeId:  string
  linkId:      string   // the suspended file link
}

export class PVFSVerifier {
  constructor(
    private db: ForestDB,
    private walker: ForestWalker,
    private authorPubKey: string,
    private privKeyHex: string,
    private encKey: Uint8Array,
    private storeDir: string = '',
  ) {}

  // Verify a file by reading bytes from the given location and checking BLAKE3 hash.
  async verify(fileNodeId: string, locationUri: string): Promise<VerifyResult> {
    const fileNode = this.db.getNode(fileNodeId)
    if (!fileNode) return { passed: false, expected_hash: '', actual_hash: null, error: 'file node not found' }

    const payload = fileNode.payload as PvfsFilePayload
    const expected = payload.content_hash

    let actualHash: string | null = null
    try {
      actualHash = await this.hashUri(locationUri)
    } catch (err) {
      return { passed: false, expected_hash: expected, actual_hash: null, error: String(err) }
    }

    if (actualHash === expected) {
      return { passed: true, expected_hash: expected, actual_hash: actualHash, error: null }
    }

    return { passed: false, expected_hash: expected, actual_hash: actualHash, error: null }
  }

  // Record an integrity failure: append an immutable failure node and suspend the file link.
  async recordFailure(
    fileNodeId: string,
    locationNodeId: string,
    expectedHash: string,
    actualHash: string,
  ): Promise<IntegrityFailureRecord> {
    const now = Date.now()

    const rawFailurePayload: PvfsIntegrityFailurePayload = {
      file_node_id:     fileNodeId,
      location_node_id: locationNodeId,
      expected_hash:    expectedHash,
      actual_hash:      actualHash,
      detected_at:      now,
    }
    const failureNode = await createNode({
      type: 'pvfs.integrity_failure',
      label: `Integrity failure: ${fileNodeId.slice(0, 12)}`,
      visibility: 'private',
      payload: serializePayload(rawFailurePayload, 'private', this.encKey),
      created_at: now,
      author: this.authorPubKey,
    }, this.privKeyHex)

    this.db.insertNode(failureNode)

    // Suspend the file link so the file cannot be served.
    const fileLinks = this.db.getParentLinks(fileNodeId)
      .filter(l => l.link_type === 'file' && !l.removed_at)
    const suspendedLinkId = fileLinks[0]?.id ?? ''
    if (suspendedLinkId) {
      this.db.suspendLink(suspendedLinkId)
    }

    return { failureNode, fileNodeId, linkId: suspendedLinkId }
  }

  // Accept replacement: append a new pvfs.file node with the new hash,
  // create a new file link from the same media parent, supersede the old link.
  async acceptReplacement(
    oldFileNodeId: string,
    newHash: string,
    sizeBytes: number,
    mimeType: string,
    originalFilename: string | null,
  ): Promise<TruthNode> {
    const oldNode = this.db.getNode(oldFileNodeId)
    if (!oldNode) throw new Error('file node not found')

    const now = Date.now()
    const newFileNode = await createNode({
      type: 'pvfs.file',
      label: oldNode.label,
      visibility: 'public',
      payload: {
        content_hash:      newHash,
        size_bytes:        sizeBytes,
        mime_type:         mimeType,
        original_filename: originalFilename,
      } satisfies PvfsFilePayload,
      created_at: now,
      author: this.authorPubKey,
    }, this.privKeyHex)

    this.db.insertNode(newFileNode)

    // Find the suspended file link and re-wire it to the new node.
    const oldLinks = this.db.getParentLinks(oldFileNodeId).filter(l => l.link_type === 'file')
    for (const oldLink of oldLinks) {
      if (!oldLink.parent_id) continue
      const newLink = await createLink({
        parent_id:    oldLink.parent_id,
        child_id:     newFileNode.id,
        link_type:    'file',
        truth_score:  oldLink.truth_score,
        sort_key:     oldLink.sort_key,
        score_method: oldLink.score_method,
        created_at:   now,
        author:       this.authorPubKey,
      }, this.privKeyHex)

      this.db.insertLink(newLink)
      this.db.supersedeLink(oldLink.id, newLink.id)
    }

    return newFileNode
  }

  // Mark a location as needing restore — unsuspend only if a passing verify clears it.
  // The caller is responsible for triggering actual file restoration externally.
  markForRestore(_fileNodeId: string): void {
    // Currently a no-op placeholder — restoration triggers re-verify externally.
    // When re-verify passes, suspendedLink will be cleared via unsuspendLink().
  }

  // Clear suspension after a successful re-verify.
  clearSuspension(linkId: string): void {
    this.db.unsuspendLink(linkId)
  }

  // ─── Ingest ──────────────────────────────────────────────────────────────────

  // Record a pointer to a local file — creates pvfs.file + pvfs.location nodes
  // pointing to the file's existing path. No copying. Hashing is opt-in only
  // (skip for large NAS libraries — 100TB+ would take days to hash up front).
  async ingest(
    localPath: string,
    opts: { mediaNodeId?: string; mimeType?: string; label?: string; computeHash?: boolean } = {},
  ): Promise<{ fileNode: TruthNode; locationNode: TruthNode; contentHash: string }> {
    const { size: sizeBytes } = await stat(localPath)
    const mimeType = opts.mimeType ?? guessMime(localPath)
    const label = opts.label ?? path.basename(localPath)
    const now = Date.now()

    // Hash only when explicitly requested — default is to skip for NAS files
    const contentHash = opts.computeHash ? await this.hashLocalFile(localPath) : ''

    const filePayload: PvfsFilePayload = {
      content_hash: contentHash,
      size_bytes: sizeBytes,
      mime_type: mimeType,
      original_filename: path.basename(localPath),
    }
    const fileNode = await createNode({
      type: 'pvfs.file',
      label,
      visibility: 'public',
      payload: filePayload,
      created_at: now,
      author: this.authorPubKey,
    }, this.privKeyHex)
    this.db.insertNode(fileNode)

    // URI points to the file's real location — no copy needed
    const uri = `file://${localPath}`
    const locationPayload: PvfsLocationPayload = {
      type: 'local',
      uri,
      peer_id: null,
      last_verified: opts.computeHash ? now : null,
      last_seen: now,
    }
    const locationNode = await createNode({
      type: 'pvfs.location',
      label: uri,
      visibility: 'public',
      payload: locationPayload,
      created_at: now,
      author: this.authorPubKey,
    }, this.privKeyHex)
    this.db.insertNode(locationNode)

    this.db.insertLink(await createLink({
      parent_id: fileNode.id, child_id: locationNode.id,
      link_type: 'member', truth_score: 1.0,
      sort_key: null, score_method: null,
      created_at: now, author: this.authorPubKey,
    }, this.privKeyHex))

    if (opts.mediaNodeId) {
      this.db.insertLink(await createLink({
        parent_id: opts.mediaNodeId, child_id: fileNode.id,
        link_type: 'file', truth_score: 1.0,
        sort_key: null, score_method: null,
        created_at: now, author: this.authorPubKey,
      }, this.privKeyHex))
    }

    await linkFileToPrimary(
      this.db, this.walker, this.authorPubKey, this.privKeyHex, this.encKey,
      fileNode.id, path.basename(localPath),
    )

    return { fileNode, locationNode, contentHash }
  }

  // ─── Hash utilities ──────────────────────────────────────────────────────────

  // Hash a file at a local path or HTTP URL. Returns BLAKE3 hex.
  private async hashUri(uri: string): Promise<string> {
    if (uri.startsWith('pvfs-local:')) {
      if (!this.storeDir) throw new Error('storeDir not configured')
      return this.hashLocalFile(path.join(this.storeDir, uri.slice('pvfs-local:'.length)))
    }
    if (uri.startsWith('file://')) {
      return this.hashLocalFile(uri.slice('file://'.length))
    }
    if (uri.startsWith('http://') || uri.startsWith('https://')) {
      return this.hashHttpStream(uri)
    }
    return this.hashLocalFile(uri)
  }

  private async hashLocalFile(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const stream = createReadStream(filePath)
      const hasher = blake3.create({})
      stream.on('data', (chunk: Buffer | string) => {
        hasher.update(typeof chunk === 'string' ? Buffer.from(chunk) : chunk)
      })
      stream.on('end', () => resolve(bytesToHex(hasher.digest())))
      stream.on('error', reject)
    })
  }

  private async hashHttpStream(url: string): Promise<string> {
    const resp = await fetch(url)
    if (!resp.ok) throw new Error(`HTTP ${resp.status} fetching ${url}`)
    const buf = await resp.arrayBuffer()
    return bytesToHex(blake3(new Uint8Array(buf)))
  }
}

function guessMime(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase()
  const map: Record<string, string> = {
    '.mkv': 'video/x-matroska',
    '.mp4': 'video/mp4',
    '.m4v': 'video/x-m4v',
    '.avi': 'video/x-msvideo',
    '.mov': 'video/quicktime',
    '.webm': 'video/webm',
    '.ts': 'video/mp2t',
    '.mp3': 'audio/mpeg',
    '.flac': 'audio/flac',
    '.aac': 'audio/aac',
    '.m4a': 'audio/mp4',
  }
  return map[ext] ?? 'application/octet-stream'
}
