/**
 * Directory scan jobs — persisted in forest.db (SQLite).
 */

import { existsSync } from 'node:fs'
import { readdir, stat } from 'node:fs/promises'
import path from 'node:path'
import { randomBytes } from 'node:crypto'
import type { ForestDB } from './db.js'
import type { PVFSVerifier } from './pvfs.js'

const DEFAULT_VIDEO_EXTENSIONS = new Set([
  '.mkv', '.mp4', '.m4v', '.avi', '.mov', '.webm',
  '.ts', '.m2ts', '.mpg', '.mpeg', '.wmv', '.flv', '.vob',
])

export interface ScanJobFile {
  path: string
  size_bytes: number
  ext: string
  already_ingested?: boolean
  file_node_id?: string
  content_hash?: string
  error?: string
}

export interface ScanJob {
  id: string
  status: 'running' | 'done' | 'error'
  startedAt: number
  finishedAt?: number
  dry_run: boolean
  root_path: string
  found: number
  new_count?: number
  already_ingested_count?: number
  ingested?: number
  failed?: number
  files: ScanJobFile[]
  failures?: Array<{ path: string; error: string }>
  error?: string
}

function rowToJob(row: import('./db.js').PvfsScanJobRow): ScanJob {
  return {
    id: row.id,
    status: row.status,
    startedAt: row.started_at,
    finishedAt: row.finished_at ?? undefined,
    dry_run: row.dry_run,
    root_path: row.root_path,
    found: row.found,
    new_count: row.new_count ?? undefined,
    already_ingested_count: row.already_ingested_count ?? undefined,
    ingested: row.ingested ?? undefined,
    failed: row.failed ?? undefined,
    files: row.files_json ? JSON.parse(row.files_json) as ScanJobFile[] : [],
    failures: row.failures_json ? JSON.parse(row.failures_json) as Array<{ path: string; error: string }> : undefined,
    error: row.error ?? undefined,
  }
}

function persistJob(db: ForestDB, job: ScanJob, patch: Partial<import('./db.js').PvfsScanJobRow> = {}): void {
  db.updateScanJob(job.id, {
    status: job.status,
    finished_at: job.finishedAt ?? null,
    found: job.found,
    new_count: job.new_count ?? null,
    already_ingested_count: job.already_ingested_count ?? null,
    ingested: job.ingested ?? null,
    failed: job.failed ?? null,
    files_json: JSON.stringify(job.files),
    failures_json: job.failures ? JSON.stringify(job.failures) : null,
    error: job.error ?? null,
    ...patch,
  })
}

export function getScanJob(db: ForestDB, jobId: string): ScanJob | undefined {
  const row = db.getScanJob(jobId)
  return row ? rowToJob(row) : undefined
}

async function walkVideoFiles(
  dirPath: string,
  extSet: Set<string> | undefined,
  limit: number | undefined,
  onFile: (file: ScanJobFile) => void,
): Promise<void> {
  let count = 0
  async function walk(dir: string): Promise<void> {
    if (limit !== undefined && count >= limit) return
    const entries = await readdir(dir, { withFileTypes: true })
    for (const ent of entries) {
      if (limit !== undefined && count >= limit) return
      const full = path.join(dir, ent.name)
      if (ent.isDirectory()) {
        await walk(full)
        continue
      }
      if (!ent.isFile()) continue
      const ext = path.extname(ent.name).toLowerCase()
      if (extSet && !extSet.has(ext)) continue
      const st = await stat(full)
      onFile({ path: full, size_bytes: st.size, ext })
      count++
    }
  }
  await walk(dirPath)
}

export function startScanJob(
  db: ForestDB,
  opts: {
    rootPath: string
    dryRun: boolean
    extensions?: string[]
    limit?: number
    computeHash?: boolean
    ingestedUris: Set<string>
    pvfs: PVFSVerifier
  },
): string {
  const jobId = randomBytes(16).toString('hex')
  const extSet = opts.extensions
    ? new Set(opts.extensions.map(e => (e.startsWith('.') ? e : `.${e}`).toLowerCase()))
    : DEFAULT_VIDEO_EXTENSIONS

  const job: ScanJob = {
    id: jobId,
    status: 'running',
    startedAt: Date.now(),
    dry_run: opts.dryRun,
    root_path: opts.rootPath,
    found: 0,
    files: [],
  }

  db.insertScanJob({
    id: jobId,
    status: 'running',
    started_at: job.startedAt,
    dry_run: opts.dryRun,
    root_path: opts.rootPath,
    found: 0,
    files_json: '[]',
  })

  ;(async () => {
    try {
      const files: ScanJobFile[] = []
      await walkVideoFiles(opts.rootPath, extSet, opts.limit, (f) => {
        f.already_ingested = opts.ingestedUris.has(`file://${f.path}`)
        files.push(f)
        job.found = files.length
        persistJob(db, job)
      })

      if (opts.dryRun) {
        job.files = files
        job.new_count = files.filter(f => !f.already_ingested).length
        job.already_ingested_count = files.length - (job.new_count ?? 0)
        job.status = 'done'
        job.finishedAt = Date.now()
        persistJob(db, job)
        return
      }

      const failures: Array<{ path: string; error: string }> = []
      let ingested = 0
      for (const file of files) {
        if (file.already_ingested) continue
        try {
          const result = await opts.pvfs.ingest(file.path, {
            label: path.basename(file.path),
            computeHash: opts.computeHash ?? false,
          })
          file.file_node_id = result.fileNode.id
          file.content_hash = result.contentHash
          ingested++
        } catch (err) {
          failures.push({
            path: file.path,
            error: err instanceof Error ? err.message : 'ingest failed',
          })
        }
        persistJob(db, job)
      }

      job.files = files
      job.new_count = files.filter(f => !f.already_ingested).length
      job.already_ingested_count = files.filter(f => f.already_ingested).length
      job.ingested = ingested
      job.failed = failures.length
      job.failures = failures
      job.status = 'done'
      job.finishedAt = Date.now()
      persistJob(db, job)
    } catch (err) {
      job.error = err instanceof Error ? err.message : 'scan failed'
      job.status = 'error'
      job.finishedAt = Date.now()
      persistJob(db, job)
    }
  })()

  return jobId
}

export function buildIngestedUriSet(
  nodes: Array<{ payload: { uri?: string | null } }>,
): Set<string> {
  const set = new Set<string>()
  for (const n of nodes) {
    if (n.payload?.uri) set.add(n.payload.uri)
  }
  return set
}

export function validateScanPath(dirPath: string): string | null {
  if (!dirPath) return 'path is required'
  if (!existsSync(dirPath)) return `directory not found: ${dirPath}`
  return null
}