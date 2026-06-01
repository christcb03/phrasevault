import { useState, useMemo, useEffect, useRef } from 'react'
import { api, UnauthorizedError } from './api'
import type { ScannedFile } from './api'

interface Props {
  onClose: () => void
  onUnauthorized: () => void
}

type FilterKind = 'all' | 'movie' | 'series' | 'unknown'

type JobResult = {
  status: 'running' | 'done' | 'error'
  found: number
  dry_run: boolean
  files: ScannedFile[]
  ingested?: number
  failed?: number
  failures?: Array<{ path: string; error: string }>
  error?: string
}

export default function ScanPage({ onClose, onUnauthorized }: Props) {
  const [dirPath, setDirPath] = useState('/media')
  const [limit, setLimit] = useState('500')
  const [busy, setBusy] = useState(false)
  const [jobResult, setJobResult] = useState<JobResult | null>(null)
  const [isIngesting, setIsIngesting] = useState(false)
  const [filterKind, setFilterKind] = useState<FilterKind>('all')
  const [filterQuery, setFilterQuery] = useState('')
  const [error, setError] = useState('')
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current) }, [])

  function startPolling(jobId: string, onDone: (result: JobResult) => void) {
    pollRef.current = setInterval(async () => {
      try {
        const res = await api.pvfsScanJob(jobId)
        if (res.status !== 'running') {
          clearInterval(pollRef.current!)
          pollRef.current = null
          onDone(res as JobResult)
        } else {
          setJobResult(res as JobResult)
        }
      } catch (e) {
        clearInterval(pollRef.current!)
        pollRef.current = null
        if (e instanceof UnauthorizedError) onUnauthorized()
        else setError(e instanceof Error ? e.message : 'Poll failed')
        setBusy(false)
        setIsIngesting(false)
      }
    }, 2000)
  }

  async function handleScan() {
    setError('')
    setJobResult(null)
    setBusy(true)
    try {
      const { jobId } = await api.pvfsScan({ path: dirPath, dry_run: true, limit: parseInt(limit) || undefined })
      startPolling(jobId, result => {
        setBusy(false)
        if (result.status === 'error') setError(result.error ?? 'Scan failed')
        else setJobResult(result)
      })
    } catch (e) {
      setBusy(false)
      if (e instanceof UnauthorizedError) { onUnauthorized(); return }
      setError(e instanceof Error ? e.message : 'Scan failed')
    }
  }

  async function handleIngest() {
    setError('')
    setIsIngesting(true)
    setBusy(true)
    try {
      const { jobId } = await api.pvfsScan({ path: dirPath, dry_run: false, limit: parseInt(limit) || undefined })
      startPolling(jobId, result => {
        setBusy(false)
        setIsIngesting(false)
        if (result.status === 'error') setError(result.error ?? 'Ingest failed')
        else setJobResult(result)
      })
    } catch (e) {
      setBusy(false)
      setIsIngesting(false)
      if (e instanceof UnauthorizedError) { onUnauthorized(); return }
      setError(e instanceof Error ? e.message : 'Ingest failed')
    }
  }

  const isDryRunDone = jobResult?.status === 'done' && jobResult.dry_run
  const isIngestDone = jobResult?.status === 'done' && !jobResult.dry_run

  const counts = useMemo(() => {
    if (!isDryRunDone || !jobResult) return { movies: 0, series: 0, unknown: 0 }
    return jobResult.files.reduce(
      (acc, f) => {
        if (f.parsed.kind === 'movie') acc.movies++
        else if (f.parsed.kind === 'series') acc.series++
        else acc.unknown++
        return acc
      },
      { movies: 0, series: 0, unknown: 0 },
    )
  }, [jobResult, isDryRunDone])

  const filtered = useMemo(() => {
    if (!isDryRunDone || !jobResult) return []
    const q = filterQuery.toLowerCase()
    return jobResult.files.filter(f => {
      if (filterKind !== 'all' && f.parsed.kind !== filterKind) return false
      if (q && !f.parsed.title.toLowerCase().includes(q)) return false
      return true
    })
  }, [jobResult, isDryRunDone, filterKind, filterQuery])

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 font-sans">
      <header className="border-b border-gray-800 px-6 py-4 flex items-center gap-4">
        <button onClick={onClose} className="text-gray-500 hover:text-gray-300 text-sm">← Back</button>
        <h1 className="text-base font-semibold text-white">Library Scan</h1>
        {busy && jobResult && (
          <span className="text-xs text-gray-500 ml-2 animate-pulse">
            {isIngesting ? 'Ingesting' : 'Scanning'} — {jobResult.found} found…
          </span>
        )}
        {isDryRunDone && (
          <span className="text-xs text-gray-500 ml-2">
            {jobResult!.found} files
            {jobResult!.found > filtered.length ? ` · ${filtered.length} shown` : ''}
          </span>
        )}
      </header>

      <div className="max-w-5xl mx-auto px-6 py-6">
        {/* Controls */}
        <div className="flex gap-3 mb-6">
          <input
            value={dirPath}
            onChange={e => setDirPath(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && !busy && handleScan()}
            placeholder="/media"
            className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:border-indigo-500 font-mono"
          />
          <input
            type="number"
            value={limit}
            onChange={e => setLimit(e.target.value)}
            placeholder="Limit"
            title="Max files to return"
            className="w-24 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-indigo-500 text-center"
          />
          <button
            onClick={handleScan}
            disabled={busy || !dirPath}
            className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-sm text-white rounded-lg px-5 py-2.5 font-medium"
          >
            {busy && !isIngesting ? 'Scanning…' : 'Scan'}
          </button>
        </div>

        {error && <p className="text-red-400 text-sm mb-4">{error}</p>}

        {/* Scanning progress */}
        {busy && !isIngesting && (
          <div className="text-center text-gray-500 py-12 text-sm animate-pulse">
            Scanning {dirPath}…{jobResult ? ` (${jobResult.found} files found so far)` : ''}
          </div>
        )}
        {busy && isIngesting && (
          <div className="text-center text-gray-500 py-12 text-sm animate-pulse">
            Ingesting… {jobResult ? `${jobResult.found} done` : ''}
          </div>
        )}

        {/* Dry scan results */}
        {isDryRunDone && jobResult && (
          <>
            <div className="flex items-center gap-4 mb-4 flex-wrap">
              <div className="flex gap-3 text-sm">
                <span className="text-blue-400 font-medium">{counts.movies} movies</span>
                <span className="text-purple-400 font-medium">{counts.series} TV</span>
                {counts.unknown > 0 && <span className="text-gray-500">{counts.unknown} unknown</span>}
              </div>
              <div className="ml-auto">
                <button
                  onClick={handleIngest}
                  disabled={busy || jobResult.found === 0}
                  className="bg-green-700 hover:bg-green-600 disabled:opacity-50 text-sm text-white rounded-lg px-4 py-2 font-medium"
                >
                  Ingest All ({jobResult.found})
                </button>
              </div>
            </div>

            <div className="flex gap-2 mb-4">
              <div className="flex rounded-lg overflow-hidden border border-gray-700 shrink-0">
                {(['all', 'movie', 'series', 'unknown'] as const).map(k => (
                  <button
                    key={k}
                    onClick={() => setFilterKind(k)}
                    className={`text-xs px-3 py-1.5 transition-colors ${
                      filterKind === k ? 'bg-gray-700 text-white' : 'bg-gray-800 text-gray-400 hover:text-white'
                    }`}
                  >
                    {k === 'all' ? `All (${jobResult.found})` : k === 'movie' ? `Movies (${counts.movies})` : k === 'series' ? `TV (${counts.series})` : `Unknown (${counts.unknown})`}
                  </button>
                ))}
              </div>
              <input
                value={filterQuery}
                onChange={e => setFilterQuery(e.target.value)}
                placeholder="Filter by title…"
                className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div className="space-y-0.5">
              {filtered.map((f, i) => <FileRow key={i} file={f} />)}
              {filtered.length === 0 && (
                <div className="text-center text-gray-600 py-12 text-sm">No files match filter</div>
              )}
            </div>
          </>
        )}

        {/* Ingest results */}
        {isIngestDone && jobResult && (
          <div className="space-y-4">
            <div className="bg-gray-900 border border-gray-700 rounded-lg p-5">
              <div className="text-base font-semibold text-white mb-3">Ingestion complete</div>
              <div className="flex gap-6 text-sm">
                <div>
                  <span className="text-2xl font-bold text-green-400">{jobResult.ingested}</span>
                  <span className="text-gray-500 ml-2">ingested</span>
                </div>
                {(jobResult.failed ?? 0) > 0 && (
                  <div>
                    <span className="text-2xl font-bold text-red-400">{jobResult.failed}</span>
                    <span className="text-gray-500 ml-2">failed</span>
                  </div>
                )}
              </div>
            </div>
            {jobResult.failures && jobResult.failures.length > 0 && (
              <div>
                <p className="text-xs text-gray-500 font-semibold uppercase tracking-wider mb-2">Failures</p>
                <div className="space-y-1">
                  {jobResult.failures.map((f, i) => (
                    <div key={i} className="bg-gray-900 border border-red-900/50 rounded px-3 py-2">
                      <div className="text-xs text-gray-400 font-mono truncate">{f.path}</div>
                      <div className="text-xs text-red-400 mt-0.5">{f.error}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
            <button
              onClick={() => setJobResult(null)}
              className="text-sm text-indigo-400 hover:text-indigo-300"
            >
              ← Scan another directory
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

function FileRow({ file }: { file: ScannedFile }) {
  const { parsed } = file

  const kindLabel =
    parsed.kind === 'series' && parsed.season != null
      ? `S${String(parsed.season).padStart(2, '0')}E${String(parsed.episode ?? 0).padStart(2, '0')}`
      : parsed.kind

  const kindColor =
    parsed.kind === 'movie' ? 'bg-blue-900 text-blue-300'
    : parsed.kind === 'series' ? 'bg-purple-900 text-purple-300'
    : 'bg-gray-800 text-gray-500'

  const fileName = file.path.split('/').slice(-2).join('/')

  return (
    <div className="flex items-center gap-3 px-3 py-2 rounded hover:bg-gray-900 transition-colors group">
      <span className={`text-xs rounded px-1.5 py-0.5 shrink-0 font-mono ${kindColor}`}>
        {kindLabel}
      </span>
      <div className="flex-1 min-w-0">
        <span className="text-sm text-white">{parsed.title || '(unknown)'}</span>
        {parsed.year && <span className="text-xs text-gray-500 ml-2">{parsed.year}</span>}
      </div>
      <span
        className="text-xs text-gray-700 group-hover:text-gray-500 truncate max-w-xs hidden md:block font-mono"
        title={file.path}
      >
        …/{fileName}
      </span>
      <span className="text-xs text-gray-600 shrink-0 tabular-nums">
        {(file.size_bytes / 1e9).toFixed(1)} GB
      </span>
    </div>
  )
}
