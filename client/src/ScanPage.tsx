import { useState, useMemo } from 'react'
import { api, UnauthorizedError } from './api'
import type { ScannedFile, ScanResult, IngestResult } from './api'

interface Props {
  onClose: () => void
  onUnauthorized: () => void
}

type FilterKind = 'all' | 'movie' | 'series' | 'unknown'

export default function ScanPage({ onClose, onUnauthorized }: Props) {
  const [dirPath, setDirPath] = useState('/media')
  const [limit, setLimit] = useState('500')
  const [scanning, setScanning] = useState(false)
  const [ingesting, setIngesting] = useState(false)
  const [scanResult, setScanResult] = useState<ScanResult | null>(null)
  const [ingestResult, setIngestResult] = useState<IngestResult | null>(null)
  const [filterKind, setFilterKind] = useState<FilterKind>('all')
  const [filterQuery, setFilterQuery] = useState('')
  const [error, setError] = useState('')

  async function handleScan() {
    setError('')
    setIngestResult(null)
    setScanResult(null)
    setScanning(true)
    try {
      const res = await api.pvfsScan({
        path: dirPath,
        dry_run: true,
        limit: parseInt(limit) || undefined,
      })
      setScanResult(res as ScanResult)
    } catch (e) {
      if (e instanceof UnauthorizedError) { onUnauthorized(); return }
      setError(e instanceof Error ? e.message : 'Scan failed')
    } finally {
      setScanning(false)
    }
  }

  async function handleIngest() {
    if (!scanResult) return
    setError('')
    setIngesting(true)
    try {
      const res = await api.pvfsScan({
        path: dirPath,
        dry_run: false,
        limit: parseInt(limit) || undefined,
      })
      setIngestResult(res as IngestResult)
    } catch (e) {
      if (e instanceof UnauthorizedError) { onUnauthorized(); return }
      setError(e instanceof Error ? e.message : 'Ingest failed')
    } finally {
      setIngesting(false)
    }
  }

  const counts = useMemo(() => {
    if (!scanResult) return { movies: 0, series: 0, unknown: 0 }
    return scanResult.files.reduce(
      (acc, f) => {
        if (f.parsed.kind === 'movie') acc.movies++
        else if (f.parsed.kind === 'series') acc.series++
        else acc.unknown++
        return acc
      },
      { movies: 0, series: 0, unknown: 0 },
    )
  }, [scanResult])

  const filtered = useMemo(() => {
    if (!scanResult) return []
    const q = filterQuery.toLowerCase()
    return scanResult.files.filter(f => {
      if (filterKind !== 'all' && f.parsed.kind !== filterKind) return false
      if (q && !f.parsed.title.toLowerCase().includes(q)) return false
      return true
    })
  }, [scanResult, filterKind, filterQuery])

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 font-sans">
      <header className="border-b border-gray-800 px-6 py-4 flex items-center gap-4">
        <button onClick={onClose} className="text-gray-500 hover:text-gray-300 text-sm">← Back</button>
        <h1 className="text-base font-semibold text-white">Library Scan</h1>
        {scanResult && !ingestResult && (
          <span className="text-xs text-gray-500 ml-2">
            {scanResult.found} files found
            {scanResult.found > filtered.length ? ` · ${filtered.length} shown` : ''}
          </span>
        )}
      </header>

      <div className="max-w-5xl mx-auto px-6 py-6">
        {/* Controls */}
        <div className="flex gap-3 mb-6">
          <input
            value={dirPath}
            onChange={e => setDirPath(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleScan()}
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
            disabled={scanning || ingesting || !dirPath}
            className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-sm text-white rounded-lg px-5 py-2.5 font-medium"
          >
            {scanning ? 'Scanning…' : 'Scan'}
          </button>
        </div>

        {error && <p className="text-red-400 text-sm mb-4">{error}</p>}

        {/* Scan results */}
        {scanResult && !ingestResult && (
          <>
            <div className="flex items-center gap-4 mb-4 flex-wrap">
              <div className="flex gap-3 text-sm">
                <span className="text-blue-400 font-medium">{counts.movies} movies</span>
                <span className="text-purple-400 font-medium">{counts.series} TV</span>
                {counts.unknown > 0 && (
                  <span className="text-gray-500">{counts.unknown} unknown</span>
                )}
              </div>
              <div className="ml-auto">
                <button
                  onClick={handleIngest}
                  disabled={ingesting || scanResult.found === 0}
                  className="bg-green-700 hover:bg-green-600 disabled:opacity-50 text-sm text-white rounded-lg px-4 py-2 font-medium"
                >
                  {ingesting ? 'Ingesting…' : `Ingest All (${scanResult.found})`}
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
                    {k === 'all' ? `All (${scanResult.found})` : k === 'movie' ? `Movies (${counts.movies})` : k === 'series' ? `TV (${counts.series})` : `Unknown (${counts.unknown})`}
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
              {filtered.map((f, i) => (
                <FileRow key={i} file={f} />
              ))}
              {filtered.length === 0 && (
                <div className="text-center text-gray-600 py-12 text-sm">No files match filter</div>
              )}
            </div>
          </>
        )}

        {/* Ingest results */}
        {ingestResult && (
          <div className="space-y-4">
            <div className="bg-gray-900 border border-gray-700 rounded-lg p-5">
              <div className="text-base font-semibold text-white mb-3">Ingestion complete</div>
              <div className="flex gap-6 text-sm">
                <div>
                  <span className="text-2xl font-bold text-green-400">{ingestResult.ingested}</span>
                  <span className="text-gray-500 ml-2">ingested</span>
                </div>
                {ingestResult.failed > 0 && (
                  <div>
                    <span className="text-2xl font-bold text-red-400">{ingestResult.failed}</span>
                    <span className="text-gray-500 ml-2">failed</span>
                  </div>
                )}
              </div>
            </div>

            {ingestResult.failures?.length > 0 && (
              <div>
                <p className="text-xs text-gray-500 font-semibold uppercase tracking-wider mb-2">Failures</p>
                <div className="space-y-1">
                  {ingestResult.failures.map((f, i) => (
                    <div key={i} className="bg-gray-900 border border-red-900/50 rounded px-3 py-2">
                      <div className="text-xs text-gray-400 font-mono truncate">{f.path}</div>
                      <div className="text-xs text-red-400 mt-0.5">{f.error}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <button
              onClick={() => { setIngestResult(null); setScanResult(null) }}
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
