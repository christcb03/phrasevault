import { useState, useMemo, useEffect, useRef, useCallback } from 'react'
import { api, UnauthorizedError } from './api'
import type { ScannedFile, MatchCandidate, MatchSource, ImportItem } from './api'

interface Props {
  onClose: () => void
  onUnauthorized: () => void
}

// ── Data structures ─────────────────────────────────────────────────────────

interface ShowGroup {
  title: string
  seasons: Map<number, ScannedFile[]>                 // season → episodes
  localArtwork: string | null
  totalFiles: number
  alreadyImported: boolean                             // all files already imported
}

interface MatchState {
  status: 'pending' | 'done' | 'error'
  candidates: MatchCandidate[]
  selected: MatchCandidate | null
  needsReview: boolean
  confirmed: boolean                                   // user explicitly accepted
  overriding: boolean                                  // search override UI open
  overrideQuery: string
}

type Phase = 'idle' | 'scanning' | 'ready' | 'importing' | 'done'

const TMDB_IMG = 'https://image.tmdb.org/t/p/w92'

// ── Helpers ─────────────────────────────────────────────────────────────────

function groupShows(files: ScannedFile[]): ShowGroup[] {
  const map = new Map<string, ShowGroup>()
  for (const f of files) {
    const title = f.parsed.title || '(unknown)'
    if (!map.has(title)) {
      map.set(title, {
        title,
        seasons: new Map(),
        localArtwork: f.local_artwork ?? null,
        totalFiles: 0,
        alreadyImported: true,
      })
    }
    const g = map.get(title)!
    const sn = f.parsed.season ?? 0
    if (!g.seasons.has(sn)) g.seasons.set(sn, [])
    g.seasons.get(sn)!.push(f)
    g.totalFiles++
    if (!f.already_ingested) g.alreadyImported = false
    // Prefer a file with local artwork to set the group poster
    if (!g.localArtwork && f.local_artwork) g.localArtwork = f.local_artwork
  }
  return [...map.values()].sort((a, b) => a.title.localeCompare(b.title))
}

function confidenceColor(c: number): string {
  if (c >= 0.9) return 'text-green-400'
  if (c >= 0.8) return 'text-yellow-400'
  return 'text-red-400'
}

// ── Component ────────────────────────────────────────────────────────────────

export default function ScanPage({ onClose, onUnauthorized }: Props) {
  const [dirPath, setDirPath] = useState('/media/Movies')
  const [limit, setLimit] = useState('5000')
  const [phase, setPhase] = useState<Phase>('idle')
  const [scanProgress, setScanProgress] = useState(0)
  const [scanFiles, setScanFiles] = useState<ScannedFile[]>([])
  const [newCount, setNewCount] = useState(0)
  const [alreadyCount, setAlreadyCount] = useState(0)
  const [error, setError] = useState('')
  const [importResult, setImportResult] = useState<{ imported: number; failed: number } | null>(null)

  // Show/movie selection: key = title, value = selected season numbers (null = all, empty Set = none)
  const [selectedShows, setSelectedShows] = useState<Map<string, Set<number> | null>>(new Map())
  const [selectedMovies, setSelectedMovies] = useState<Set<string>>(new Set())

  // Match state per title
  const [matchStates, setMatchStates] = useState<Map<string, MatchState>>(new Map())
  const [matchingProgress, setMatchingProgress] = useState({ done: 0, total: 0 })
  const [threshold] = useState(0.8)

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const matchedTitlesRef = useRef(new Set<string>())   // keys already submitted for matching
  const matchInFlightRef = useRef(false)                // one match request at a time
  const pendingMatchRef = useRef<Array<{ title: string; year: number | null; kind: 'movie' | 'series' | 'unknown' }>>([])

  const detectedKind = useMemo(() => {
    const tv = scanFiles.filter(f => f.parsed.kind === 'series').length
    const movie = scanFiles.filter(f => f.parsed.kind === 'movie').length
    return tv > movie ? 'series' : 'movie'
  }, [scanFiles])

  const shows = useMemo(() =>
    groupShows(scanFiles.filter(f => f.parsed.kind === 'series' || f.parsed.kind === 'unknown' && detectedKind === 'series')),
    [scanFiles, detectedKind],
  )
  const movies = useMemo(() =>
    scanFiles.filter(f => f.parsed.kind === 'movie'),
    [scanFiles],
  )

  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current) }, [])

  // ── Scan ──────────────────────────────────────────────────────────────────

  // Fire a batch match request for queued titles. Serialized so only one is
  // in flight at a time — prevents concurrent TMDB rate-limit collisions.
  const flushMatchQueue = useCallback(async () => {
    if (matchInFlightRef.current || pendingMatchRef.current.length === 0) return
    matchInFlightRef.current = true
    const batch = pendingMatchRef.current.splice(0)  // drain queue
    const total = batch.length

    // Initialize all as pending
    setMatchStates(prev => {
      const next = new Map(prev)
      for (const q of batch) {
        const key = `${q.title}::${q.kind}`
        if (!next.has(key)) {
          next.set(key, { status: 'pending', candidates: [], selected: null, needsReview: true, confirmed: false, overriding: false, overrideQuery: '' })
        }
      }
      return next
    })
    setMatchingProgress(p => ({ done: p.done, total: p.total + total }))

    // Process in chunks of 20 to keep each server request manageable
    const CHUNK = 20
    for (let i = 0; i < batch.length; i += CHUNK) {
      const chunk = batch.slice(i, i + CHUNK)
      try {
        const { results } = await api.matchSearch({ items: chunk, threshold })
        setMatchStates(prev => {
          const next = new Map(prev)
          chunk.forEach((q, idx) => {
            const r = results[idx]
            const key = `${q.title}::${q.kind}`
            if (r) {
              next.set(key, {
                status: 'done',
                candidates: r.candidates,
                selected: r.best,
                needsReview: r.needs_review,
                confirmed: !r.needs_review,
                overriding: false,
                overrideQuery: '',
              })
            }
          })
          return next
        })
      } catch {
        setMatchStates(prev => {
          const next = new Map(prev)
          chunk.forEach(q => {
            const key = `${q.title}::${q.kind}`
            next.set(key, { ...next.get(key)!, status: 'error' })
          })
          return next
        })
      }
      setMatchingProgress(p => ({ done: p.done + chunk.length, total: p.total }))
    }

    matchInFlightRef.current = false
    // Flush again if more arrived while we were in flight
    if (pendingMatchRef.current.length > 0) flushMatchQueue()
  }, [threshold])

  function queueNewTitlesForMatching(files: ScannedFile[]) {
    const newQueries: typeof pendingMatchRef.current = []
    for (const f of files) {
      if (f.already_ingested) continue
      const key = `${f.parsed.title}::${f.parsed.kind}`
      if (!matchedTitlesRef.current.has(key)) {
        matchedTitlesRef.current.add(key)
        newQueries.push({ title: f.parsed.title, year: f.parsed.year, kind: f.parsed.kind })
      }
    }
    if (newQueries.length > 0) {
      pendingMatchRef.current.push(...newQueries)
      flushMatchQueue()
    }
  }

  async function handleScan() {
    setError('')
    setScanFiles([])
    setSelectedShows(new Map())
    setSelectedMovies(new Set())
    setMatchStates(new Map())
    setMatchingProgress({ done: 0, total: 0 })
    setImportResult(null)
    setPhase('scanning')
    setScanProgress(0)
    matchedTitlesRef.current = new Set()
    pendingMatchRef.current = []
    matchInFlightRef.current = false
    try {
      const { jobId } = await api.pvfsScan({ path: dirPath, dry_run: true, limit: parseInt(limit) || undefined })
      let lastFileCount = 0
      pollRef.current = setInterval(async () => {
        try {
          const res = await api.pvfsScanJob(jobId)
          setScanProgress(res.found)

          // Progressive: show files and start matching as they stream in
          if (res.files.length > lastFileCount) {
            const newFiles = res.files.slice(lastFileCount)
            lastFileCount = res.files.length
            setScanFiles(res.files)
            autoSelectNew(newFiles)
            queueNewTitlesForMatching(newFiles)
          }

          if (res.status !== 'running') {
            clearInterval(pollRef.current!)
            pollRef.current = null
            if (res.status === 'error') {
              setError(res.error ?? 'Scan failed')
              setPhase('idle')
            } else {
              // Final counts from the completed job
              setNewCount(res.new_count ?? res.files.filter(f => !f.already_ingested).length)
              setAlreadyCount(res.already_ingested_count ?? res.files.filter(f => f.already_ingested).length)
              setPhase('ready')
            }
          }
        } catch (e) {
          clearInterval(pollRef.current!)
          pollRef.current = null
          if (e instanceof UnauthorizedError) onUnauthorized()
          else setError(e instanceof Error ? e.message : 'Poll failed')
          setPhase('idle')
        }
      }, 2000)
    } catch (e) {
      setPhase('idle')
      if (e instanceof UnauthorizedError) { onUnauthorized(); return }
      setError(e instanceof Error ? e.message : 'Scan failed')
    }
  }

  // Called incrementally with each new batch of files — merges into existing selection.
  function autoSelectNew(newFiles: ScannedFile[]) {
    setSelectedShows(prev => {
      const next = new Map(prev)
      for (const f of newFiles) {
        if (f.already_ingested || f.parsed.kind !== 'series') continue
        const sn = f.parsed.season ?? 0
        if (!next.has(f.parsed.title)) next.set(f.parsed.title, new Set())
        next.get(f.parsed.title)!.add(sn)
      }
      return next
    })
    setSelectedMovies(prev => {
      const next = new Set(prev)
      for (const f of newFiles) {
        if (!f.already_ingested && f.parsed.kind === 'movie') next.add(f.path)
      }
      return next
    })
  }


  // ── Override search ────────────────────────────────────────────────────────

  async function runOverrideSearch(title: string, kind: 'movie' | 'series' | 'unknown', query: string) {
    const key = `${title}::${kind}`
    setMatchStates(prev => {
      const next = new Map(prev)
      next.set(key, { ...next.get(key)!, status: 'pending' })
      return next
    })
    try {
      const { results } = await api.matchSearch({ items: [{ title: query, year: null, kind }], threshold })
      const r = results[0]
      setMatchStates(prev => {
        const next = new Map(prev)
        next.set(key, {
          status: 'done',
          candidates: r?.candidates ?? [],
          selected: r?.best ?? null,
          needsReview: r ? r.needs_review : true,
          confirmed: false,
          overriding: false,
          overrideQuery: '',
        })
        return next
      })
    } catch {
      setMatchStates(prev => {
        const next = new Map(prev)
        next.set(key, { ...next.get(key)!, status: 'error', overriding: false })
        return next
      })
    }
  }

  function setMatchSelected(title: string, kind: 'movie' | 'series' | 'unknown', candidate: MatchCandidate | null) {
    const key = `${title}::${kind}`
    setMatchStates(prev => {
      const next = new Map(prev)
      next.set(key, { ...next.get(key)!, selected: candidate, confirmed: true, overriding: false })
      return next
    })
  }

  function confirmMatch(title: string, kind: 'movie' | 'series' | 'unknown') {
    const key = `${title}::${kind}`
    setMatchStates(prev => {
      const next = new Map(prev)
      next.set(key, { ...next.get(key)!, confirmed: true })
      return next
    })
  }

  function setManualMatch(title: string, kind: 'movie' | 'series' | 'unknown') {
    const key = `${title}::${kind}`
    setMatchStates(prev => {
      const next = new Map(prev)
      next.set(key, { ...next.get(key)!, selected: null, confirmed: true })
      return next
    })
  }

  function toggleOverride(title: string, kind: 'movie' | 'series' | 'unknown') {
    const key = `${title}::${kind}`
    setMatchStates(prev => {
      const next = new Map(prev)
      const cur = next.get(key)!
      next.set(key, { ...cur, overriding: !cur.overriding, overrideQuery: cur.overrideQuery || title })
      return next
    })
  }

  // ── Selection helpers ─────────────────────────────────────────────────────

  function toggleShow(title: string, seasons: Map<number, ScannedFile[]>) {
    setSelectedShows(prev => {
      const next = new Map(prev)
      if (next.has(title)) {
        next.delete(title)
      } else {
        next.set(title, new Set([...seasons.keys()]))
      }
      return next
    })
  }

  function toggleSeason(title: string, seasonNum: number, allSeasons: Map<number, ScannedFile[]>) {
    setSelectedShows(prev => {
      const next = new Map(prev)
      const cur = new Set(next.get(title) ?? [...allSeasons.keys()])
      if (cur.has(seasonNum)) {
        cur.delete(seasonNum)
      } else {
        cur.add(seasonNum)
      }
      if (cur.size === 0) next.delete(title)
      else next.set(title, cur)
      return next
    })
  }

  function toggleMovie(filePath: string) {
    setSelectedMovies(prev => {
      const next = new Set(prev)
      if (next.has(filePath)) next.delete(filePath)
      else next.add(filePath)
      return next
    })
  }

  // ── Import ────────────────────────────────────────────────────────────────

  const unconfirmedNeedsReview = useMemo(() => {
    let count = 0
    for (const title of [...selectedShows.keys()]) {
      const kind = shows.find(s => s.title === title) ? 'series' : 'unknown'
      const ms = matchStates.get(`${title}::${kind}`) ?? matchStates.get(`${title}::unknown`)
      if (ms?.needsReview && !ms.confirmed) count++
    }
    for (const filePath of selectedMovies) {
      const f = movies.find(m => m.path === filePath)
      if (!f) continue
      const ms = matchStates.get(`${f.parsed.title}::movie`) ?? matchStates.get(`${f.parsed.title}::unknown`)
      if (ms?.needsReview && !ms.confirmed) count++
    }
    return count
  }, [selectedShows, selectedMovies, matchStates, shows, movies])

  async function handleImport() {
    if (unconfirmedNeedsReview > 0) {
      if (!window.confirm(`${unconfirmedNeedsReview} item(s) have low-confidence matches and haven't been confirmed. Import anyway?`)) return
    }

    setPhase('importing')
    const items: ImportItem[] = []

    // Shows
    for (const [title, seasonSet] of selectedShows) {
      const group = shows.find(s => s.title === title)
      if (!group) continue
      const ms = matchStates.get(`${title}::series`) ?? matchStates.get(`${title}::unknown`)
      const matchSrc = buildMatchSource(ms, title, 'series')
      const selectedSeasons = seasonSet ? [...seasonSet] : null
      const files: ScannedFile[] = []
      for (const [sn, eps] of group.seasons) {
        if (!selectedSeasons || selectedSeasons.includes(sn)) files.push(...eps)
      }
      items.push({ kind: 'series', files, selected_seasons: selectedSeasons, match: matchSrc })
    }

    // Movies
    for (const filePath of selectedMovies) {
      const f = movies.find(m => m.path === filePath)
      if (!f) continue
      const ms = matchStates.get(`${f.parsed.title}::movie`) ?? matchStates.get(`${f.parsed.title}::unknown`)
      const matchSrc = buildMatchSource(ms, f.parsed.title, 'movie')
      items.push({ kind: 'movie', files: [f], match: matchSrc })
    }

    try {
      const result = await api.importBatch({ items })
      setImportResult({ imported: result.imported, failed: result.failed })
      setPhase('done')
    } catch (e) {
      if (e instanceof UnauthorizedError) { onUnauthorized(); return }
      setError(e instanceof Error ? e.message : 'Import failed')
      setPhase('ready')
    }
  }

  function buildMatchSource(ms: MatchState | undefined, title: string, kind: 'movie' | 'series'): MatchSource {
    if (ms?.selected) {
      return {
        source: 'tmdb',
        tmdb_id: ms.selected.tmdb_id,
        media_type: ms.selected.media_type,
        title: ms.selected.title,
        year: ms.selected.year,
        poster_path: ms.selected.poster_path,
        overview: ms.selected.overview,
      }
    }
    return { source: 'manual', title, year: null, kind }
  }

  // ── Derived counts ────────────────────────────────────────────────────────

  const selectedCount = selectedShows.size + selectedMovies.size
  const matchingDone = matchingProgress.total > 0 && matchingProgress.done >= matchingProgress.total

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 font-sans">
      <header className="border-b border-gray-800 px-6 py-4 flex items-center gap-4">
        <button onClick={onClose} className="text-gray-500 hover:text-gray-300 text-sm">← Back</button>
        <h1 className="text-base font-semibold text-white">Library Import</h1>
        {phase === 'scanning' && (
          <span className="text-xs text-gray-500 ml-2 animate-pulse">Scanning… {scanProgress} files found</span>
        )}
        {phase === 'ready' && matchingProgress.total > 0 && !matchingDone && (
          <span className="text-xs text-gray-500 ml-2 animate-pulse">
            Matching… {matchingProgress.done}/{matchingProgress.total}
          </span>
        )}
        {phase === 'ready' && matchingDone && (
          <span className="text-xs text-gray-500 ml-2">
            {newCount} new · {alreadyCount} already imported
          </span>
        )}
      </header>

      <div className="max-w-6xl mx-auto px-6 py-6">

        {/* Scan controls */}
        <div className="flex gap-3 mb-6">
          <input
            value={dirPath}
            onChange={e => setDirPath(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && phase === 'idle' && handleScan()}
            placeholder="/media"
            disabled={phase !== 'idle' && phase !== 'ready'}
            className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:border-indigo-500 font-mono disabled:opacity-50"
          />
          <input
            type="number"
            value={limit}
            onChange={e => setLimit(e.target.value)}
            placeholder="Limit"
            title="Max files"
            disabled={phase !== 'idle' && phase !== 'ready'}
            className="w-24 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-indigo-500 text-center disabled:opacity-50"
          />
          <button
            onClick={handleScan}
            disabled={phase === 'scanning' || phase === 'importing'}
            className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-sm text-white rounded-lg px-5 py-2.5 font-medium"
          >
            {phase === 'scanning' ? 'Scanning…' : 'Scan'}
          </button>
          {phase === 'ready' && selectedCount > 0 && (
            <button
              onClick={handleImport}
              disabled={phase !== 'ready'}
              className="bg-green-700 hover:bg-green-600 disabled:opacity-50 text-sm text-white rounded-lg px-5 py-2.5 font-medium"
            >
              Import {selectedCount} selected
              {unconfirmedNeedsReview > 0 && (
                <span className="ml-1.5 bg-yellow-600 text-white rounded-full text-xs px-1.5 py-0.5">
                  {unconfirmedNeedsReview} review
                </span>
              )}
            </button>
          )}
        </div>

        {error && <p className="text-red-400 text-sm mb-4">{error}</p>}

        {/* Scanning progress */}
        {phase === 'scanning' && (
          <div className="text-center text-gray-500 py-16 text-sm animate-pulse">
            Scanning {dirPath}…
          </div>
        )}

        {/* Done */}
        {phase === 'done' && importResult && (
          <div className="space-y-4">
            <div className="bg-gray-900 border border-gray-700 rounded-lg p-6">
              <div className="text-base font-semibold text-white mb-3">Import complete</div>
              <div className="flex gap-6 text-sm">
                <div>
                  <span className="text-2xl font-bold text-green-400">{importResult.imported}</span>
                  <span className="text-gray-500 ml-2">imported</span>
                </div>
                {importResult.failed > 0 && (
                  <div>
                    <span className="text-2xl font-bold text-red-400">{importResult.failed}</span>
                    <span className="text-gray-500 ml-2">failed</span>
                  </div>
                )}
              </div>
            </div>
            <button onClick={() => { setPhase('idle'); setScanFiles([]) }} className="text-sm text-indigo-400 hover:text-indigo-300">
              ← Scan another directory
            </button>
          </div>
        )}

        {/* Results */}
        {phase === 'ready' && (
          <div className="space-y-8">
            {/* TV Shows */}
            {shows.length > 0 && (
              <section>
                <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">
                  TV Shows ({shows.filter(s => !s.alreadyImported).length} new)
                </h2>
                <div className="space-y-3">
                  {shows.map(show => (
                    <ShowCard
                      key={show.title}
                      show={show}
                      matchState={matchStates.get(`${show.title}::series`) ?? matchStates.get(`${show.title}::unknown`)}
                      selected={selectedShows.has(show.title)}
                      selectedSeasons={selectedShows.get(show.title) ?? null}
                      onToggleShow={() => toggleShow(show.title, show.seasons)}
                      onToggleSeason={sn => toggleSeason(show.title, sn, show.seasons)}
                      onConfirmMatch={() => confirmMatch(show.title, 'series')}
                      onManualMatch={() => setManualMatch(show.title, 'series')}
                      onSelectCandidate={c => setMatchSelected(show.title, 'series', c)}
                      onToggleOverride={() => toggleOverride(show.title, 'series')}
                      onOverrideSearch={q => runOverrideSearch(show.title, 'series', q)}
                      onOverrideQueryChange={q => {
                        const key = `${show.title}::series`
                        setMatchStates(prev => {
                          const next = new Map(prev)
                          next.set(key, { ...next.get(key)!, overrideQuery: q })
                          return next
                        })
                      }}
                    />
                  ))}
                </div>
              </section>
            )}

            {/* Movies */}
            {movies.length > 0 && (
              <section>
                <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">
                  Movies ({movies.filter(m => !m.already_ingested).length} new)
                </h2>
                <div className="space-y-1">
                  {movies.map((movie, i) => (
                    <MovieRow
                      key={i}
                      file={movie}
                      matchState={matchStates.get(`${movie.parsed.title}::movie`) ?? matchStates.get(`${movie.parsed.title}::unknown`)}
                      selected={selectedMovies.has(movie.path)}
                      onToggle={() => toggleMovie(movie.path)}
                      onConfirmMatch={() => confirmMatch(movie.parsed.title, 'movie')}
                      onManualMatch={() => setManualMatch(movie.parsed.title, 'movie')}
                      onSelectCandidate={c => setMatchSelected(movie.parsed.title, 'movie', c)}
                      onToggleOverride={() => toggleOverride(movie.parsed.title, 'movie')}
                      onOverrideSearch={q => runOverrideSearch(movie.parsed.title, 'movie', q)}
                      onOverrideQueryChange={q => {
                        const key = `${movie.parsed.title}::movie`
                        setMatchStates(prev => {
                          const next = new Map(prev)
                          next.set(key, { ...next.get(key)!, overrideQuery: q })
                          return next
                        })
                      }}
                    />
                  ))}
                </div>
              </section>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

// ── ShowCard ─────────────────────────────────────────────────────────────────

interface ShowCardProps {
  show: ShowGroup
  matchState: MatchState | undefined
  selected: boolean
  selectedSeasons: Set<number> | null
  onToggleShow: () => void
  onToggleSeason: (sn: number) => void
  onConfirmMatch: () => void
  onManualMatch: () => void
  onSelectCandidate: (c: MatchCandidate) => void
  onToggleOverride: () => void
  onOverrideSearch: (q: string) => void
  onOverrideQueryChange: (q: string) => void
}

function ShowCard({ show, matchState, selected, selectedSeasons, onToggleShow, onToggleSeason, onConfirmMatch, onManualMatch, onSelectCandidate, onToggleOverride, onOverrideSearch, onOverrideQueryChange }: ShowCardProps) {
  const sortedSeasons = [...show.seasons.entries()].sort(([a], [b]) => a - b)
  const opacity = show.alreadyImported ? 'opacity-40' : ''

  return (
    <div className={`bg-gray-900 border border-gray-800 rounded-lg overflow-hidden ${opacity}`}>
      <div className="flex gap-4 p-4">
        {/* Checkbox + Poster */}
        <div className="flex items-start gap-3 shrink-0">
          <input
            type="checkbox"
            checked={selected}
            onChange={onToggleShow}
            className="mt-1 accent-indigo-500"
          />
          <Poster src={show.localArtwork ? `/pvfs/artwork?path=${encodeURIComponent(show.localArtwork)}` : null} />
        </div>

        {/* Show info + season pills */}
        <div className="flex-1 min-w-0">
          <div className="font-medium text-white text-sm mb-2">{show.title}</div>
          <div className="flex flex-wrap gap-1.5">
            {sortedSeasons.map(([sn, eps]) => {
              const isSelected = !selectedSeasons || selectedSeasons.has(sn)
              return (
                <button
                  key={sn}
                  onClick={() => onToggleSeason(sn)}
                  className={`text-xs rounded px-2 py-1 transition-colors ${
                    isSelected
                      ? 'bg-purple-800 text-purple-200 hover:bg-purple-700'
                      : 'bg-gray-800 text-gray-500 hover:bg-gray-700'
                  }`}
                >
                  {sn === 0 ? 'Specials' : `S${sn}`} ({eps.length} ep)
                </button>
              )
            })}
          </div>
          <div className="text-xs text-gray-600 mt-1.5">{show.totalFiles} files total</div>
        </div>

        {/* Match column */}
        <div className="w-64 shrink-0">
          <MatchColumn
            matchState={matchState}
            kind="series"
            onConfirm={onConfirmMatch}
            onManual={onManualMatch}
            onSelect={onSelectCandidate}
            onToggleOverride={onToggleOverride}
            onSearch={onOverrideSearch}
            onQueryChange={onOverrideQueryChange}
          />
        </div>
      </div>
    </div>
  )
}

// ── MovieRow ──────────────────────────────────────────────────────────────────

interface MovieRowProps {
  file: ScannedFile
  matchState: MatchState | undefined
  selected: boolean
  onToggle: () => void
  onConfirmMatch: () => void
  onManualMatch: () => void
  onSelectCandidate: (c: MatchCandidate) => void
  onToggleOverride: () => void
  onOverrideSearch: (q: string) => void
  onOverrideQueryChange: (q: string) => void
}

function MovieRow({ file, matchState, selected, onToggle, onConfirmMatch, onManualMatch, onSelectCandidate, onToggleOverride, onOverrideSearch, onOverrideQueryChange }: MovieRowProps) {
  const opacity = file.already_ingested ? 'opacity-40' : ''

  return (
    <div className={`flex items-center gap-4 px-3 py-2.5 rounded-lg hover:bg-gray-900 transition-colors ${opacity}`}>
      <input
        type="checkbox"
        checked={selected}
        onChange={onToggle}
        disabled={!!file.already_ingested}
        className="accent-indigo-500 shrink-0"
      />
      <Poster src={file.local_artwork ? `/pvfs/artwork?path=${encodeURIComponent(file.local_artwork)}` : null} small />
      <div className="flex-1 min-w-0">
        <span className="text-sm text-white">{file.parsed.title || '(unknown)'}</span>
        {file.parsed.year && <span className="text-xs text-gray-500 ml-2">{file.parsed.year}</span>}
        {file.already_ingested && <span className="text-xs text-gray-600 ml-2 italic">imported</span>}
        <div className="text-xs text-gray-600 font-mono truncate mt-0.5">{file.path.split('/').slice(-2).join('/')}</div>
      </div>
      <div className="w-56 shrink-0">
        <MatchColumn
          matchState={matchState}
          kind="movie"
          onConfirm={onConfirmMatch}
          onManual={onManualMatch}
          onSelect={onSelectCandidate}
          onToggleOverride={onToggleOverride}
          onSearch={onOverrideSearch}
          onQueryChange={onOverrideQueryChange}
        />
      </div>
    </div>
  )
}

// ── MatchColumn ───────────────────────────────────────────────────────────────

interface MatchColumnProps {
  matchState: MatchState | undefined
  kind: 'movie' | 'series'
  onConfirm: () => void
  onManual: () => void
  onSelect: (c: MatchCandidate) => void
  onToggleOverride: () => void
  onSearch: (q: string) => void
  onQueryChange: (q: string) => void
}

function MatchColumn({ matchState, kind: _kind, onConfirm, onManual, onSelect, onToggleOverride, onSearch, onQueryChange }: MatchColumnProps) {
  if (!matchState || matchState.status === 'pending') {
    return <div className="text-xs text-gray-600 animate-pulse">Matching…</div>
  }

  if (matchState.status === 'error') {
    return (
      <div className="text-xs text-red-400">
        Match failed —{' '}
        <button onClick={onManual} className="underline hover:text-red-300">use manual</button>
      </div>
    )
  }

  const { selected, candidates, needsReview, confirmed, overriding, overrideQuery } = matchState

  return (
    <div className="space-y-1.5">
      {/* Selected match display */}
      {selected ? (
        <div className="flex items-center gap-2">
          {selected.poster_path && (
            <img
              src={`${TMDB_IMG}${selected.poster_path}`}
              alt=""
              className="w-8 h-12 object-cover rounded shrink-0"
            />
          )}
          <div className="min-w-0">
            <div className="text-xs text-white font-medium truncate">{selected.title}</div>
            {selected.year && <div className="text-xs text-gray-500">{selected.year}</div>}
            <span className={`text-xs font-mono ${confidenceColor(selected.confidence)}`}>
              {Math.round(selected.confidence * 100)}%
            </span>
          </div>
        </div>
      ) : confirmed ? (
        <div className="text-xs text-gray-500 italic">Manual / no match</div>
      ) : null}

      {/* Action buttons */}
      <div className="flex flex-wrap gap-1">
        {needsReview && !confirmed && (
          <button
            onClick={onConfirm}
            className="text-xs bg-yellow-800 hover:bg-yellow-700 text-yellow-200 rounded px-2 py-0.5"
          >
            Confirm
          </button>
        )}
        <button
          onClick={onToggleOverride}
          className="text-xs text-gray-500 hover:text-gray-300 underline"
        >
          {overriding ? 'Cancel' : 'Change'}
        </button>
        {selected && (
          <button onClick={onManual} className="text-xs text-gray-600 hover:text-gray-400 underline">
            No match
          </button>
        )}
      </div>

      {/* Override search */}
      {overriding && (
        <div className="space-y-1">
          <input
            value={overrideQuery}
            onChange={e => onQueryChange(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && onSearch(overrideQuery)}
            placeholder="Search TMDB…"
            className="w-full bg-gray-800 border border-gray-600 rounded px-2 py-1 text-xs focus:outline-none focus:border-indigo-500"
          />
          <div className="space-y-0.5 max-h-32 overflow-y-auto">
            {candidates.map(c => (
              <button
                key={c.tmdb_id}
                onClick={() => onSelect(c)}
                className="w-full flex items-center gap-2 px-2 py-1 rounded hover:bg-gray-700 text-left"
              >
                {c.poster_path && (
                  <img src={`${TMDB_IMG}${c.poster_path}`} alt="" className="w-6 h-9 object-cover rounded shrink-0" />
                )}
                <div className="min-w-0">
                  <div className="text-xs text-white truncate">{c.title}</div>
                  <div className="text-xs text-gray-500">{c.year} · <span className={confidenceColor(c.confidence)}>{Math.round(c.confidence * 100)}%</span></div>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Poster ────────────────────────────────────────────────────────────────────

function Poster({ src, small = false }: { src: string | null; small?: boolean }) {
  const cls = small ? 'w-8 h-12' : 'w-12 h-16'
  if (!src) {
    return <div className={`${cls} bg-gray-800 rounded shrink-0`} />
  }
  return (
    <img
      src={src}
      alt=""
      className={`${cls} object-cover rounded shrink-0`}
      onError={e => { (e.target as HTMLImageElement).style.display = 'none' }}
    />
  )
}
