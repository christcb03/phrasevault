import { useState, useRef } from 'react'
import { api, UnauthorizedError } from './api'
import type { TmdbSearchResult, TmdbDetails } from './api'

const POSTER_BASE = 'https://image.tmdb.org/t/p/w92'

interface Props {
  onClose: () => void
  onAdded: () => void
  onUnauthorized: () => void
}

type Step = 'search' | 'details'

export default function AddMediaModal({ onClose, onAdded, onUnauthorized }: Props) {
  const [step, setStep] = useState<Step>('search')
  const [query, setQuery] = useState('')
  const [searching, setSearching] = useState(false)
  const [results, setResults] = useState<TmdbSearchResult[]>([])
  const [selected, setSelected] = useState<TmdbDetails | null>(null)
  const [loadingDetails, setLoadingDetails] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const searchRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Storage form state
  const [endpointUrl, setEndpointUrl] = useState('')
  const [encoding, setEncoding] = useState('1080p')
  const [sizeGb, setSizeGb] = useState('')
  const [container, setContainer] = useState('mkv')
  const [codecVideo, setCodecVideo] = useState('h264')
  const [codecAudio, setCodecAudio] = useState('aac')
  const [contentHash, setContentHash] = useState('')
  const [addToWatchlist, setAddToWatchlist] = useState(false)

  async function handleSearch(q: string) {
    setQuery(q)
    setError('')
    if (searchRef.current) clearTimeout(searchRef.current)
    if (!q.trim()) { setResults([]); return }
    searchRef.current = setTimeout(async () => {
      setSearching(true)
      try {
        const res = await api.tmdbSearch(q)
        setResults(res.results)
      } catch (e) {
        if (e instanceof UnauthorizedError) { onUnauthorized(); return }
        setError(e instanceof Error ? e.message : 'Search failed')
      } finally {
        setSearching(false)
      }
    }, 350)
  }

  async function handleSelect(r: TmdbSearchResult) {
    setLoadingDetails(true)
    setError('')
    try {
      const d = await api.tmdbDetails(r.tmdb_id, r.media_type)
      setSelected(d)
      setStep('details')
    } catch (e) {
      if (e instanceof UnauthorizedError) { onUnauthorized(); return }
      setError('Failed to load details from TMDB.')
    } finally {
      setLoadingDetails(false)
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!selected) return
    setError('')
    setSubmitting(true)
    try {
      const kind = selected.media_type === 'tv' ? 'series' : 'movie'
      const mediaRes = await api.addMedia({
        title: selected.title,
        year: parseInt(selected.year) || 0,
        kind,
        tmdb_id: selected.tmdb_id,
        imdb_id: selected.imdb_id,
        tvdb_id: selected.tvdb_id,
        genres: selected.genres,
        duration_ms: selected.runtime_min ? selected.runtime_min * 60 * 1000 : undefined,
      })
      await api.addStorage({
        media_node_id: mediaRes.id,
        endpoint_url: endpointUrl,
        content_hash: contentHash || '0'.repeat(64),
        size_bytes: Math.round(parseFloat(sizeGb) * 1e9) || 0,
        encoding,
        container,
        codec_video: codecVideo || undefined,
        codec_audio: codecAudio || undefined,
        available: true,
      })
      if (addToWatchlist) {
        await api.updateWatchlist(mediaRes.id, 'unwatched')
      }
      onAdded()
      onClose()
    } catch (e) {
      if (e instanceof UnauthorizedError) { onUnauthorized(); return }
      setError(e instanceof Error ? e.message : 'Error adding media')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/75 flex items-center justify-center z-50 p-6" onClick={onClose}>
      <div
        className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-xl max-h-[90vh] overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-6 pt-5 pb-4 border-b border-gray-800">
          <h2 className="text-base font-semibold text-white">
            {step === 'search' ? 'Add Media — Search TMDB' : `Add "${selected?.title}"`}
          </h2>
          <button onClick={onClose} className="text-gray-500 hover:text-white text-xl leading-none">×</button>
        </div>

        {step === 'search' && (
          <div className="p-6">
            <input
              autoFocus
              value={query}
              onChange={e => handleSearch(e.target.value)}
              placeholder="Search movies & TV shows…"
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:border-indigo-500 mb-4"
            />
            {searching && <div className="text-sm text-gray-500 text-center py-4">Searching…</div>}
            {!searching && results.length === 0 && query && (
              <div className="text-sm text-gray-600 text-center py-4">No results.</div>
            )}
            <div className="space-y-2">
              {results.map(r => (
                <button
                  key={r.tmdb_id}
                  onClick={() => handleSelect(r)}
                  disabled={loadingDetails}
                  className="flex items-center gap-3 w-full bg-gray-800 hover:bg-gray-750 border border-gray-700 hover:border-indigo-600 rounded-lg px-3 py-2.5 text-left transition-colors disabled:opacity-50"
                >
                  {r.poster_path ? (
                    <img
                      src={`${POSTER_BASE}${r.poster_path}`}
                      alt=""
                      className="w-8 h-12 object-cover rounded shrink-0"
                    />
                  ) : (
                    <div className="w-8 h-12 bg-gray-700 rounded shrink-0 flex items-center justify-center text-gray-600 text-xs">?</div>
                  )}
                  <div className="min-w-0">
                    <div className="text-sm font-medium text-white truncate">{r.title}</div>
                    <div className="text-xs text-gray-500">{r.year} · {r.media_type === 'tv' ? 'TV Series' : 'Movie'}</div>
                  </div>
                </button>
              ))}
            </div>
            {error && <p className="text-red-400 text-xs mt-3">{error}</p>}
          </div>
        )}

        {step === 'details' && selected && (
          <form onSubmit={handleSubmit} className="p-6 space-y-4">
            <div className="flex gap-3 items-start mb-2">
              {selected.poster_path && (
                <img
                  src={`${POSTER_BASE}${selected.poster_path}`}
                  alt=""
                  className="w-12 h-18 object-cover rounded shrink-0"
                />
              )}
              <div>
                <div className="font-medium text-white">{selected.title}</div>
                <div className="text-xs text-gray-400 mt-0.5">
                  {selected.year} · {selected.media_type === 'tv' ? 'TV Series' : 'Movie'}
                  {selected.genres?.length ? ' · ' + selected.genres.slice(0, 3).join(', ') : ''}
                </div>
                {selected.imdb_id && (
                  <div className="text-xs text-gray-600 mt-0.5">IMDb: {selected.imdb_id}</div>
                )}
              </div>
            </div>

            <div className="border-t border-gray-800 pt-4">
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Storage details</p>
              <div className="space-y-3">
                <label className="block">
                  <span className="text-xs text-gray-400">Stream URL *</span>
                  <input
                    required
                    value={endpointUrl}
                    onChange={e => setEndpointUrl(e.target.value)}
                    placeholder="https://…"
                    className="mt-1 w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-indigo-500"
                  />
                </label>

                <div className="grid grid-cols-2 gap-3">
                  <label className="block">
                    <span className="text-xs text-gray-400">Quality</span>
                    <select
                      value={encoding}
                      onChange={e => setEncoding(e.target.value)}
                      className="mt-1 w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none"
                    >
                      <option>4K HDR</option>
                      <option>4K SDR</option>
                      <option>1080p</option>
                      <option>720p</option>
                      <option>480p</option>
                    </select>
                  </label>
                  <label className="block">
                    <span className="text-xs text-gray-400">Container</span>
                    <select
                      value={container}
                      onChange={e => setContainer(e.target.value)}
                      className="mt-1 w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none"
                    >
                      <option>mkv</option>
                      <option>mp4</option>
                      <option>m4v</option>
                      <option>avi</option>
                    </select>
                  </label>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <label className="block">
                    <span className="text-xs text-gray-400">Video codec</span>
                    <select
                      value={codecVideo}
                      onChange={e => setCodecVideo(e.target.value)}
                      className="mt-1 w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none"
                    >
                      <option>h264</option>
                      <option>h265</option>
                      <option>av1</option>
                      <option>vp9</option>
                    </select>
                  </label>
                  <label className="block">
                    <span className="text-xs text-gray-400">Audio codec</span>
                    <select
                      value={codecAudio}
                      onChange={e => setCodecAudio(e.target.value)}
                      className="mt-1 w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none"
                    >
                      <option>aac</option>
                      <option>ac3</option>
                      <option>eac3</option>
                      <option>truehd</option>
                      <option>dts</option>
                    </select>
                  </label>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <label className="block">
                    <span className="text-xs text-gray-400">File size (GB)</span>
                    <input
                      type="number"
                      min="0"
                      step="0.1"
                      value={sizeGb}
                      onChange={e => setSizeGb(e.target.value)}
                      placeholder="e.g. 8.5"
                      className="mt-1 w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-indigo-500"
                    />
                  </label>
                  <label className="block">
                    <span className="text-xs text-gray-400">BLAKE3 hash (optional)</span>
                    <input
                      value={contentHash}
                      onChange={e => setContentHash(e.target.value)}
                      placeholder="leave blank to skip"
                      className="mt-1 w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-indigo-500"
                    />
                  </label>
                </div>
              </div>
            </div>

            <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer pt-1">
              <input
                type="checkbox"
                checked={addToWatchlist}
                onChange={e => setAddToWatchlist(e.target.checked)}
                className="accent-indigo-500"
              />
              Add to watchlist (unwatched)
            </label>

            {error && <p className="text-red-400 text-xs">{error}</p>}

            <div className="flex gap-3 pt-2">
              <button
                type="button"
                onClick={() => setStep('search')}
                className="text-sm text-gray-400 hover:text-white px-4 py-2 rounded border border-gray-700 hover:border-gray-500"
              >
                ← Back
              </button>
              <button
                type="submit"
                disabled={submitting || !endpointUrl}
                className="flex-1 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-sm text-white rounded px-4 py-2 font-medium"
              >
                {submitting ? 'Adding…' : 'Add to Library'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}
