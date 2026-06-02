// Confidence scoring for metadata provider matches.

export interface MatchCandidate {
  tmdb_id: string
  media_type: 'movie' | 'tv'
  title: string
  year: string         // "2010" or ""
  poster_path: string | null
  overview: string | null
  confidence: number   // 0.0–1.0
}

export interface MatchSearchResult {
  query: { title: string; year: number | null; kind: 'movie' | 'series' | 'unknown' }
  candidates: MatchCandidate[]
  best: MatchCandidate | null
  needs_review: boolean
}

function normalizeTitle(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
}

function wordSet(s: string): Set<string> {
  return new Set(normalizeTitle(s).split(' ').filter(Boolean))
}

// Dice coefficient on normalized word sets.
function diceSimilarity(a: string, b: string): number {
  const wa = wordSet(a)
  const wb = wordSet(b)
  if (wa.size === 0 && wb.size === 0) return 1.0
  if (wa.size === 0 || wb.size === 0) return 0.0
  const intersection = [...wa].filter(w => wb.has(w)).length
  return (2 * intersection) / (wa.size + wb.size)
}

export function matchConfidence(
  query: { title: string; year: number | null },
  candidate: { title: string; year: string },
): number {
  const titleScore = diceSimilarity(query.title, candidate.title)
  const candYear = candidate.year ? parseInt(candidate.year, 10) : null
  let yearScore = 0.5  // neutral when year is unknown on either side
  if (query.year && candYear) {
    const diff = Math.abs(query.year - candYear)
    yearScore = diff === 0 ? 1.0 : diff === 1 ? 0.85 : diff <= 3 ? 0.5 : 0.0
  }
  // Title carries most of the weight; year breaks ties and boosts exact matches.
  return titleScore * 0.75 + yearScore * 0.25
}

export function scoreCandidates(
  query: { title: string; year: number | null; kind: 'movie' | 'series' | 'unknown' },
  rawCandidates: Omit<MatchCandidate, 'confidence'>[],
  threshold = 0.8,
): MatchSearchResult {
  // Filter to matching kind when known.
  const filtered = query.kind === 'unknown'
    ? rawCandidates
    : rawCandidates.filter(c =>
        query.kind === 'movie' ? c.media_type === 'movie' : c.media_type === 'tv',
      )

  const candidates = filtered
    .map(c => ({ ...c, confidence: matchConfidence(query, c) }))
    .sort((a, b) => b.confidence - a.confidence)

  const best = candidates[0] ?? null
  return {
    query,
    candidates: candidates.slice(0, 5),
    best,
    needs_review: !best || best.confidence < threshold,
  }
}
