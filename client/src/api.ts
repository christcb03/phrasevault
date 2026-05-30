const BASE = import.meta.env.DEV ? '/api' : '';

export interface MediaSource {
  storageNodeId: string;
  endpointUrl: string;
  encoding: string;
  available: boolean;
  sizeBytes: number;
  feedOwner: string;
}

export interface WatchlistInfo {
  status: 'unwatched' | 'watching' | 'watched' | 'skipped';
  addedAt: number;
  progressMs?: number;
}

export interface MediaResult {
  id: string;
  title: string;
  year: number;
  kind: 'movie' | 'series' | 'episode' | 'short';
  genres?: string[];
  imdb_id?: string;
  sources: MediaSource[];
  bestSource: { endpointUrl: string; encoding: string } | null;
  watchlist: WatchlistInfo | null;
}

export interface SearchResponse {
  count: number;
  results: MediaResult[];
}

export interface HealthResponse {
  status: string;
  identity: string;
  feedLength: number;
  following: number;
  indexed: number;
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export const api = {
  health: () => get<HealthResponse>('/health'),
  search: (params: { q?: string; kind?: string; available?: boolean; watchStatus?: string }) => {
    const qs = new URLSearchParams();
    if (params.q)           qs.set('q', params.q);
    if (params.kind)        qs.set('kind', params.kind);
    if (params.available)   qs.set('available', 'true');
    if (params.watchStatus) qs.set('watchStatus', params.watchStatus);
    return get<SearchResponse>(`/search?${qs}`);
  },
  getMedia: (id: string) => get<MediaResult>(`/media/${id}`),
  follow: (feedKey: string) => post('/follow', { feedKey }),
  following: () => get<{ keys: string[] }>('/following'),
  addWatchlist: (body: object) => post('/watchlist', body),
  addCrosslink: (body: object) => post('/crosslink', body),
};
