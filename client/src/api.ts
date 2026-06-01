const BASE = import.meta.env.DEV ? '/api' : '';

export const TOKEN_KEY = 'pv_token';

function authHeaders(): Record<string, string> {
  const token = sessionStorage.getItem(TOKEN_KEY);
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export class UnauthorizedError extends Error {}


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
  const res = await fetch(`${BASE}${path}`, { headers: authHeaders() });
  if (res.status === 401) throw new UnauthorizedError('session expired');
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    throw new Error(body?.error ?? `${res.status} ${res.statusText}`);
  }
  return res.json();
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body),
  });
  if (res.status === 401) throw new UnauthorizedError('session expired');
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

async function patch<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body),
  });
  if (res.status === 401) throw new UnauthorizedError('session expired');
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export interface TmdbSearchResult {
  tmdb_id: string;
  media_type: 'movie' | 'tv';
  title: string;
  year: string;
  poster_path: string | null;
  overview: string | null;
}

export interface TmdbDetails extends TmdbSearchResult {
  genres: string[];
  imdb_id?: string;
  tvdb_id?: string;
  runtime_min?: number;
}

export type WatchStatus = 'unwatched' | 'watching' | 'watched' | 'skipped';

export interface ProviderConfig {
  node_id: string;
  provider_id: string;
  name: string;
  enabled: boolean;
  config: Record<string, unknown>;
}

export interface ScannedFile {
  path: string;
  size_bytes: number;
  ext: string;
  parsed: {
    title: string;
    year: number | null;
    kind: 'movie' | 'series' | 'unknown';
    season: number | null;
    episode: number | null;
  };
}

export interface ScanResult {
  found: number;
  dry_run: true;
  files: ScannedFile[];
}

export interface IngestResult {
  found: number;
  dry_run: false;
  ingested: number;
  failed: number;
  files: Array<{ path: string; fileNodeId: string; contentHash: string; streamUrl: string }>;
  failures: Array<{ path: string; error: string }>;
}

async function put<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body),
  });
  if (res.status === 401) throw new UnauthorizedError('session expired');
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
  addMedia: (body: object) => post<{ id: string }>('/media', body),
  addStorage: (body: object) => post<{ id: string }>('/storage', body),
  addWatchlist: (body: object) => post('/watchlist', body),
  addCrosslink: (body: object) => post('/crosslink', body),
  updateWatchlist: (mediaId: string, status: WatchStatus, progressMs?: number) =>
    patch<{ id: string; status: string }>(`/watchlist/${mediaId}`, { status, progress_ms: progressMs }),
  tmdbSearch: (q: string) => get<{ results: TmdbSearchResult[] }>(`/tmdb/search?q=${encodeURIComponent(q)}`),
  tmdbDetails: (id: string, type: 'movie' | 'tv') => get<TmdbDetails>(`/tmdb/details?id=${id}&type=${type}`),
  getProviders: () => get<ProviderConfig[]>('/config/providers'),
  upsertProvider: (providerId: string, body: { read_access_token?: string; enabled?: boolean; name?: string }) =>
    put<{ provider_id: string; enabled: boolean; updated: boolean }>(`/config/providers/${providerId}`, body),
  pvfsScan: (body: { path: string; dry_run?: boolean; extensions?: string[]; limit?: number }) =>
    post<ScanResult | IngestResult>('/pvfs/scan', body),
};
