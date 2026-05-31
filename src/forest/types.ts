// Truth Forest — core type definitions.
// All DB access, signing, and traversal modules import from here.

// ─── Node Types ───────────────────────────────────────────────────────────────

export type NodeType =
  // Forest structure
  | 'forest.root'
  | 'tree.root'
  // Config
  | 'config.section'
  | 'config.provider'
  | 'config.value'
  | 'config.prune_policy'
  // Media
  | 'media.movie'
  | 'media.series'
  | 'media.season'
  | 'media.episode'
  | 'media.person'
  | 'media.genre'
  | 'media.tag'
  | 'media.metadata'
  // PVFS
  | 'pvfs.file'
  | 'pvfs.location'
  | 'pvfs.integrity_failure'
  // User
  | 'user.watchlist_entry'
  | 'user.rating'
  | 'user.note'
  // Events
  | 'event.prune_record'

// ─── Link Types ───────────────────────────────────────────────────────────────

export type LinkType =
  | 'branch'      // primary parent→child tree structure
  | 'cross'       // node participates in another tree (e.g. genre)
  | 'supersedes'  // new node supersedes old; old link gets superseded_by set
  | 'metadata'    // provider metadata blob attached to a media node
  | 'file'        // pvfs.file attached to a media node
  | 'member'      // collection membership (episode→season, season→series)

// ─── Core Structures ──────────────────────────────────────────────────────────

// Immutable. ID = BLAKE3(type + label + JSON(payload) + created_at + author).
export interface TruthNode {
  id:         string
  type:       NodeType
  label:      string
  payload:    unknown
  created_at: number    // unix ms
  author:     string    // secp256k1 pubkey hex
  sig:        string    // secp256k1 signature over id
}

// Content-addressed ID, but soft-delete and supersede fields are mutable.
export interface TruthLink {
  id:           string
  parent_id:    string | null   // null = child is a root node
  child_id:     string
  link_type:    LinkType
  truth_score:  number          // 0.0–1.0, default 1.0
  sort_key:     string | null   // explicit sibling ordering (e.g. "S01E03")
  score_method: string | null   // "manual" | "bayesian:..." | "computed:cosine"
  created_at:   number
  author:       string
  sig:          string
  // Mutable state
  removed_at:    number | null
  removed_by:    string | null
  removal_sig:   string | null
  superseded_by: string | null  // link ID that replaced this one
  suspended_at:  number | null  // set by PVFS integrity failure; cleared on re-verify
}

// Mutable sibling-order index — separate from content-addressed links.
export interface SiblingOrderEntry {
  parent_id:    string
  link_id:      string
  next_link_id: string | null   // null = last in list
}

// ─── Payload Interfaces ───────────────────────────────────────────────────────

export interface ConfigValuePayload {
  key:   string
  value: string | number | boolean | null
}

export interface ConfigProviderPayload {
  provider_id: string    // e.g. "tmdb", "tvdb"
  name:        string
  enabled:     boolean
}

export interface PrunePolicyPayload {
  target_id:          string | null   // null = forest default
  retain_orphan_days: number | null   // null = never auto-prune
  warn_before_days:   number | null
  auto:               boolean
}

export interface MediaMoviePayload {
  title:    string
  year:     number | null
  genres:   string[]
  imdb_id:  string | null
  tmdb_id:  string | null
  overview: string | null
}

export interface MediaSeriesPayload {
  title:    string
  year:     number | null
  genres:   string[]
  imdb_id:  string | null
  tmdb_id:  string | null
  overview: string | null
  status:   string | null    // "Ended" | "Returning Series" | etc.
}

export interface MediaSeasonPayload {
  season_number: number
  title:         string | null
  year:          number | null
  episode_count: number | null
}

export interface MediaEpisodePayload {
  season_number:  number
  episode_number: number
  title:          string
  air_date:       string | null
  overview:       string | null
  runtime_ms:     number | null
}

export interface MediaMetadataPayload {
  provider_id: string         // "tmdb" | "tvdb" | etc.
  external_id: string         // provider's own ID
  fetched_at:  number
  raw:         Record<string, unknown>
}

export interface PvfsFilePayload {
  content_hash:      string    // BLAKE3 hex
  size_bytes:        number
  mime_type:         string
  original_filename: string | null
}

export interface PvfsLocationPayload {
  type:          'local' | 'http' | 'peer' | 'torrent' | 'magnet'
  uri:           string
  peer_id:       string | null
  last_verified: number | null   // unix ms of last passing hash check
  last_seen:     number | null
}

export interface PvfsIntegrityFailurePayload {
  file_node_id:     string
  location_node_id: string
  expected_hash:    string
  actual_hash:      string
  detected_at:      number
}

export type WatchStatus = 'unwatched' | 'watching' | 'watched' | 'skipped'

export interface UserWatchlistEntryPayload {
  media_node_id: string
  status:        WatchStatus
  progress_ms:   number | null
  added_at:      number
  watched_at:    number | null
}

export interface UserRatingPayload {
  media_node_id: string
  score:         number    // 0.0–10.0 (user-facing 1–5 stars maps to 0–10)
  rated_at:      number
}

export interface UserNotePayload {
  media_node_id: string
  text:          string
  created_at:    number
}

export interface PruneRecordPayload {
  pruned_at:   number
  dry_run:     boolean
  node_count:  number
  link_count:  number
  node_ids:    string[]    // pruned node IDs
  policy_id:   string | null
}

// ─── Walker Result Types ──────────────────────────────────────────────────────

export interface LinkedChild {
  node:        TruthNode
  link:        TruthLink
  truth_score: number
}

export interface WalkResult {
  node:     TruthNode
  link:     TruthLink | null    // null for the root of the walk
  children: WalkResult[]
}

export interface VerificationResult {
  valid:  boolean
  chain:  TruthLink[]
  reason: string | null
}

// ─── Prune Types ─────────────────────────────────────────────────────────────

export interface PruneCandidate {
  node:        TruthNode
  orphaned_at: number | null   // earliest time it became orphaned (approx)
  reason:      string
}

export interface PrunePreview {
  candidates:  PruneCandidate[]
  node_count:  number
  link_count:  number          // inactive links that would also be removed
}

export interface PruneResult extends PrunePreview {
  executed_at: number
  record_id:   string          // ID of the event.prune_record node appended
}

// ─── DB-layer input types (no sig/id required — computed at write time) ──────

export type NewNode = Omit<TruthNode, 'id' | 'sig'>

export type NewLink = Omit<TruthLink,
  'id' | 'sig' | 'removed_at' | 'removed_by' | 'removal_sig' | 'superseded_by' | 'suspended_at'>
