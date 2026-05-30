/**
 * PlexVault application node types.
 *
 * These are Layer 2 (application layer) built on top of PhraseVault's
 * base PVNode schema. PhraseVault doesn't know or care about these types —
 * it stores, signs, and replicates them the same as any other node.
 *
 * Node type hierarchy:
 *
 *   media              — one per title/episode, deduplicated by content
 *   storage_pointer    — one per (user, file), attached to a media node
 *   crosslink          — one per (user, target), "I have access to this"
 *   watchlist_entry    — one per (user, title), "I want to watch this"
 */

// ── media ─────────────────────────────────────────────────────────────────

export type MediaKind = "movie" | "series" | "episode" | "short";

export interface MediaPayload extends Record<string, unknown> {
  title: string;
  year: number;
  kind: MediaKind;
  tmdb_id?: string;
  imdb_id?: string;
  tvdb_id?: string;
  season?: number;
  episode?: number;
  duration_ms?: number;
  genres?: string[];
}

// ── storage_pointer ───────────────────────────────────────────────────────

export interface StoragePointerPayload extends Record<string, unknown> {
  media_node_id: string;   // id of the media node this points to
  endpoint_url: string;    // where to stream from (Jellyfin/Plex share URL)
  content_hash: string;    // BLAKE3 of the actual file (for dedup and verification)
  size_bytes: number;
  encoding: string;        // e.g. "1080p", "4K HDR", "720p"
  container: string;       // e.g. "mkv", "mp4"
  codec_video?: string;    // e.g. "h265", "h264", "av1"
  codec_audio?: string;    // e.g. "aac", "ac3", "truehd"
  available: boolean;      // owner can set false without removing the node
}

// ── crosslink ──────────────────────────────────────────────────────────────
// Created when a user "adds" a friend's content to their library.
// No file is copied — this is a DAG link only.

export interface CrosslinkPayload extends Record<string, unknown> {
  target_node_id: string;      // id of the storage_pointer being linked
  source_author: string;       // pubkey hex of the friend who owns the pointer
  media_node_id: string;       // denormalized for query convenience
  added_at: number;            // unix ms
}

// ── watchlist_entry ────────────────────────────────────────────────────────
// A user's "I want to watch this" record.
// size_bytes is recorded at add-time for watchlist capacity accounting.

export type WatchStatus = "unwatched" | "watching" | "watched" | "skipped";

export interface WatchlistEntryPayload extends Record<string, unknown> {
  media_node_id: string;
  crosslink_node_id: string;   // which crosslink provides access
  status: WatchStatus;
  added_at: number;
  watched_at?: number;
  progress_ms?: number;        // playback position for resume
  size_bytes: number;          // capacity cost (file size of the linked content)
}

// ── Type union ─────────────────────────────────────────────────────────────

export type PlexVaultPayload =
  | MediaPayload
  | StoragePointerPayload
  | CrosslinkPayload
  | WatchlistEntryPayload;

export type PlexVaultNodeType =
  | "media"
  | "storage_pointer"
  | "crosslink"
  | "watchlist_entry";

// ── Typed node wrappers ─────────────────────────────────────────────────────
// These are convenience types that narrow PVNode to a specific PlexVault type.

import { PVNode } from "../../node/types.js";

export interface MediaNode extends PVNode<MediaPayload> {
  type: "media";
}

export interface StoragePointerNode extends PVNode<StoragePointerPayload> {
  type: "storage_pointer";
}

export interface CrosslinkNode extends PVNode<CrosslinkPayload> {
  type: "crosslink";
}

export interface WatchlistEntryNode extends PVNode<WatchlistEntryPayload> {
  type: "watchlist_entry";
}

export type PlexVaultNode =
  | MediaNode
  | StoragePointerNode
  | CrosslinkNode
  | WatchlistEntryNode;

// ── Type guards ─────────────────────────────────────────────────────────────

export function isMediaNode(n: PVNode): n is MediaNode {
  return n.type === "media";
}

export function isStoragePointerNode(n: PVNode): n is StoragePointerNode {
  return n.type === "storage_pointer";
}

export function isCrosslinkNode(n: PVNode): n is CrosslinkNode {
  return n.type === "crosslink";
}

export function isWatchlistEntryNode(n: PVNode): n is WatchlistEntryNode {
  return n.type === "watchlist_entry";
}
