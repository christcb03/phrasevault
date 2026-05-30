/**
 * Relay query engine — multi-feed search across followed peers.
 *
 * Given a set of HypercoreStores (own + followed friends), the engine:
 * 1. Scans all feeds for media, storage_pointer, crosslink, and watchlist nodes
 * 2. Builds an in-memory index: media_id → { media, sources[], watchlist? }
 * 3. Exposes search (text/filter) and lookup (by id) over that index
 *
 * The index is rebuilt on demand (call refresh()). In production this would
 * be kept warm by subscribing to each feed's 'append' event.
 */

import { HypercoreStore } from "../../store/hypercore.js";
import {
  isMediaNode, isStoragePointerNode, isCrosslinkNode, isWatchlistEntryNode,
  MediaNode, StoragePointerNode, CrosslinkNode, WatchlistEntryNode,
  MediaKind, WatchStatus,
} from "./types.js";
import { PVNode } from "../../node/types.js";

export interface MediaSource {
  storagePointer: StoragePointerNode;
  crosslink: CrosslinkNode | null;  // null if this is your own storage_pointer
  feedOwner: string;                // pubkey hex of the feed this came from
}

export interface MediaResult {
  media: MediaNode;
  sources: MediaSource[];           // all available sources across all feeds
  watchlistEntry: WatchlistEntryNode | null;
  // Convenience: best available source (prefer available=true, then highest quality)
  bestSource: MediaSource | null;
}

export interface SearchFilters {
  kind?: MediaKind;
  query?: string;       // matches title (case-insensitive substring)
  availableOnly?: boolean;
  watchStatus?: WatchStatus;
}

export class RelayQueryEngine {
  private feeds: Map<string, HypercoreStore> = new Map(); // feedKeyHex → store
  // Indexes rebuilt by refresh()
  private mediaIndex = new Map<string, MediaResult>();

  /**
   * Add a feed to query. Call refresh() after adding all feeds.
   * feedKeyHex identifies which peer this came from (used in MediaSource).
   */
  addFeed(feedKeyHex: string, store: HypercoreStore): void {
    this.feeds.set(feedKeyHex, store);
  }

  removeFeed(feedKeyHex: string): void {
    this.feeds.delete(feedKeyHex);
    // Index will be stale until next refresh()
  }

  /**
   * Rebuild the full index from all feeds.
   * Should be called after feeds are added and after replication catches up.
   */
  async refresh(): Promise<void> {
    this.mediaIndex.clear();

    // Pass 1: collect all nodes from all feeds
    const allMedia = new Map<string, MediaNode>();
    const allPointers = new Map<string, StoragePointerNode & { feedOwner: string }>();
    const allCrosslinks = new Map<string, CrosslinkNode>();
    const allWatchlist = new Map<string, WatchlistEntryNode>();

    for (const [feedOwner, store] of this.feeds) {
      for await (const node of store.list()) {
        if (isMediaNode(node))            allMedia.set(node.id, node);
        if (isStoragePointerNode(node))   allPointers.set(node.id, { ...node, feedOwner });
        if (isCrosslinkNode(node))        allCrosslinks.set(node.id, node);
        if (isWatchlistEntryNode(node))   allWatchlist.set(node.payload.media_node_id, node);
      }
    }

    // Pass 2: group pointers by media_node_id
    const pointersByMedia = new Map<string, Array<StoragePointerNode & { feedOwner: string }>>();
    for (const ptr of allPointers.values()) {
      const list = pointersByMedia.get(ptr.payload.media_node_id) ?? [];
      list.push(ptr);
      pointersByMedia.set(ptr.payload.media_node_id, list);
    }

    // Pass 3: build crosslink lookup by target_node_id (storage_pointer id)
    const crosslinkByPointer = new Map<string, CrosslinkNode>();
    for (const cl of allCrosslinks.values()) {
      crosslinkByPointer.set(cl.payload.target_node_id, cl);
    }

    // Pass 4: assemble MediaResults
    for (const [mediaId, media] of allMedia) {
      const pointers = pointersByMedia.get(mediaId) ?? [];
      const sources: MediaSource[] = pointers.map(ptr => ({
        storagePointer: ptr,
        crosslink: crosslinkByPointer.get(ptr.id) ?? null,
        feedOwner: ptr.feedOwner,
      }));

      this.mediaIndex.set(mediaId, {
        media,
        sources,
        watchlistEntry: allWatchlist.get(mediaId) ?? null,
        bestSource: this.pickBestSource(sources),
      });
    }
  }

  /**
   * Search across all indexed media.
   */
  search(filters: SearchFilters = {}): MediaResult[] {
    let results = [...this.mediaIndex.values()];

    if (filters.kind) {
      results = results.filter(r => r.media.payload.kind === filters.kind);
    }

    if (filters.query) {
      const q = filters.query.toLowerCase();
      results = results.filter(r =>
        r.media.payload.title.toLowerCase().includes(q)
      );
    }

    if (filters.availableOnly) {
      results = results.filter(r =>
        r.sources.some(s => s.storagePointer.payload.available)
      );
    }

    if (filters.watchStatus) {
      results = results.filter(r =>
        r.watchlistEntry?.payload.status === filters.watchStatus
      );
    }

    // Sort: watchlist items first, then alphabetical
    return results.sort((a, b) => {
      const aW = a.watchlistEntry ? 1 : 0;
      const bW = b.watchlistEntry ? 1 : 0;
      if (aW !== bW) return bW - aW;
      return a.media.payload.title.localeCompare(b.media.payload.title);
    });
  }

  /**
   * Look up a specific title by media node id.
   */
  getById(mediaNodeId: string): MediaResult | null {
    return this.mediaIndex.get(mediaNodeId) ?? null;
  }

  /**
   * How many titles are currently indexed.
   */
  get size(): number {
    return this.mediaIndex.size;
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  private pickBestSource(sources: MediaSource[]): MediaSource | null {
    if (sources.length === 0) return null;
    const available = sources.filter(s => s.storagePointer.payload.available);
    const pool = available.length > 0 ? available : sources;
    // Prefer higher quality: 4K > 1080p > 720p > anything else
    const quality = (enc: string) => {
      if (enc.startsWith("4K") || enc.startsWith("2160")) return 3;
      if (enc.startsWith("1080")) return 2;
      if (enc.startsWith("720")) return 1;
      return 0;
    };
    return pool.sort((a, b) =>
      quality(b.storagePointer.payload.encoding) -
      quality(a.storagePointer.payload.encoding)
    )[0];
  }
}
