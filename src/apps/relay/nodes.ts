/**
 * Relay node factory functions.
 * Each creates a fully signed PhraseVault node with the correct Relay type.
 */

import { createNode } from "../../node/index.js";
import {
  MediaNode, MediaPayload,
  StoragePointerNode, StoragePointerPayload,
  CrosslinkNode, CrosslinkPayload,
  WatchlistEntryNode, WatchlistEntryPayload,
} from "./types.js";

/**
 * Create a media node.
 * Links are empty — media nodes are roots in the DAG.
 * The node id serves as the dedup key: same metadata → same id.
 */
export async function createMediaNode(
  privKeyHex: string,
  payload: MediaPayload,
): Promise<MediaNode> {
  const node = await createNode(privKeyHex, {
    type: "media",
    timestamp: Date.now(),
    links: [],
    score: 0.0,
    payload,
  });
  return node as unknown as MediaNode;
}

/**
 * Create a storage_pointer node.
 * Links to the media node it describes.
 */
export async function createStoragePointerNode(
  privKeyHex: string,
  payload: StoragePointerPayload,
): Promise<StoragePointerNode> {
  const node = await createNode(privKeyHex, {
    type: "storage_pointer",
    timestamp: Date.now(),
    links: [payload.media_node_id],
    score: 0.0,
    payload,
  });
  return node as unknown as StoragePointerNode;
}

/**
 * Create a crosslink node.
 * Links to both the storage_pointer and the media node for easy traversal.
 */
export async function createCrosslinkNode(
  privKeyHex: string,
  payload: CrosslinkPayload,
): Promise<CrosslinkNode> {
  const node = await createNode(privKeyHex, {
    type: "crosslink",
    timestamp: payload.added_at,
    links: [payload.target_node_id, payload.media_node_id],
    score: 0.0,
    payload,
  });
  return node as unknown as CrosslinkNode;
}

/**
 * Create a watchlist_entry node.
 * Links to the media node and the crosslink providing access.
 */
export async function createWatchlistEntryNode(
  privKeyHex: string,
  payload: WatchlistEntryPayload,
): Promise<WatchlistEntryNode> {
  const node = await createNode(privKeyHex, {
    type: "watchlist_entry",
    timestamp: payload.added_at,
    links: [payload.media_node_id, payload.crosslink_node_id],
    score: 0.0,
    payload,
  });
  return node as unknown as WatchlistEntryNode;
}
