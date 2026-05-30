/**
 * ReplicationManager — connects PhraseVault feeds to the Hyperswarm DHT.
 *
 * Each Hypercore feed has a discoveryKey (32 bytes, derived from its public key).
 * Peers who want to sync a feed join the Hyperswarm topic = discoveryKey.
 *
 * Own feed (writable): join as server to announce availability.
 * Friend feeds (read-only): join as client to find and sync from peers.
 *
 * When a connection is established, both sides pipe their replicate() streams
 * together. Hypercore handles Merkle tree verification, sparse sync, and
 * incremental updates automatically.
 *
 * Usage:
 *   const mgr = new ReplicationManager(dataDir);
 *   await mgr.shareOwnFeed(myStore);
 *   const friendStore = await mgr.followFeed(friendFeedKeyHex);
 *   // friendStore.list() populates in the background as peers sync
 *   await mgr.close();
 */

import Hyperswarm from "hyperswarm";
import { Duplex } from "stream";
import { HypercoreStore } from "../store/hypercore.js";

interface ManagedFeed {
  store: HypercoreStore;
  writable: boolean;
}

export class ReplicationManager {
  private swarm: Hyperswarm;
  private dataDir: string;
  // discoveryKey hex → feed
  private feeds = new Map<string, ManagedFeed>();

  constructor(dataDir: string, opts: { seed?: Buffer } = {}) {
    this.dataDir = dataDir;
    this.swarm = new Hyperswarm(opts);
    this.swarm.on("connection", (socket: Duplex, info) => {
      this.onConnection(socket, info.client);
    });
  }

  /**
   * Announce your own writable feed to the DHT so friends can replicate it.
   * store must already be open.
   */
  async shareOwnFeed(store: HypercoreStore): Promise<void> {
    const topicHex = store.discoveryKey.toString("hex");
    this.feeds.set(topicHex, { store, writable: true });
    this.swarm.join(store.discoveryKey, { server: true, client: false });
  }

  /**
   * Start following a friend's feed by their Hypercore public key (hex).
   * Returns a HypercoreStore backed by a read-only replica.
   * The store populates in the background as peers connect and replicate.
   */
  async followFeed(feedKeyHex: string): Promise<HypercoreStore> {
    const feedKey = Buffer.from(feedKeyHex, "hex");
    const store = new HypercoreStore(this.dataDir, feedKeyHex, {
      writable: false,
      key: feedKey,
    });
    await store.open();

    const topicHex = store.discoveryKey.toString("hex");
    this.feeds.set(topicHex, { store, writable: false });
    this.swarm.join(store.discoveryKey, { server: false, client: true });

    return store;
  }

  /**
   * Stop following a feed and clean up its swarm topic.
   */
  async unfollow(feedKeyHex: string): Promise<void> {
    for (const [topicHex, feed] of this.feeds) {
      if (feed.store.feedKey.toString("hex") === feedKeyHex) {
        await this.swarm.leave(Buffer.from(topicHex, "hex"));
        await feed.store.close();
        this.feeds.delete(topicHex);
        return;
      }
    }
  }

  /**
   * Wait for the swarm to complete its current discovery round.
   */
  async flush(): Promise<void> {
    await this.swarm.flush();
  }

  /**
   * Shut down the swarm and close all feeds.
   */
  async close(): Promise<void> {
    await this.swarm.destroy();
    await Promise.all([...this.feeds.values()].map(f => f.store.close()));
    this.feeds.clear();
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  private onConnection(socket: Duplex, isClient: boolean): void {
    for (const { store } of this.feeds.values()) {
      const repl = store._core.replicate(isClient) as unknown as Duplex;
      socket.pipe(repl).pipe(socket);
    }
  }
}
