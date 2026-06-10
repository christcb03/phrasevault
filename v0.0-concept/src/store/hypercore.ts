/**
 * HypercoreStore — persistent append-only feed backed by Hypercore v10.
 *
 * Each user gets one feed stored under:
 *   <dataDir>/<hex-pubkey>/
 *
 * The Hypercore keypair is generated on first use and stored by Hypercore
 * in the feed directory. The PhraseVault identity (secp256k1) is separate
 * and used for node-level signing — the two concerns are distinct.
 *
 * An in-memory id→blockIndex map is built at open time by reading the
 * full feed. For large feeds a Hyperbee index layer would be more efficient,
 * but this is correct and simple for now.
 */

import path from "path";
import Hypercore, { HypercoreOptions } from "hypercore";
import { NodeStore } from "./index.js";
import { PVNode } from "../node/types.js";
import { verifyNode } from "../node/index.js";

interface HypercoreStoreOptions {
  writable?: boolean;
  key?: Buffer; // Provide to open a read-only replica of a known feed
}

export class HypercoreStore implements NodeStore {
  /** Exposed for the replication layer — not intended for application code. */
  readonly _core: Hypercore<PVNode>;
  private indexById = new Map<string, number>(); // node id → block index
  private opened = false;

  constructor(dataDir: string, feedKeyHex: string, opts: HypercoreStoreOptions = {}) {
    const feedPath = path.join(dataDir, feedKeyHex);
    const coreOpts: HypercoreOptions = { valueEncoding: "json" };
    if (opts.writable === false) coreOpts.writable = false;

    if (opts.key) {
      this._core = new Hypercore<PVNode>(feedPath, opts.key, coreOpts);
    } else {
      this._core = new Hypercore<PVNode>(feedPath, coreOpts);
    }
  }

  /**
   * Open the feed and build the in-memory id→index map.
   * Must be called before any other method.
   */
  async open(): Promise<void> {
    await this._core.ready();
    await this.buildIndex();
    this.opened = true;
  }

  async close(): Promise<void> {
    await this._core.close();
    this.opened = false;
  }

  /** The Hypercore public key for this feed (used for replication). */
  get feedKey(): Buffer {
    return this._core.key;
  }

  /** The Hypercore discovery key — used as the Hyperswarm topic. */
  get discoveryKey(): Buffer {
    return this._core.discoveryKey;
  }

  get length(): number {
    return this._core.length;
  }

  async append(node: PVNode): Promise<void> {
    this.assertOpen();
    if (this.indexById.has(node.id)) return; // idempotent
    if (!verifyNode(node)) throw new Error(`Node ${node.id} failed signature verification`);
    const index = this._core.length;
    await this._core.append(node);
    this.indexById.set(node.id, index);
  }

  async get(id: string): Promise<PVNode | null> {
    this.assertOpen();
    const index = this.indexById.get(id);
    if (index === undefined) return null;
    return this._core.get(index);
  }

  async *list(): AsyncIterable<PVNode> {
    this.assertOpen();
    const stream = this._core.createReadStream();
    for await (const block of stream) {
      yield block;
    }
  }

  /**
   * Rebuild the in-memory index from the feed, then refresh with any new
   * blocks that arrived via replication since last open.
   */
  async refresh(): Promise<void> {
    await this.buildIndex();
  }

  private async buildIndex(): Promise<void> {
    this.indexById.clear();
    const len = this._core.length;
    for (let i = 0; i < len; i++) {
      // No { wait: false } — blocks from replication may not be in the
      // local page cache yet even though core.length reflects them.
      const node = await this._core.get(i);
      if (node?.id) this.indexById.set(node.id, i);
    }
  }

  private assertOpen(): void {
    if (!this.opened) throw new Error("HypercoreStore not open — call open() first");
  }
}
