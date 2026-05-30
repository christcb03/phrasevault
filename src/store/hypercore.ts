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
import Hypercore from "hypercore";
import { NodeStore } from "./index.js";
import { PVNode } from "../node/types.js";
import { verifyNode } from "../node/index.js";

export class HypercoreStore implements NodeStore {
  private core: Hypercore<PVNode>;
  private indexById = new Map<string, number>(); // node id → block index
  private opened = false;

  constructor(dataDir: string, authorPubKeyHex: string) {
    const feedPath = path.join(dataDir, authorPubKeyHex);
    this.core = new Hypercore<PVNode>(feedPath, { valueEncoding: "json" });
  }

  /**
   * Open the feed and build the in-memory id→index map.
   * Must be called before any other method.
   */
  async open(): Promise<void> {
    await this.core.ready();
    await this.buildIndex();
    this.opened = true;
  }

  async close(): Promise<void> {
    await this.core.close();
    this.opened = false;
  }

  /** The Hypercore public key for this feed (used for replication). */
  get feedKey(): Buffer {
    return this.core.key;
  }

  get length(): number {
    return this.core.length;
  }

  async append(node: PVNode): Promise<void> {
    this.assertOpen();
    if (this.indexById.has(node.id)) return; // idempotent
    if (!verifyNode(node)) throw new Error(`Node ${node.id} failed signature verification`);
    const index = this.core.length;
    await this.core.append(node);
    this.indexById.set(node.id, index);
  }

  async get(id: string): Promise<PVNode | null> {
    this.assertOpen();
    const index = this.indexById.get(id);
    if (index === undefined) return null;
    return this.core.get(index);
  }

  async *list(): AsyncIterable<PVNode> {
    this.assertOpen();
    const stream = this.core.createReadStream();
    for await (const block of stream) {
      yield block;
    }
  }

  private async buildIndex(): Promise<void> {
    this.indexById.clear();
    const len = this.core.length;
    for (let i = 0; i < len; i++) {
      const node = await this.core.get(i, { wait: false });
      if (node?.id) this.indexById.set(node.id, i);
    }
  }

  private assertOpen(): void {
    if (!this.opened) throw new Error("HypercoreStore not open — call open() first");
  }
}
