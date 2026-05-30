/**
 * Storage layer — Hypercore feed abstraction.
 * Stub: interface defined, Hypercore wiring to follow.
 *
 * Each user's nodes live in their own Hypercore feed, keyed by their
 * secp256k1 public key. The feed key IS the user's identity.
 */

import { PVNode } from "../node/types.js";

export interface NodeStore {
  /** Append a node to this feed. Node must be fully signed. */
  append(node: PVNode): Promise<void>;

  /** Get a node by id. Returns null if not found. */
  get(id: string): Promise<PVNode | null>;

  /** Iterate all nodes in this feed in append order. */
  list(): AsyncIterable<PVNode>;
}

/**
 * In-memory store for development/testing.
 * Replace with HypercoreStore once Hypercore wiring is complete.
 */
export class MemoryStore implements NodeStore {
  private nodes = new Map<string, PVNode>();
  private order: string[] = [];

  async append(node: PVNode): Promise<void> {
    if (this.nodes.has(node.id)) return; // idempotent
    this.nodes.set(node.id, node);
    this.order.push(node.id);
  }

  async get(id: string): Promise<PVNode | null> {
    return this.nodes.get(id) ?? null;
  }

  async *list(): AsyncIterable<PVNode> {
    for (const id of this.order) {
      const node = this.nodes.get(id);
      if (node) yield node;
    }
  }
}

export { HypercoreStore } from "./hypercore.js";
