/**
 * Minimal type declarations for hyperswarm v4 (CJS, no bundled types).
 */

declare module "hyperswarm" {
  import { EventEmitter } from "events";
  import { Duplex } from "stream";

  interface PeerInfo {
    publicKey: Buffer;
    topics: Buffer[];
    client: boolean;
    server: boolean;
  }

  interface JoinOptions {
    server?: boolean;
    client?: boolean;
    limit?: number;
  }

  interface PeerDiscovery {
    flushed(): Promise<void>;
    destroy(): Promise<void>;
  }

  interface HyperswarmOptions {
    seed?: Buffer;
    maxPeers?: number;
    keyPair?: { publicKey: Buffer; secretKey: Buffer };
    firewall?: (remotePublicKey: Buffer) => boolean;
  }

  class Hyperswarm extends EventEmitter {
    constructor(opts?: HyperswarmOptions);

    readonly connections: Set<Duplex>;
    readonly peers: Map<string, PeerInfo>;
    readonly connecting: number;

    on(event: "connection", listener: (socket: Duplex, info: PeerInfo) => void): this;
    on(event: string, listener: (...args: unknown[]) => void): this;

    join(topic: Buffer, opts?: JoinOptions): PeerDiscovery;
    leave(topic: Buffer): Promise<void>;
    joinPeer(noisePublicKey: Buffer): void;
    leavePeer(noisePublicKey: Buffer): void;
    flush(): Promise<void>;
    listen(): Promise<void>;
    destroy(): Promise<void>;
  }

  export = Hyperswarm;
}
