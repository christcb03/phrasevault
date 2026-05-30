/**
 * Minimal type declarations for hypercore v10 (CJS, no bundled types).
 * Only covers the API surface we actually use.
 */

declare module "hypercore" {
  import { Readable } from "stream";

  interface HypercoreOptions {
    valueEncoding?: "json" | "utf-8" | "binary";
    writable?: boolean;
    keyPair?: { publicKey: Buffer; secretKey: Buffer };
    sparse?: boolean;
  }

  interface AppendResult {
    length: number;
    byteLength: number;
  }

  interface ReadStreamOptions {
    start?: number;
    end?: number;
    live?: boolean;
  }

  class Hypercore<T = unknown> {
    constructor(storage: string, options?: HypercoreOptions);
    constructor(storage: string, key: Buffer | string, options?: HypercoreOptions);

    readonly length: number;
    readonly byteLength: number;
    readonly writable: boolean;
    readonly key: Buffer;
    readonly discoveryKey: Buffer;

    ready(): Promise<void>;
    close(): Promise<void>;
    append(block: T | T[]): Promise<AppendResult>;
    get(index: number, options?: { wait?: boolean; timeout?: number }): Promise<T>;
    createReadStream(options?: ReadStreamOptions): Readable & AsyncIterable<T>;
    update(options?: { wait?: boolean }): Promise<boolean>;
  }

  export = Hypercore;
}
