/**
 * PhraseVault / Relay HTTP API server.
 *
 * Single-user server: one identity (passphrase from env), one writable feed,
 * N followed feeds. Exposes the Relay query engine and node operations over REST.
 *
 * Start with:
 *   PV_PASSPHRASE=... PV_DATA_DIR=./data node dist/server/index.js
 */

import Fastify from "fastify";
import cors from "@fastify/cors";
import staticFiles from "@fastify/static";
import path from "path";
import { fileURLToPath } from "url";
import { randomBytes } from "crypto";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
import { deriveIdentity } from "../identity/index.js";
import { HypercoreStore } from "../store/hypercore.js";
import { ReplicationManager } from "../replication/index.js";
import { RelayQueryEngine } from "../apps/relay/query.js";
import {
  createMediaNode, createStoragePointerNode,
  createCrosslinkNode, createWatchlistEntryNode,
  MediaPayload, StoragePointerPayload, CrosslinkPayload, WatchlistEntryPayload,
} from "../apps/relay/index.js";
import { deriveApiToken, verifyBearer } from "../auth/index.js";

// ── Config from environment ────────────────────────────────────────────────

const PASSPHRASE = process.env.PV_PASSPHRASE;
const DATA_DIR   = process.env.PV_DATA_DIR ?? "./data";
const PORT       = parseInt(process.env.PV_PORT ?? "8080", 10);
const HOST       = process.env.PV_HOST ?? "0.0.0.0";
const LOG_LEVEL  = process.env.PV_LOG_LEVEL ?? "info";

if (!PASSPHRASE) {
  console.error("PV_PASSPHRASE environment variable is required");
  process.exit(1);
}

// ── Auth token (derived from passphrase, distinct domain from keypair) ─────

const API_TOKEN = deriveApiToken(PASSPHRASE);

// Routes exempt from bearer-token auth
const PUBLIC_ROUTES = new Set(["/health", "/auth/login", "/auth/challenge"]);
// API route prefixes that require auth (SPA routes pass through without auth)
const API_PREFIXES = [
  "/search", "/media", "/storage", "/crosslink", "/watchlist",
  "/follow", "/following", "/identity", "/auth",
];

// ── Bootstrap ─────────────────────────────────────────────────────────────

const identity   = await deriveIdentity(PASSPHRASE);
const pubKeyHex  = Buffer.from(identity.publicKey).toString("hex");
const ownStore   = new HypercoreStore(path.join(DATA_DIR, "feeds"), pubKeyHex);
await ownStore.open();

const replication = new ReplicationManager(path.join(DATA_DIR, "feeds"));
await replication.shareOwnFeed(ownStore);

const engine = new RelayQueryEngine();
engine.addFeed(pubKeyHex, ownStore);

// Load previously followed feeds from disk (persisted in followed.json)
import { readFileSync, writeFileSync, existsSync } from "fs";
const FOLLOWED_PATH = path.join(DATA_DIR, "followed.json");
const followedKeys: string[] = existsSync(FOLLOWED_PATH)
  ? JSON.parse(readFileSync(FOLLOWED_PATH, "utf-8"))
  : [];

for (const key of followedKeys) {
  const store = await replication.followFeed(key);
  engine.addFeed(key, store);
}

await engine.refresh();

// ── Fastify ────────────────────────────────────────────────────────────────

const app = Fastify({ logger: { level: LOG_LEVEL } });
await app.register(cors, { origin: true });

// ── Auth middleware ────────────────────────────────────────────────────────

app.addHook("onRequest", async (req, reply) => {
  const url = req.url.split("?")[0];

  // Pass through public routes unconditionally
  if (PUBLIC_ROUTES.has(url)) return;

  // Pass through SPA/frontend routes (they load the React app which shows login)
  const isApiRoute = API_PREFIXES.some(p => url === p || url.startsWith(p + "/"));
  if (!isApiRoute) return;

  // All API routes require a valid bearer token
  const header = req.headers.authorization ?? "";
  if (!header.startsWith("Bearer ") || !verifyBearer(header.slice(7), API_TOKEN)) {
    return reply.status(401).send({ error: "unauthorized" });
  }
});

// ── Auth endpoints ─────────────────────────────────────────────────────────

app.post<{ Body: { passphrase?: string } }>("/auth/login", async (req, reply) => {
  const { passphrase } = req.body ?? {};
  if (!passphrase || !verifyBearer(deriveApiToken(passphrase), API_TOKEN)) {
    await new Promise(r => setTimeout(r, 200)); // slow down brute force
    return reply.status(401).send({ error: "invalid passphrase" });
  }
  return { token: API_TOKEN, identity: pubKeyHex };
});

// Placeholder for future challenge-response upgrade
app.get("/auth/challenge", async () => ({
  challenge: randomBytes(32).toString("hex"),
  note: "sign this nonce with your secp256k1 private key, then POST to /auth/verify",
}));

// ── Static files + SPA fallback ────────────────────────────────────────────

const clientDir = path.join(__dirname, "../client");
await app.register(staticFiles, {
  root: clientDir,
  prefix: "/",
  decorateReply: false,
});

app.setNotFoundHandler(async (req, reply) => {
  if (req.url.startsWith("/health") || req.url.startsWith("/search") ||
      req.url.startsWith("/media") || req.url.startsWith("/storage") ||
      req.url.startsWith("/crosslink") || req.url.startsWith("/watchlist") ||
      req.url.startsWith("/follow") || req.url.startsWith("/identity") ||
      req.url.startsWith("/following") || req.url.startsWith("/auth")) {
    return reply.status(404).send({ error: "not found" });
  }
  return reply.sendFile("index.html");
});

// ── Health (public) ────────────────────────────────────────────────────────

app.get("/health", async () => ({
  status: "ok",
  identity: pubKeyHex,
  feedLength: ownStore.length,
  following: followedKeys.length,
  indexed: engine.size,
}));

// ── Identity ───────────────────────────────────────────────────────────────

app.get("/identity", async () => ({
  publicKey: pubKeyHex,
  did: identity.did,
  feedKey: ownStore.feedKey.toString("hex"),
}));

// ── Search ─────────────────────────────────────────────────────────────────

app.get<{
  Querystring: { q?: string; kind?: string; available?: string; watchStatus?: string }
}>("/search", async (req) => {
  const { q, kind, available, watchStatus } = req.query;
  const results = engine.search({
    query: q,
    kind: kind as never,
    availableOnly: available === "true",
    watchStatus: watchStatus as never,
  });
  return { count: results.length, results: results.map(serializeResult) };
});

app.get<{ Params: { id: string } }>("/media/:id", async (req, reply) => {
  const result = engine.getById(req.params.id);
  if (!result) return reply.status(404).send({ error: "not found" });
  return serializeResult(result);
});

// ── Publish media (own library) ────────────────────────────────────────────

app.post<{ Body: MediaPayload }>("/media", async (req, reply) => {
  const node = await createMediaNode(PASSPHRASE!, req.body);
  await ownStore.append(node);
  await engine.refresh();
  reply.status(201);
  return { id: node.id };
});

app.post<{ Body: StoragePointerPayload }>("/storage", async (req, reply) => {
  const node = await createStoragePointerNode(PASSPHRASE!, req.body);
  await ownStore.append(node);
  await engine.refresh();
  reply.status(201);
  return { id: node.id };
});

// ── Watchlist ──────────────────────────────────────────────────────────────

app.post<{ Body: CrosslinkPayload }>("/crosslink", async (req, reply) => {
  const node = await createCrosslinkNode(PASSPHRASE!, {
    ...req.body,
    added_at: req.body.added_at ?? Date.now(),
  });
  await ownStore.append(node);
  await engine.refresh();
  reply.status(201);
  return { id: node.id };
});

app.post<{ Body: WatchlistEntryPayload }>("/watchlist", async (req, reply) => {
  const node = await createWatchlistEntryNode(PASSPHRASE!, {
    ...req.body,
    added_at: req.body.added_at ?? Date.now(),
  });
  await ownStore.append(node);
  await engine.refresh();
  reply.status(201);
  return { id: node.id };
});

// ── Follow / unfollow peers ────────────────────────────────────────────────

app.post<{ Body: { feedKey: string } }>("/follow", async (req, reply) => {
  const { feedKey } = req.body;
  if (followedKeys.includes(feedKey)) {
    return reply.status(409).send({ error: "already following" });
  }
  const store = await replication.followFeed(feedKey);
  engine.addFeed(feedKey, store);
  followedKeys.push(feedKey);
  writeFileSync(FOLLOWED_PATH, JSON.stringify(followedKeys));
  await engine.refresh();
  reply.status(201);
  return { following: feedKey };
});

app.delete<{ Params: { feedKey: string } }>("/follow/:feedKey", async (req) => {
  const { feedKey } = req.params;
  await replication.unfollow(feedKey);
  engine.removeFeed(feedKey);
  const idx = followedKeys.indexOf(feedKey);
  if (idx !== -1) followedKeys.splice(idx, 1);
  writeFileSync(FOLLOWED_PATH, JSON.stringify(followedKeys));
  await engine.refresh();
  return { unfollowed: feedKey };
});

app.get("/following", async () => ({ keys: followedKeys }));

// ── Shutdown ───────────────────────────────────────────────────────────────

async function shutdown() {
  await app.close();
  await replication.close();
  await ownStore.close();
  process.exit(0);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

// ── Start ──────────────────────────────────────────────────────────────────

await app.listen({ port: PORT, host: HOST });
app.log.info(`identity: ${pubKeyHex.slice(0, 16)}...`);
app.log.info(`feed: ${ownStore.feedKey.toString("hex").slice(0, 16)}...`);

// ── Helpers ────────────────────────────────────────────────────────────────

function serializeResult(r: import("../apps/relay/query.js").MediaResult) {
  return {
    id: r.media.id,
    title: r.media.payload.title,
    year: r.media.payload.year,
    kind: r.media.payload.kind,
    genres: r.media.payload.genres,
    imdb_id: r.media.payload.imdb_id,
    sources: r.sources.map(s => ({
      storageNodeId: s.storagePointer.id,
      endpointUrl: s.storagePointer.payload.endpoint_url,
      encoding: s.storagePointer.payload.encoding,
      available: s.storagePointer.payload.available,
      sizeBytes: s.storagePointer.payload.size_bytes,
      feedOwner: s.feedOwner,
    })),
    bestSource: r.bestSource ? {
      endpointUrl: r.bestSource.storagePointer.payload.endpoint_url,
      encoding: r.bestSource.storagePointer.payload.encoding,
    } : null,
    watchlist: r.watchlistEntry ? {
      status: r.watchlistEntry.payload.status,
      addedAt: r.watchlistEntry.payload.added_at,
      progressMs: r.watchlistEntry.payload.progress_ms,
    } : null,
  };
}
