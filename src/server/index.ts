import Fastify from "fastify";
import cors from "@fastify/cors";
import staticFiles from "@fastify/static";
import path from "path";
import { fileURLToPath } from "url";
import { readFileSync, writeFileSync, existsSync } from "fs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

import { deriveIdentity, derivePrivKeyHex } from "../identity/index.js";
import { HypercoreStore } from "../store/hypercore.js";
import { ReplicationManager } from "../replication/index.js";
import { RelayQueryEngine } from "../apps/relay/query.js";
import {
  createMediaNode, createStoragePointerNode,
  createCrosslinkNode, createWatchlistEntryNode,
  MediaPayload, StoragePointerPayload, CrosslinkPayload, WatchlistEntryPayload,
} from "../apps/relay/index.js";
import {
  deriveAuthPubKey,
  createChallenge, consumeChallenge, verifyAuthSignature,
  createSession, verifySession,
} from "../auth/index.js";
import {
  ForestDB, ForestWalker, PVFSVerifier, Pruner,
  registerForestRoutes, createNode, createLink,
} from "../forest/index.js";
import type { ConfigProviderPayload } from "../forest/types.js";

// ── Config from environment ────────────────────────────────────────────────

const PASSPHRASE   = process.env.PV_PASSPHRASE;
const DATA_DIR     = process.env.PV_DATA_DIR ?? "./data";
const PORT         = parseInt(process.env.PV_PORT ?? "8080", 10);
const HOST         = process.env.PV_HOST ?? "0.0.0.0";
const LOG_LEVEL    = process.env.PV_LOG_LEVEL ?? "info";
const TMDB_KEY_ENV = process.env.PV_TMDB_KEY ?? "";  // legacy fallback only

if (!PASSPHRASE) {
  console.error("PV_PASSPHRASE environment variable is required");
  process.exit(1);
}

// ── Auth state ─────────────────────────────────────────────────────────────

const AUTH_PUB_KEY = deriveAuthPubKey(PASSPHRASE);
const challenges   = new Map<string, number>();
const sessions     = new Map<string, number>();

const PUBLIC_ROUTES = new Set(["/health", "/auth/challenge", "/auth/verify"]);
const API_PREFIXES = [
  "/search", "/media", "/storage", "/crosslink", "/watchlist",
  "/follow", "/following", "/identity", "/auth", "/tmdb",
  "/forest", "/config", "/pvfs",
];

// ── Identity & forest ──────────────────────────────────────────────────────

const identity  = await deriveIdentity(PASSPHRASE);
const pubKeyHex = Buffer.from(identity.publicKey).toString("hex");
const privKeyHex = await derivePrivKeyHex(PASSPHRASE);

const FOREST_DB_PATH = process.env.FOREST_DB_PATH ?? path.join(DATA_DIR, "forest.db");
const forestDb = new ForestDB(FOREST_DB_PATH);
const forestWalker = new ForestWalker(forestDb);
const pvfsVerifier = new PVFSVerifier(forestDb, forestWalker, pubKeyHex, privKeyHex);
const pruner = new Pruner(forestDb, forestWalker, pubKeyHex, privKeyHex);

await bootstrapForest(forestDb, forestWalker, pubKeyHex, privKeyHex);

// ── Hypercore / relay ──────────────────────────────────────────────────────

const ownStore = new HypercoreStore(path.join(DATA_DIR, "feeds"), pubKeyHex);
await ownStore.open();

const replication = new ReplicationManager(path.join(DATA_DIR, "feeds"));
await replication.shareOwnFeed(ownStore);

const engine = new RelayQueryEngine();
engine.addFeed(pubKeyHex, ownStore);

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
  if (PUBLIC_ROUTES.has(url)) return;
  const isApiRoute = API_PREFIXES.some(p => url === p || url.startsWith(p + "/"));
  if (!isApiRoute) return;
  const header = req.headers.authorization ?? "";
  if (!header.startsWith("Bearer ") || !verifySession(sessions, header.slice(7))) {
    return reply.status(401).send({ error: "unauthorized" });
  }
});

// ── Auth endpoints ─────────────────────────────────────────────────────────

app.get("/auth/challenge", async () => ({
  challenge: createChallenge(challenges),
}));

app.post<{ Body: { challenge?: string; signature?: string } }>("/auth/verify", async (req, reply) => {
  const { challenge, signature } = req.body ?? {};
  if (!challenge || !signature) return reply.status(400).send({ error: "missing fields" });
  if (!consumeChallenge(challenges, challenge)) {
    return reply.status(401).send({ error: "invalid or expired challenge" });
  }
  if (!verifyAuthSignature(AUTH_PUB_KEY, challenge, signature)) {
    await new Promise(r => setTimeout(r, 200));
    return reply.status(401).send({ error: "invalid signature" });
  }
  return { token: createSession(sessions), identity: pubKeyHex };
});

// ── Forest routes (forest, config, pvfs, prune) ───────────────────────────

registerForestRoutes(app, forestDb, forestWalker, pvfsVerifier, pruner, pubKeyHex, privKeyHex);

// ── Static files + SPA fallback ────────────────────────────────────────────

const clientDir = path.join(__dirname, "../client");
await app.register(staticFiles, {
  root: clientDir,
  prefix: "/",
  decorateReply: false,
});

app.setNotFoundHandler(async (req, reply) => {
  if (API_PREFIXES.some(p => req.url === p || req.url.startsWith(p + "/") || req.url.startsWith(p + "?")) ||
      req.url.startsWith("/health")) {
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

// ── Publish media ──────────────────────────────────────────────────────────

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

app.patch<{
  Params: { mediaId: string };
  Body: { status?: string; progress_ms?: number };
}>("/watchlist/:mediaId", async (req, reply) => {
  const result = engine.getById(req.params.mediaId);
  if (!result) return reply.status(404).send({ error: "media not found" });

  const existing = result.watchlistEntry;
  const status = (req.body.status ?? existing?.payload.status ?? "unwatched") as import("../apps/relay/types.js").WatchStatus;
  const node = await createWatchlistEntryNode(PASSPHRASE!, {
    media_node_id: req.params.mediaId,
    crosslink_node_id: existing?.payload.crosslink_node_id ?? "",
    status,
    added_at: existing?.payload.added_at ?? Date.now(),
    progress_ms: req.body.progress_ms ?? existing?.payload.progress_ms,
    size_bytes: existing?.payload.size_bytes ?? 0,
    ...(status === "watched" ? { watched_at: Date.now() } : {}),
  });
  await ownStore.append(node);
  await engine.refresh();
  return { id: node.id, status };
});

// ── TMDB proxy ────────────────────────────────────────────────────────────
// Forest config takes priority; PV_TMDB_KEY env var is legacy fallback.

const TMDB_BASE = "https://api.themoviedb.org/3";

function getTmdbKey(): string {
  try {
    const cfg = forestWalker.getProviderConfig("tmdb");
    const key = cfg?.["api_key"] as string | undefined;
    if (key) return key;
  } catch { /* fall through */ }
  return TMDB_KEY_ENV;
}

app.get<{ Querystring: { q?: string } }>("/tmdb/search", async (req, reply) => {
  const TMDB_KEY = getTmdbKey();
  if (!TMDB_KEY) return reply.status(503).send({ error: "TMDB not configured — add API key in Settings" });
  const { q } = req.query;
  if (!q) return reply.status(400).send({ error: "q is required" });

  const res = await fetch(`${TMDB_BASE}/search/multi?api_key=${TMDB_KEY}&query=${encodeURIComponent(q)}&include_adult=false`);
  const data = await res.json() as { results?: Record<string, unknown>[] };

  const results = (data.results ?? [])
    .filter((r) => r.media_type === "movie" || r.media_type === "tv")
    .slice(0, 12)
    .map((r) => ({
      tmdb_id: String(r.id),
      media_type: r.media_type as string,
      title: (r.media_type === "movie" ? r.title : r.name) as string,
      year: ((r.media_type === "movie" ? r.release_date : r.first_air_date) as string ?? "").slice(0, 4),
      poster_path: (r.poster_path as string | null) ?? null,
      overview: (r.overview as string | null) ?? null,
    }));

  return { results };
});

app.get<{ Querystring: { id?: string; type?: string } }>("/tmdb/details", async (req, reply) => {
  const TMDB_KEY = getTmdbKey();
  if (!TMDB_KEY) return reply.status(503).send({ error: "TMDB not configured — add API key in Settings" });
  const { id, type } = req.query;
  if (!id || !type) return reply.status(400).send({ error: "id and type are required" });

  const segment = type === "tv" ? "tv" : "movie";
  const res = await fetch(`${TMDB_BASE}/${segment}/${id}?api_key=${TMDB_KEY}&append_to_response=external_ids`);
  const d = await res.json() as Record<string, unknown>;

  const extIds = (d.external_ids ?? {}) as Record<string, unknown>;
  return {
    tmdb_id: String(d.id),
    media_type: type,
    title: (type === "movie" ? d.title : d.name) as string,
    year: ((type === "movie" ? d.release_date : d.first_air_date) as string ?? "").slice(0, 4),
    genres: ((d.genres as { name: string }[] | undefined) ?? []).map((g) => g.name),
    imdb_id: (d.imdb_id ?? extIds.imdb_id ?? undefined) as string | undefined,
    tvdb_id: extIds.tvdb_id ? String(extIds.tvdb_id) : undefined,
    runtime_min: (type === "movie" ? d.runtime : (d.episode_run_time as number[] | undefined)?.[0]) as number | undefined,
    poster_path: (d.poster_path as string | null) ?? null,
    overview: (d.overview as string | null) ?? null,
  };
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
  forestDb.close();
  process.exit(0);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

// ── Start ──────────────────────────────────────────────────────────────────

await app.listen({ port: PORT, host: HOST });
app.log.info(`identity: ${pubKeyHex.slice(0, 16)}...`);
app.log.info(`feed: ${ownStore.feedKey.toString("hex").slice(0, 16)}...`);
app.log.info(`forest: ${FOREST_DB_PATH}`);

// ── Bootstrap forest (runs once on first start) ────────────────────────────

async function bootstrapForest(
  db: ForestDB,
  walker: ForestWalker,
  authorPubKey: string,
  privKey: string,
): Promise<void> {
  if (db.getNodesByType("forest.root").length > 0) return;

  const now = Date.now();

  const forestRoot = await createNode({
    type: "forest.root", label: "MediaForest",
    payload: { version: 1 }, created_at: now, author: authorPubKey,
  }, privKey);
  db.insertNode(forestRoot);

  // Null-parent link marks it as the forest root.
  const forestRootLink = await createLink({
    parent_id: null, child_id: forestRoot.id,
    link_type: "branch", truth_score: 1.0, sort_key: null,
    score_method: null, created_at: now, author: authorPubKey,
  }, privKey);
  db.insertLink(forestRootLink);

  const configRoot = await createNode({
    type: "tree.root", label: "Configuration",
    payload: {}, created_at: now, author: authorPubKey,
  }, privKey);
  db.insertNode(configRoot);
  db.insertLink(await createLink({
    parent_id: forestRoot.id, child_id: configRoot.id,
    link_type: "branch", truth_score: 1.0, sort_key: "config",
    score_method: null, created_at: now, author: authorPubKey,
  }, privKey));

  const providersSection = await createNode({
    type: "config.section", label: "Metadata Providers",
    payload: {}, created_at: now, author: authorPubKey,
  }, privKey);
  db.insertNode(providersSection);
  db.insertLink(await createLink({
    parent_id: configRoot.id, child_id: providersSection.id,
    link_type: "branch", truth_score: 1.0, sort_key: "metadata_providers",
    score_method: null, created_at: now, author: authorPubKey,
  }, privKey));

  const tmdbProvider = await createNode({
    type: "config.provider", label: "TMDB",
    payload: {
      provider_id: "tmdb",
      name: "The Movie Database (TMDB)",
      enabled: false,
    } satisfies ConfigProviderPayload,
    created_at: now, author: authorPubKey,
  }, privKey);
  db.insertNode(tmdbProvider);
  db.insertLink(await createLink({
    parent_id: providersSection.id, child_id: tmdbProvider.id,
    link_type: "branch", truth_score: 1.0, sort_key: "tmdb",
    score_method: null, created_at: now, author: authorPubKey,
  }, privKey));

  // If legacy env var is set, migrate it into the config tree automatically.
  if (TMDB_KEY_ENV) {
    const apiKeyNode = await createNode({
      type: "config.value", label: "api_key",
      payload: { key: "api_key", value: TMDB_KEY_ENV },
      created_at: now, author: authorPubKey,
    }, privKey);
    db.insertNode(apiKeyNode);
    db.insertLink(await createLink({
      parent_id: tmdbProvider.id, child_id: apiKeyNode.id,
      link_type: "branch", truth_score: 1.0, sort_key: "api_key",
      score_method: null, created_at: now, author: authorPubKey,
    }, privKey));
  }
}

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
