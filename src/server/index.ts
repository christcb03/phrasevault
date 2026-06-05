import Fastify from "fastify";
import cors from "@fastify/cors";
import path from "path";
import { fileURLToPath } from "url";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

import { deriveIdentity, derivePrivKeyHex, identityFromPrivKey, generatePrivKey } from "../identity/index.js";
import {
  deriveAuthPubKey,
  createChallenge, consumeChallenge, verifyAuthSignature,
  createSession, verifySession,
} from "../auth/index.js";
import {
  ForestDB, ForestWalker, PVFSVerifier, Pruner,
  registerForestRoutes, createNode, createLink,
  deriveForestEncKey, serializePayload, defaultVisibility,
  ensurePrimaryRoot, backfillPrimaryTree,
} from "../forest/index.js";
import type { ConfigProviderPayload } from "../forest/types.js";

// ── Config from environment ────────────────────────────────────────────────

const PASSPHRASE     = process.env.PV_PASSPHRASE;   // deprecated — backward compat only
const DATA_DIR       = process.env.PV_DATA_DIR ?? "./data";
const PORT           = parseInt(process.env.PV_PORT ?? "8081", 10);  // default 8081 (platform port)
const HOST           = process.env.PV_HOST ?? "0.0.0.0";
const LOG_LEVEL      = process.env.PV_LOG_LEVEL ?? "info";
const TMDB_TOKEN_ENV = process.env.PV_TMDB_KEY ?? "";

// ── Server key ─────────────────────────────────────────────────────────────

interface ServerKey {
  version: number;
  identityPrivKey: string;
  authPubKey: string | null;
}

const SERVER_KEY_PATH = path.join(DATA_DIR, "server_key.json");

function loadOrCreateServerKey(): ServerKey {
  if (existsSync(SERVER_KEY_PATH)) {
    return JSON.parse(readFileSync(SERVER_KEY_PATH, "utf-8")) as ServerKey;
  }
  mkdirSync(DATA_DIR, { recursive: true });
  const key: ServerKey = { version: 1, identityPrivKey: generatePrivKey(), authPubKey: null };
  writeFileSync(SERVER_KEY_PATH, JSON.stringify(key, null, 2), { mode: 0o600 });
  return key;
}

function saveServerKey(key: ServerKey): void {
  writeFileSync(SERVER_KEY_PATH, JSON.stringify(key, null, 2), { mode: 0o600 });
}

// ── Identity & forest ──────────────────────────────────────────────────────

let privKeyHex: string;
let identity: Awaited<ReturnType<typeof deriveIdentity>>;

if (PASSPHRASE) {
  console.warn("[PhraseVault] PV_PASSPHRASE is deprecated. Server will migrate to server_key.json on next fresh deploy.");
  privKeyHex = await derivePrivKeyHex(PASSPHRASE);
  identity   = await deriveIdentity(PASSPHRASE);
} else {
  const serverKey = loadOrCreateServerKey();
  privKeyHex = serverKey.identityPrivKey;
  identity   = identityFromPrivKey(privKeyHex);
}

const pubKeyHex    = Buffer.from(identity.publicKey).toString("hex");
const forestEncKey = PASSPHRASE ? deriveForestEncKey(PASSPHRASE) : deriveForestEncKey(privKeyHex);

const FOREST_DB_PATH = process.env.FOREST_DB_PATH ?? path.join(DATA_DIR, "forest.db");
const PVFS_STORE_DIR = path.join(DATA_DIR, "pvfs");
mkdirSync(PVFS_STORE_DIR, { recursive: true });

const forestDb     = new ForestDB(FOREST_DB_PATH);
const forestWalker = new ForestWalker(forestDb, forestEncKey);
const pvfsVerifier = new PVFSVerifier(forestDb, forestWalker, pubKeyHex, privKeyHex, forestEncKey, PVFS_STORE_DIR);
const pruner       = new Pruner(forestDb, forestWalker, pubKeyHex, privKeyHex, forestEncKey);

await bootstrapForest(forestDb, forestWalker, pubKeyHex, privKeyHex, forestEncKey);
await ensurePrimaryRoot(forestDb, forestWalker, pubKeyHex, privKeyHex, forestEncKey);
const backfill = await backfillPrimaryTree(forestDb, forestWalker, pubKeyHex, privKeyHex, forestEncKey);
if (backfill.linked > 0) {
  console.info(`[PhraseVault] Linked ${backfill.linked} existing pvfs.file node(s) into primary tree`);
}

// ── Auth state ─────────────────────────────────────────────────────────────

let AUTH_PUB_KEY: Uint8Array | null = PASSPHRASE ? deriveAuthPubKey(PASSPHRASE) : (() => {
  const sk = loadOrCreateServerKey();
  return sk.authPubKey ? Buffer.from(sk.authPubKey, "hex") : null;
})();

const challenges = new Map<string, number>();
const sessions   = new Map<string, number>();

const PUBLIC_ROUTES = new Set(["/health", "/auth/challenge", "/auth/verify", "/auth/register"]);
const API_PREFIXES  = ["/forest", "/config", "/pvfs", "/auth", "/identity"];

// ── Fastify ────────────────────────────────────────────────────────────────

const app = Fastify({ logger: { level: LOG_LEVEL } });
await app.register(cors, { origin: true });

// ── Auth middleware ────────────────────────────────────────────────────────

app.addHook("onRequest", async (req, reply) => {
  const url = req.url.split("?")[0];
  if (PUBLIC_ROUTES.has(url)) return;
  const isApiRoute = API_PREFIXES.some(p => url === p || url.startsWith(p + "/"));
  if (!isApiRoute) return;
  if (!AUTH_PUB_KEY) {
    return reply.status(401).send({ error: "server not configured: POST /auth/register first" });
  }
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
  if (!AUTH_PUB_KEY) return reply.status(401).send({ error: "server not configured: POST /auth/register first" });
  if (!consumeChallenge(challenges, challenge)) {
    return reply.status(401).send({ error: "invalid or expired challenge" });
  }
  if (!verifyAuthSignature(AUTH_PUB_KEY, challenge, signature)) {
    await new Promise(r => setTimeout(r, 200));
    return reply.status(401).send({ error: "invalid signature" });
  }
  return { token: createSession(sessions), identity: pubKeyHex };
});

app.post<{ Body: { pubKey?: string } }>("/auth/register", async (req, reply) => {
  if (PASSPHRASE) {
    return reply.status(400).send({ error: "server uses passphrase auth — registration not applicable" });
  }
  const { pubKey } = req.body ?? {};
  if (!pubKey || !/^[0-9a-f]{66}$/.test(pubKey)) {
    return reply.status(400).send({ error: "pubKey must be a 33-byte compressed secp256k1 key in hex (66 chars)" });
  }
  if (AUTH_PUB_KEY) {
    // Idempotent: if the same key is already registered, return success
    const existing = Buffer.from(AUTH_PUB_KEY).toString("hex");
    if (existing === pubKey) return { registered: true, serverIdentity: pubKeyHex };
    return reply.status(409).send({ error: "already registered with a different key" });
  }
  const serverKey = loadOrCreateServerKey();
  serverKey.authPubKey = pubKey;
  saveServerKey(serverKey);
  AUTH_PUB_KEY = Buffer.from(pubKey, "hex");
  return { registered: true, serverIdentity: pubKeyHex };
});

// ── Forest routes ──────────────────────────────────────────────────────────

registerForestRoutes(app, forestDb, forestWalker, pvfsVerifier, pruner, pubKeyHex, privKeyHex, forestEncKey, PVFS_STORE_DIR);

// ── Health ─────────────────────────────────────────────────────────────────

app.get("/health", async () => ({
  status: "ok",
  identity: pubKeyHex,
  forest: FOREST_DB_PATH,
}));

// ── Identity ───────────────────────────────────────────────────────────────

app.get("/identity", async () => ({
  publicKey: pubKeyHex,
  did: identity.did,
}));

// ── Shutdown ───────────────────────────────────────────────────────────────

async function shutdown() {
  await app.close();
  forestDb.close();
  process.exit(0);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

// ── Start ──────────────────────────────────────────────────────────────────

await app.listen({ port: PORT, host: HOST });
app.log.info(`identity: ${pubKeyHex.slice(0, 16)}...`);
app.log.info(`forest: ${FOREST_DB_PATH}`);

// ── Bootstrap forest ───────────────────────────────────────────────────────

async function bootstrapForest(
  db: ForestDB,
  walker: ForestWalker,
  authorPubKey: string,
  privKey: string,
  encKey: Uint8Array,
): Promise<void> {
  if (db.getNodesByType("forest.root").length > 0) return;

  const now = Date.now();

  async function makeNode(type: Parameters<typeof createNode>[0]["type"], label: string, rawPayload: unknown) {
    const vis = defaultVisibility(type);
    const payload = serializePayload(rawPayload, vis, vis === "public" ? null : encKey);
    return createNode({ type, label, visibility: vis, payload, created_at: now, author: authorPubKey }, privKey);
  }

  const forestRoot = await makeNode("forest.root", "MediaForest", { version: 1 });
  db.insertNode(forestRoot);
  db.insertLink(await createLink({
    parent_id: null, child_id: forestRoot.id,
    link_type: "branch", truth_score: 1.0, sort_key: null,
    score_method: null, created_at: now, author: authorPubKey,
  }, privKey));

  const configRoot = await makeNode("tree.root", "Configuration", {});
  db.insertNode(configRoot);
  db.insertLink(await createLink({
    parent_id: forestRoot.id, child_id: configRoot.id,
    link_type: "branch", truth_score: 1.0, sort_key: "config",
    score_method: null, created_at: now, author: authorPubKey,
  }, privKey));

  const providersSection = await makeNode("config.section", "Metadata Providers", {});
  db.insertNode(providersSection);
  db.insertLink(await createLink({
    parent_id: configRoot.id, child_id: providersSection.id,
    link_type: "branch", truth_score: 1.0, sort_key: "metadata_providers",
    score_method: null, created_at: now, author: authorPubKey,
  }, privKey));

  const tmdbProvider = await makeNode("config.provider", "TMDB", {
    provider_id: "tmdb",
    name: "The Movie Database (TMDB)",
    enabled: false,
  } satisfies ConfigProviderPayload);
  db.insertNode(tmdbProvider);
  db.insertLink(await createLink({
    parent_id: providersSection.id, child_id: tmdbProvider.id,
    link_type: "branch", truth_score: 1.0, sort_key: "tmdb",
    score_method: null, created_at: now, author: authorPubKey,
  }, privKey));

  if (TMDB_TOKEN_ENV) {
    const tokenNode = await makeNode("config.value", "read_access_token", { key: "read_access_token", value: TMDB_TOKEN_ENV });
    db.insertNode(tokenNode);
    db.insertLink(await createLink({
      parent_id: tmdbProvider.id, child_id: tokenNode.id,
      link_type: "branch", truth_score: 1.0, sort_key: "read_access_token",
      score_method: null, created_at: now, author: authorPubKey,
    }, privKey));
  }
}

