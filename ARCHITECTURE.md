# PhraseVault Architecture Log

This file is the canonical planning log. Update it when decisions are made.
It exists so context can be recovered after conversation resets.

Last updated: 2026-05-31

---

## What PhraseVault Is

A decentralized, open-source knowledge platform. Anyone can run a server.
No single entity controls it. The platform is the infrastructure layer.

**MediaForest** (working name — permanent name TBD) is the media application
currently being built on PhraseVault. It is a personal media library + friend
sharing layer backed by the Truth Forest data model and PVFS file abstraction.

**eBable** is a separate commercial application built on top of PhraseVault,
run by Chris on his own servers. eBable is the IT application-integration
tool ("Babel Fish for apps") — it uses PhraseVault as its data storage layer.

---

## Core Concepts

**Node** — the base unit of knowledge in PhraseVault. Every node has a
platform-defined base schema (id, author, signature, timestamp, type, payload,
visibility). The `type` field and payload schema are defined by the application
layer. Node IDs are content-addressed (BLAKE3 hash of content) — immutable by design.

**Truth Forest** — a collection of Truth Trees. Every user maintains one logical
forest. In a multi-tenant server deployment, each user's forest is a separate
SQLite DB file on the server, isolated from all others.

**Truth Tree** — a DAG of nodes with a named root. A node can be the root of
one tree and a branch of another simultaneously. Trees are traversed by
following branch links downward from a root, or cross-links to nodes that
participate in multiple trees.

**Link** — a directed edge in the forest between two nodes. Links are content-
addressed and signed. The forest link layer is mutable (links can be soft-
deleted or superseded); the node layer is append-only.

**Truth Score** — a value on each link (0.0–1.0) describing how well the child
node adheres to the parent node's premise. The score is relational: the same
node can have different scores under different parents (e.g. "Alien" might be
0.90 under "Sci-Fi" and 0.65 under "Horror"). A `score_method` field records
how the score was derived ("manual", "bayesian:P(x|evidence)", etc.).

**Validity Rule** — a node is valid in the forest if and only if there exists
an unbroken, unaltered signed link chain from that node to a root. If any link
in the chain is removed or superseded, all nodes below it become orphaned and
lose validity until re-linked.

**PVFS (PhraseVault File System)** — a torrent-like file abstraction layer.
Files are identified by BLAKE3 content hash, not by path. A `pvfs.file` node
holds the hash, size, and MIME type; `pvfs.location` child nodes hold the
actual endpoint URIs (local disk, HTTP, peer, torrent). When a file is served,
PVFS verifies the bytes match the node's hash before streaming.

**Credit** — a reputation token earned by creating nodes that get used/
referenced. Signed and verifiable, not a blockchain token (no gas fees).

---

## Data Model: Two-Layer Design

### Layer 1 — PhraseVault Platform (infrastructure, application-agnostic)

Every node, regardless of application, has these base fields:

```
{
  id:         string       // BLAKE3 content hash (immutable identity)
  type:       string       // application-defined (e.g. "media.movie")
  label:      string       // human-readable name
  author:     string       // secp256k1 public key (hex)
  sig:        string       // secp256k1 signature over node content
  created_at: number       // unix timestamp ms
  visibility: string       // "public" | "private" | "community:<id>"
  payload:    object|string // plaintext object if public; AES-GCM ciphertext if private/community
}
```

The platform handles: storage, replication, signing verification, DAG
traversal, score propagation, credit attestations. Nothing else.

### Layer 2 — Application Layer (MediaForest, eBable, or any other app)

Applications define their own node types and payload schemas.
PhraseVault does not validate payload content — only signature and structure.

---

## Encryption Model

### Design Principle

The server is a dumb, trusted storage node. It stores and replicates bytes.
**Server operators can never read private or community content**, regardless of
whether they have filesystem access to the SQLite DB files.

Public nodes (library index, PVFS file/location metadata) are stored as
plaintext — this is intentional; they are meant to be discoverable and shareable.
All other nodes are opaque ciphertext to the server.

### Visibility Levels

**`"public"`**
- Payload stored as plaintext JSON.
- Readable by anyone with access to the server (authenticated or unauthenticated,
  depending on server policy).
- Used for: `media.*`, `pvfs.file`, `pvfs.location` — content the user wants
  to share and make discoverable.

**`"private"`**
- Payload AES-256-GCM encrypted before writing to DB.
- Encryption key: `BLAKE3("phrasevault:forest-enc-v1:" + passphrase)`
- IV (nonce) is random 12 bytes, prepended to ciphertext.
- Stored as base64 in the `payload` column.
- Server stores opaque ciphertext. Only the owner (with their passphrase) can
  decrypt — in the companion app or client code. Never decrypted on the server.
- Used for: `user.watchlist_entry`, `user.rating`, `user.note`, `config.*`

**`"community:<community-node-id>"`**
- Payload encrypted with a community shared key (AES-256-GCM).
- The community key is itself wrapped (ECIES) once per member using each
  member's secp256k1 public key, and stored in the `community` node.
- To read: fetch community node → ECDH-unwrap your copy of the community key
  → decrypt payload.
- To share a node with a community: re-encrypt payload with the community key,
  set visibility to `community:<id>`.
- Used for: friend-shared library entries, watch-together rooms, shared lists.

### Key Derivation

```
Forest encryption key (private nodes):
  forestEncKey = BLAKE3("phrasevault:forest-enc-v1:" + passphrase)

Auth private key (login challenge-response, browser-safe):
  authPrivKey = BLAKE3("phrasevault:api-auth-v1:" + passphrase)

Identity keypair (node signing, peer identity):
  identityPrivKey = Argon2id(passphrase, salt=BLAKE3("phrasevault:identity:v1:" + passphrase))

Community key exchange (ECIES):
  sharedSecret  = ECDH(ephemeralPrivKey, recipientPubKey)
  wrapKey       = BLAKE3("phrasevault:community-wrap-v1:" + hex(sharedSecret))
  wrappedCommKey = AES-256-GCM(wrapKey, communityKey)
```

All three derivation paths are domain-separated. The identity path uses Argon2id
(memory-hard) because it protects the long-term signing key; the encryption and
auth paths use plain BLAKE3 because they need to run in lightweight contexts
(browser, companion).

### What the server can see

- Which public keys have registered forests
- When nodes were created (timestamps)
- Node types and labels of **public** nodes (used for server-side search)
- Payloads of **public** nodes
- That private/community nodes exist (their IDs, types, timestamps) but
  not their contents — payload column is opaque ciphertext

### Search on Encrypted Data

Server-side full-text search works on public nodes only (which covers the
primary use case: searching the media library by title, genre, year). Private
nodes (watchlist, ratings) are searched client-side in the companion/browser
after decryption.

---

## Multi-Tenant Server Model

### Overview

A server node hosts multiple independent user forests. It operates in one of
two modes:

**Open mode** (default on fresh install): any client companion app can connect
and register a new forest. The server derives no identity from a passphrase.
It is a neutral storage host.

**Closed mode**: set by operator config. New forest registrations are rejected.
Only pubKeys already registered can authenticate. Used for servers you want to
lock down after your own forest is created.

### Server Identity

The server has its own identity keypair (generated once on first start, stored
in `$PV_DATA_DIR/server_key.json`) used for:
- Signing its own nodes in the p2p mesh (when acting as a peer)
- TLS certificate identity (future)

This is separate from any user's identity. Users never share their passphrase
with the server.

### Registration Flow

```
1. Companion app: generates/reads user's authPubKey from passphrase
2. Companion app: POST /auth/register { pubKey } (only accepted in Open mode)
3. Server: creates users DB entry (pubKey → forest_db path), creates empty ForestDB
4. Server: returns { registered: true, serverPubKey }
5. Companion: stores { serverUrl, serverPubKey } in its servers list
```

Registration is idempotent — registering the same pubKey twice is a no-op.

### Per-Request Auth & Forest Routing

```
GET /auth/challenge?pubKey=<hex>
  → server looks up pubKey, creates per-user challenge nonce
  → if pubKey unknown and server is Open: reject (must register first)
  → if pubKey unknown and server is Closed: 403

POST /auth/verify { pubKey, challenge, signature }
  → server verifies sig against stored pubKey
  → issues session token scoped to that pubKey
  → all subsequent requests routed to that user's ForestDB instance
```

### Per-User Forest Isolation

Each user's forest is a separate SQLite file:
```
$PV_DATA_DIR/forests/<pubKey-hex>.db
```

ForestDB instances are cached in a Map on the server process. No data ever
crosses between users' DB files. A server operator with filesystem access sees
only public node payloads (ciphertext for private nodes).

### Users Registry

A small `users.db` (separate SQLite) stores:
```sql
CREATE TABLE users (
  pub_key      TEXT PRIMARY KEY,
  forest_db    TEXT NOT NULL,          -- path to this user's forest.db
  registered_at INTEGER NOT NULL,
  last_seen_at  INTEGER
);

CREATE TABLE server_config (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
-- key 'mode' = 'open' | 'closed'
-- key 'server_pub_key' = hex
-- key 'server_priv_key' = hex (encrypted with server-derived key)
```

### Revocation

Client sends a signed `DELETE /auth/forest` request. Server:
1. Verifies the signature matches the forest owner's pubKey
2. Deletes `forests/<pubKey>.db`
3. Removes the pubKey from `users.db`
4. Returns `{ revoked: true }`

The user's data is gone from that server. The companion removes that server
from its servers list.

### `PV_PASSPHRASE` env var (deprecated)

The single-passphrase model is deprecated in favor of multi-tenant. For
backward compatibility during migration, if `PV_PASSPHRASE` is set, the server
boots in single-user compatibility mode: it registers one forest for that
passphrase's pubKey and enters Closed mode automatically.

---

## Sync — Hypercore as the Replication Layer

### Architecture

Each user's forest has a Hypercore feed keyed by their public key. Forest
nodes are serialized as Hypercore entries as they are written. SQLite is a
local query index derived from the Hypercore feed — it can be fully rebuilt
from the feed at any time.

This means sync between servers is just Hypercore replication:
- User logs into Server B (registers their pubKey)
- Companion tells Server A to replicate the user's Hypercore feed to Server B
- Server B's SQLite index is populated from the feed
- From that point, new writes on either server propagate via Hypercore's
  built-in real-time replication protocol

Near-real-time sync (sub-second on LAN) is Hypercore's default behavior —
it's push-based over persistent connections.

### Companion Manages Server List

The companion's `~/.config/phrasevault/config.json` stores:
```json
{
  "passphrase": "...",
  "servers": [
    { "url": "http://192.168.0.184:8080", "pubKey": "<server-pub-key-hex>", "registered": true }
  ]
}
```

On startup, the companion verifies its passphrase against each registered
server (challenge-response). On write, it pushes to all online servers.

### Conflict Resolution

Trivially resolved: nodes are immutable and content-addressed. Two servers
with the same forest will converge to identical state — there are no write
conflicts, only additions. Link soft-deletes and supersedes are also append-
only operations.

---

## Truth Forest — Full Database Design

### Node Types

```
Forest structure:
  forest.root         The single root of the entire forest (1 per user)
  tree.root           Root of a named tree (e.g. "Movies", "Config", "Sci-Fi")

Config:
  config.section      A named config namespace
  config.provider     A metadata/storage provider configuration entry
  config.value        A single config key/value leaf
  config.prune_policy Prune retention policy (attached to a node or tree root)

Community / access control:
  community           Community definition node; holds member list and wrapped
                      community encryption keys (one per member)

Media:
  media.movie
  media.series
  media.season
  media.episode
  media.person        Actor, director, crew
  media.genre
  media.tag
  media.metadata      Raw metadata blob from an external provider (TMDB etc.)

PVFS:
  pvfs.file           File identity (content_hash, size, MIME)
  pvfs.location       A resolvable endpoint for a pvfs.file
  pvfs.integrity_failure  Recorded hash mismatch event

User:
  user.watchlist_entry   Watch status + progress for a media node [private]
  user.rating            [private]
  user.note              [private]

Events:
  event.prune_record  Audit record written when a prune runs
```

### Default Visibility by Node Type

| Type pattern | Default visibility |
|---|---|
| `media.*` | public |
| `pvfs.file`, `pvfs.location` | public |
| `pvfs.integrity_failure` | private |
| `user.*` | private |
| `config.*` | private |
| `community` | public (metadata), members/keys portion private |
| `event.*` | private |
| `forest.root`, `tree.root` | public |

### TypeScript Interfaces

```typescript
// Immutable — ID is BLAKE3(type + label + visibility + JSON(payload) + created_at + author)
interface TruthNode {
  id:         string    // content hash (includes visibility in preimage)
  type:       NodeType
  label:      string
  visibility: 'public' | 'private' | `community:${string}`
  payload:    unknown   // plaintext object if public; base64 AES-GCM ciphertext if private/community
  created_at: number    // unix ms
  author:     string    // secp256k1 pubkey
  sig:        string    // signature over id
}

// Content-addressed but with mutable soft-delete / supersede fields
interface TruthLink {
  id:           string          // BLAKE3(parent_id + child_id + link_type + created_at)
  parent_id:    string | null   // null = child is a root
  child_id:     string
  link_type:    LinkType
  truth_score:  number          // 0.0–1.0, default 1.0
  sort_key:     string | null
  score_method: string | null
  created_at:   number
  author:       string
  sig:          string
  removed_at:    number | null
  removed_by:    string | null
  removal_sig:   string | null
  superseded_by: string | null
  suspended_at:  number | null
}

type LinkType =
  | 'branch'     // primary parent→child tree structure
  | 'cross'      // cross-link: node participates in another tree (e.g. genre)
  | 'supersedes' // new node supersedes old (old link deactivated)
  | 'metadata'   // metadata blob attached to a media node
  | 'file'       // pvfs.file attached to a media node
  | 'member'     // collection membership (episode→season, season→series)
```

### Sibling Order Index

Content-addressed link IDs cannot embed a `sort_next` pointer without a
circular hash dependency. A separate mutable table provides O(1) sorted sibling
traversal without contaminating link IDs:

```sql
CREATE TABLE link_sibling_order (
  parent_id    TEXT NOT NULL,
  link_id      TEXT NOT NULL REFERENCES truth_links(id),
  next_link_id TEXT REFERENCES truth_links(id),
  PRIMARY KEY (parent_id, link_id)
);
```

### SQLite Schema

```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE truth_nodes (
  id         TEXT PRIMARY KEY,
  type       TEXT NOT NULL,
  label      TEXT NOT NULL,
  visibility TEXT NOT NULL DEFAULT 'public',  -- 'public' | 'private' | 'community:<id>'
  payload    TEXT NOT NULL,                   -- plaintext JSON or base64 AES-GCM ciphertext
  created_at INTEGER NOT NULL,
  author     TEXT NOT NULL,
  sig        TEXT NOT NULL
);

CREATE TABLE truth_links (
  id            TEXT PRIMARY KEY,
  parent_id     TEXT,
  child_id      TEXT NOT NULL REFERENCES truth_nodes(id),
  link_type     TEXT NOT NULL,
  truth_score   REAL NOT NULL DEFAULT 1.0,
  sort_key      TEXT,
  score_method  TEXT,
  created_at    INTEGER NOT NULL,
  author        TEXT NOT NULL,
  sig           TEXT NOT NULL,
  removed_at    INTEGER,
  removed_by    TEXT,
  removal_sig   TEXT,
  superseded_by TEXT REFERENCES truth_links(id),
  suspended_at  INTEGER
);

CREATE TABLE link_sibling_order (
  parent_id    TEXT NOT NULL,
  link_id      TEXT NOT NULL REFERENCES truth_links(id),
  next_link_id TEXT REFERENCES truth_links(id),
  PRIMARY KEY (parent_id, link_id)
);

CREATE INDEX idx_links_parent  ON truth_links(parent_id) WHERE removed_at IS NULL;
CREATE INDEX idx_links_child   ON truth_links(child_id)  WHERE removed_at IS NULL;
CREATE INDEX idx_links_type    ON truth_links(link_type) WHERE removed_at IS NULL;
CREATE INDEX idx_nodes_type    ON truth_nodes(type);
CREATE INDEX idx_nodes_vis     ON truth_nodes(visibility);
CREATE INDEX idx_sibling_next  ON link_sibling_order(next_link_id);
```

Note: `visibility` is included in the node ID hash preimage, so changing a
node's visibility (e.g. making a private node public) creates a new node.

### PVFS File Verification

Verification happens on the read path, not in a background job:

1. Walker resolves `pvfs.file` node → reads `content_hash`
2. Bytes are read from the active `pvfs.location` and hashed (BLAKE3)
3. **Match** → serve the file
4. **Mismatch**:
   - Append a `pvfs.integrity_failure` node (immutable record)
   - Set `suspended_at` on the `file` link → file is blocked from serving
   - User options: **Restore original** or **Accept replacement** (new `pvfs.file` node)

### Prune

Policies stored as `config.prune_policy` nodes. Scoped at forest/tree/branch/node.
Two-phase: preview (`GET /forest/prune/preview`) + execute (`POST /forest/prune`).

---

## Forest Module Layout

```
src/forest/
  types.ts       — all interfaces (TruthNode, TruthLink, NodeType, LinkType, payloads)
  schema.sql     — SQLite DDL (nodes, links, sibling_order, visibility index)
  db.ts          — better-sqlite3, WAL mode, migrations
  signer.ts      — BLAKE3 ID derivation, secp256k1 sign/verify
  cipher.ts      — AES-256-GCM encrypt/decrypt for private nodes (NEW)
  walker.ts      — ForestWalker: walk, verify, children, parents, orphans
  pvfs.ts        — PVFSVerifier: verify, recordFailure, acceptReplacement
  pruner.ts      — prune preview + execute + policy resolution
  api.ts         — Fastify routes for all forest, config, PVFS, prune operations

src/auth/
  index.ts       — challenge-response auth (secp256k1 + BLAKE3)

src/identity/
  index.ts       — identity keypair derivation (secp256k1 + Argon2id)

src/multi-tenant/          (NEW — Phase 5)
  users.ts       — users registry DB (users.db)
  router.ts      — per-request forest routing (pubKey → ForestDB instance)
  registration.ts — open/closed mode, register/revoke endpoints
```

---

## Local Auth Agent (Companion)

A lightweight Node.js service (`agent/companion.mjs`) that runs on the user's
Mac. Eliminates the need to ever type a passphrase into a browser.

**Security model:**
- Reads passphrase from `~/.config/phrasevault/config.json` (chmod 600) on startup
- Derives `authPrivKey = BLAKE3("phrasevault:api-auth-v1:" + passphrase)` and
  discards the passphrase reference
- Listens only on `127.0.0.1:8765` — never exposed to the network
- Responds to Chrome's Private Network Access preflight with
  `Access-Control-Allow-Private-Network: true`

**Endpoints:**
- `GET /health` → `{ ok: true, version: "1" }`
- `POST /sign { challenge }` → `{ signature }` — signs challenge with auth key

**Browser flow:**
1. LoginPage probes `http://localhost:8765/health` on mount (2s timeout)
2. If alive: silently fetches challenge, sends to companion `/sign`, uses
   signature to call `/auth/verify` → auto-login with no UI interaction
3. If not alive: shows manual passphrase form as fallback

**Config file (`~/.config/phrasevault/config.json`, chmod 600):**
```json
{
  "passphrase": "your-passphrase",
  "servers": [
    { "url": "https://pvtest.turnernetworking.com", "name": "pvtest", "registered": true }
  ]
}
```

**Auto-start (macOS):**
`agent/com.phrasevault.companion.plist` — launchd plist, loads via
`launchctl load ~/Library/LaunchAgents/com.phrasevault.companion.plist`

**Companion capabilities (implemented):**
- Setup wizard — first-run interactive prompt; tests passphrase against each server
- Startup self-test — challenge-response verify at each start
- Background daemon mode — PID file, `--stop`/`--status` flags
- Normal UX requires no flags: detects existing config, offers background start

**Future companion responsibilities:**
- Encrypt payloads before write (forest encryption key derivation)
- Decrypt payloads on read (companion acts as crypto proxy)
- Community key management (ECIES wrap/unwrap)
- Server sync coordination (push new nodes to all registered servers)

---

## Relay — Media Application Layer

Relay is the media middleware layer. Lives in `src/apps/relay/`.

### Three-Layer Stack

```
[MediaForest — React frontend]
         ↓
[Relay / MediaNode — node types, query engine, HTTP API]
         ↓
[PhraseVault — crypto, Hypercore feeds, Hyperswarm replication]
         ↓
[Truth Forest — forest.db (SQLite), indexed DAG, encrypted payloads]
```

### Node Types (`src/apps/relay/types.ts`)

- **MediaNode** — one node per title (movie, series, episode, short). Public.
- **StoragePointerNode** — maps to `pvfs.file` + `pvfs.location`. Public.
- **CrosslinkNode** — maps to a `cross` link. Public.
- **WatchlistEntryNode** — maps to `user.watchlist_entry`. **Private.**

### Metadata Providers

Provider configuration lives in the Config tree (private nodes):
```
config.root "Configuration"
  └─branch─ config.section "Metadata Providers"
               └─branch─ config.provider "TMDB"
                            ├─branch─ config.value "read_access_token"  → (encrypted)
                            └─branch─ config.value "enabled"            → (encrypted)
```

**TMDB uses a v4 Read Access Token** (Bearer auth), not a v3 API Key. The token
is stored under the key `read_access_token` in the `config.provider "TMDB"` node.
Get a token at https://www.themoviedb.org/settings/api — use the "API Read Access Token"
(the long JWT), not the shorter "API Key".

### HTTP API

Current endpoints (`src/server/index.ts`):

Auth (public — no token required):
- `GET /auth/status` — `{ hasOwner: bool }` — tells UI whether owner is registered
- `GET /auth/challenge` — one-time nonce
- `POST /auth/register { pubKey, inviteToken?, name? }` — first user: no token; subsequent users: token required
- `POST /auth/verify { challenge, signature }` — returns `{ token, identity, userPubKey, userRole, userName }`

Auth (owner only):
- `POST /auth/invite` — generate a single-use 7-day invite token
- `GET /auth/users` — list all registered users

Media / library:
- `GET /health` — status, identity pubkey, feed/forest counts, `hasOwner`
- `GET /identity` — publicKey hex, DID, feedKey hex
- `GET /search?q=&kind=&available=&watchStatus=` — results scoped to current user's watchlist
- `GET /media/:id`
- `POST /media`, `POST /storage`, `POST /crosslink`
- `POST /watchlist`, `PATCH /watchlist/:mediaId` — watchlist entries tagged with current user's pubkey
- `POST /follow`, `DELETE /follow/:feedKey`, `GET /following`
- `GET /tmdb/search?q=`, `GET /tmdb/details?id=&type=`
- Forest/config/PVFS/prune routes (see Forest HTTP API section below)

### Forest HTTP API

```
Forest:
GET  /forest/roots
GET  /forest/walk/:nodeId
GET  /forest/node/:nodeId
POST /forest/node
POST /forest/link
DELETE /forest/link/:linkId
GET  /forest/verify/:nodeId
GET  /forest/orphans

Config:
GET  /config
PUT  /config/:section/:key
DELETE /config/:section/:key
GET  /config/providers
PUT  /config/providers/:providerId

PVFS:
GET  /pvfs/file/:nodeId
GET  /pvfs/file/:nodeId/verify
POST /pvfs/file
POST /pvfs/file/:nodeId/location
POST /pvfs/file/:nodeId/replace

Prune:
GET  /forest/prune/preview
POST /forest/prune
```

---

## Settled Architecture Decisions

### Language: Node.js / TypeScript
Python is dropped. Node.js/TypeScript matches the Hypercore ecosystem natively.

### Storage: Two-layer
- **Hypercore**: append-only signed feeds, peer-to-peer sync transport
- **SQLite (WAL mode)**: local indexed Truth Forest (`$PV_DATA_DIR/forests/<pubkey>.db`)
- **PVFS store**: `$PV_DATA_DIR/pvfs/` for locally cached file content

### Node IDs: Content-Addressed (BLAKE3)
ID = BLAKE3(type + label + visibility + JSON(payload) + created_at + author).
Visibility is part of the preimage — changing visibility creates a new node.

### Truth Score: On the Link
Relational — describes adherence to the parent's premise in the context of this
specific link, not an intrinsic property of the child node.

### Sibling Order: Separate Mutable Table
Content-addressed link IDs cannot embed `sort_next` without circular hashing.
The `link_sibling_order` table provides O(1) sorted sibling traversal separately.

### Identity: secp256k1 keypairs
One keypair per user, derived deterministically from passphrase (Argon2id).
Same passphrase = same identity across all devices. Private key never stored.

### Encryption: AES-256-GCM at the node payload level
Private and community nodes are encrypted before they leave the companion/client.
The server stores and replicates ciphertext only. Key is derived via BLAKE3
(not Argon2id) so it can run in the companion without native deps.

### Crypto primitives
- BLAKE3 — node IDs, content addressing, chain linking, PVFS hashing, key derivation
- Argon2id — memory-hard derivation for long-term identity keypair only
- AES-256-GCM — authenticated encryption for private/community node payloads
- secp256k1 — node signing, link signing, auth challenge-response, ECIES community key wrap
- ECIES (ECDH + AES-256-GCM) — community key exchange (wrap community key per recipient)

### Multi-tenant server model
Server hosts N independent forests. Per-user SQLite DB files. Open/Closed mode
flag. No single `PV_PASSPHRASE` — the server has its own identity key generated
once at first start. `PV_PASSPHRASE` env var triggers backward-compat
single-user mode.

### Hypercore is the sync layer
Each user's forest is backed by a Hypercore feed. SQLite is a derived index.
Multiple servers replicate the same Hypercore feed in real time. No custom
sync protocol needed for the forest itself.

### Debian not Alpine for runtime image
`sodium-native` ships glibc binaries only; Alpine (musl) crashes. Use `node:22-slim`.

### Credit system: off-chain signed attestations
No blockchain. Each use/endorsement is a signed secp256k1 message referencing
the node ID. Verifiable by anyone with the signer's public key. No gas fees.

---

## Open Questions

1. **Sybil prevention** — what stops someone from farming credit with 1000
   identities? Options: proof-of-work on identity creation, invite-only
   bootstrap, stake-based.

2. **Server discovery** — how do clients find servers hosting a feed?
   Options: DHT (like BitTorrent), well-known bootstrap nodes, DNS-based.

3. **Score propagation rules** — how does a low-scoring child affect ancestor
   scores?

4. **Permission revocation cascade** — unfriend: how far does it propagate in
   the DAG? Cross-links to their nodes still exist in your forest — should they
   be auto-soft-deleted?

5. **Gossip between open servers** — should open-mode servers advertise each
   other so clients can discover new hosts?

6. **Community key rotation** — if a member is removed from a community, old
   content encrypted under the old community key is still accessible to them.
   Rotation requires re-encrypting all community nodes with a new key.
   Decision: accept this for now (same limitation as Signal group key rotation);
   flag as a future improvement.

---

## Build Phases

### Phase 1–3 ✅ DONE
- Core server, Hypercore store, relay query engine, watchlist, TMDB proxy,
  Add Media modal, Config UI (settings page for TMDB API key)

### Phase 4 — Truth Forest Database ✅ DONE (2026-05-31)
- `types.ts`, `schema.sql`, `db.ts`, `signer.ts`, `walker.ts`, `pvfs.ts`,
  `pruner.ts`, `api.ts` — full forest module implemented
- Config tree bootstrap, provider management, TMDB key migrated to forest config
- Settings page in frontend reads/writes config tree

### Phase 5 — Node Encryption (in progress, 2026-05-31)

Add payload encryption for private and community nodes:

1. `src/forest/cipher.ts` — `encryptPayload(payload, encKey)` / `decryptPayload(ciphertext, encKey)`
2. Update `TruthNode` interface — add `visibility` field
3. Update `deriveNodeId` in `signer.ts` — include `visibility` in BLAKE3 preimage
4. Update `db.ts` — schema migration to add `visibility` column
5. Update `schema.sql` — add `visibility TEXT NOT NULL DEFAULT 'public'`
6. Update `walker.ts` / `api.ts` — pass `encKey` where needed; encrypt on write, decrypt on read
7. Update companion — derive `forestEncKey` on startup; companion is the crypto boundary
8. Default node types to correct visibility (public/private per table above)

### Phase 6 — Multi-User Auth ✅ Done in MediaForest (2026-06-03)

MediaForest implements a pragmatic multi-user model on top of the single shared Hypercore feed (per-user SQLite forests are a future PhraseVault platform concern):

- `server_key.json` holds a `users[]` array of `{ pubKey, name, role, createdAt }` records
- First user to register becomes owner (no invite needed); all others require a one-time invite token
- Invite tokens: single-use, 7-day TTL, stored in `DATA_DIR/invites.json`
- Sessions map to a specific user pubkey; `verifySession()` returns the `UserRecord`
- `/auth/status` lets the UI detect unregistered servers and show "Set up" vs "Login"
- Watchlist entries carry `user_pub_key` in their payload; query engine filters per user at request time
- Existing entries without `user_pub_key` are treated as "legacy" shared entries

Full PhraseVault platform multi-tenant (per-user forest isolation) remains future work:
1. `src/multi-tenant/users.ts` — users.db (pubKey → forest path registry)
2. `src/multi-tenant/router.ts` — per-request ForestDB routing
3. `src/multi-tenant/registration.ts` — open/closed mode, `/auth/register`, `/auth/revoke`
4. Server generates own identity key on first start (not from env var)
5. `PV_PASSPHRASE` env var triggers backward-compat single-user mode
6. Update companion to register with each server in its servers list

### Phase 7 — Companion Upgrade ✅ Partially done (2026-05-31)

1. ✅ Setup wizard (first-run: prompt passphrase, test against server, save)
2. ✅ Startup self-test (challenge-response verify at each start)
3. ✅ Background daemon mode, PID file, `--stop`/`--status` flags
4. Derive and manage `forestEncKey`; encrypt/decrypt as crypto proxy for browser
5. Server list management; auto-register on new server connection
6. Revoke flow (signed DELETE to server)

### Phase 8 — Community / Access Control

1. `community` node type, member list, ECIES-wrapped key per member
2. Community key derive/unwrap in companion
3. "Share with Friends" UI — select community, re-encrypt node, update visibility
4. Community key rotation (remove member → new key → re-encrypt)

### Phase 9 — Watch Together (future)
- WebSocket sync room, embedded player, text chat sidebar

### Phase 10 — Browser Extension (future)
- Same React components, different mounting point
- Inject into Plex/Jellyfin web UI

### Phase 11 — Production + Premium Tier (future)
- Friend discovery via Hyperswarm DHT
- Hosted storage with BLAKE3 dedup
- Credit system for watchlist capacity billing

---

## Deployment Infrastructure

### Pipeline

```
git push → GitHub Actions (CI) → GHCR → Watchtower → presubuntu
```

- **CI:** `.github/workflows/docker.yml` — builds two-stage Docker image on every
  push to `main`, pushes to `ghcr.io/christcb03/phrasevault:latest` and `sha-<short>`.
  Actions versions: `actions/checkout@v5`, `docker/build-push-action@v6`.
- **GHCR:** GitHub Container Registry. Image is public.
- **Watchtower:** Polls GHCR every 300 seconds, pulls and restarts automatically.
- **Ansible playbook:** `HomeLab/playbooks/relay.yml` — initial deploy and re-deploys.

### Test Server: presubuntu

- **Host:** `presubuntu-vpn` (Ansible inventory)
- **IP:** `192.168.0.184` (internal, accessible via VPN to pveprod)
- **URL:** `http://192.168.0.184:8080` (HTTP, VPN) | `https://pvtest.turnernetworking.com` (HTTPS)
- **VM:** Proxmox VM 101 on pveprod — Ubuntu 24.04 LTS, 2 vCPU, 8GB RAM, 100GB disk
- **Data dir:** `/opt/phrasevault/data` (bind-mounted to container `/data`)
- **Forest DB:** `/opt/phrasevault/data/forest.db` (migrating to `forests/<pubkey>.db`)
- **PVFS store:** `/opt/phrasevault/data/pvfs/`
- **Container:** `phrasevault` (plus `watchtower-phrasevault` sidecar)
- **Telegram notifications:** Watchtower notify URL stored in `HomeLab/vault.yml` as `vault_phrasevault_telegram_url`

### HTTPS via Traefik + Cloudflare

Traefik handles TLS via Cloudflare DNS challenge (resolver: `cfdns`).
**No Authelia** — PhraseVault has its own auth.

### Authentication

secp256k1 challenge-response. **Passphrase never enters browser or server.**
The companion app signs challenges locally. Browser falls back to manual
passphrase form when companion is not running (passphrase still never sent
over network — only signature is sent).

Auth keypair derivation:
```
authPrivKey = BLAKE3("phrasevault:api-auth-v1:" + passphrase)
authPubKey  = secp256k1.getPublicKey(authPrivKey)
```

Login flow:
1. `GET /auth/challenge` → one-time nonce (5-min TTL, consumed on use)
2. Companion (or browser) signs `BLAKE3("phrasevault:auth-challenge:v1:" + nonce)`
3. `POST /auth/verify { challenge, signature }` → server verifies, issues session token
4. All API routes require `Authorization: Bearer <session-token>`

Session tokens expire on server restart (acceptable for now).

---

## Auth Design Principles (Canonical)

These are hard requirements, not implementation suggestions. All future auth
work must conform to them.

### Passphrase is sacred

- The passphrase **never leaves the user's machine**. It is never typed into a
  browser form field, never sent over the network, and never stored on the server.
- The server stores only the derived `authPubKey` (secp256k1, compressed hex).
  From this it can verify signatures but cannot derive the passphrase or any
  encryption key.
- The companion app is the only place the passphrase lives at rest
  (`~/.config/phrasevault/config.json`, chmod 600). It derives the keypair on
  startup and clears the passphrase reference from memory.
- The browser derives the keypair in JS when the user manually enters their
  passphrase. This is the fallback path, not the primary path.

### Server never knows encrypted user data

- The server stores ciphertext only for private/community nodes. It cannot
  decrypt them — it does not hold the encryption key.
- Even when a user is logged in, the server only sees what the client sends it.
  The companion (or browser) decrypts before display; the server is a blind store.

### Registration is companion-first

- The primary registration path: user runs `node agent/companion.mjs` → wizard
  derives `authPubKey` from passphrase → companion POSTs only the pubkey to
  `/auth/register`. Passphrase never reaches the server.
- The browser can also register (derive pubkey in JS, POST it) — this is
  acceptable since the passphrase still never leaves the browser.
- The server **must not** accept a passphrase as a registration credential.
  It accepts a pubkey only.

### Server Open / Closed modes

Two registration modes, set by the server operator:

**Open mode** (default on fresh server):
- Any user can self-register by deriving their pubkey and calling `/auth/register`
- No invite token required
- Suitable for small trusted groups, self-hosted family servers, testing
- Server becomes Closed when the operator explicitly sets it

**Closed mode**:
- `/auth/register` rejects requests without a valid invite token
- Invite tokens are generated by the owner (`POST /auth/invite`, owner-only)
- Single-use, time-limited (default 7 days)
- Suitable for locked-down personal servers

The mode is stored in `server_key.json` as `"registrationMode": "open" | "closed"`.
Default is `"open"`.

> **Current implementation status:** MediaForest currently always behaves as
> Closed (first user is owner, all others need invite). Open mode needs to be
> added — when `registrationMode === "open"`, skip the invite token check.

### Recovery password (non-passphrase fallback)

Problem: user is away from their machine with the companion. The companion
signs challenges automatically — without it, the user must type their
passphrase manually. For users who don't want to memorize their passphrase,
or in a recovery situation (passphrase forgotten), a separate recovery
credential is needed.

**Design:**
- At registration time, the user optionally sets a **recovery password**
  (a normal human-memorable password, separate from the passphrase)
- Server stores `bcrypt(recoveryPassword)` — never plaintext
- Recovery login: user submits recovery password → server verifies bcrypt →
  issues a session token scoped to that user's pubkey
- **What recovery login can do:** access all app features that don't require
  decryption (shared library, search, watchlist when data is not encrypted)
- **What recovery login cannot do:** decrypt private node payloads (watchlist
  entries, ratings, notes) — the encryption key derives from the passphrase,
  not the recovery password. For MediaForest v1 where watchlist is scoped by
  pubkey but not truly encrypted, recovery login works fully.
- **Account recovery (passphrase lost):** owner can trigger a re-registration
  for the user. This issues a short-lived re-registration token. User runs
  companion wizard with a new passphrase → new pubkey replaces old one. Encrypted
  data under the old key is lost (acceptable for non-sensitive data like
  watchlists). For high-security deployments, this recovery path is simply
  disabled — data is unrecoverable if passphrase is lost, which is the correct
  behavior when the data is truly sensitive.

**Recovery password is NOT the passphrase.** The server admin cannot use
it to impersonate the user cryptographically. They can only grant a session.

### Server owner / admin capabilities

The server owner (first registered user, `role: "owner"`) can:
- List all registered users (`GET /auth/users`)
- Generate invite tokens (`POST /auth/invite`)
- Reset a user's recovery password (owner-initiated, not the passphrase)
- Remove a user (deregisters their pubkey; their data remains until pruned)
- Switch server between Open and Closed mode

The server owner **cannot**:
- See or recover any user's passphrase (server never has it)
- Decrypt any user's private data
- Log in as another user via challenge-response (they don't have their keypair)

### Access away from companion

Preferred order for users who need to log in from an unfamiliar machine:

1. **Set up companion on the new machine** — best option for machines you use
   regularly. Run `node agent/companion.mjs`, enter passphrase once, companion
   handles all future logins.
2. **Type passphrase in browser** — passphrase is derived to keypair in JS,
   never sent. Works anywhere, but requires you to know your passphrase.
3. **Recovery password** — for when passphrase is not known or not handy.
   Server grants a session; encryption-dependent features may be limited
   depending on the app.

A local native client app that is *required* to access the service is
explicitly rejected — it would prevent access from mobile, shared machines,
and new devices, which defeats the purpose of a web app.

---

## eBable App Scope (separate from PhraseVault platform)

eBable = Chris's commercial app running on Chris's servers.
Uses PhraseVault as the data layer. Focus: IT application integration knowledge.
Full Solutions, Leaves (fixes/tips), Credit system for contributors.
eBable is NOT decentralized — it is a product. PhraseVault is decentralized.

---

## PlexVault — Media Sharing Application on PhraseVault

PlexVault is a separate commercial application built on PhraseVault, targeting
Plex/Jellyfin users who want to share libraries with trusted friends.

### Core Architecture

Uses the Truth Forest model. Media titles are `media.*` nodes (public).
Friends' feeds are separate tree roots in your forest. Watchlist entries are
`user.watchlist_entry` nodes (private, encrypted). File locations are
`pvfs.location` nodes (public). Shared content uses community visibility.

**Crosslink = friend share**: cross-link from your library tree to their
`pvfs.file` node. No file copy; stream live from their node.

### Discovery Layer

Universal search across friends' shares and streaming sources.
AI-assisted natural language search. Server-side search works on public nodes;
private watchlist data searched client-side post-decryption.

### Monetization Tiers

**Free / self-hosted:** friend sharing, discovery. Up to 5 shares.
**Premium hosted:** Hosted media server + storage. BLAKE3 dedup (same file =
one physical copy). Torrent-like delivery from nearest available node.
**Anonymous Encrypted Storage:** Generic encrypted vault, zero server knowledge.
Completely separate branding from PlexVault.

### Watch Together

Synchronized group watch: virtual room, shared playback state, text/voice chat.
Sync hosted by PlexVault; media streams from source directly to each viewer.

### Legal Notes

- Discovery layer: indexing and launching only, not hosting
- "Share your own library with your own friends" scope — no public index
- Encrypted storage product: generic marketing, willful blindness doctrine
- Watch Together: sync only; each viewer streams independently
- Final name TBD (PlexVault is working name)
