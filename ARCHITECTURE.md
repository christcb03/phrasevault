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
platform-defined base schema (id, author, signature, timestamp, type, payload).
The `type` field and payload schema are defined by the application layer.
Node IDs are content-addressed (BLAKE3 hash of content) — immutable by design.

**Truth Forest** — a collection of Truth Trees. Every application instance
maintains one local forest, stored in a SQLite database (`forest.db`).

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
  id:        string       // BLAKE3 content hash (immutable identity)
  type:      string       // application-defined (e.g. "media.movie")
  label:     string       // human-readable name
  author:    string       // secp256k1 public key (hex)
  signature: string       // secp256k1 signature over node content
  created_at: number      // unix timestamp ms
  payload:   object       // application-defined content (schema varies by type)
}
```

The platform handles: storage, replication, signing verification, DAG
traversal, score propagation, credit attestations. Nothing else.

### Layer 2 — Application Layer (MediaForest, eBable, or any other app)

Applications define their own node types and payload schemas.
PhraseVault does not validate payload content — only signature and structure.

---

## Truth Forest — Full Database Design

### Node Types

```
Forest structure:
  forest.root         The single root of the entire forest (1 per instance)
  tree.root           Root of a named tree (e.g. "Movies", "Config", "Sci-Fi")

Config:
  config.section      A named config namespace
  config.provider     A metadata/storage provider configuration entry
  config.value        A single config key/value leaf
  config.prune_policy Prune retention policy (attached to a node or tree root)

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
  user.watchlist_entry   Watch status + progress for a media node
  user.rating
  user.note

Events:
  event.prune_record  Audit record written when a prune runs
```

### TypeScript Interfaces

```typescript
// Immutable — ID is BLAKE3(type + label + JSON(payload) + created_at + author)
interface TruthNode {
  id:         string    // content hash
  type:       NodeType
  label:      string
  payload:    unknown   // type-specific, validated by type schema
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
  sort_key:     string | null   // explicit sibling order (e.g. "S01E03", ISO date)
  score_method: string | null   // "manual" | "bayesian:..." | "computed:cosine"
  created_at:   number
  author:       string
  sig:          string
  // Soft-delete / replacement
  removed_at:    number | null
  removed_by:    string | null
  removal_sig:   string | null
  superseded_by: string | null  // ID of the link that replaced this one
  suspended_at:  number | null  // set when PVFS integrity check fails
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
-- Mutable — updated whenever a sibling is inserted or removed under a parent.
-- Siblings are sorted descending by truth_score, then by sort_key.
CREATE TABLE link_sibling_order (
  parent_id    TEXT NOT NULL,
  link_id      TEXT NOT NULL REFERENCES truth_links(id),
  next_link_id TEXT REFERENCES truth_links(id),  -- NULL = end of list
  PRIMARY KEY (parent_id, link_id)
);
CREATE INDEX idx_sibling_order_next ON link_sibling_order(next_link_id);
```

The ForestWalker can iterate children by `ORDER BY truth_score DESC, sort_key`
(full sort, O(n log n), fine for small sets) or by following `next_link_id`
pointers (O(1) per step, preferred for large ordered sets like episode lists).

### SQLite Schema

```sql
CREATE TABLE truth_nodes (
  id         TEXT PRIMARY KEY,   -- BLAKE3 content hash
  type       TEXT NOT NULL,
  label      TEXT NOT NULL,
  payload    TEXT NOT NULL,      -- JSON
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
  suspended_at  INTEGER             -- set by PVFS integrity failure, clears on re-verify
);

CREATE TABLE link_sibling_order (
  parent_id    TEXT NOT NULL,
  link_id      TEXT NOT NULL REFERENCES truth_links(id),
  next_link_id TEXT REFERENCES truth_links(id),
  PRIMARY KEY (parent_id, link_id)
);

-- Indexes for fast traversal
CREATE INDEX idx_links_parent  ON truth_links(parent_id) WHERE removed_at IS NULL;
CREATE INDEX idx_links_child   ON truth_links(child_id)  WHERE removed_at IS NULL;
CREATE INDEX idx_links_type    ON truth_links(link_type) WHERE removed_at IS NULL;
CREATE INDEX idx_nodes_type    ON truth_nodes(type);
CREATE INDEX idx_sibling_next  ON link_sibling_order(next_link_id);
```

SQLite with WAL mode handles this scale comfortably. At 44K+ media nodes
(2000+ movies, 700+ shows, 40K+ episodes) plus metadata and PVFS nodes, the
total node count is roughly 300K and total DB size is ~300–400 MB — well within
SQLite's performance envelope (WAL mode, NVMe: 1M+ reads/sec). PVFS file bytes
are never stored in the DB; the DB is metadata only.

### DAG Traversal

Edges are directed parent→child. The indexes support traversal in both
directions:
- Downward (root → leaves): use `idx_links_parent`, follow branch links
- Upward (node → root): use `idx_links_child`, walk to validity-check chain
- Sibling (ordered children): follow `link_sibling_order.next_link_id`

Cross-links allow a node to appear under multiple parents simultaneously
without duplication. Walking the "Sci-Fi" tree returns the same node objects
as walking "Movies" — only the link context differs.

### Peer Feeds as Tree Roots

When you follow a peer's PhraseVault feed, their root node is added to your
forest. Their nodes are valid under their root (chain is unbroken back to their
root, which you've explicitly trusted). You can then create cross-links from
your own trees to their nodes — e.g. your "Watchlist" tree cross-links to their
`media.movie` node. Hypercore is the sync transport; SQLite is the local index.

### PVFS File Verification

Verification happens on the read path, not in a background job:

1. Walker resolves `pvfs.file` node → reads `content_hash`
2. Bytes are read from the active `pvfs.location` and hashed (BLAKE3)
3. **Match** → serve the file
4. **Mismatch**:
   - Append a `pvfs.integrity_failure` node (immutable record: file_node_id,
     location_node_id, expected_hash, actual_hash, detected_at)
   - Set `suspended_at` on the `file` link → file is blocked from serving
   - User is presented with two options:
     - **Restore original**: mark location as needing restore; link stays
       suspended until a passing verify clears `suspended_at`
     - **Accept replacement**: append a new `pvfs.file` node with the new
       hash, create a new `file` link from the media node to it, set
       `superseded_by` on the old link → both versions exist in history

### Prune

Orphaned node = no active incoming branch or cross link from any valid chain.

Prune policies are stored as `config.prune_policy` nodes in the config tree,
making them part of the auditable forest record. Policies can be scoped at
forest / tree / branch / individual node level; more specific scopes override
the default.

```typescript
interface PrunePolicyPayload {
  target_id:           string | null  // null = forest default
  retain_orphan_days:  number | null  // null = never auto-prune
  warn_before_days:    number | null  // emit event.prune_record warning N days before
  auto:                boolean        // if false, prune only runs on manual call
}
```

Prune is two-phase:
- `GET /forest/prune/preview` — dry run: lists nodes that would be removed with reasons
- `POST /forest/prune` — executes and appends an `event.prune_record` node to the log

### Forest Module Layout

```
src/forest/
  types.ts       — all interfaces (TruthNode, TruthLink, NodeType, LinkType, payloads)
  schema.sql     — SQLite DDL (nodes, links, sibling_order)
  db.ts          — better-sqlite3 setup, migrations, WAL mode
  signer.ts      — BLAKE3 ID derivation + secp256k1 sign/verify for nodes and links
  walker.ts      — ForestWalker: walk, verify, children, parents, orphans, cross-links
  pvfs.ts        — PVFSVerifier: verify, recordFailure, acceptReplacement, markForRestore
  pruner.ts      — prune preview + execute + policy resolution
  api.ts         — Fastify routes for all forest, config, and PVFS operations
```

### Forest HTTP API

```
Forest:
GET  /forest/roots                   list root nodes
GET  /forest/walk/:nodeId            walk tree from node (depth, link_type filter)
GET  /forest/node/:nodeId            get single node
POST /forest/node                    append new node
POST /forest/link                    create new link (updates sibling_order)
DELETE /forest/link/:linkId          soft-delete link
GET  /forest/verify/:nodeId          verify chain to root
GET  /forest/orphans                 list orphaned nodes

Config (forest-backed):
GET  /config                         walk config tree
PUT  /config/:section/:key           set config value (creates/supersedes node)
DELETE /config/:section/:key         remove config value link

PVFS:
GET  /pvfs/file/:nodeId              file metadata
GET  /pvfs/file/:nodeId/verify       trigger integrity check
POST /pvfs/file                      register new file node
POST /pvfs/file/:nodeId/location     add location node
POST /pvfs/file/:nodeId/replace      accept replacement after integrity failure

Prune:
GET  /forest/prune/preview           dry run — list what would be removed
POST /forest/prune                   execute prune
GET  /forest/prune/policy            get active policies
PUT  /forest/prune/policy            set policy
```

---

## Relay — Media Application Layer (built 2026-05-30)

Relay is the media middleware layer sitting between the PhraseVault platform and
the final user-facing app (MediaForest). Lives in `src/apps/relay/`.

### Three-Layer Stack

```
[MediaForest — user-facing app, React frontend]
         ↓
[Relay / MediaNode — node types, query engine, HTTP API]
         ↓
[PhraseVault — crypto, Hypercore feeds, Hyperswarm replication]
         ↓
[Truth Forest — forest.db (SQLite), indexed DAG of all nodes and links]
```

### Node Types (`src/apps/relay/types.ts`)

These will migrate into Truth Forest node types over time. Current flat types:

- **MediaNode** — one node per title (movie, series, episode, short). Metadata:
  title, year, kind, genres, imdb_id. Maps to `media.movie` / `media.series` etc.

- **StoragePointerNode** — maps to `pvfs.file` + `pvfs.location`. Points to
  where the actual file lives: endpoint_url, content_hash (BLAKE3), size_bytes,
  encoding, available flag.

- **CrosslinkNode** — maps to a `cross` link in the forest. No file copy.

- **WatchlistEntryNode** — maps to `user.watchlist_entry`. Watch status
  (unwatched / watching / watched / skipped) and progress_ms.

### Metadata Providers

TMDB is the first metadata provider. The provider abstraction is designed for
easy addition of further sources (TVDB, IMDB, MusicBrainz, etc.).

Provider configuration lives in the Config tree:
```
config.root "Configuration"
  └─branch─ config.section "Metadata Providers"
               └─branch─ config.provider "TMDB"
                            ├─branch─ config.value "api_key"  → "..."
                            └─branch─ config.value "enabled"  → true
```

Each provider is a module implementing a `MetadataProvider` interface:
```typescript
interface MetadataProvider {
  id:      string
  name:    string
  search(query: string): Promise<ProviderSearchResult[]>
  details(id: string):   Promise<ProviderDetails>
}
```

The server reads enabled providers from the config tree at startup (and on
config change). TMDB API key is stored as a config.value node — not an env var.
Existing `PV_TMDB_KEY` env var support stays for backward compatibility only.

### Query Engine (`src/apps/relay/query.ts`)

`RelayQueryEngine` aggregates multiple Hypercore feeds into a unified view.
4-pass index build per `refresh()` call:
1. Collect all nodes from all feeds
2. Group StoragePointers by media_node_id, ranked by encoding quality
3. Build crosslink + watchlist lookup
4. Assemble `MediaResult[]` with deduped sources

`search(filters)` supports: text query, kind filter, availableOnly, watchStatus.
`getById(id)` returns a single MediaResult with all sources and watchlist state.
`pickBestSource()` ranks: 4K HDR > 4K > 2160p > 1080p > 720p > other.

### HTTP API (`src/server/index.ts`)

Fastify server. Config from env (required: `PV_PASSPHRASE`; optional: `PV_DATA_DIR`,
`PV_PORT`, `PV_HOST`, `PV_LOG_LEVEL`, `PV_TMDB_KEY` (legacy)).

Current endpoints:
- `GET /health` — status, identity pubkey, feed length, following count, indexed count
- `GET /identity` — publicKey hex, DID, feedKey hex
- `GET /search?q=&kind=&available=&watchStatus=` — search across all feeds
- `GET /media/:id` — single title by id
- `POST /media` — publish a new media node to own feed
- `POST /storage` — publish a storage pointer
- `POST /crosslink` — crosslink a friend's storage pointer into your library
- `POST /watchlist` — add/update watchlist entry (deprecated by PATCH)
- `PATCH /watchlist/:mediaId` — update watch status (append-only)
- `POST /follow` — start following a peer's feed
- `DELETE /follow/:feedKey` — unfollow a peer
- `GET /following` — list followed feed keys
- `GET /tmdb/search?q=` — TMDB multi-search proxy (keeps API key server-side)
- `GET /tmdb/details?id=&type=` — TMDB details + external IDs proxy

Followed feed keys are persisted to `$PV_DATA_DIR/followed.json`.

### Frontend (`client/`)

React + Vite + TypeScript + Tailwind CSS (v4). Dark theme.
- Search bar with kind filter and available-only toggle
- MediaCard list — title, year, encoding, source count, watchlist badge
- DetailPanel modal — sources with Play buttons, IMDb link, watchlist status buttons
- Add Media modal — 2-step: TMDB search → storage details form
- Follow peer form in header
- Dev proxy: `/api` → `http://localhost:8080`
- Build output: `dist/client/` (served by Fastify's @fastify/static as SPA)

---

## Settled Architecture Decisions

### Language: Node.js / TypeScript
Python is dropped. Node.js/TypeScript matches the Hypercore ecosystem natively.

### Storage: Two-layer
- **Hypercore**: append-only signed feeds, peer-to-peer sync transport
- **SQLite (WAL mode)**: local indexed Truth Forest (`$PV_DATA_DIR/forest.db`)
- **PVFS store**: `$PV_DATA_DIR/pvfs/` for locally cached file content

### Node IDs: Content-Addressed (BLAKE3)
ID = BLAKE3(type + label + JSON(payload) + created_at + author). Modifying a
node produces a new node with a new ID. Superseding is explicit via link update.

### Truth Score: On the Link
The score is relational — it describes adherence to the parent's premise in the
context of this specific link, not an intrinsic property of the child node.

### Sibling Order: Separate Mutable Table
Content-addressed link IDs cannot embed `sort_next` without circular hashing.
The `link_sibling_order` table provides O(1) sorted sibling traversal separately.

### Identity: secp256k1 keypairs
One keypair per user, derived deterministically from passphrase (Argon2id).
Same passphrase = same identity across all devices. Private key never stored.

### Crypto primitives
- BLAKE3 — node IDs, content addressing, chain linking, fingerprinting, PVFS hashing
- Argon2id — memory-hard key derivation (64 MB, 3 iterations)
- XSalsa20-Poly1305 — authenticated encryption for private content
- secp256k1 — node signing, link signing, credit attestations, identity

### Debian not Alpine for runtime image
`sodium-native` ships glibc binaries only; Alpine (musl) crashes. Use `node:22-slim`.

### Credit system: off-chain signed attestations
No blockchain. Each use/endorsement is a signed secp256k1 message referencing
the node ID. Verifiable by anyone with the signer's public key. No gas fees.

---

## Open Questions (platform-level)

1. **Sybil prevention** — what stops someone from farming credit with 1000 identities?
   Options: proof-of-work on identity creation, invite-only bootstrap, stake-based.

2. **Server discovery** — how do clients find servers hosting a feed?
   Options: DHT (like BitTorrent), well-known bootstrap nodes, DNS-based.

3. **Score propagation rules** — how does a low-scoring child affect ancestor scores?

4. **Private vs public nodes** — all public by default? Encrypted nodes for specific keypairs?

5. **Gossip/sync protocol for the forest** — per-query federation vs. full replication?

6. **Permission revocation** — unfriend cascade: how far does it propagate in the DAG?

---

## Deployment Infrastructure

### Pipeline

```
git push → GitHub Actions (CI) → GHCR → Watchtower → presubuntu
```

- **CI:** `.github/workflows/docker.yml` — builds two-stage Docker image on every
  push to `main`, pushes to `ghcr.io/christcb03/phrasevault:latest` and `sha-<short>`.
  Actions versions: `actions/checkout@v5`, `docker/build-push-action@v6` (updated 2026-05-31).
- **GHCR:** GitHub Container Registry. Image is public (readable without auth).
- **Watchtower:** Polls GHCR every 300 seconds, pulls and restarts automatically.
- **Ansible playbook:** `HomeLab/playbooks/relay.yml` — initial deploy and re-deploys.

### Test Server: presubuntu

- **Host:** `presubuntu-vpn` (Ansible inventory)
- **IP:** `192.168.0.184` (internal, accessible via VPN to pveprod)
- **URL:** `http://192.168.0.184:8080` (HTTP, VPN) | `https://pvtest.turnernetworking.com` (HTTPS)
- **VM:** Proxmox VM 101 on pveprod — Ubuntu 24.04 LTS, 2 vCPU, 8GB RAM, 100GB disk
- **Data dir:** `/opt/phrasevault/data` (bind-mounted to container `/data`)
- **Forest DB:** `/opt/phrasevault/data/forest.db`
- **PVFS store:** `/opt/phrasevault/data/pvfs/`
- **Container:** `phrasevault` (plus `watchtower-phrasevault` sidecar)
- **Passphrase:** stored encrypted in `HomeLab/vault.yml` as `vault_phrasevault_passphrase`

### HTTPS via Traefik + Cloudflare

Container runs on the `saltbox` Docker network. Traefik handles TLS via
Cloudflare DNS challenge (resolver: `cfdns`). Direct port binding stays for VPN.

**Traefik labels (no Authelia — PhraseVault has its own auth):**
- `traefik.http.routers.phrasevault.entrypoints: websecure`
- `traefik.http.routers.phrasevault.tls: true`
- `traefik.http.routers.phrasevault.tls.certresolver: cfdns`
- `traefik.http.routers.phrasevault.middlewares: globalHeaders@file,hsts@file`

### Re-deploying

```bash
cd ~/Projects/HomeLab
ansible-playbook playbooks/relay.yml
```

---

### Authentication

secp256k1 challenge-response. **The passphrase never leaves the browser.**

Auth keypair derivation:
```
authPrivKey = BLAKE3("phrasevault:api-auth-v1:" + passphrase)
authPubKey  = secp256k1.getPublicKey(authPrivKey)
```

Login flow:
1. `GET /auth/challenge` → one-time nonce (5-min TTL, consumed on use)
2. Browser signs `BLAKE3("phrasevault:auth-challenge:v1:" + nonce)` with auth private key
3. `POST /auth/verify { challenge, signature }` → server verifies against known pubkey
4. Server issues 24-hour session token (random 32 bytes, in-memory Map)
5. All API routes require `Authorization: Bearer <session-token>`

Session tokens expire on server restart (acceptable for single-user server).

---

### Node Identity

The server's identity is deterministically derived from `PV_PASSPHRASE`.
Feed data lives in `$PV_DATA_DIR/feeds/<pubkey-hex>/`. Back up the passphrase.

---

## What's Next

### Phase 3 — Content ✅ DONE (2026-05-30)
- TMDB search proxy (server-side API key, `PV_TMDB_KEY` env var)
- Watchlist status UI (unwatched/watching/watched/skip)
- Add Media modal — 2-step TMDB search → storage form

### Phase 4 — Truth Forest Database (in progress, 2026-05-31)

Build `src/forest/` as the definitive data layer:

1. `types.ts` — all TypeScript interfaces (TruthNode, TruthLink, all payload types)
2. `schema.sql` — SQLite DDL with sibling_order table and all indexes
3. `db.ts` — better-sqlite3, WAL mode, migrations
4. `signer.ts` — BLAKE3 ID derivation, secp256k1 sign/verify
5. `walker.ts` — ForestWalker class (walk, verify, children, parents, orphans)
6. `pvfs.ts` — PVFSVerifier (verify, recordFailure, acceptReplacement)
7. `pruner.ts` — prune preview + execute + policy resolution
8. `api.ts` — Fastify routes for forest, config, PVFS, prune APIs
9. Config UI page in frontend — reads config tree, editable provider settings
10. Wire TMDB API key through config tree (deprecate `PV_TMDB_KEY` env var)
11. Migrate Relay node types to forest node types over time

### Phase 5 — TMDB Key via Config UI (follows Phase 4)
- Config page live at `/settings`
- TMDB provider enabled/disabled toggle + API key input
- Key stored as `config.value` node in forest; no longer needs env var or Ansible redeploy

### Phase 6 — Watch Together (future)
- WebSocket sync room
- Embedded player + text chat sidebar

### Phase 7 — Browser Extension (future)
- Same React components, different mounting point
- Inject into Plex/Jellyfin web UI

### Phase 8 — Production + Premium Tier (future)
- Jellyfin integration
- Friend discovery via Hyperswarm DHT
- Hosted storage with BLAKE3 dedup
- Credit system for watchlist capacity billing

---

## eBable App Scope (separate from PhraseVault platform)

eBable = Chris's commercial app running on Chris's servers.
Uses PhraseVault as the data layer (like a GitHub-hosted app using git).

Focus: IT application integration knowledge.
- Full Solutions: complete guides (e.g. "Install OpenClaw on macOS 26.5")
- Leaves: fixes, updates, tips attached to solutions or standalone
- Credit system rewards contributors whose solutions actually work

eBable is NOT decentralized — it is a product. PhraseVault is decentralized.

---

## PlexVault — Media Sharing Application on PhraseVault

PlexVault is a separate commercial application built on PhraseVault, targeting
Plex/Jellyfin users who want to share libraries with trusted friends. It builds
on the MediaForest foundation and adds the friend-sharing and hosted premium layers.

### Core Architecture

Uses the Truth Forest model. A media title is a `media.movie` or `media.series`
node. Friends' feeds are separate tree roots in your forest. Watchlist entries
are `user.watchlist_entry` nodes cross-linked to media nodes (yours or friends').
File locations are `pvfs.location` nodes under `pvfs.file` nodes.

**Crosslink = friend share**: you create a cross-link from your library tree to
their `pvfs.file` node. No file copy. File streams live from their node.

### Discovery Layer

Universal search across all sources: friends' shares, streaming subscriptions
(Netflix, Apple TV+, Disney+, YouTube), custom sources. AI-assisted natural
language search across the full combined graph.

### Watchlist Capacity

Denominated in total size of bookmarked content (not item count). Reflects real
infrastructure cost. Credit flows back to the sharer when their server bears the
serving cost.

### Server Scaling Model

Each server node serves up to 5 friends. Horizontal scaling only.

### Monetization Tiers

**Free / self-hosted:** friend sharing, selective adds, discovery. Up to 5 shares.

**Premium hosted:** We host a media server + online storage. Back-end
deduplication via BLAKE3 content addressing (same file = one physical copy,
multiple account pointers). Torrent-like delivery from nearest available node.
Optional redundancy tier (multiple physical copies, higher availability SLA).

**Anonymous Encrypted Storage (separate standalone product):**
Generic encrypted cloud vault. Client-side encryption, zero server knowledge.
Opaque blobs only; completely separate branding from PlexVault.

### Watch Together

Synchronized group watch: virtual room, shared playback state, text/voice chat.
Sync coordination hosted by PlexVault; media streams from source directly to
each viewer. Distinguishes from Teleparty/Scener: native to the multi-source
interface, not a per-platform bolt-on.

### Legal Notes

- Discovery layer: indexing and launching only, not hosting
- "Share your own library with your own friends" scope — no public index
- Encrypted storage product: generic marketing, willful blindness doctrine
- Watch Together: sync only; each viewer streams from source independently
- Final name TBD (PlexVault is working name)
