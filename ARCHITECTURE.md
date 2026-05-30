# PhraseVault Architecture Log

This file is the canonical planning log. Update it when decisions are made.
It exists so context can be recovered after conversation resets.

Last updated: 2026-05-30 (12:30 EDT)

---

## What PhraseVault Is

A decentralized, open-source knowledge platform. Anyone can run a server.
No single entity controls it. The platform is the infrastructure layer.

**eBable** is a separate commercial application built on top of PhraseVault,
run by Chris on his own servers. eBable is the IT application-integration
tool ("Babel Fish for apps") — it uses PhraseVault as its data storage layer.

---

## Core Concepts

**Node** — the base unit of knowledge in PhraseVault. Every node has a
platform-defined base schema (id, author, signature, timestamp, type, links,
score). The `type` field and any additional fields are defined by the
application layer, not the platform. PhraseVault doesn't care what type means.

**Truth Tree** — a DAG of nodes linked by relationships, with confidence/
falsehood scoring. Lower score = more certain. Nodes inherit scores from
their ancestors weighted by link strength.

**Credit** — a reputation token earned by:
- Creating nodes that get used/referenced
- Creating solutions that get used
- Marking solutions as useful (smaller credit)
Credit is signed and verifiable, not a blockchain token (no gas fees, no chain).

---

## Data Model: Two-Layer Design

### Layer 1 — PhraseVault Platform (infrastructure, application-agnostic)

Every node, regardless of application, has these base fields:

```
{
  id:        string       // content-addressed hash of the node
  type:      string       // application-defined (e.g. "full_solution", "leaf")
  author:    string       // secp256k1 public key (hex)
  signature: string       // secp256k1 signature over the node content
  timestamp: number       // unix timestamp ms
  links:     string[]     // ids of nodes this node references/depends on
  score:     number       // falsehood probability (0.0 = certain, →1.0 = impossible)
  payload:   object       // application-defined content (schema varies by type)
}
```

The platform handles: storage, replication, signing verification, DAG
traversal, score propagation, credit attestations. Nothing else.

### Layer 2 — Application Layer (eBable or any other app)

Applications define their own node types and payload schemas.
PhraseVault does not validate payload content — only signature and structure.

---

## eBable Node Types (application layer, not platform)

### Full Solution
A complete, standalone guide to achieving a specific IT goal.

```
type: "full_solution"
payload: {
  goal:        string       // e.g. "Install OpenClaw on macOS 26.5"
  steps:       string[]     // ordered list of step node ids (Leaves) or inline text
  tags: {
    platform:  string       // e.g. "macOS 26.5"
    app:       string       // e.g. "OpenClaw"
    version:   string       // app version this was tested on
    env:       string[]     // other conditions (e.g. "Homebrew", "Apple Silicon")
  }
  tested:      boolean      // author attests this was verified working
  tested_at:   number       // timestamp when tested
  summary:     string       // short description for search/display
}
```

### Leaf
A single fix, update, tip, or nugget of IT information. Can attach to a
Full Solution as a related item, or stand completely alone.

```
type: "leaf"
payload: {
  claim:       string       // the actual information (fix, tip, warning, etc.)
  parent:      string|null  // id of parent Full Solution, or null if standalone
  tags: {
    platform:  string
    app:       string
    version:   string
    env:       string[]
  }
  leaf_type:   string       // "fix" | "update" | "warning" | "tip" | "related"
}
```

**Examples of standalone Leaves:**
- "OpenClaw Telegram bot fails when claude-cli context exceeds 100%"
- "Homebrew installs OpenClaw to /opt/homebrew on Apple Silicon, not /usr/local"

**Examples of attached Leaves:**
- An update to a Full Solution when a newer app version changes a step
- A warning that a step no longer works on a newer OS version

---

## Extensibility Principle

The platform is customizable. eBable's "full_solution" and "leaf" types are
just one application's choice. Another app built on PhraseVault could define
completely different types — medical claims, legal precedents, recipe steps,
code snippets — and the infrastructure handles storage, signing, replication,
and credit the same way for all of them.

To build on PhraseVault, an application only needs to:
1. Define its node types and payload schemas
2. Register a schema validator (optional, for server-side enforcement)
3. Use the PhraseVault SDK to create, sign, and publish nodes

---

## Settled Architecture Decisions

### Language: Node.js / TypeScript
Python is dropped. Rewriting in Node.js/TypeScript to match the Hypercore
ecosystem natively. No sidecar process needed.

### Storage Layer: Hypercore Protocol
Chosen over OrbitDB. Reasons:
- Append-only, cryptographically signed feeds — one keypair owns one feed
- Immutable history: you can only append, never rewrite (true read-only DAG)
- Anyone can host/replicate a feed without owning it (like git clone)
- Sparse replication — no need to hold the full dataset to participate
- Native creator signing maps directly to the credit/ownership model
- "GitHub repo" ownership model fits the use case exactly

Each user's nodes live in their own Hypercore feed, signed by their identity
keypair. The feed key IS the user's public key.

### Identity: secp256k1 keypairs
One keypair per user, derived deterministically from passphrase (Argon2id).
Same passphrase = same identity across all devices.
Private key never stored — always re-derived when needed.

### Crypto primitives
- BLAKE3 — node id / content addressing, chain linking, fingerprinting
- Argon2id — memory-hard key derivation (64 MB, 3 iterations)
- XSalsa20-Poly1305 — authenticated encryption for private content
- secp256k1 — node signing, credit attestations, identity

Node.js packages: `blake3`, `argon2`, `tweetnacl`, `@noble/secp256k1`

### Credit system: off-chain signed attestations
Credit does NOT require a blockchain. Each use/endorsement is a signed
secp256k1 message referencing the node id. Verifiable by anyone with the
signer's public key. Aggregated by servers. No gas fees.

---

## Open Questions (to resolve before coding)

1. **Sybil prevention** — what stops someone from creating 1000 identities
   to farm credit? Options:
   - Proof-of-work on identity creation
   - Invite-only bootstrap
   - Stake-based (credit required to create identity)
   - Rate limiting by server policy

2. **Server discovery** — how do clients find servers hosting a feed?
   Options: DHT (like BitTorrent), well-known bootstrap nodes, DNS-based.

3. **Score propagation rules** — when a Leaf is attached to a Full Solution,
   how does a low-scoring Leaf affect the Solution's score? Does a "fix" Leaf
   lower or raise the Solution's score?

4. **Private vs public nodes** — are all nodes public by default? Or can a
   user publish an encrypted node that only specific keypairs can read?
   (PhraseVault already has XSalsa20 encryption — this may just need a policy.)

---

## Current Code Status (as of 2026-05-26)

Python codebase at `~/Projects/phrasevault-repo/`. Will be superseded by
Node.js rewrite. Parts worth porting:

- `crypto.py` — BLAKE3 + Argon2id + XSalsa20 logic → port to Node.js
- `identity.py` — secp256k1 DID derivation → port using `@noble/secp256k1`
- `truth_forest_v5.json` — keep as reference/test fixture

Parts to discard:
- `store.py` — stubbed, replace with Hypercore feeds
- `forest.py` — stub, rebuild from scratch
- `server.py` — thin wrapper, rebuild as Hypercore node + HTTP API
- `transfer.py` — .pvx format likely replaced by Hypercore replication

---

## PlexVault — Media Sharing Application on PhraseVault

PlexVault is a separate commercial application built on PhraseVault, targeting
Plex/Jellyfin users who want to share libraries with trusted friends.

### Core Architecture

**Library node** — a PhraseVault node representing a title (e.g. "The Office
S01E01") with media metadata in the payload. One node per title, not per file.

**Storage pointer** — a sub-node attached to a library node by a specific user,
pointing to where the actual file lives (their disk, their Jellyfin instance).
Multiple users can attach storage pointers to the same title node.

**Crosslink node** — created when a user "adds" a friend's content to their own
library. No file is copied. The crosslink is a DAG link from your library view
to their storage pointer. The file stays on their server and streams live.

This means: your library = your local files + crosslink nodes to friends' content.

### Discovery Layer — Universal Media Interface

A web interface / browser add-on providing unified search across ALL of a
user's media sources simultaneously. Sources include:

- Friends' published Plex/Jellyfin shares (crosslink-addressable)
- Streaming subscriptions the user has: Netflix, Apple TV+, Disney+, etc.
- YouTube
- User-added custom media sites (extensible source list)
- AI-assisted natural language search across the full combined graph

Search returns deduplicated results. User picks a title, picks a source, and
the interface loads that platform's native player (embedded where the platform
supports it, or opens the page directly). PlexVault is not re-hosting or
transcoding — it is a discovery and launch layer only.

Friends explicitly publish their shares; the interface surfaces them alongside
paid subscription sources. No content is hosted by PlexVault.

### Watchlist and Credit Flow

**Watchlist** — a user's saved list of content they want to watch later.
Content is not copied. Each watchlist entry is a crosslink node pointing to
the source (friend's server, streaming platform, etc.).

**Watchlist capacity** — denominated in the *size* of bookmarked content, not
item count. Reflects the real cost: a 50GB 4K rip takes more of a friend's
server resources than a 2GB 1080p file. Larger items cost more capacity.

**Credit as payment back to the sharer:** PhraseVault's credit system is the
mechanism for compensating friends whose servers are hosting content kept on
others' watchlists. When a user pays for watchlist capacity, a portion of that
fee flows as PhraseVault credit to the friend whose server bears the storage
and serving cost. This creates a direct incentive to share high-quality content
and keep your server reliable.

### Server Scaling Model

Each PlexVault server node is sized to serve up to 5 friends (the share limit).
Scaling is horizontal: add more server nodes to the farm as the network grows.
This means capacity planning is straightforward — no single server needs to
handle unbounded load. The network of nodes scales out, not up.

### Monetization Tiers

**Free / self-hosted:** sidecar alongside existing Plex or Jellyfin. Friend
sharing, selective adds, discovery layer. Up to 5 active shares.

**Premium hosted tier:** We host a media server for the user AND provide online
storage space for them to upload media they own. Key features:

- User uploads their own media files (rips, etc.) to their hosted storage
- **Back-end deduplication:** PhraseVault's BLAKE3 content-addressing gives this
  for free — two users uploading the same file produce the same hash. The backend
  stores one physical copy and both accounts get a pointer. Users pay for their
  "storage quota" but the platform only uses actual disk for unique content.
- **Torrent-like delivery:** the storage pointer is not a fixed server path — it
  resolves to whichever node in the network currently has that content available
  (user's own upload, or any friend in the network who shares it). Streaming is
  served from the nearest/fastest available source, like BitTorrent content
  addressing but for streaming.
- **Optional redundancy tier:** user can request that more than one physical copy
  of their media be maintained across separate nodes. Higher tier = more redundancy
  = higher availability guarantee. Priced accordingly.
- Friends' content streams live from their nodes (not copied), but dedup means
  if a friend also uploaded the same file, your watchlist item resolves to their
  node at no extra storage cost to anyone.

**Anonymous Encrypted Storage (separate standalone product — NOT PlexVault):**
Generic encrypted cloud vault. Client-side encryption, zero server knowledge.
Marketed as a privacy-first backup product with no media association. The
server stores opaque blobs; passphrase lost = data gone (intentional, legal
cover). Completely separate from PlexVault's feature set and branding.

### Watch Together

Synchronized group watch feature:

- Creates a virtual room with text chat + optional voice chat
- Shared media player synced across all room members
- Source can be anything the room host has access to: their Plex share, a
  Netflix stream (where technically feasible), YouTube, etc.
- Friends join the room and watch in sync
- PlexVault hosts the room/sync coordination layer; actual media streams from
  the source platform to each viewer independently (not re-streamed through us)

Existing competition: Teleparty, Scener, Kosmi. Differentiation: those are
browser extensions bolt-on to specific platforms; Watch Together is native to
PlexVault's multi-source interface and works across all connected sources.

### Offline / Unavailability Handling

When a friend's server goes offline:
1. If another friend has the same title (via deduped node), resolve silently to them
2. Otherwise show as unavailable at play-time (not filtered from search)

### Key Differentiators

- Universal search across all sources in one interface
- Watchlist capacity tied to real infrastructure cost; credit flows back to sharers
- Watch Together native across all sources (not a per-platform bolt-on)
- Curation: browse a friend's library, selectively add (not auto-import everything)
- Parental controls tied to source — adult content filtered regardless of friend's settings
- AI passive rules engine: standing rules run continuously against the graph
- "New item from friend" notifications with approve-before-appears workflow

### Legal Notes

- Discovery layer: indexing and launching only, not hosting — clean legal profile
- Scope remains "share your own library with your own friends" — no public index
- Encrypted storage product: must stay generic in marketing — willful blindness doctrine
  means media-adjacent marketing weakens the zero-knowledge defense even with encryption
- Watch Together: sync coordination only; each viewer streams from source independently

### Open Questions

- Gossip/sync protocol for the graph, or per-query federation?
- Permission revocation propagation (unfriend cascade across the DAG)
- Streaming model for friend shares: direct P2P vs lightweight relay
- How to handle streaming service embeds that block iframes (Netflix, etc.) —
  may need to open in new tab/window rather than embed for some platforms
- Watch Together is scoped to platforms that permit embedding/sync (settled — not a technical problem to solve, just a feature availability constraint communicated to users)
- Ownership verification for uploads: user self-attests responsibility via ToS (settled). The 5-friend sharing limit keeps content non-publicly-indexable, significantly reducing legal exposure vs. a public locker service.
- Final name TBD (PlexVault is working name)

---

## Relay — Media Application Layer (built 2026-05-30)

Relay is the media middleware layer sitting between the PhraseVault platform and
the final user-facing app (name TBD). Lives in `src/apps/relay/`.

### Three-Layer Stack

```
[Final App TBD — catchy name, user-facing]
         ↓
[Relay / MediaNode — node types, query engine, HTTP API]
         ↓
[PhraseVault — crypto, Hypercore feeds, Hyperswarm replication]
```

The final app name has not been chosen yet. Do NOT conflate the user app with
the Relay middleware or the PhraseVault infrastructure.

### Node Types (`src/apps/relay/types.ts`)

All payload interfaces extend `Record<string, unknown>` for PVNode<P> compatibility.

- **MediaNode** — one node per title (movie, series, episode, short). Metadata:
  title, year, kind, genres, imdb_id. Not per-file — one node represents the
  concept, regardless of how many copies exist across friends.

- **StoragePointerNode** — attached to a MediaNode by a specific user. Points
  to where the actual file lives: endpoint_url, content_hash (BLAKE3),
  size_bytes, encoding, available flag. Multiple users can attach pointers to
  the same MediaNode (dedup at the concept layer).

- **CrosslinkNode** — created when a user "adds" a friend's content. Links to
  a StoragePointer. No file copy. File streams live from the friend's node.

- **WatchlistEntryNode** — tracks a user's watch status for a title (unwatched /
  watching / watched / skipped) and progress in milliseconds.

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
`PV_PORT`, `PV_HOST`, `PV_LOG_LEVEL`).

Endpoints:
- `GET /health` — status, identity pubkey, feed length, following count, indexed count
- `GET /identity` — publicKey hex, DID, feedKey hex
- `GET /search?q=&kind=&available=&watchStatus=` — search across all feeds
- `GET /media/:id` — single title by id
- `POST /media` — publish a new media node to own feed
- `POST /storage` — publish a storage pointer
- `POST /crosslink` — crosslink a friend's storage pointer into your library
- `POST /watchlist` — add/update watchlist entry
- `POST /follow` — start following a peer's feed
- `DELETE /follow/:feedKey` — unfollow a peer
- `GET /following` — list followed feed keys

Followed feed keys are persisted to `$PV_DATA_DIR/followed.json`.

### Frontend (`client/`)

React + Vite + TypeScript + Tailwind CSS (v4). Dark theme.
- Search bar with kind filter (movie/series/episode/short) and available-only toggle
- MediaCard list — title, year, encoding, source count, watchlist badge
- DetailPanel modal — all sources with Play buttons, IMDb link, watchlist status
- Follow peer form in header
- Dev proxy: `/api` → `http://localhost:8080`
- Build output: `dist/client/` (served by Fastify's @fastify/static as SPA)

### Key Technical Decisions

- **Debian not Alpine for runtime image** — `sodium-native` (used by hypercore)
  ships prebuilt `linux-x64` (glibc) binaries but NOT `linux-x64-musl`. Alpine
  uses musl, so the binary never loads and the server crashes. Use `node:22-slim`
  (Debian Bookworm slim).

- **Use `node` user (UID 1000) not a custom system user** — `node:22-slim` ships
  with a `node` user at UID/GID 1000. Creating a system user with `useradd -r`
  assigns an unpredictable UID that won't match the Ansible-provisioned host data
  directory (which is also 1000:1000 to match the primary ubuntu user `chris`).

- **Builder stage uses build tools; runtime does not** — `python3/make/g++` are
  needed in the builder for any packages that fall back to source compilation.
  The runtime stage uses the Debian prebuilt binaries — no build tools needed.

---

## Deployment Infrastructure (as of 2026-05-30)

### Pipeline

```
git push → GitHub Actions (CI) → GHCR → Watchtower → presubuntu
```

- **CI:** `.github/workflows/docker.yml` — builds two-stage Docker image on every
  push to `main`, pushes to `ghcr.io/christcb03/phrasevault:latest` and `sha-<short>`.
- **GHCR:** GitHub Container Registry. Image is public (readable without auth).
- **Watchtower:** Runs alongside the app on presubuntu. Polls GHCR every 300 seconds,
  pulls and restarts the container automatically when a new image is available.
  This is the CD (Continuous Delivery) loop — no SSH from GitHub needed.
- **Ansible playbook:** `HomeLab/playbooks/relay.yml` — used for initial deployment
  and passphrase-changing re-deploys. Installs Docker CE if not present.

### Test Server: presubuntu

- **Host:** `presubuntu-vpn` (Ansible inventory)
- **IP:** `192.168.0.184` (internal, accessible via VPN to pveprod)
- **URL:** `http://192.168.0.184:8080` (HTTP, VPN required)
- **VM:** Proxmox VM 101 on pveprod — Ubuntu 24.04 LTS, 2 vCPU, 8GB RAM, 100GB disk
- **Data dir:** `/opt/phrasevault/data` (bind-mounted to container `/data`)
- **Container:** `phrasevault` (plus `watchtower-phrasevault` sidecar)
- **Passphrase:** stored encrypted in `HomeLab/vault.yml` as `vault_phrasevault_passphrase`

### Re-deploying (if Watchtower hasn't picked up yet, or passphrase changes)

```bash
cd ~/Projects/HomeLab
ansible-playbook playbooks/relay.yml
```

### Deploying alongside HomeLab Panel

PhraseVault (Relay) and **homelab-panel** share the same presubuntu deployment
pattern. They are separate containers, separate GHCR images, and separate
Watchtower sidecars — no code coupling between the repos.

| | PhraseVault (Relay) | homelab-panel |
|---|---|---|
| **Repo** | `phrasevault-repo` | `HomeLab/services/homelab-panel` |
| **Image** | `ghcr.io/christcb03/phrasevault:latest` | `ghcr.io/christcb03/homelab-panel:latest` |
| **Port** | `8080` | `3001` |
| **Container** | `phrasevault` | `homelab-panel` |
| **Watchtower** | `watchtower-phrasevault` | `watchtower-homelab-panel` |
| **Data dir** | `/opt/phrasevault/data` | `/opt/homelab-panel/data` |
| **Playbook** | `HomeLab/playbooks/relay.yml` | `HomeLab/playbooks/homelab_panel.yml` |

**Deploy both apps:**

```bash
cd ~/Projects/HomeLab
ansible-playbook playbooks/presubuntu.yml
```

**CD loop (identical for both):**

```
git push main → GitHub Actions → GHCR → Watchtower (300s poll) → container restart
```

homelab-panel additionally mounts `/opt/homelab` (HomeLab git clone),
`~/.ssh`, and `~/.vault_encryption_key` so it can spawn `ansible-playbook` and
`terraform` from the UI. PhraseVault does not need these mounts.

**URLs on presubuntu (VPN):**

- Relay: `http://192.168.0.184:8080`
- HomeLab panel: `http://192.168.0.184:3001`

Before the first homelab-panel GHCR image exists, set
`homelab_panel_build_from_source: true` in `playbooks/homelab_panel.yml`
(same pattern as PhraseVault's `phrasevault_build_from_source`).

### HTTPS via Traefik + Cloudflare (2026-05-30)

The container runs on the `saltbox` Docker network alongside Traefik. Traefik
handles TLS termination; certificates are issued automatically via Cloudflare DNS
challenge (resolver: `cfdns`). The direct port binding stays for VPN access.

**Live URLs:**
- VPN: `http://192.168.0.184:8080`
- Public HTTPS: `https://pvtest.turnernetworking.com`

**Re-deploy (updates container, DNS record, and cert if needed):**
```bash
cd ~/Projects/HomeLab
ansible-playbook playbooks/relay.yml
```

The playbook reads Cloudflare API credentials from `/srv/git/saltbox/accounts.yml`
on the target host, looks up the server's public IP via ipify, and keeps the DNS
A record in sync. Set `phrasevault_cloudflare_dns: false` to skip DNS on hosts
that don't run Saltbox.

**Traefik labels applied (no Authelia — PhraseVault has its own auth):**
- `traefik.http.routers.phrasevault.entrypoints: websecure`
- `traefik.http.routers.phrasevault.middlewares: globalHeaders@file,hsts@file`

---

### Authentication (2026-05-30)

secp256k1 challenge-response. **The passphrase never leaves the browser.**

Auth keypair derivation (browser-safe, no argon2):
```
authPrivKey = BLAKE3("phrasevault:api-auth-v1:" + passphrase)   // 32 bytes
authPubKey  = secp256k1.getPublicKey(authPrivKey)               // 33 bytes compressed
```

This is domain-separated from the identity keypair (which uses argon2id and
is derived server-side only). Same domain tag as the old API token — so the
key material is the same bytes, just treated as a keypair instead of a hex string.

**Login flow:**
1. `GET /auth/challenge` → one-time nonce (5-min TTL, consumed on use)
2. Browser signs `BLAKE3("phrasevault:auth-challenge:v1:" + nonce)` with auth private key
3. `POST /auth/verify { challenge, signature }` → server verifies sig against known auth pubkey
4. Server issues 24-hour session token (random 32 bytes, stored in-memory Map)
5. All API routes require `Authorization: Bearer <session-token>`

**Client crypto** (`client/src/crypto.ts`): `@noble/secp256k1` v3 + `@noble/hashes`
(BLAKE3, SHA256, HMAC). `prehash: false` on sign since we pre-hash with BLAKE3.

**Session tokens** are in-memory — they expire on server restart (users re-auth).
This is acceptable for a single-user personal server.

**Upgrade path to multi-user:** replace session Map with JWTs; keep the
challenge-response flow identical; derive auth keypair per-user with argon2id.

---

### Node Identity

The server's identity (keypair and feed key) is deterministically derived from
`PV_PASSPHRASE`. The same passphrase always produces the same identity. Feed data
lives in `/opt/phrasevault/data/feeds/<pubkey-hex>/`. **Back up the passphrase —
losing it means losing the feed identity.**

---

## Actions GitHub Workflow Note

The workflow uses `actions/checkout@v4`, `docker/build-push-action@v5`, etc. These
are still on Node.js 20. GitHub will force Node.js 24 by default from June 16, 2026
and remove Node.js 20 from runners September 16, 2026. Update action versions before
then: `@v5` for checkout, `@v6` for build-push-action, etc.

---

## What's Next (as of 2026-05-30)

**Phase 3 — Content:**
- TMDB API integration for movie poster images and richer metadata
- Watchlist management UI (update status, track progress_ms)
- Add media via TMDB search (not just manual JSON input)

**Phase 4 — Domain + HTTPS: ✅ DONE (2026-05-30)**
- Traefik on presubuntu (Saltbox) with Cloudflare DNS challenge for cert
- `https://pvtest.turnernetworking.com` (port forward 443→192.168.0.184 required on router)
- Cloudflare A record auto-registered by Ansible playbook

**Phase 5 — Watch Together (future):**
- WebSocket sync room on the server
- Embedded player in the frontend
- Text chat sidebar

**Phase 6 — Browser Extension (future):**
- Same React components, different mounting point
- Inject into Plex/Jellyfin web UI or run as standalone side panel

**Phase 7 — Production + Premium Tier (future):**
- Jellyfin integration
- Friend discovery via Hyperswarm DHT
- Hosted storage with BLAKE3 dedup
- Credit system for watchlist capacity billing

---

## eBable App Scope (separate from PhraseVault platform)

eBable = Chris's commercial app running on Chris's servers.
Uses PhraseVault as the data layer (like a GitHub-hosted app using git).

Focus: IT application integration knowledge.
- Full Solutions: complete guides (e.g. "Install OpenClaw on macOS 26.5",
  "Get OpenClaw working with Telegram")
- Leaves: fixes, updates, tips attached to solutions or standalone
- Credit system rewards contributors whose solutions actually work
- Users who mark solutions useful get a small credit for the feedback

eBable is NOT decentralized — it's a product. PhraseVault is decentralized.
