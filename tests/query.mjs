/**
 * Relay query engine test.
 * Two users (alice, bob) each have feeds. Bob follows Alice.
 * Tests: search, filter by kind, dedup, availability filtering, watchlist status.
 * Run with: node tests/query.mjs  (after npm run build)
 */

import { createMediaNode, createStoragePointerNode, createCrosslinkNode, createWatchlistEntryNode } from "../dist/apps/relay/nodes.js";
import { RelayQueryEngine } from "../dist/apps/relay/query.js";
import { HypercoreStore } from "../dist/store/hypercore.js";
import { deriveIdentity } from "../dist/identity/index.js";
import os from "os";
import path from "path";
import fs from "fs";

const ALICE_PASS = "alice-test-passphrase";
const BOB_PASS   = "bob-test-passphrase";
const DATA_DIR = path.join(os.tmpdir(), "relay-query-test-" + Date.now());

let passed = 0, failed = 0;
function assert(cond, label) {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else       { console.error(`  ✗ ${label}`); failed++; }
}

async function run() {
  console.log("Relay query engine test\n");

  const aliceId = await deriveIdentity(ALICE_PASS);
  const bobId   = await deriveIdentity(BOB_PASS);
  const aliceKey = Buffer.from(aliceId.publicKey).toString("hex");
  const bobKey   = Buffer.from(bobId.publicKey).toString("hex");

  // Open stores
  const aliceStore = new HypercoreStore(path.join(DATA_DIR, "alice"), aliceKey);
  const bobStore   = new HypercoreStore(path.join(DATA_DIR, "bob"), bobKey);
  await aliceStore.open();
  await bobStore.open();

  // 1. Alice publishes two movies and a series
  console.log("1. Alice publishes media");
  const inception = await createMediaNode(ALICE_PASS, {
    title: "Inception", year: 2010, kind: "movie", imdb_id: "tt1375666",
    genres: ["sci-fi", "thriller"],
  });
  const interstellar = await createMediaNode(ALICE_PASS, {
    title: "Interstellar", year: 2014, kind: "movie", imdb_id: "tt0816692",
    genres: ["sci-fi", "drama"],
  });
  const office = await createMediaNode(ALICE_PASS, {
    title: "The Office", year: 2005, kind: "series", imdb_id: "tt0386676",
  });

  const inceptionPtr = await createStoragePointerNode(ALICE_PASS, {
    media_node_id: inception.id, endpoint_url: "https://alice.local/inception.mkv",
    content_hash: "abc123", size_bytes: 8_000_000_000, encoding: "1080p",
    container: "mkv", available: true,
  });
  const interstellarPtr = await createStoragePointerNode(ALICE_PASS, {
    media_node_id: interstellar.id, endpoint_url: "https://alice.local/interstellar.mkv",
    content_hash: "def456", size_bytes: 10_000_000_000, encoding: "4K HDR",
    container: "mkv", available: true,
  });
  const officePtr = await createStoragePointerNode(ALICE_PASS, {
    media_node_id: office.id, endpoint_url: "https://alice.local/office/",
    content_hash: "ghi789", size_bytes: 50_000_000_000, encoding: "1080p",
    container: "mkv", available: false, // offline
  });

  await aliceStore.append(inception);
  await aliceStore.append(interstellar);
  await aliceStore.append(office);
  await aliceStore.append(inceptionPtr);
  await aliceStore.append(interstellarPtr);
  await aliceStore.append(officePtr);
  assert(aliceStore.length === 6, "alice feed has 6 nodes");

  // 2. Bob crosslinks Inception to his library and adds it to watchlist
  console.log("\n2. Bob crosslinks and watchlists Inception");
  const bobCrosslink = await createCrosslinkNode(BOB_PASS, {
    target_node_id: inceptionPtr.id,
    source_author: aliceKey,
    media_node_id: inception.id,
    added_at: Date.now(),
  });
  const bobWatchlist = await createWatchlistEntryNode(BOB_PASS, {
    media_node_id: inception.id,
    crosslink_node_id: bobCrosslink.id,
    status: "unwatched",
    added_at: Date.now(),
    size_bytes: 8_000_000_000,
  });
  // Bob also publishes Interstellar independently (same media node — dedup test)
  const bobInterstellarPtr = await createStoragePointerNode(BOB_PASS, {
    media_node_id: interstellar.id, endpoint_url: "https://bob.local/interstellar.mkv",
    content_hash: "def456", size_bytes: 10_000_000_000, encoding: "1080p",
    container: "mkv", available: true,
  });

  await bobStore.append(inception);       // bob also has the media node
  await bobStore.append(interstellar);
  await bobStore.append(bobCrosslink);
  await bobStore.append(bobWatchlist);
  await bobStore.append(bobInterstellarPtr);
  assert(bobStore.length === 5, "bob feed has 5 nodes");

  // 3. Build query engine with both feeds
  console.log("\n3. Build query engine");
  const engine = new RelayQueryEngine();
  engine.addFeed(aliceKey, aliceStore);
  engine.addFeed(bobKey, bobStore);
  await engine.refresh();
  assert(engine.size === 3, "engine indexes 3 unique titles");

  // 4. Search
  console.log("\n4. Search");
  const allResults = engine.search();
  assert(allResults.length === 3, "search() returns all 3 titles");

  const sciResults = engine.search({ query: "inter" });
  assert(sciResults.length === 1, "search 'inter' returns Interstellar");
  assert(sciResults[0].media.payload.title === "Interstellar", "correct title");

  // 5. Kind filter
  console.log("\n5. Kind filter");
  const movies = engine.search({ kind: "movie" });
  assert(movies.length === 2, "filter movies returns 2");
  const series = engine.search({ kind: "series" });
  assert(series.length === 1, "filter series returns 1 (The Office)");

  // 6. Dedup — Interstellar has two sources (alice 4K + bob 1080p)
  console.log("\n6. Dedup and multi-source");
  const interstellarResult = engine.getById(interstellar.id);
  assert(interstellarResult !== null, "getById works");
  assert(interstellarResult?.sources.length === 2, "Interstellar has 2 sources");
  assert(interstellarResult?.bestSource?.storagePointer.payload.encoding === "4K HDR",
    "bestSource picks 4K HDR over 1080p");

  // 7. Availability filter
  console.log("\n7. Availability filter");
  const available = engine.search({ availableOnly: true });
  assert(available.length === 2, "availableOnly excludes The Office (offline)");

  // 8. Watchlist
  console.log("\n8. Watchlist");
  const inceptionResult = engine.getById(inception.id);
  assert(inceptionResult?.watchlistEntry !== null, "Inception has watchlist entry");
  assert(inceptionResult?.watchlistEntry?.payload.status === "unwatched", "status is unwatched");

  const watchlistItems = engine.search({ watchStatus: "unwatched" });
  assert(watchlistItems.length === 1, "one unwatched item");
  assert(watchlistItems[0].media.payload.title === "Inception", "it's Inception");

  // Cleanup
  await aliceStore.close();
  await bobStore.close();
  fs.rmSync(DATA_DIR, { recursive: true, force: true });

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

run().catch(e => { console.error(e); process.exit(1); });
