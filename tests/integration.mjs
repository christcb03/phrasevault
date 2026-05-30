/**
 * End-to-end integration test — no test framework needed.
 * Run with: node tests/integration.mjs
 *
 * Tests: createNode → HypercoreStore.append → get → list → verifyNode
 */

import { createNode, verifyNode } from "../dist/node/index.js";
import { HypercoreStore } from "../dist/store/hypercore.js";
import { deriveIdentity } from "../dist/identity/index.js";
import os from "os";
import path from "path";
import fs from "fs";

const PASSPHRASE = "test-passphrase-do-not-use-in-production";
const DATA_DIR = path.join(os.tmpdir(), "phrasevault-test-" + Date.now());

let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) {
    console.log(`  ✓ ${label}`);
    passed++;
  } else {
    console.error(`  ✗ ${label}`);
    failed++;
  }
}

async function run() {
  console.log("PhraseVault integration test\n");

  // 1. Derive identity
  console.log("1. Identity derivation");
  const identity = await deriveIdentity(PASSPHRASE);
  assert(identity.publicKey.length === 33, "public key is 33 bytes (compressed secp256k1)");
  assert(identity.did.startsWith("did:key:"), "DID starts with did:key:");
  const pubKeyHex = Buffer.from(identity.publicKey).toString("hex");

  // 2. Create a signed node
  console.log("\n2. Node creation & signing");
  const node = await createNode(PASSPHRASE, {
    type: "test",
    timestamp: Date.now(),
    links: [],
    score: 0.1,
    payload: { message: "hello phrasevault" },
  });
  assert(typeof node.id === "string" && node.id.length === 64, "node id is 64-char hex");
  assert(node.author === pubKeyHex, "node author matches derived public key");
  assert(typeof node.signature === "string" && node.signature.length === 128, "signature is 128-char hex");
  assert(verifyNode(node), "node passes signature verification");

  // 3. Tamper detection
  console.log("\n3. Tamper detection");
  const tampered = { ...node, payload: { message: "tampered" } };
  assert(!verifyNode(tampered), "tampered node fails verification");

  // 4. HypercoreStore: write and read back
  console.log("\n4. HypercoreStore persistence");
  const store = new HypercoreStore(DATA_DIR, pubKeyHex);
  await store.open();

  await store.append(node);
  assert(store.length === 1, "feed length is 1 after append");

  const retrieved = await store.get(node.id);
  assert(retrieved !== null, "get() returns the node");
  assert(retrieved?.id === node.id, "retrieved node has correct id");
  assert(verifyNode(retrieved), "retrieved node still passes verification");

  // 5. Idempotent append
  console.log("\n5. Idempotency");
  await store.append(node); // should not throw or duplicate
  assert(store.length === 1, "feed length stays 1 on duplicate append");

  // 6. List
  console.log("\n6. List");
  const nodes = [];
  for await (const n of store.list()) nodes.push(n);
  assert(nodes.length === 1, "list() returns 1 node");
  assert(nodes[0].id === node.id, "listed node matches");

  // 7. Reopen and verify index rebuild
  console.log("\n7. Reopen & index rebuild");
  await store.close();
  const store2 = new HypercoreStore(DATA_DIR, pubKeyHex);
  await store2.open();
  assert(store2.length === 1, "length preserved after reopen");
  const retrieved2 = await store2.get(node.id);
  assert(retrieved2?.id === node.id, "node retrievable after reopen");
  await store2.close();

  // Cleanup
  fs.rmSync(DATA_DIR, { recursive: true, force: true });

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

run().catch(e => { console.error(e); process.exit(1); });
