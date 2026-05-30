/**
 * Replication integration test — no network required.
 *
 * Two Hypercore feeds (writer + reader) are connected by piping their
 * replicate() streams together in-process. This proves the protocol works
 * before adding Hyperswarm peer discovery on top.
 *
 * Run with: node tests/replication.mjs  (after npm run build)
 */

import { createNode, verifyNode } from "../dist/node/index.js";
import { HypercoreStore } from "../dist/store/hypercore.js";
import { deriveIdentity } from "../dist/identity/index.js";
import os from "os";
import path from "path";
import fs from "fs";
import { PassThrough } from "stream";

const WRITER_PASS = "writer-passphrase-test";
const DATA_DIR = path.join(os.tmpdir(), "phrasevault-repl-test-" + Date.now());
const WRITER_DIR = path.join(DATA_DIR, "writer");
const READER_DIR = path.join(DATA_DIR, "reader");

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

function waitForAppend(core, targetLength) {
  return new Promise((resolve) => {
    if (core.length >= targetLength) return resolve();
    core.on("append", function check() {
      if (core.length >= targetLength) {
        core.off("append", check);
        resolve();
      }
    });
  });
}

async function run() {
  console.log("PhraseVault replication test\n");

  // 1. Writer: create feed and write nodes
  console.log("1. Writer: create and populate feed");
  const identity = await deriveIdentity(WRITER_PASS);
  const pubKeyHex = Buffer.from(identity.publicKey).toString("hex");

  const writerStore = new HypercoreStore(WRITER_DIR, pubKeyHex);
  await writerStore.open();

  const node1 = await createNode(WRITER_PASS, {
    type: "test",
    timestamp: Date.now(),
    links: [],
    score: 0.1,
    payload: { message: "first node" },
  });
  const node2 = await createNode(WRITER_PASS, {
    type: "test",
    timestamp: Date.now() + 1,
    links: [node1.id],
    score: 0.2,
    payload: { message: "second node" },
  });

  await writerStore.append(node1);
  await writerStore.append(node2);
  assert(writerStore.length === 2, "writer has 2 nodes");

  const feedKeyHex = writerStore.feedKey.toString("hex");
  console.log(`  feed key: ${feedKeyHex.slice(0, 16)}...`);

  // 2. Reader: open read-only replica
  console.log("\n2. Reader: open read-only replica");
  const readerStore = new HypercoreStore(READER_DIR, feedKeyHex, {
    writable: false,
    key: Buffer.from(feedKeyHex, "hex"),
  });
  await readerStore.open();
  assert(readerStore.length === 0, "reader starts empty");

  // 3. Replicate: pipe the two replicate streams together (in-process)
  console.log("\n3. Replication: connect writer ↔ reader");
  const writerRepl = writerStore._core.replicate(true);  // initiator
  const readerRepl = readerStore._core.replicate(false); // receiver

  writerRepl.pipe(readerRepl).pipe(writerRepl);

  // Wait for reader to receive both blocks
  await waitForAppend(readerStore._core, 2);

  assert(readerStore._core.length === 2, "reader received 2 blocks from replication");

  // 4. Rebuild reader index and verify nodes
  console.log("\n4. Verify replicated nodes");
  await readerStore.refresh();

  const r1 = await readerStore.get(node1.id);
  const r2 = await readerStore.get(node2.id);

  assert(r1 !== null, "reader can get node1 by id");
  assert(r2 !== null, "reader can get node2 by id");
  assert(r1?.payload?.message === "first node", "node1 payload intact");
  assert(r2?.payload?.message === "second node", "node2 payload intact");
  assert(verifyNode(r1), "replicated node1 passes signature verification");
  assert(verifyNode(r2), "replicated node2 passes signature verification");

  // 5. Incremental: writer adds a third node, reader syncs it
  console.log("\n5. Incremental sync: writer adds node3");
  const node3 = await createNode(WRITER_PASS, {
    type: "test",
    timestamp: Date.now() + 2,
    links: [node2.id],
    score: 0.05,
    payload: { message: "third node" },
  });
  await writerStore.append(node3);

  await waitForAppend(readerStore._core, 3);
  await readerStore.refresh();

  const r3 = await readerStore.get(node3.id);
  assert(r3 !== null, "reader received node3 via incremental sync");
  assert(verifyNode(r3), "node3 passes verification after sync");

  // 6. DAG integrity: links are preserved
  console.log("\n6. DAG integrity");
  assert(r2?.links.includes(node1.id), "node2 links to node1");
  assert(r3?.links.includes(node2.id), "node3 links to node2");

  // Cleanup
  writerRepl.destroy();
  readerRepl.destroy();
  await writerStore.close();
  await readerStore.close();
  fs.rmSync(DATA_DIR, { recursive: true, force: true });

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

run().catch(e => { console.error(e); process.exit(1); });
