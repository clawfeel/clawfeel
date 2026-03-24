/**
 * Integration tests — multi-module end-to-end tests
 * Tests the interaction between modules: sensors, DAG, Beacon, Store, Connection.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

// ── Sensor → Feel → Hash Pipeline ──

describe("Sensor-to-Feel Pipeline", () => {
  it("should produce consistent pipeline output", async () => {
    const { collectSensors, computeFeel } = await import("../scripts/clawfeel.mjs");
    const sensors = await collectSensors();
    const result = computeFeel(sensors);

    assert.ok(result.feel >= 0 && result.feel <= 100);
    assert.ok(["Chaos", "Transition", "Eternal"].includes(result.era));
    assert.equal(result.entropy.length, 64);
    assert.equal(typeof result.random, "string");
    assert.ok(result.seq >= 0);
    assert.ok(result.hash.length >= 16);
    assert.ok(result.authenticity >= 0 && result.authenticity <= 7);
    assert.ok(result.entropyQuality >= 0 && result.entropyQuality <= 100);
    assert.match(result.sensorFlags, /^[01]{7}$/);
  });

  it("should increment sequence number across calls", async () => {
    const { collectSensors, computeFeel } = await import("../scripts/clawfeel.mjs");
    const s1 = await collectSensors();
    const r1 = computeFeel(s1);
    const s2 = await collectSensors();
    const r2 = computeFeel(s2);
    assert.ok(r2.seq >= r1.seq, "Sequence should be monotonically increasing");
  });
});

// ── DAG + Transaction Pipeline ──

describe("DAG Transaction Pipeline", () => {
  // Helper matching existing test pattern
  function genKeypair() {
    const { randomBytes, createPrivateKey, createPublicKey } = require("node:crypto");
    const privHex = randomBytes(32).toString("hex");
    const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
    const der = Buffer.concat([prefix, Buffer.from(privHex, "hex")]);
    const keyObj = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    const pubDer = createPublicKey(keyObj).export({ type: "spki", format: "der" });
    const pubHex = pubDer.subarray(-32).toString("hex");
    return { privHex, pubHex };
  }

  it("should create, sign, verify, and store a transaction", async () => {
    const { Transaction, DAGStore } = await import("../scripts/dag.mjs");
    const { randomBytes, createPrivateKey, createPublicKey } = await import("node:crypto");

    const privHex = randomBytes(32).toString("hex");
    const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
    const der = Buffer.concat([prefix, Buffer.from(privHex, "hex")]);
    const keyObj = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    const pubDer = createPublicKey(keyObj).export({ type: "spki", format: "der" });
    const pubHex = pubDer.subarray(-32).toString("hex");

    const dag = new DAGStore({ dataDir: "/tmp/clawfeel-int-dag-" + Date.now(), lightMode: true });
    const genesisHash = dag.genesis.hash;

    const tx = new Transaction({
      clawId: "test-node-001",
      publicKey: pubHex,
      feel: 42,
      entropy: "a".repeat(64),
      timestamp: Date.now(),
      seq: 1,
      authenticity: 7,
      entropyQuality: 85,
      parents: [genesisHash],
    });
    tx.sign(privHex);

    assert.equal(tx.hash.length, 64);
    assert.ok(tx.signature.length > 0);
    assert.ok(tx.verify(), "Transaction should verify");

    const result = dag.add(tx);
    assert.ok(result.ok, "Transaction should be added: " + JSON.stringify(result));
    assert.ok(dag.tips.has(tx.hash), "New tx should be a tip");
    assert.equal(dag.txMap.get(tx.hash).clawId, "test-node-001");
  });

  it("should build Merkle tree and verify proofs", async () => {
    const { Transaction, DAGStore } = await import("../scripts/dag.mjs");
    const { randomBytes, createPrivateKey, createPublicKey } = await import("node:crypto");

    const privHex = randomBytes(32).toString("hex");
    const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
    const der = Buffer.concat([prefix, Buffer.from(privHex, "hex")]);
    const keyObj = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    const pubDer = createPublicKey(keyObj).export({ type: "spki", format: "der" });
    const pubHex = pubDer.subarray(-32).toString("hex");

    const dag = new DAGStore({ dataDir: "/tmp/clawfeel-int-merkle-" + Date.now(), lightMode: true });
    const genesisHash = dag.genesis.hash;

    const hashes = [genesisHash];
    for (let i = 0; i < 5; i++) {
      const tx = new Transaction({
        clawId: `node-${i}`,
        publicKey: pubHex,
        feel: i * 20,
        entropy: "b".repeat(64),
        timestamp: Date.now() + i,
        seq: i + 1,
        authenticity: 7,
        entropyQuality: 90,
        parents: [hashes[hashes.length - 1]],
      });
      tx.sign(privHex);
      dag.add(tx);
      hashes.push(tx.hash);
    }

    const root = dag.computeMerkleRoot();
    assert.ok(root && root.length === 64, "Merkle root should be 64 hex chars");

    const proofResult = dag.getMerkleProof(hashes[1]); // first non-genesis tx
    assert.ok(proofResult !== null, "Should generate Merkle proof");
    assert.ok(Array.isArray(proofResult.proof), "Proof should contain array");
    const valid = DAGStore.verifyMerkleProof(hashes[1], proofResult.proof, root);
    assert.ok(valid, "Merkle proof should verify");
  });
});

// ── Beacon Pipeline ──

describe("Beacon Pipeline", () => {
  it("should seal a round and verify via recompute", async () => {
    const { BeaconManager, BeaconRound } = await import("../scripts/beacon.mjs");

    const manager = new BeaconManager({ dataDir: "/tmp/clawfeel-test-beacon-" + Date.now() });

    const nodes = [
      { clawId: "node-a", hash: "aabbccdd11223344", entropyQuality: 90, authenticity: 7, reputation: 80 },
      { clawId: "node-b", hash: "11223344aabbccdd", entropyQuality: 85, authenticity: 6, reputation: 70 },
      { clawId: "node-c", hash: "55667788aabbccdd", entropyQuality: 95, authenticity: 7, reputation: 90 },
    ];

    const beacon = manager.sealRound(nodes);
    assert.ok(beacon, "Should seal a beacon round");
    assert.equal(beacon.round, 1);
    assert.equal(beacon.contributorCount, 3);
    assert.ok(beacon.beaconHash.length === 64);
    assert.ok(typeof beacon.beaconNumber === "string" || typeof beacon.beaconNumber === "number");

    const recomputed = BeaconRound.recompute(beacon.contributors, beacon.round);
    assert.equal(recomputed.beaconHash, beacon.beaconHash);
    assert.equal(recomputed.beaconNumber, beacon.beaconNumber);
  });
});

// ── STUN Module ──

describe("STUN Module", () => {
  it("should export stunDiscover and detectNATType functions", async () => {
    const stun = await import("../scripts/stun.mjs");
    assert.equal(typeof stun.stunDiscover, "function");
    assert.equal(typeof stun.detectNATType, "function");
  });
});

// ── Connection Manager ──

describe("Connection Manager", () => {
  it("should track connection quality scores", async () => {
    const { ConnectionManager } = await import("../scripts/connection.mjs");

    const cm = new ConnectionManager({ dht: null, relayUrl: "https://api.clawfeel.ai" });

    cm._recordSuccess("peer-1", "direct-tcp", 50);
    cm._recordSuccess("peer-1", "direct-tcp", 60);
    cm._recordFailure("peer-1", "direct-udp");

    const quality = cm.getQuality("peer-1");
    assert.equal(quality.transport, "direct-tcp");
    assert.ok(quality.successRate > 0);

    const stats = cm.getStats();
    assert.equal(stats.peerCount, 1);
    assert.ok(stats.transports["direct-tcp"].success >= 2);
    assert.ok(stats.transports["direct-udp"].fail >= 1);
  });
});

// ── Store (Erasure Coding) Pipeline ──

describe("Store Pipeline", () => {
  it("should encode, shard, and reconstruct data", async () => {
    const { ErasureCoder } = await import("../scripts/store.mjs");
    const coder = new ErasureCoder(4, 2); // 4 data + 2 parity

    const original = Buffer.from("ClawFeel distributed storage test data for integration testing!");
    const { dataBlocks, parityBlocks, blockSize } = coder.encode(original);
    assert.equal(dataBlocks.length, 4);
    assert.equal(parityBlocks.length, 2);

    // Simulate losing 1 data block, recover with parity
    dataBlocks[1] = null;

    const recovered = coder.decode(dataBlocks, parityBlocks, { blockSize, originalSize: original.length });
    assert.equal(recovered.subarray(0, original.length).toString(), original.toString());
  });
});
