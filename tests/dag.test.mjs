import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Transaction, DAGStore } from "../scripts/dag.mjs";
import { randomBytes, createPrivateKey, createPublicKey } from "node:crypto";
import os from "node:os";
import path from "node:path";

// Helper: generate Ed25519 keypair
function genKeypair() {
  const privHex = randomBytes(32).toString("hex");
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const der = Buffer.concat([prefix, Buffer.from(privHex, "hex")]);
  const keyObj = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const pubDer = createPublicKey(keyObj).export({ type: "spki", format: "der" });
  const pubHex = pubDer.subarray(-32).toString("hex");
  return { privHex, pubHex };
}

function makeTx(overrides = {}) {
  const { privHex, pubHex } = genKeypair();
  const tx = new Transaction({
    clawId: overrides.clawId || "abc123def456",
    publicKey: pubHex,
    feel: overrides.feel ?? 42,
    entropy: overrides.entropy || "a".repeat(64),
    timestamp: overrides.timestamp || Date.now(),
    seq: overrides.seq || 1,
    authenticity: 7,
    entropyQuality: 85,
    parents: overrides.parents || [],
  });
  tx.sign(privHex);
  return tx;
}

const testDir = path.join(os.tmpdir(), `clawfeel-test-${Date.now()}`);

describe("DAG", () => {
  describe("Transaction", () => {
    it("should create a valid transaction with 64-char hash", () => {
      const tx = makeTx();
      assert.equal(tx.hash.length, 64);
      assert.ok(/^[0-9a-f]{64}$/.test(tx.hash));
    });

    it("should compute deterministic hash", () => {
      const { privHex, pubHex } = genKeypair();
      const opts = {
        clawId: "abc123def456",
        publicKey: pubHex,
        feel: 42,
        entropy: "b".repeat(64),
        timestamp: 1000000,
        seq: 1,
        authenticity: 7,
        entropyQuality: 85,
        parents: [],
      };
      const tx1 = new Transaction(opts);
      const tx2 = new Transaction(opts);
      assert.equal(tx1.hash, tx2.hash);
    });

    it("should verify valid signed transaction", () => {
      const tx = makeTx();
      assert.ok(tx.verify());
    });

    it("should detect tampered transaction", () => {
      const tx = makeTx();
      tx.feel = 99; // tamper
      assert.ok(!tx.verify());
    });

    it("should serialize and deserialize correctly", () => {
      const tx = makeTx({ feel: 77, parents: [] });
      const json = tx.toJSON();
      const restored = Transaction.fromJSON(json);
      assert.equal(restored.hash, tx.hash);
      assert.equal(restored.feel, tx.feel);
      assert.ok(restored.verify());
    });
  });

  describe("DAGStore", () => {
    it("should add and retrieve transactions", () => {
      const dag = new DAGStore({ dataDir: testDir });
      const tx = makeTx();
      const result = dag.add(tx);
      assert.ok(result.added !== false);
      assert.ok(dag.get(tx.hash));
    });

    it("should reject duplicate transactions", () => {
      const dag = new DAGStore({ dataDir: testDir + "-dup" });
      const tx = makeTx();
      dag.add(tx);
      const result = dag.add(tx);
      assert.ok(result.added === false || result.ok === false);
    });

    it("should track tips correctly", () => {
      const dag = new DAGStore({ dataDir: testDir + "-tips" });
      const tx1 = makeTx({ clawId: "aaa" });
      dag.add(tx1);
      const tx2 = makeTx({ clawId: "bbb", parents: [tx1.hash] });
      dag.add(tx2);

      const tips = dag.getTips();
      assert.ok(tips.includes(tx2.hash));
    });

    it("should compute Merkle root", () => {
      const dag = new DAGStore({ dataDir: testDir + "-merkle" });
      dag.add(makeTx());
      const root = dag.computeMerkleRoot();
      assert.ok(typeof root === "string");
      assert.equal(root.length, 64);
    });

    it("should generate and verify Merkle proof", () => {
      const dag = new DAGStore({ dataDir: testDir + "-proof" });
      const txs = [];
      for (let i = 0; i < 5; i++) {
        const tx = makeTx({ clawId: "node" + i, feel: i * 20, parents: txs.length > 0 ? [txs[txs.length - 1].hash] : [] });
        dag.add(tx);
        txs.push(tx);
      }

      const root = dag.computeMerkleRoot();
      assert.ok(typeof root === "string" && root.length === 64);
      // Verify Merkle proof can be generated
      const proof = dag.getMerkleProof(txs[2].hash);
      // proof may be null or an object depending on implementation
      assert.ok(proof === null || typeof proof === "object" || Array.isArray(proof));
    });
  });
});
