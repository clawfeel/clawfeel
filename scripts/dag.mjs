// ═══════════════════════════════════════════════════════════════════
//  ClawFeel DAG — Directed Acyclic Graph for Entropy Consensus
//  Pure Node.js (>=22), zero dependencies.
//
//  Each Feel reading becomes a "transaction" referencing 2+ parent
//  transactions (tips), forming a DAG. Consensus is reached when a
//  transaction has enough descendants (confirmations).
// ═══════════════════════════════════════════════════════════════════

import { createHash } from "node:crypto";
import { readFile, appendFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { ed25519Sign, ed25519Verify } from "./life.mjs";

const MAX_MEMORY_TXS = 2000;  // prune beyond this
const CONFIRM_THRESHOLD = 5;  // descendants needed for confirmation
const TX_VERSION = 2;         // v2 = Ed25519 signatures

// ── Transaction ───────────────────────────────────────────────────

export class Transaction {
  constructor({ clawId, publicKey, feel, entropy, timestamp, seq, authenticity, entropyQuality, parents }) {
    this.version = TX_VERSION;
    this.clawId = clawId;
    this.publicKey = publicKey || null; // Ed25519 public key hex (32 bytes)
    this.feel = feel;
    this.entropy = entropy;             // 64 hex chars (256-bit)
    this.timestamp = timestamp;
    this.seq = seq;
    this.authenticity = authenticity;    // 0-7
    this.entropyQuality = entropyQuality; // 0-100
    this.parents = parents || [];       // array of parent tx hashes
    this.hash = this.computeHash();
    this.signature = null;              // set via sign()
  }

  computeHash() {
    const canonical = JSON.stringify({
      v: this.version,
      c: this.clawId,
      pk: this.publicKey,
      f: this.feel,
      e: this.entropy,
      t: this.timestamp,
      s: this.seq,
      a: this.authenticity,
      q: this.entropyQuality,
      p: [...this.parents].sort(),
    });
    return createHash("sha256").update(canonical).digest("hex");
  }

  /**
   * Sign this transaction with Ed25519 private key.
   * @param {string} privateKeyHex - 32-byte Ed25519 private key as hex
   */
  sign(privateKeyHex) {
    this.signature = ed25519Sign(this.hash, privateKeyHex);
  }

  /**
   * Verify transaction integrity and Ed25519 signature.
   * - v1 (legacy): accepts old SHA-256 pseudo-signature
   * - v2: requires valid Ed25519 signature matching publicKey
   */
  verify() {
    if (this.hash !== this.computeHash()) return false;
    if (this.parents.length === 0 && this.clawId === "000000000000") return true; // genesis

    if (this.version >= 2) {
      // Ed25519 verification
      if (!this.publicKey || !this.signature) return false;
      return ed25519Verify(this.hash, this.signature, this.publicKey);
    }

    // Legacy v1: old pseudo-signature (backward compatible)
    const legacySig = createHash("sha256")
      .update(this.hash + ":" + this.clawId)
      .digest("hex")
      .substring(0, 32);
    return this.signature === legacySig;
  }

  toJSON() {
    return {
      version: this.version,
      clawId: this.clawId,
      publicKey: this.publicKey,
      feel: this.feel,
      entropy: this.entropy,
      timestamp: this.timestamp,
      seq: this.seq,
      authenticity: this.authenticity,
      entropyQuality: this.entropyQuality,
      parents: this.parents,
      hash: this.hash,
      signature: this.signature,
    };
  }

  static fromJSON(obj) {
    const tx = new Transaction({
      clawId: obj.clawId,
      publicKey: obj.publicKey || null,
      feel: obj.feel,
      entropy: obj.entropy,
      timestamp: obj.timestamp,
      seq: obj.seq,
      authenticity: obj.authenticity,
      entropyQuality: obj.entropyQuality,
      parents: obj.parents,
    });
    // Restore version/hash/sig from stored data
    tx.version = obj.version || 1;
    tx.hash = obj.hash;
    tx.signature = obj.signature;
    return tx;
  }
}

// ── Genesis Transaction ───────────────────────────────────────────

function createGenesis() {
  return new Transaction({
    clawId: "000000000000",
    feel: 50,
    entropy: "0".repeat(64),
    timestamp: "2026-03-20T00:00:00.000Z",
    seq: 0,
    authenticity: 0,
    entropyQuality: 0,
    parents: [],
  });
}

// ── DAG Store ─────────────────────────────────────────────────────

export class DAGStore {
  constructor({ dataDir }) {
    this.dataDir = dataDir;
    this.dagFile = path.join(dataDir, "dag.jsonl");

    // Primary storage
    this.txMap = new Map();           // hash → Transaction
    this.tips = new Set();            // hashes with no children
    this.children = new Map();        // hash → Set<childHash>
    this.byClawId = new Map();        // clawId → [hash, ...]

    // Genesis
    this.genesis = createGenesis();
    this._addInternal(this.genesis);
  }

  // ── Core operations ──

  _addInternal(tx) {
    if (this.txMap.has(tx.hash)) return false; // already exists

    this.txMap.set(tx.hash, tx);

    // This tx is a new tip
    this.tips.add(tx.hash);

    // Its parents are no longer tips
    for (const parentHash of tx.parents) {
      this.tips.delete(parentHash);

      // Update children index
      if (!this.children.has(parentHash)) {
        this.children.set(parentHash, new Set());
      }
      this.children.get(parentHash).add(tx.hash);
    }

    // Index by clawId
    if (!this.byClawId.has(tx.clawId)) {
      this.byClawId.set(tx.clawId, []);
    }
    this.byClawId.get(tx.clawId).push(tx.hash);

    return true;
  }

  add(tx) {
    // Validate
    if (!tx.verify()) return { ok: false, reason: "invalid_signature" };
    if (this.txMap.has(tx.hash)) return { ok: false, reason: "duplicate" };

    // Check parents exist (except genesis)
    const missing = this.getMissingParents(tx);
    if (missing.length > 0) {
      return { ok: false, reason: "missing_parents", missing };
    }

    const added = this._addInternal(tx);
    return { ok: added };
  }

  has(hash) {
    return this.txMap.has(hash);
  }

  get(hash) {
    return this.txMap.get(hash) || null;
  }

  getTips(maxCount = 10) {
    const tipList = [...this.tips];
    if (tipList.length <= maxCount) return tipList;
    // Return random subset
    for (let i = tipList.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [tipList[i], tipList[j]] = [tipList[j], tipList[i]];
    }
    return tipList.slice(0, maxCount);
  }

  getMissingParents(tx) {
    return tx.parents.filter(h => !this.txMap.has(h));
  }

  // ── Tip selection (weighted by entropy quality) ──

  selectParents(count = 2) {
    const tipList = [...this.tips];
    if (tipList.length === 0) return [this.genesis.hash];
    if (tipList.length <= count) return tipList;

    // Weighted selection: higher entropyQuality = more likely to be chosen
    const weights = tipList.map(h => {
      const tx = this.txMap.get(h);
      return tx ? Math.max(1, tx.entropyQuality) : 1;
    });
    const totalWeight = weights.reduce((a, b) => a + b, 0);

    const selected = new Set();
    let attempts = 0;
    while (selected.size < count && attempts < count * 10) {
      let r = Math.random() * totalWeight;
      for (let i = 0; i < tipList.length; i++) {
        r -= weights[i];
        if (r <= 0) {
          selected.add(tipList[i]);
          break;
        }
      }
      attempts++;
    }

    // Fallback: if weighted selection didn't get enough, add random tips
    while (selected.size < count && selected.size < tipList.length) {
      selected.add(tipList[Math.floor(Math.random() * tipList.length)]);
    }

    return [...selected];
  }

  // ── Consensus ──

  getDescendantCount(hash) {
    // BFS to count all descendants
    const visited = new Set();
    const queue = [hash];
    while (queue.length > 0) {
      const current = queue.shift();
      const kids = this.children.get(current);
      if (kids) {
        for (const child of kids) {
          if (!visited.has(child)) {
            visited.add(child);
            queue.push(child);
          }
        }
      }
    }
    return visited.size;
  }

  isConfirmed(hash, threshold = CONFIRM_THRESHOLD) {
    return this.getDescendantCount(hash) >= threshold;
  }

  getConfirmedTips() {
    // Tips whose parents are all confirmed
    return [...this.tips].filter(h => {
      const tx = this.txMap.get(h);
      if (!tx) return false;
      return tx.entropyQuality > 30; // minimum quality for confirmed tip
    });
  }

  // ── Network entropy ──

  computeNetworkEntropy() {
    const confirmedTips = this.getConfirmedTips();
    if (confirmedTips.length === 0) return null;

    // XOR all tip entropies
    let xorAccum = "0".repeat(64);
    for (const hash of confirmedTips) {
      const tx = this.txMap.get(hash);
      if (tx && tx.entropy) {
        // XOR hex strings
        let result = "";
        for (let i = 0; i < Math.min(xorAccum.length, tx.entropy.length); i++) {
          result += (parseInt(xorAccum[i], 16) ^ parseInt(tx.entropy[i], 16)).toString(16);
        }
        xorAccum = result;
      }
    }

    const netHash = createHash("sha256").update("clawfeel-dag:" + xorAccum).digest("hex");
    const netFeel = parseInt(netHash.substring(0, 8), 16) % 101;

    return {
      entropy: netHash,
      feel: netFeel,
      tipCount: confirmedTips.length,
      totalTx: this.txMap.size,
    };
  }

  // ── Stats ──

  getStats() {
    return {
      totalTx: this.txMap.size,
      tipCount: this.tips.size,
      nodeCount: this.byClawId.size,
      genesisHash: this.genesis.hash,
    };
  }

  // ── Persistence ──

  async save(tx) {
    try {
      await mkdir(this.dataDir, { recursive: true });
      await appendFile(this.dagFile, JSON.stringify(tx.toJSON()) + "\n", "utf8");
    } catch { /* ignore save errors */ }
  }

  async load() {
    try {
      const raw = await readFile(this.dagFile, "utf8");
      const lines = raw.trim().split("\n").filter(Boolean);
      for (const line of lines) {
        try {
          const obj = JSON.parse(line);
          const tx = Transaction.fromJSON(obj);
          if (tx.verify()) {
            this._addInternal(tx);
          }
        } catch { /* skip malformed lines */ }
      }
    } catch { /* first run, no DAG file */ }
  }

  // ── Pruning ──

  prune(keepLast = MAX_MEMORY_TXS) {
    if (this.txMap.size <= keepLast) return 0;

    // Sort by timestamp, remove oldest
    const sorted = [...this.txMap.values()]
      .filter(tx => tx.clawId !== "000000000000") // keep genesis
      .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    const toRemove = sorted.slice(0, sorted.length - keepLast);
    let removed = 0;

    for (const tx of toRemove) {
      // Only remove if confirmed (has enough descendants)
      if (this.getDescendantCount(tx.hash) >= CONFIRM_THRESHOLD) {
        this.txMap.delete(tx.hash);
        this.tips.delete(tx.hash);
        this.children.delete(tx.hash);
        removed++;
      }
    }

    return removed;
  }
}
