// ═══════════════════════════════════════════════════════════════════
//  ClawFeel Gossip — Transaction Propagation Protocol
//  Pure Node.js (>=22), zero dependencies.
//
//  Bridges DHT (peer discovery) with DAG (transaction storage).
//  Uses the DHT's TCP server for message passing.
// ═══════════════════════════════════════════════════════════════════

import { Transaction } from "./dag.mjs";
import { randomBytes } from "node:crypto";

const DEFAULT_FANOUT = 6;       // peers to forward each tx to
const SEEN_MAX = 10_000;        // max seen-set size
const SYNC_BATCH = 50;          // max txs per sync response
const PULL_BATCH = 20;          // max txs per pull request

export class GossipManager {
  constructor({ dht, dag, clawId, signKey, signPub, fanout = DEFAULT_FANOUT, lightMode = false }) {
    this.dht = dht;
    this.dag = dag;
    this.clawId = clawId;
    this.signKey = signKey || null;   // Ed25519 private key hex
    this.signPub = signPub || null;   // Ed25519 public key hex
    this.fanout = fanout;
    this.lightMode = lightMode;
    this.seenMax = lightMode ? 500 : SEEN_MAX;

    // Dedup: recently seen tx hashes
    this.seen = new Set();
    this.seenOrder = []; // for LRU eviction

    // Stats
    this.stats = { txGossiped: 0, txReceived: 0, syncsDone: 0 };

    // Register gossip message handler on DHT
    this.dht.onMessage(async (msg, socket) => {
      return this._handleMessage(msg);
    });
  }

  // ── Seen-set management ──

  _markSeen(hash) {
    if (this.seen.has(hash)) return;
    this.seen.add(hash);
    this.seenOrder.push(hash);
    while (this.seenOrder.length > this.seenMax) {
      const old = this.seenOrder.shift();
      this.seen.delete(old);
    }
  }

  // ── Create transaction from a Feel reading ──

  onNewLocalReading(result) {
    const parents = this.dag.selectParents(2);

    const tx = new Transaction({
      clawId: this.clawId,
      publicKey: this.signPub,
      feel: result.feel,
      entropy: result.entropy,
      timestamp: result.timestamp,
      seq: result.seq,
      authenticity: result.authenticity,
      entropyQuality: result.entropyQuality,
      parents,
    });

    // Sign with Ed25519 private key
    if (this.signKey) {
      tx.sign(this.signKey);
    }

    const addResult = this.dag.add(tx);
    if (addResult.ok) {
      // Persist
      this.dag.save(tx).catch(() => {});
      // Gossip to peers
      this.broadcast(tx).catch(() => {});
      return tx;
    }

    return null;
  }

  // ── Broadcast a transaction to random peers ──

  async broadcast(tx) {
    this._markSeen(tx.hash);

    const peers = this.dht.getRandomContacts(this.fanout);
    if (peers.length === 0) return;

    const promises = peers.map(async (contact) => {
      try {
        await this.dht.sendRpc(contact, {
          id: randomBytes(4).toString("hex"),
          type: "GOSSIP_TX",
          tx: tx.toJSON(),
        });
        this.stats.txGossiped++;
      } catch {
        // peer unreachable, ignore
      }
    });

    await Promise.allSettled(promises);
  }

  // ── Handle incoming gossip messages ──

  async _handleMessage(msg) {
    switch (msg.type) {
      case "GOSSIP_TX":
        return this._handleGossipTx(msg);

      case "GOSSIP_SYNC_REQ":
        return this._handleSyncRequest(msg);

      case "GOSSIP_PULL_REQ":
        return this._handlePullRequest(msg);

      case "GOSSIP_MERKLE_PROOF":
        return this._handleMerkleProof(msg);

      default:
        return null; // not a gossip message
    }
  }

  _handleMerkleProof(msg) {
    if (!msg.txHash) return { id: msg.id, type: "GOSSIP_MERKLE_RES", error: "missing txHash" };
    const proof = this.dag.getMerkleProof(msg.txHash);
    if (!proof) return { id: msg.id, type: "GOSSIP_MERKLE_RES", found: false };
    return {
      id: msg.id,
      type: "GOSSIP_MERKLE_RES",
      found: true,
      root: proof.root,
      proof: proof.proof,
      leaf: proof.leaf,
    };
  }

  async _handleGossipTx(msg) {
    const tx = Transaction.fromJSON(msg.tx);

    // Already seen?
    if (this.seen.has(tx.hash) || this.dag.has(tx.hash)) {
      this._markSeen(tx.hash);
      return { id: msg.id, type: "GOSSIP_TX_ACK", known: true };
    }

    // Validate
    if (!tx.verify()) {
      return { id: msg.id, type: "GOSSIP_TX_ACK", error: "invalid" };
    }

    this._markSeen(tx.hash);
    this.stats.txReceived++;

    // Try to add
    const result = this.dag.add(tx);

    if (result.ok) {
      // Persist
      this.dag.save(tx).catch(() => {});
      // Re-gossip to other peers (not back to sender)
      this.broadcast(tx).catch(() => {});
    } else if (result.reason === "missing_parents") {
      // Request missing parents from sender
      if (msg.from) {
        this._pullMissing(result.missing, msg.from).catch(() => {});
      }
    }

    return { id: msg.id, type: "GOSSIP_TX_ACK", ok: result.ok };
  }

  async _handleSyncRequest(msg) {
    const myTips = this.dag.getTips(SYNC_BATCH);
    const theirTips = msg.tips || [];

    // Find transactions they might be missing
    const missing = [];
    for (const tipHash of myTips) {
      if (!theirTips.includes(tipHash)) {
        const tx = this.dag.get(tipHash);
        if (tx) missing.push(tx.toJSON());
      }
      if (missing.length >= SYNC_BATCH) break;
    }

    // Limit response for light nodes
    const maxTxs = msg.lightNode ? Math.min(msg.maxTxs || 50, 50) : SYNC_BATCH;
    const txs = missing.slice(0, maxTxs);

    return {
      id: msg.id,
      type: "GOSSIP_SYNC_RES",
      tips: myTips,
      txs,
      merkleRoot: this.dag.computeMerkleRoot(),
    };
  }

  async _handlePullRequest(msg) {
    const hashes = msg.hashes || [];
    const txs = [];

    for (const h of hashes.slice(0, PULL_BATCH)) {
      const tx = this.dag.get(h);
      if (tx) txs.push(tx.toJSON());
    }

    return {
      id: msg.id,
      type: "GOSSIP_PULL_RES",
      txs,
    };
  }

  // ── Pull missing transactions from a peer ──

  async _pullMissing(hashes, contact, depth = 0) {
    if (depth > 5) return; // prevent recursive amplification DoS
    try {
      const res = await this.dht.sendRpc(contact, {
        id: randomBytes(4).toString("hex"),
        type: "GOSSIP_PULL_REQ",
        hashes: hashes.slice(0, PULL_BATCH),
      });

      if (res.txs) {
        for (const txData of res.txs) {
          const tx = Transaction.fromJSON(txData);
          if (tx.verify()) {
            const result = this.dag.add(tx);
            if (result.ok) {
              this.dag.save(tx).catch(() => {});
            }
            // Recursively pull if still missing parents
            if (result.reason === "missing_parents") {
              await this._pullMissing(result.missing, contact, depth + 1);
            }
          }
        }
      }
    } catch {
      // peer unreachable
    }
  }

  // ── Full sync with peers (run on bootstrap) ──

  async fullSync() {
    const peers = this.dht.getRandomContacts(3);
    if (peers.length === 0) return;

    const myTips = this.dag.getTips(SYNC_BATCH);

    for (const contact of peers) {
      try {
        const res = await this.dht.sendRpc(contact, {
          id: randomBytes(4).toString("hex"),
          type: "GOSSIP_SYNC_REQ",
          tips: myTips,
        });

        if (res.txs) {
          for (const txData of res.txs) {
            const tx = Transaction.fromJSON(txData);
            if (tx.verify()) {
              const result = this.dag.add(tx);
              if (result.ok) {
                this.dag.save(tx).catch(() => {});
              }
            }
          }
        }

        this.stats.syncsDone++;
      } catch {
        // peer unreachable
      }
    }
  }

  // ── Stats ──

  // ── Light Sync (for light nodes) ──

  async lightSync() {
    const peers = this.dht.getRandomContacts(2); // fewer peers
    if (peers.length === 0) return;

    const myTips = this.dag.getTips(5); // only 5 tips

    for (const contact of peers) {
      try {
        const res = await this.dht.sendRpc(contact, {
          id: randomBytes(4).toString("hex"),
          type: "GOSSIP_SYNC_REQ",
          tips: myTips,
          lightNode: true,
          maxTxs: 50,
        });

        if (res.txs) {
          // Only accept up to 50 transactions
          for (const txData of res.txs.slice(0, 50)) {
            const tx = Transaction.fromJSON(txData);
            if (tx.verify()) {
              const result = this.dag.add(tx);
              if (result.ok) {
                this.dag.save(tx).catch(() => {});
              }
            }
          }
        }

        // Request Merkle root for verification
        if (res.merkleRoot) {
          this._lastPeerMerkleRoot = res.merkleRoot;
        }

        this.stats.syncsDone++;
      } catch {
        // peer unreachable
      }
    }

    // Aggressive prune for light nodes
    this.dag.prune();
  }

  // ── Merkle Proof Request ──

  async requestMerkleProof(txHash, contact) {
    try {
      const res = await this.dht.sendRpc(contact, {
        id: randomBytes(4).toString("hex"),
        type: "GOSSIP_MERKLE_PROOF",
        txHash,
      });
      if (res.proof && res.root) {
        const { DAGStore } = await import("./dag.mjs");
        return DAGStore.verifyMerkleProof(txHash, res.proof, res.root);
      }
      return false;
    } catch {
      return false;
    }
  }

  // ── Stats ──

  getStats() {
    return {
      ...this.stats,
      dagStats: this.dag.getStats(),
      networkEntropy: this.dag.computeNetworkEntropy(),
      dhtPeers: this.dht.stats.peers,
      lightMode: this.lightMode,
    };
  }
}
