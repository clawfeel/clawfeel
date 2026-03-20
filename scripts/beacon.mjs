/**
 * ClawFeel Random Beacon — Verifiable Decentralized Randomness
 *
 * Every N seconds, seals a beacon round:
 *   Collect node hashes → Filter by quality → XOR → SHA-256 → Sign → Persist
 *
 * Anyone can verify: given the contributor list, recompute XOR → hash → number.
 */

import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFile, writeFile, appendFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";

// ── Utility: XOR two hex strings ──

function xorHex(a, b) {
  const bufA = Buffer.from(a.padEnd(64, "0").substring(0, 64), "hex");
  const bufB = Buffer.from(b.padEnd(64, "0").substring(0, 64), "hex");
  const result = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) result[i] = bufA[i] ^ bufB[i];
  return result.toString("hex");
}

// ── Utility: SHA-256 hash ──

function sha256(data) {
  return createHash("sha256").update(data).digest("hex");
}

// ── BeaconRound: Immutable sealed round ──

class BeaconRound {
  constructor({
    round,
    timestamp,
    duration,
    contributors,
    contributorCount,
    xorAccum,
    beaconHash,
    beaconNumber,
    era,
    signature,
    publicKey,
  }) {
    this.round = round;
    this.timestamp = timestamp;
    this.duration = duration;
    this.contributors = contributors;
    this.contributorCount = contributorCount;
    this.xorAccum = xorAccum;
    this.beaconHash = beaconHash;
    this.beaconNumber = beaconNumber;
    this.era = era;
    this.signature = signature;
    this.publicKey = publicKey;
  }

  /**
   * Verify this beacon round:
   * 1. Recompute XOR from contributors
   * 2. Recompute beacon hash
   * 3. Verify Ed25519 signature
   */
  verify() {
    try {
      // Step 1: Recompute XOR accumulator from contributors
      const recomputed = BeaconRound.recompute(this.contributors, this.round);

      if (recomputed.xorAccum !== this.xorAccum) return { valid: false, reason: "XOR mismatch" };
      if (recomputed.beaconHash !== this.beaconHash) return { valid: false, reason: "Hash mismatch" };
      if (recomputed.beaconNumber !== this.beaconNumber) return { valid: false, reason: "Number mismatch" };

      // Step 2: Verify Ed25519 signature
      if (this.signature && this.publicKey) {
        const pubKeyObj = createPublicKey({
          key: Buffer.from(this.publicKey, "hex"),
          format: "der",
          type: "spki",
        });
        const valid = verify(
          null,
          Buffer.from(this.beaconHash, "hex"),
          pubKeyObj,
          Buffer.from(this.signature, "hex"),
        );
        if (!valid) return { valid: false, reason: "Signature invalid" };
      }

      return { valid: true };
    } catch (err) {
      return { valid: false, reason: err.message };
    }
  }

  /**
   * Recompute beacon from contributor list (anyone can do this).
   */
  static recompute(contributors, round) {
    let xorAccum = "0".repeat(64);

    // Sort contributors by clawId for deterministic order
    const sorted = [...contributors].sort((a, b) => a.clawId.localeCompare(b.clawId));

    for (const c of sorted) {
      if (c.hash && c.hash.length >= 12) {
        // Expand short hash to 64 chars for XOR
        const fullHash = c.hash.padEnd(64, "0");
        xorAccum = xorHex(xorAccum, fullHash);
      }
    }

    const beaconHash = sha256(`beacon:${round}:${xorAccum}`);
    const beaconNumber = BigInt("0x" + beaconHash.substring(0, 16)).toString();
    const feel = Number(BigInt("0x" + beaconHash.substring(0, 8)) % 101n);
    const era = feel <= 30 ? "Chaos" : feel <= 70 ? "Transition" : "Eternal";

    return { xorAccum, beaconHash, beaconNumber, era };
  }

  toJSON() {
    return {
      round: this.round,
      timestamp: this.timestamp,
      duration: this.duration,
      contributors: this.contributors,
      contributorCount: this.contributorCount,
      xorAccum: this.xorAccum,
      beaconHash: this.beaconHash,
      beaconNumber: this.beaconNumber,
      era: this.era,
      signature: this.signature,
      publicKey: this.publicKey,
    };
  }

  static fromJSON(data) {
    return new BeaconRound(data);
  }
}

// ── BeaconManager: Round lifecycle + persistence ──

class BeaconManager {
  constructor({
    dataDir = path.join(process.env.HOME || "/tmp", ".clawfeel"),
    roundDuration = 10_000, // 10 seconds
    signKey = null,         // Ed25519 private key hex (DER)
    signPub = null,         // Ed25519 public key hex (DER)
    maxHistory = 1000,      // keep last N rounds in memory
  } = {}) {
    this.dataDir = dataDir;
    this.beaconFile = path.join(dataDir, "beacons.jsonl");
    this.roundDuration = roundDuration;
    this.signKey = signKey;
    this.signPub = signPub;
    this.maxHistory = maxHistory;

    this.currentRound = 0;
    this.history = [];       // recent rounds (newest last)
    this.roundMap = new Map(); // round number → BeaconRound
    this.latest = null;
    this.startTime = Date.now();
  }

  async init() {
    await mkdir(this.dataDir, { recursive: true });
    await this._loadHistory();
    if (this.history.length > 0) {
      const last = this.history[this.history.length - 1];
      this.currentRound = last.round;
      this.latest = last;
    }
    return this;
  }

  /**
   * Seal the current round with the given online nodes.
   * Called by relay every roundDuration ms.
   */
  sealRound(nodes) {
    this.currentRound++;
    const now = new Date().toISOString();

    // Filter: only quality nodes
    const qualified = nodes.filter(n =>
      n.hash &&
      (n.entropyQuality || 0) > 30 &&
      (n.reputation || 50) > 20
    );

    // Build contributor list
    const contributors = qualified.map(n => ({
      clawId: (n.clawId || "").substring(0, 12),
      hash: n.hash || "",
      quality: n.entropyQuality || 0,
      authenticity: n.authenticity || 0,
      weight: Math.round(
        ((n.entropyQuality || 50) / 100) *
        ((n.reputation || 50) / 100) *
        ((n.authenticity || 4) / 7) * 100
      ) / 100,
    }));

    // Compute beacon
    const computed = BeaconRound.recompute(contributors, this.currentRound);

    // Sign with relay's Ed25519 key
    let signature = null;
    if (this.signKey) {
      try {
        const privKeyObj = createPrivateKey({
          key: Buffer.from(this.signKey, "hex"),
          format: "der",
          type: "pkcs8",
        });
        signature = sign(
          null,
          Buffer.from(computed.beaconHash, "hex"),
          privKeyObj,
        ).toString("hex");
      } catch { /* signing optional */ }
    }

    const round = new BeaconRound({
      round: this.currentRound,
      timestamp: now,
      duration: this.roundDuration,
      contributors,
      contributorCount: contributors.length,
      xorAccum: computed.xorAccum,
      beaconHash: computed.beaconHash,
      beaconNumber: computed.beaconNumber,
      era: computed.era,
      signature,
      publicKey: this.signPub || null,
    });

    // Store
    this.latest = round;
    this.history.push(round);
    this.roundMap.set(round.round, round);

    // Evict old rounds
    while (this.history.length > this.maxHistory) {
      const old = this.history.shift();
      this.roundMap.delete(old.round);
    }

    // Persist async (fire and forget)
    this._save(round).catch(() => {});

    return round;
  }

  // ── Query ──

  getLatest() {
    return this.latest;
  }

  getRound(id) {
    return this.roundMap.get(Number(id)) || null;
  }

  getRange(from, to, limit = 100) {
    const results = [];
    const start = Math.max(Number(from) || 1, 1);
    const end = Math.min(Number(to) || this.currentRound, this.currentRound);
    for (let i = end; i >= start && results.length < limit; i--) {
      const r = this.roundMap.get(i);
      if (r) results.push(r);
    }
    return results;
  }

  // ── Persistence ──

  async _save(round) {
    try {
      await appendFile(this.beaconFile, JSON.stringify(round.toJSON()) + "\n", "utf8");
    } catch { /* ignore write errors */ }
  }

  async _loadHistory() {
    try {
      if (!existsSync(this.beaconFile)) return;
      const content = await readFile(this.beaconFile, "utf8");
      const lines = content.trim().split("\n").filter(Boolean);

      // Load last maxHistory rounds
      const start = Math.max(0, lines.length - this.maxHistory);
      for (let i = start; i < lines.length; i++) {
        try {
          const round = BeaconRound.fromJSON(JSON.parse(lines[i]));
          this.history.push(round);
          this.roundMap.set(round.round, round);
        } catch { /* skip malformed lines */ }
      }
    } catch { /* file doesn't exist yet */ }
  }
}

export { BeaconRound, BeaconManager };
export default BeaconManager;
