// ═══════════════════════════════════════════════════════════════════
//  ClawToken — Incentive system for ClawFeel network contributions
//  Pure Node.js (>=22), zero dependencies.
//
//  Nodes earn ClawTokens for contributing entropy to the network.
//  Full nodes earn more than light nodes. Rewards are proportional
//  to entropy quality, uptime, and node type.
// ═══════════════════════════════════════════════════════════════════

import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import os from "node:os";

// ── Token Economics ──
const REWARD_PER_READING = {
  full: 10,       // Full node: 10 tokens per reading
  light: 3,       // Light node: 3 tokens per reading
  browser: 1,     // Browser node: 1 token per reading
};

const BONUS_MULTIPLIERS = {
  highQuality: 1.5,    // entropyQuality >= 80 → 1.5x
  fullAuth: 1.3,       // authenticity 7/7 → 1.3x
  longUptime: 1.2,     // online > 24h straight → 1.2x
  beaconContrib: 2.0,  // contributed to a sealed beacon round → 2x
};

const REPUTATION_MULTIPLIER_MIN = 0.1;  // reputation 0 → 0.1x
const REPUTATION_MULTIPLIER_MAX = 1.5;  // reputation 100 → 1.5x

// ── Token Ledger ──

export class TokenLedger {
  constructor({ dataDir } = {}) {
    this.dataDir = dataDir || path.join(os.homedir(), ".clawfeel");
    this.ledgerFile = path.join(this.dataDir, "tokens.json");
    this.accounts = new Map(); // clawId → { balance, earned, spent, history[] }
  }

  async init() {
    await mkdir(this.dataDir, { recursive: true });
    try {
      const data = JSON.parse(await readFile(this.ledgerFile, "utf8"));
      for (const [id, acct] of Object.entries(data.accounts || {})) {
        this.accounts.set(id, acct);
      }
    } catch {
      // Fresh ledger
    }
  }

  async save() {
    const data = {
      version: 1,
      savedAt: new Date().toISOString(),
      totalAccounts: this.accounts.size,
      accounts: Object.fromEntries(this.accounts),
    };
    await writeFile(this.ledgerFile, JSON.stringify(data, null, 2), "utf8");
  }

  // ── Get or create account ──
  _getAccount(clawId) {
    if (!this.accounts.has(clawId)) {
      this.accounts.set(clawId, {
        balance: 0,
        totalEarned: 0,
        totalSpent: 0,
        lastReward: null,
        rewardCount: 0,
        history: [],
      });
    }
    return this.accounts.get(clawId);
  }

  // ── Calculate reward for a reading ──
  calculateReward({ nodeType = "light", entropyQuality = 50, authenticity = 4,
                     reputation = 50, uptimeHours = 0, beaconContrib = false }) {
    // Base reward by node type
    let base = REWARD_PER_READING[nodeType] || REWARD_PER_READING.light;

    // Quality bonus
    let multiplier = 1.0;
    if (entropyQuality >= 80) multiplier *= BONUS_MULTIPLIERS.highQuality;
    if (authenticity >= 7) multiplier *= BONUS_MULTIPLIERS.fullAuth;
    if (uptimeHours >= 24) multiplier *= BONUS_MULTIPLIERS.longUptime;
    if (beaconContrib) multiplier *= BONUS_MULTIPLIERS.beaconContrib;

    // Reputation multiplier (linear interpolation)
    const repFactor = REPUTATION_MULTIPLIER_MIN +
      (reputation / 100) * (REPUTATION_MULTIPLIER_MAX - REPUTATION_MULTIPLIER_MIN);
    multiplier *= repFactor;

    return Math.round(base * multiplier * 100) / 100; // 2 decimal places
  }

  // ── Award tokens for a contribution ──
  reward(clawId, { nodeType, entropyQuality, authenticity, reputation,
                    uptimeHours, beaconContrib, feel, hash }) {
    const amount = this.calculateReward({
      nodeType, entropyQuality, authenticity, reputation, uptimeHours, beaconContrib,
    });

    const acct = this._getAccount(clawId);
    acct.balance += amount;
    acct.totalEarned += amount;
    acct.rewardCount++;
    acct.lastReward = new Date().toISOString();

    // Keep last 100 history entries
    acct.history.push({
      amount,
      nodeType,
      quality: entropyQuality,
      auth: authenticity,
      reputation,
      beacon: beaconContrib,
      feel,
      hash: hash?.substring(0, 16),
      at: acct.lastReward,
    });
    if (acct.history.length > 100) acct.history.shift();

    return { amount, balance: acct.balance };
  }

  // ── Get account balance ──
  getBalance(clawId) {
    const acct = this.accounts.get(clawId);
    return acct ? acct.balance : 0;
  }

  // ── Get account details ──
  getAccount(clawId) {
    return this.accounts.get(clawId) || null;
  }

  // ── Get leaderboard ──
  getLeaderboard(limit = 20) {
    return Array.from(this.accounts.entries())
      .map(([clawId, acct]) => ({
        clawId,
        balance: acct.balance,
        totalEarned: acct.totalEarned,
        rewardCount: acct.rewardCount,
        lastReward: acct.lastReward,
      }))
      .sort((a, b) => b.balance - a.balance)
      .slice(0, limit);
  }

  // ── Network stats ──
  getStats() {
    let totalSupply = 0;
    let totalAccounts = 0;
    for (const acct of this.accounts.values()) {
      totalSupply += acct.balance;
      totalAccounts++;
    }
    return {
      totalSupply: Math.round(totalSupply * 100) / 100,
      totalAccounts,
      leaderboard: this.getLeaderboard(10),
    };
  }

  // ── Spend tokens (future: redeem for API calls, etc.) ──
  spend(clawId, amount, reason = "") {
    const acct = this.accounts.get(clawId);
    if (!acct || acct.balance < amount) {
      return { success: false, error: "Insufficient balance" };
    }
    acct.balance -= amount;
    acct.totalSpent += amount;
    return { success: true, balance: acct.balance };
  }
}

// ── Reward rates documentation ──
export const REWARD_RATES = {
  perReading: REWARD_PER_READING,
  bonuses: BONUS_MULTIPLIERS,
  reputationRange: [REPUTATION_MULTIPLIER_MIN, REPUTATION_MULTIPLIER_MAX],
  description: {
    full: "Full nodes (sensor + relay) earn 10 tokens/reading",
    light: "Light nodes (sensor only) earn 3 tokens/reading",
    browser: "Browser nodes earn 1 token/reading",
    quality: "High entropy quality (≥80) → 1.5x bonus",
    auth: "All 7 sensors authentic → 1.3x bonus",
    uptime: "24h+ continuous uptime → 1.2x bonus",
    beacon: "Contributing to sealed beacon → 2x bonus",
    reputation: "Reputation 0→100 maps to 0.1x→1.5x multiplier",
    maxPerReading: "Maximum: 10 × 1.5 × 1.3 × 1.2 × 2.0 × 1.5 = 70.2 tokens",
  },
};
