/**
 * ClawFeel Agent — AI Agent Integration Module
 *
 * Provides verifiable random decision-making for AI agents using
 * ClawFeel's decentralized hardware entropy.
 *
 * Usage:
 *   import { ClawAgent } from 'clawfeel/agent'
 *
 *   const agent = new ClawAgent({ mode: 'fast' })
 *   const choice = await agent.decide(['left', 'right', 'straight'])
 *   // → { choice: 'right', index: 1, entropy: '...', proof: {...} }
 *
 * Modes:
 *   - 'fast'       — local hardware sensors, lowest latency
 *   - 'fair'       — commit-reveal via beacon, provably fair
 *   - 'enterprise' — HKDF from beacon seed, millions/sec
 *
 * @module clawfeel/agent
 */

import { ClawRandom } from "./sdk.mjs";
import { createHash } from "node:crypto";

/**
 * AI Agent integration for ClawFeel randomness.
 */
class ClawAgent {
  /** @type {ClawRandom} */
  #claw;
  /** @type {'fast'|'fair'|'enterprise'} */
  #mode;
  /** @type {import('./sdk.mjs').EnterpriseGenerator|null} */
  #enterprise = null;
  /** @type {boolean} */
  #ready = false;

  /**
   * Create a new ClawAgent.
   * @param {Object} [options]
   * @param {'fast'|'fair'|'enterprise'} [options.mode='fast'] - Entropy source mode
   * @param {string} [options.relay='https://api.clawfeel.ai'] - Relay URL for fair/enterprise modes
   */
  constructor({ mode = "fast", relay = "https://api.clawfeel.ai" } = {}) {
    this.#mode = mode;
    this._relay = relay;
  }

  /**
   * Initialize the entropy source. Called automatically on first use.
   * @returns {Promise<void>}
   */
  async init() {
    if (this.#ready) return;
    if (this.#mode === "fast") {
      this.#claw = await ClawRandom.local();
    } else {
      this.#claw = await ClawRandom.remote(this._relay);
      if (this.#mode === "enterprise") {
        this.#enterprise = await this.#claw.enterprise();
      }
    }
    this.#ready = true;
  }

  /** Ensure initialization before use. */
  async #ensure() {
    if (!this.#ready) await this.init();
  }

  /**
   * Build a proof object for the current decision.
   * @returns {Promise<{entropy: string, timestamp: string, mode: string}>}
   */
  async #proof(entropy) {
    return {
      entropy,
      timestamp: new Date().toISOString(),
      mode: this.#mode,
    };
  }

  /**
   * Get a random float in [0, 1) from the configured source.
   * @returns {Promise<number>}
   */
  async #float() {
    if (this.#mode === "enterprise" && this.#enterprise) {
      const hex = this.#enterprise.nextHex(52);
      return Number(BigInt("0x" + hex.substring(0, 13))) / (2 ** 52);
    }
    return this.#claw.randomFloat();
  }

  /**
   * Get entropy hex string from the configured source.
   * @param {number} [bits=256]
   * @returns {Promise<string>}
   */
  async #entropy(bits = 256) {
    if (this.#mode === "enterprise" && this.#enterprise) {
      return this.#enterprise.nextHex(bits);
    }
    return this.#claw.getEntropy(bits);
  }

  // ── Decision Methods ──────────────────────────────────────────

  /**
   * Pick one option randomly from an array.
   * @param {Array} options - Array of options to choose from
   * @returns {Promise<{choice: *, index: number, entropy: string, proof: Object}>}
   */
  async decide(options) {
    if (!Array.isArray(options) || options.length === 0) {
      throw new TypeError("options must be a non-empty array");
    }
    await this.#ensure();
    const ent = await this.#entropy(64);
    const index = Number(BigInt("0x" + ent) % BigInt(options.length));
    return {
      choice: options[index],
      index,
      entropy: ent,
      proof: await this.#proof(ent),
    };
  }

  /**
   * Weighted random selection.
   * @param {Array} options - Array of options
   * @param {number[]} weights - Corresponding weights (must sum > 0)
   * @returns {Promise<{choice: *, index: number, entropy: string, proof: Object}>}
   */
  async weighted(options, weights) {
    if (!Array.isArray(options) || options.length === 0) {
      throw new TypeError("options must be a non-empty array");
    }
    if (options.length !== weights.length) {
      throw new TypeError("options and weights must have the same length");
    }
    const total = weights.reduce((s, w) => s + w, 0);
    if (total <= 0) throw new RangeError("weights must sum to a positive number");

    await this.#ensure();
    const r = (await this.#float()) * total;
    const ent = await this.#entropy(64);
    let cumulative = 0;
    for (let i = 0; i < weights.length; i++) {
      cumulative += weights[i];
      if (r < cumulative) {
        return { choice: options[i], index: i, entropy: ent, proof: await this.#proof(ent) };
      }
    }
    // Fallback to last option (rounding edge case)
    const last = options.length - 1;
    return { choice: options[last], index: last, entropy: ent, proof: await this.#proof(ent) };
  }

  /**
   * Cryptographically random shuffle (Fisher-Yates with ClawFeel entropy).
   * @param {Array} array - Array to shuffle (not mutated)
   * @returns {Promise<Array>} New shuffled array
   */
  async shuffle(array) {
    if (!Array.isArray(array)) throw new TypeError("array must be an array");
    await this.#ensure();
    const result = [...array];
    for (let i = result.length - 1; i > 0; i--) {
      const ent = await this.#entropy(32);
      const j = Number(BigInt("0x" + ent) % BigInt(i + 1));
      [result[i], result[j]] = [result[j], result[i]];
    }
    return result;
  }

  /**
   * Pick n unique items randomly from an array.
   * @param {Array} array - Source array
   * @param {number} n - Number of items to pick
   * @returns {Promise<Array>} Array of n unique items
   */
  async sample(array, n) {
    if (!Array.isArray(array)) throw new TypeError("array must be an array");
    if (n < 0 || n > array.length) {
      throw new RangeError(`n must be 0-${array.length}`);
    }
    const shuffled = await this.shuffle(array);
    return shuffled.slice(0, n);
  }

  /**
   * Return true with probability p.
   * @param {number} p - Probability in [0, 1]
   * @returns {Promise<boolean>}
   */
  async probability(p) {
    if (p < 0 || p > 1) throw new RangeError("p must be between 0 and 1");
    if (p === 0) return false;
    if (p === 1) return true;
    await this.#ensure();
    return (await this.#float()) < p;
  }

  /**
   * Generate a normally distributed random number (Box-Muller transform).
   * @param {number} [mean=0] - Mean of the distribution
   * @param {number} [stddev=1] - Standard deviation
   * @returns {Promise<number>}
   */
  async gaussian(mean = 0, stddev = 1) {
    await this.#ensure();
    const u1 = await this.#float();
    const u2 = await this.#float();
    // Box-Muller transform
    const z = Math.sqrt(-2 * Math.log(u1 || 1e-10)) * Math.cos(2 * Math.PI * u2);
    return mean + z * stddev;
  }

  /**
   * Stop the agent and clean up resources.
   */
  stop() {
    if (this.#enterprise) this.#enterprise.stop();
  }
}

// ── LangChain / OpenAI Tool Definition ──────────────────────────

/**
 * ClawFeel tool definition for LangChain / OpenAI function calling.
 * @type {{name: string, description: string, parameters: Object, execute: Function}}
 */
const clawfeelTool = {
  name: "clawfeel_random",
  description:
    "Generate verifiable random decisions using decentralized hardware entropy. " +
    "Supports: decide (pick one from options), weighted (weighted selection), " +
    "shuffle, sample (pick n), probability (coin flip), gaussian (normal distribution).",
  parameters: {
    type: "object",
    properties: {
      action: {
        type: "string",
        enum: ["decide", "weighted", "shuffle", "sample", "probability", "gaussian"],
        description: "The random action to perform",
      },
      options: {
        type: "array",
        items: { type: "string" },
        description: "Array of options (for decide, weighted, shuffle, sample)",
      },
      weights: {
        type: "array",
        items: { type: "number" },
        description: "Weight for each option (for weighted action)",
      },
      n: {
        type: "number",
        description: "Number of items to pick (for sample action)",
      },
      p: {
        type: "number",
        description: "Probability threshold 0-1 (for probability action)",
      },
      mean: {
        type: "number",
        description: "Mean for gaussian distribution (default: 0)",
      },
      stddev: {
        type: "number",
        description: "Standard deviation for gaussian distribution (default: 1)",
      },
    },
    required: ["action"],
  },
  execute: async (params) => {
    const agent = new ClawAgent({ mode: "fast" });
    try {
      switch (params.action) {
        case "decide":
          return await agent.decide(params.options);
        case "weighted":
          return await agent.weighted(params.options, params.weights);
        case "shuffle":
          return await agent.shuffle(params.options);
        case "sample":
          return await agent.sample(params.options, params.n || 1);
        case "probability":
          return await agent.probability(params.p ?? 0.5);
        case "gaussian":
          return await agent.gaussian(params.mean ?? 0, params.stddev ?? 1);
        default:
          return { error: `Unknown action: ${params.action}` };
      }
    } finally {
      agent.stop();
    }
  },
};

export { ClawAgent, clawfeelTool };
export default ClawAgent;
