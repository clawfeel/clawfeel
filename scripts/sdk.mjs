/**
 * ClawFeel SDK — Decentralized Hardware Entropy
 *
 * Usage:
 *   import { ClawRandom } from 'clawfeel'
 *
 *   // Local mode (uses this machine's hardware sensors)
 *   const claw = await ClawRandom.local()
 *   const entropy = await claw.getEntropy(256)
 *
 *   // Remote mode (fetch from ClawFeel network)
 *   const net = await ClawRandom.remote()
 *   const random = await net.getNetworkRandom()
 */

import { createHash } from "node:crypto";

// ── Local Mode: Hardware Sensor Entropy ──

class LocalProvider {
  #collectSensors;
  #computeFeel;

  constructor(collectSensors, computeFeel) {
    this.#collectSensors = collectSensors;
    this.#computeFeel = computeFeel;
  }

  async read() {
    const sensors = await this.#collectSensors();
    return this.#computeFeel(sensors);
  }
}

// ── Remote Mode: Relay Network Client ──

class RemoteProvider {
  #url;
  #timeout;

  constructor(url, timeout = 10_000) {
    this.#url = url.replace(/\/+$/, "");
    this.#timeout = timeout;
  }

  async fetchNetwork() {
    const res = await fetch(`${this.#url}/api/network`, {
      signal: AbortSignal.timeout(this.#timeout),
    });
    if (!res.ok) throw new Error(`Relay error: ${res.status}`);
    return res.json();
  }

  subscribe(callback) {
    const url = `${this.#url}/api/stream`;
    let controller = new AbortController();

    const connect = async () => {
      try {
        const res = await fetch(url, { signal: controller.signal });
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buf = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          const lines = buf.split("\n");
          buf = lines.pop() || "";
          for (const line of lines) {
            if (line.startsWith("data: ")) {
              try {
                callback(JSON.parse(line.slice(6)));
              } catch { /* skip malformed */ }
            }
          }
        }
      } catch (err) {
        if (err.name !== "AbortError") {
          // Reconnect after 3s
          setTimeout(connect, 3000);
        }
      }
    };

    connect();
    return () => controller.abort(); // unsubscribe function
  }
}

// ── ClawRandom: Main SDK Class ──

class ClawRandom {
  #provider;
  #mode; // "local" | "remote"

  constructor(provider, mode) {
    this.#provider = provider;
    this.#mode = mode;
  }

  /**
   * Create a local ClawRandom instance (hardware sensors on this machine).
   * @returns {Promise<ClawRandom>}
   */
  static async local() {
    const { collectSensors, computeFeel } = await import("./clawfeel.mjs");
    return new ClawRandom(new LocalProvider(collectSensors, computeFeel), "local");
  }

  /**
   * Create a remote ClawRandom instance (fetch from relay network).
   * @param {string} url - Relay URL (default: ClawFeel public relay)
   * @param {number} timeout - Request timeout in ms (default: 10000)
   * @returns {Promise<ClawRandom>}
   */
  static async remote(url = "https://clawfeel-relay.fly.dev", timeout = 10_000) {
    return new ClawRandom(new RemoteProvider(url, timeout), "remote");
  }

  // ── Core Methods ──

  /**
   * Get a Feel reading (0-100 score + all metadata).
   * @returns {Promise<Object>} { feel, era, hash, entropy, random, randomBytes, ... }
   */
  async getFeel() {
    if (this.#mode === "local") {
      return this.#provider.read();
    }
    const net = await this.#provider.fetchNetwork();
    return {
      feel: net.networkRandom,
      era: net.networkRandom <= 30 ? "Chaos" : net.networkRandom <= 70 ? "Transition" : "Eternal",
      hash: net.consensusHash,
      entropy: net.consensusHash,
      nodes: net.stats?.online || 0,
      timestamp: net.timestamp,
    };
  }

  /**
   * Get cryptographic-grade entropy as hex string.
   * @param {number} bits - Number of bits (default: 256, max: 8192)
   * @returns {Promise<string>} Hex string
   */
  async getEntropy(bits = 256) {
    if (bits < 1 || bits > 8192) throw new RangeError("bits must be 1-8192");
    const needed = Math.ceil(bits / 256);
    const hashes = [];

    for (let i = 0; i < needed; i++) {
      if (this.#mode === "local") {
        const result = await this.#provider.read();
        hashes.push(result.entropy || result.hash);
      } else {
        const net = await this.#provider.fetchNetwork();
        // Mix with timestamp to ensure each call is unique
        const mixed = createHash("sha256")
          .update(net.consensusHash + ":" + Date.now() + ":" + i)
          .digest("hex");
        hashes.push(mixed);
      }
    }

    const combined = hashes.join("");
    const hexChars = Math.ceil(bits / 4);
    return combined.substring(0, hexChars);
  }

  /**
   * Get a random integer in [min, max] (inclusive).
   * @param {number} min
   * @param {number} max
   * @returns {Promise<number>}
   */
  async range(min, max) {
    if (min >= max) throw new RangeError("min must be less than max");
    const entropy = await this.getEntropy(64);
    const n = BigInt("0x" + entropy);
    const range = BigInt(max - min + 1);
    return min + Number(n % range);
  }

  /**
   * Get n random bytes as a Buffer.
   * @param {number} n - Number of bytes (max: 1024)
   * @returns {Promise<Buffer>}
   */
  async randomBytes(n) {
    if (n < 1 || n > 1024) throw new RangeError("n must be 1-1024");
    const hex = await this.getEntropy(n * 8);
    return Buffer.from(hex, "hex");
  }

  /**
   * Get a random float in [0, 1) like Math.random().
   * @returns {Promise<number>}
   */
  async randomFloat() {
    const hex = await this.getEntropy(52); // 52 bits for double precision
    const n = Number(BigInt("0x" + hex.substring(0, 13)));
    return n / (2 ** 52);
  }

  // ── Network Methods (remote mode) ──

  /**
   * Get the network aggregated random number.
   * @returns {Promise<Object>} { networkRandom, consensusHash, online, timestamp }
   */
  async getNetworkRandom() {
    if (this.#mode !== "remote") {
      throw new Error("getNetworkRandom() requires remote mode: ClawRandom.remote()");
    }
    const net = await this.#provider.fetchNetwork();
    return {
      networkRandom: net.networkRandom,
      consensusHash: net.consensusHash,
      online: net.stats?.online || 0,
      timestamp: net.timestamp,
    };
  }

  /**
   * Get list of online nodes.
   * @returns {Promise<Array>}
   */
  async getNodes() {
    if (this.#mode !== "remote") {
      throw new Error("getNodes() requires remote mode: ClawRandom.remote()");
    }
    const net = await this.#provider.fetchNetwork();
    return net.nodes || [];
  }

  /**
   * Subscribe to real-time network updates (SSE).
   * @param {Function} callback - Called with network state on each update
   * @returns {Function} Unsubscribe function
   */
  subscribe(callback) {
    if (this.#mode !== "remote") {
      throw new Error("subscribe() requires remote mode: ClawRandom.remote()");
    }
    return this.#provider.subscribe(callback);
  }

  /**
   * Get current mode.
   * @returns {string} "local" or "remote"
   */
  get mode() { return this.#mode; }
}

export { ClawRandom };
export default ClawRandom;
