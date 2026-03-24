/**
 * connection.mjs — Unified connection manager
 *
 * Abstracts over multiple transports (TCP, UDP, WebRTC, HTTP relay)
 * with automatic fallback and quality scoring.
 *
 * Priority: direct-tcp → direct-udp → hole-punch → relay-http
 */

import { randomBytes } from "node:crypto";

const TRANSPORT_PRIORITY = ["direct-tcp", "direct-udp", "hole-punch", "relay-http"];
const SCORE_DECAY = 0.95; // Exponential moving average decay

export class ConnectionManager {
  /**
   * @param {Object} opts
   * @param {Object} opts.dht - KademliaNode instance
   * @param {string} opts.relayUrl - Relay HTTP URL for fallback
   */
  constructor({ dht, relayUrl }) {
    this.dht = dht;
    this.relayUrl = relayUrl;

    // Connection quality scores per peer per transport
    // Map<dhtId, Map<transport, { success, fail, avgLatency }>>
    this._scores = new Map();
  }

  /**
   * Send a message to a contact using the best available transport.
   * Tries transports in priority order, returns first successful response.
   */
  async send(contact, message) {
    const transports = this._rankTransports(contact);
    let lastError = null;

    for (const transport of transports) {
      try {
        const t0 = Date.now();
        const result = await this._sendVia(transport, contact, message);
        this._recordSuccess(contact.dhtId, transport, Date.now() - t0);
        return result;
      } catch (err) {
        this._recordFailure(contact.dhtId, transport);
        lastError = err;
      }
    }

    throw lastError || new Error("All transports failed");
  }

  /**
   * Send via a specific transport.
   */
  async _sendVia(transport, contact, message) {
    switch (transport) {
      case "direct-tcp":
        return this.dht.sendRpc(contact, message);

      case "direct-udp":
        return this.dht.sendRpcUdp(contact, message);

      case "hole-punch": {
        // Try UDP to known public address (after prior hole-punch)
        if (contact.publicIP && contact.publicPort) {
          return this.dht.sendRpcUdp({
            ...contact,
            host: contact.publicIP,
            udpPort: contact.publicPort,
          }, message);
        }
        throw new Error("No public address for hole-punch");
      }

      case "relay-http": {
        if (!this.relayUrl) throw new Error("No relay URL");
        const url = this.relayUrl.replace(/\/$/, "") + "/api/dht/forward";
        const res = await fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target: contact, message }),
          signal: AbortSignal.timeout(10000),
        });
        return res.json();
      }

      default:
        throw new Error(`Unknown transport: ${transport}`);
    }
  }

  /**
   * Rank transports for a given contact based on:
   * 1. Availability (does the contact support this transport?)
   * 2. Historical success rate and latency
   */
  _rankTransports(contact) {
    const available = [];

    // TCP: always available if we have host:port
    if (contact.host && contact.port) {
      available.push("direct-tcp");
    }

    // UDP: available if contact has udpPort and our DHT has UDP socket
    if (contact.udpPort && this.dht._udpSocket) {
      available.push("direct-udp");
    }

    // Hole-punch: available if contact has public address and is behind cone NAT
    if (contact.publicIP && contact.natType !== "symmetric") {
      available.push("hole-punch");
    }

    // Relay HTTP: always available as last resort
    if (this.relayUrl) {
      available.push("relay-http");
    }

    // Sort by historical score (success rate × inverse latency)
    const scores = this._scores.get(contact.dhtId);
    if (scores) {
      available.sort((a, b) => {
        const sa = scores.get(a);
        const sb = scores.get(b);
        if (!sa && !sb) return 0;
        if (!sa) return 1;
        if (!sb) return -1;
        const scoreA = (sa.success / Math.max(1, sa.success + sa.fail)) * (1000 / Math.max(1, sa.avgLatency));
        const scoreB = (sb.success / Math.max(1, sb.success + sb.fail)) * (1000 / Math.max(1, sb.avgLatency));
        return scoreB - scoreA;
      });
    }

    return available;
  }

  _recordSuccess(dhtId, transport, latencyMs) {
    if (!this._scores.has(dhtId)) this._scores.set(dhtId, new Map());
    const scores = this._scores.get(dhtId);
    if (!scores.has(transport)) scores.set(transport, { success: 0, fail: 0, avgLatency: 500 });
    const s = scores.get(transport);
    s.success++;
    s.avgLatency = s.avgLatency * SCORE_DECAY + latencyMs * (1 - SCORE_DECAY);
  }

  _recordFailure(dhtId, transport) {
    if (!this._scores.has(dhtId)) this._scores.set(dhtId, new Map());
    const scores = this._scores.get(dhtId);
    if (!scores.has(transport)) scores.set(transport, { success: 0, fail: 0, avgLatency: 5000 });
    scores.get(transport).fail++;
  }

  /**
   * Get connection quality info for a peer.
   */
  getQuality(dhtId) {
    const scores = this._scores.get(dhtId);
    if (!scores) return { bestTransport: "unknown", latency: 0, successRate: 0 };

    let best = null;
    let bestScore = -1;
    for (const [transport, s] of scores) {
      const rate = s.success / Math.max(1, s.success + s.fail);
      const score = rate * (1000 / Math.max(1, s.avgLatency));
      if (score > bestScore) {
        bestScore = score;
        best = { transport, latency: Math.round(s.avgLatency), successRate: Math.round(rate * 100) };
      }
    }

    return best || { bestTransport: "unknown", latency: 0, successRate: 0 };
  }

  /**
   * Get overall connection stats.
   */
  getStats() {
    const peerCount = this._scores.size;
    const transports = {};
    for (const [, scores] of this._scores) {
      for (const [t, s] of scores) {
        if (!transports[t]) transports[t] = { success: 0, fail: 0 };
        transports[t].success += s.success;
        transports[t].fail += s.fail;
      }
    }
    return { peerCount, transports };
  }
}
