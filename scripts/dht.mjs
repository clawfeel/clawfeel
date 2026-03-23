// ═══════════════════════════════════════════════════════════════════
//  ClawFeel DHT — Kademlia-style Distributed Hash Table
//  Pure Node.js (>=22), zero dependencies.
//
//  Provides peer discovery for the ClawFeel P2P network.
//  Uses TCP with length-prefix framing for RPCs.
//  160-bit ID space, 160 k-buckets, k=20.
// ═══════════════════════════════════════════════════════════════════

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, createConnection } from "node:net";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";

const K = 20;               // bucket size
const ALPHA = 3;             // concurrency for iterative lookups
const ID_BITS = 160;         // SHA-1 produces 160 bits
const RPC_TIMEOUT = 5000;    // 5s timeout for RPCs
const REFRESH_INTERVAL = 60_000; // refresh stale buckets every 60s
const DEFAULT_PORT = 31416;
const DEFAULT_BOOTSTRAP = ["clawfeel-relay.fly.dev:31416"];
const MAX_STORE_ENTRIES = 10_000;  // max key-value pairs
const MAX_VALUE_SIZE = 65536;      // 64KB max per value
const NETWORK_KEY = "clawfeel-dht-v1"; // shared network key for HMAC
const MAX_RPC_PER_IP = 60;  // max RPCs per IP per minute
const RPC_WINDOW_MS = 60_000;

// ── Message authentication ──────────────────────────────────────

function signMessage(msg) {
  const payload = JSON.stringify(msg);
  const hmac = createHmac("sha256", NETWORK_KEY).update(payload).digest("hex").substring(0, 16);
  return { ...msg, _hmac: hmac, _ts: Date.now() };
}

function verifyMessage(msg) {
  if (!msg._hmac || !msg._ts) return false;
  // Reject messages older than 30 seconds (replay defense)
  if (Math.abs(Date.now() - msg._ts) > 30_000) return false;
  const { _hmac, ...rest } = msg;
  const expected = createHmac("sha256", NETWORK_KEY).update(JSON.stringify(rest)).digest("hex").substring(0, 16);
  try {
    return timingSafeEqual(Buffer.from(_hmac, "hex"), Buffer.from(expected, "hex"));
  } catch { return false; }
}

// ── Rate limiter ────────────────────────────────────────────────

class RateLimiter {
  constructor(maxPerWindow = MAX_RPC_PER_IP, windowMs = RPC_WINDOW_MS) {
    this.max = maxPerWindow;
    this.windowMs = windowMs;
    this.counts = new Map(); // ip → { count, resetAt }
  }
  allow(ip) {
    const now = Date.now();
    let entry = this.counts.get(ip);
    if (!entry || now > entry.resetAt) {
      entry = { count: 0, resetAt: now + this.windowMs };
      this.counts.set(ip, entry);
    }
    entry.count++;
    return entry.count <= this.max;
  }
  cleanup() {
    const now = Date.now();
    for (const [ip, entry] of this.counts) {
      if (now > entry.resetAt) this.counts.delete(ip);
    }
  }
}

// ── ID utilities ──────────────────────────────────────────────────

export function makeDhtId(clawId) {
  return createHash("sha1").update("clawfeel-dht:" + clawId).digest("hex");
}

function xorDistance(a, b) {
  // Returns BigInt XOR distance between two hex ID strings
  const aBig = BigInt("0x" + a);
  const bBig = BigInt("0x" + b);
  return aBig ^ bBig;
}

function bucketIndex(ownId, otherId) {
  const dist = xorDistance(ownId, otherId);
  if (dist === 0n) return 0;
  // Find position of highest set bit (0-indexed from LSB)
  return ID_BITS - 1 - dist.toString(2).length + 1;
  // Simplified: floor(log2(distance))
}

function randomId() {
  return randomBytes(20).toString("hex"); // 160-bit random ID
}

// ── TCP framing ───────────────────────────────────────────────────

function frameSend(socket, obj) {
  const json = JSON.stringify(obj);
  const jsonBuf = Buffer.from(json, "utf8");
  const header = Buffer.alloc(4);
  header.writeUInt32BE(jsonBuf.length, 0);
  socket.write(Buffer.concat([header, jsonBuf]));
}

function frameReceive(socket, timeout = RPC_TIMEOUT) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("RPC timeout"));
    }, timeout);

    socket.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length >= 4) {
        const len = buf.readUInt32BE(0);
        if (buf.length >= 4 + len) {
          clearTimeout(timer);
          try {
            resolve(JSON.parse(buf.subarray(4, 4 + len).toString("utf8")));
          } catch (e) {
            reject(new Error("Invalid JSON in frame"));
          }
        }
      }
    });

    socket.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });

    socket.on("close", () => {
      clearTimeout(timer);
      reject(new Error("Connection closed"));
    });
  });
}

// ── Kademlia Node ─────────────────────────────────────────────────

export class KademliaNode {
  constructor({ clawId, host = "0.0.0.0", port = DEFAULT_PORT, bootstrapNodes, dataDir, lightMode = false }) {
    this.clawId = clawId;
    this.dhtId = makeDhtId(clawId);
    this.host = host;
    this.port = port;
    this.bootstrapNodes = bootstrapNodes || DEFAULT_BOOTSTRAP;
    this.dataDir = dataDir;
    this.routingFile = path.join(dataDir, "routing.json");
    this.lightMode = lightMode;
    this.k = lightMode ? 5 : K; // smaller buckets for light nodes

    // 160 k-buckets, each holding up to k contacts
    this.buckets = Array.from({ length: ID_BITS }, () => []);

    // Storage for DHT key-value pairs
    this.store = new Map();

    // TCP server
    this._server = null;

    // External RPC handler (for gossip messages)
    this._externalHandler = null;

    // Refresh timer
    this._refreshTimer = null;

    // Stats
    this.stats = { rpcSent: 0, rpcReceived: 0, peers: 0 };
  }

  // ── Contact object ──
  _makeContact() {
    return {
      dhtId: this.dhtId,
      clawId: this.clawId,
      host: this.host,
      port: this.port,
    };
  }

  // ── Routing table operations ──

  updateContact(contact) {
    if (contact.dhtId === this.dhtId) return; // don't add self

    const idx = bucketIndex(this.dhtId, contact.dhtId);
    const bucket = this.buckets[idx];

    // Check if contact already exists
    const existing = bucket.findIndex(c => c.dhtId === contact.dhtId);
    if (existing !== -1) {
      // Move to tail (most recently seen)
      bucket.splice(existing, 1);
      bucket.push({ ...contact, lastSeen: Date.now() });
      return;
    }

    // Add new contact
    if (bucket.length < this.k) {
      bucket.push({ ...contact, lastSeen: Date.now() });
    } else {
      // Bucket full — replace oldest if it's unresponsive
      // For simplicity, just replace the oldest (head)
      // A full Kademlia would ping the oldest first
      bucket.shift();
      bucket.push({ ...contact, lastSeen: Date.now() });
    }

    this._updatePeerCount();
  }

  findClosest(targetId, count = K) {
    const all = [];
    for (const bucket of this.buckets) {
      for (const contact of bucket) {
        all.push({ contact, dist: xorDistance(targetId, contact.dhtId) });
      }
    }
    all.sort((a, b) => (a.dist < b.dist ? -1 : a.dist > b.dist ? 1 : 0));
    return all.slice(0, count).map(e => e.contact);
  }

  getAllContacts() {
    const all = [];
    for (const bucket of this.buckets) {
      for (const contact of bucket) {
        all.push(contact);
      }
    }
    return all;
  }

  getRandomContacts(count) {
    const all = this.getAllContacts();
    // Fisher-Yates shuffle
    for (let i = all.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [all[i], all[j]] = [all[j], all[i]];
    }
    return all.slice(0, count);
  }

  _updatePeerCount() {
    let count = 0;
    for (const bucket of this.buckets) count += bucket.length;
    this.stats.peers = count;
  }

  // ── TCP server ──

  async _startServer() {
    return new Promise((resolve, reject) => {
      this._server = createServer((socket) => {
        this._handleConnection(socket);
      });

      this._server.on("error", (err) => {
        if (err.code === "EADDRINUSE") {
          // Port in use, try next
          this.port++;
          this._server.listen(this.port, this.host, () => resolve());
        } else {
          reject(err);
        }
      });

      this._server.listen(this.port, this.host, () => resolve());
    });
  }

  async _handleConnection(socket) {
    try {
      // Rate limit by IP
      const remoteIP = socket.remoteAddress || "unknown";
      if (!this._rateLimiter) this._rateLimiter = new RateLimiter();
      if (!this._rateLimiter.allow(remoteIP)) {
        socket.destroy();
        return;
      }

      const msg = await frameReceive(socket);
      this.stats.rpcReceived++;

      // Verify HMAC authentication (accept unsigned for backward compat, log warning)
      if (msg._hmac && !verifyMessage(msg)) {
        socket.destroy();
        return; // Invalid HMAC — drop silently
      }

      // Update routing table with sender
      if (msg.from) {
        this.updateContact(msg.from);
      }

      let response;

      switch (msg.type) {
        case "PING":
          response = { id: msg.id, type: "PONG", from: this._makeContact() };
          break;

        case "FIND_NODE":
          response = {
            id: msg.id,
            type: "NODES",
            from: this._makeContact(),
            nodes: this.findClosest(msg.target, K),
          };
          break;

        case "FIND_VALUE":
          if (this.store.has(msg.key)) {
            response = {
              id: msg.id,
              type: "VALUE",
              from: this._makeContact(),
              value: this.store.get(msg.key),
            };
          } else {
            response = {
              id: msg.id,
              type: "NODES",
              from: this._makeContact(),
              nodes: this.findClosest(msg.target || makeDhtId(msg.key), K),
            };
          }
          break;

        case "STORE": {
          const valStr = JSON.stringify(msg.value || "");
          const keyValid = typeof msg.key === "string" && /^[0-9a-f]+$/i.test(msg.key);
          if (!keyValid || valStr.length > MAX_VALUE_SIZE) {
            response = { id: msg.id, type: "ERROR", error: "Invalid key or value too large" };
          } else {
            // Evict oldest if at capacity
            if (this.store.size >= MAX_STORE_ENTRIES && !this.store.has(msg.key)) {
              const oldest = this.store.keys().next().value;
              this.store.delete(oldest);
            }
            this.store.set(msg.key, msg.value);
            response = { id: msg.id, type: "STORED", from: this._makeContact() };
          }
          break;
        }

        default:
          // Pass to external handler (gossip messages)
          if (this._externalHandler) {
            response = await this._externalHandler(msg, socket);
          }
          if (!response) {
            response = { id: msg.id, type: "ERROR", error: "Unknown RPC type" };
          }
          break;
      }

      frameSend(socket, signMessage(response));
    } catch {
      // Connection error, ignore
    } finally {
      socket.destroy();
    }
  }

  // ── RPC client ──

  async sendRpc(contact, message) {
    return new Promise((resolve, reject) => {
      const socket = createConnection({
        host: contact.host,
        port: contact.port,
      }, () => {
        frameSend(socket, signMessage({ ...message, from: this._makeContact() }));
        this.stats.rpcSent++;
      });

      socket.on("error", reject);

      frameReceive(socket).then((response) => {
        socket.destroy();
        if (response.from) {
          this.updateContact(response.from);
        }
        resolve(response);
      }).catch(reject);
    });
  }

  async ping(contact) {
    try {
      const res = await this.sendRpc(contact, {
        id: randomBytes(4).toString("hex"),
        type: "PING",
      });
      return res.type === "PONG";
    } catch {
      return false;
    }
  }

  async findNode(contact, targetId) {
    try {
      const res = await this.sendRpc(contact, {
        id: randomBytes(4).toString("hex"),
        type: "FIND_NODE",
        target: targetId,
      });
      return res.nodes || [];
    } catch {
      return [];
    }
  }

  // ── Iterative lookup ──

  async lookup(targetId) {
    const closest = this.findClosest(targetId, ALPHA);
    if (closest.length === 0) return [];

    const queried = new Set();
    const found = new Map(); // dhtId → contact

    // Seed with local closest
    for (const c of closest) {
      found.set(c.dhtId, c);
    }

    for (let round = 0; round < 5; round++) {
      // Pick ALPHA closest not yet queried
      const sorted = [...found.values()]
        .filter(c => !queried.has(c.dhtId))
        .sort((a, b) => {
          const da = xorDistance(targetId, a.dhtId);
          const db = xorDistance(targetId, b.dhtId);
          return da < db ? -1 : da > db ? 1 : 0;
        })
        .slice(0, ALPHA);

      if (sorted.length === 0) break;

      const results = await Promise.allSettled(
        sorted.map(async (contact) => {
          queried.add(contact.dhtId);
          return this.findNode(contact, targetId);
        })
      );

      let foundNew = false;
      for (const result of results) {
        if (result.status === "fulfilled") {
          for (const node of result.value) {
            if (!found.has(node.dhtId) && node.dhtId !== this.dhtId) {
              found.set(node.dhtId, node);
              this.updateContact(node);
              foundNew = true;
            }
          }
        }
      }

      if (!foundNew) break; // converged
    }

    // Return K closest
    return [...found.values()]
      .sort((a, b) => {
        const da = xorDistance(targetId, a.dhtId);
        const db = xorDistance(targetId, b.dhtId);
        return da < db ? -1 : da > db ? 1 : 0;
      })
      .slice(0, K);
  }

  // ── Bootstrap ──

  async bootstrap() {
    // Load saved routing table
    await this.loadRoutingTable();

    // Contact bootstrap nodes
    for (const addr of this.bootstrapNodes) {
      const [host, portStr] = addr.split(":");
      const port = parseInt(portStr || String(DEFAULT_PORT), 10);
      const contact = {
        dhtId: makeDhtId("bootstrap-" + addr),
        clawId: "bootstrap",
        host,
        port,
      };

      try {
        const nodes = await this.findNode(contact, this.dhtId);
        for (const n of nodes) {
          this.updateContact(n);
        }
      } catch {
        // Bootstrap node unreachable, continue
      }
    }

    // Iterative lookup for self to populate routing table
    if (this.stats.peers > 0) {
      await this.lookup(this.dhtId);
    }
  }

  // ── Persistence ──

  async saveRoutingTable() {
    const contacts = this.getAllContacts();
    const data = {
      version: 1,
      savedAt: new Date().toISOString(),
      ownId: this.dhtId,
      contacts,
    };
    try {
      await mkdir(this.dataDir, { recursive: true });
      await writeFile(this.routingFile, JSON.stringify(data, null, 2), "utf8");
    } catch { /* ignore save errors */ }
  }

  async loadRoutingTable() {
    try {
      const raw = await readFile(this.routingFile, "utf8");
      const data = JSON.parse(raw);
      if (data.contacts) {
        for (const contact of data.contacts) {
          if (contact.dhtId && contact.host && contact.port) {
            this.updateContact(contact);
          }
        }
      }
    } catch { /* first run, no saved table */ }
  }

  // ── Refresh ──

  async refresh() {
    // For each bucket that hasn't been updated recently,
    // perform a lookup for a random ID in that bucket's range
    const now = Date.now();
    for (let i = 0; i < ID_BITS; i++) {
      const bucket = this.buckets[i];
      if (bucket.length === 0) continue;

      const oldest = bucket[0];
      if (oldest.lastSeen && now - oldest.lastSeen > REFRESH_INTERVAL * 2) {
        // Refresh this bucket with a random lookup
        const rid = randomId();
        await this.lookup(rid).catch(() => {});
        break; // one refresh per cycle
      }
    }

    await this.saveRoutingTable();
  }

  // ── Register external handler (for gossip) ──

  onMessage(handler) {
    this._externalHandler = handler;
  }

  // ── Lifecycle ──

  async start() {
    await this._startServer();
    await this.bootstrap();

    this._refreshTimer = setInterval(() => {
      this.refresh().catch(() => {});
      if (this._rateLimiter) this._rateLimiter.cleanup();
    }, REFRESH_INTERVAL);

    return this;
  }

  async stop() {
    if (this._refreshTimer) clearInterval(this._refreshTimer);
    if (this._server) this._server.close();
    await this.saveRoutingTable();
  }
}
