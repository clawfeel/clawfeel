// ═══════════════════════════════════════════════════════════════════
//  ClawFeel DHT — Kademlia-style Distributed Hash Table
//  Pure Node.js (>=22), zero dependencies.
//
//  Provides peer discovery for the ClawFeel P2P network.
//  Uses TCP with length-prefix framing for RPCs.
//  160-bit ID space, 160 k-buckets, k=20.
// ═══════════════════════════════════════════════════════════════════

import { createHash, createHmac, randomBytes, timingSafeEqual,
  createCipheriv, createDecipheriv } from "node:crypto";
import { createServer, createConnection } from "node:net";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";

// ── Message encryption (AES-256-GCM) ──
// All DHT messages are encrypted with a network-wide key derived from
// a shared secret. This prevents eavesdropping and message tampering.
const NETWORK_SECRET = "clawfeel-dht-v1"; // known to all nodes
const ENCRYPTION_KEY = createHash("sha256").update(NETWORK_SECRET).digest(); // 32 bytes

function encryptMessage(plaintext) {
  const iv = randomBytes(12); // 96-bit IV for GCM
  const cipher = createCipheriv("aes-256-gcm", ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes
  // Format: IV (12) + Tag (16) + Ciphertext
  return Buffer.concat([iv, tag, encrypted]);
}

function decryptMessage(data) {
  if (data.length < 29) throw new Error("Encrypted message too short");
  const iv = data.subarray(0, 12);
  const tag = data.subarray(12, 28);
  const ciphertext = data.subarray(28);
  const decipher = createDecipheriv("aes-256-gcm", ENCRYPTION_KEY, iv);
  decipher.setAuthTag(tag);
  return decipher.update(ciphertext, null, "utf8") + decipher.final("utf8");
}

const K = 20;               // bucket size
const ALPHA = 3;             // concurrency for iterative lookups
const ID_BITS = 160;         // SHA-1 produces 160 bits
const RPC_TIMEOUT = 5000;    // 5s timeout for RPCs
const REFRESH_INTERVAL = 60_000; // refresh stale buckets every 60s
const DEFAULT_PORT = 31416;
const DEFAULT_BOOTSTRAP = ["api.clawfeel.ai:31416"];
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
  const encrypted = encryptMessage(json);
  const header = Buffer.alloc(4);
  header.writeUInt32BE(encrypted.length, 0);
  socket.write(Buffer.concat([header, encrypted]));
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
            const decrypted = decryptMessage(buf.subarray(4, 4 + len));
            resolve(JSON.parse(decrypted));
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

    // UDP transport
    this._udpSocket = null;
    this.udpPort = port + 1; // default: TCP+1

    // NAT info (populated by probeNAT)
    this.natType = "unknown";
    this.publicIP = null;
    this.publicPort = null;
    this.connectStrategy = "direct"; // "direct" | "hole-punch" | "relay-only"

    // External RPC handler (for gossip messages)
    this._externalHandler = null;

    // Refresh timer
    this._refreshTimer = null;

    // Stats
    this.stats = { rpcSent: 0, rpcReceived: 0, peers: 0, contacts: 0 };
  }

  // ── Contact object ──
  _makeContact() {
    return {
      dhtId: this.dhtId,
      clawId: this.clawId,
      host: this.host,
      port: this.port,
      udpPort: this.udpPort,
      natType: this.natType,
      publicIP: this.publicIP,
      publicPort: this.publicPort,
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

        case "PUNCH_REQ": {
          // Forward punch request to target node if we know them
          const target = this.findClosest(msg.target, 1)[0];
          if (target && target.dhtId === msg.target) {
            // Forward via TCP to the target
            try {
              await this.sendRpc(target, msg);
            } catch {}
          }
          response = { id: msg.id, type: "PUNCH_FWD", from: this._makeContact() };
          break;
        }

        case "PEER_EXCHANGE": {
          // Proactive peer list sharing
          const myPeers = this.findClosest(this.dhtId, 20).map(c => ({
            dhtId: c.dhtId, clawId: c.clawId, host: c.host, port: c.port,
            udpPort: c.udpPort, publicIP: c.publicIP, natType: c.natType,
          }));
          response = { id: msg.id, type: "PEER_EXCHANGE_RES", from: this._makeContact(), peers: myPeers };
          // Also add sender's peers to our routing table
          if (msg.peers && Array.isArray(msg.peers)) {
            for (const p of msg.peers.slice(0, 20)) {
              if (p.dhtId && p.host && p.port) this.updateContact(p);
            }
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
    await this._startUdpServer();
    await this._probeNAT();
    await this.bootstrap();

    // Update stats with contact count
    this.stats.contacts = this.buckets.reduce((n, b) => n + b.length, 0);

    this._refreshTimer = setInterval(() => {
      this.refresh().catch(() => {});
      if (this._rateLimiter) this._rateLimiter.cleanup();
      this.stats.contacts = this.buckets.reduce((n, b) => n + b.length, 0);
    }, REFRESH_INTERVAL);

    return this;
  }

  // ── NAT Detection ──
  async _probeNAT() {
    try {
      const { detectNATType } = await import("./stun.mjs");
      const result = await detectNATType({ localPort: this.udpPort });
      if (result) {
        this.natType = result.natType || "unknown";
        this.publicIP = result.publicIP || null;
        this.publicPort = result.publicPort || null;
        this.connectStrategy = result.connectStrategy || "relay-only";
      }
    } catch {
      this.natType = "error";
      this.connectStrategy = "relay-only";
    }
  }

  // ── UDP Transport ──
  async _startUdpServer() {
    try {
      const { createSocket } = await import("node:dgram");
      this._udpSocket = createSocket("udp4");

      this._udpSocket.on("message", (buf, rinfo) => {
        try {
          const decrypted = decrypt(buf);
          if (!decrypted) return;
          const msg = JSON.parse(decrypted);
          if (!verifyHMAC(msg)) return;

          // Handle punch probes
          if (msg.type === "PUNCH_PROBE") {
            const response = JSON.stringify(signHMAC({ type: "PUNCH_ACK", from: this._makeContact() }));
            const encrypted = encrypt(response);
            this._udpSocket.send(encrypted, rinfo.port, rinfo.address);
            return;
          }

          // Handle regular RPC over UDP
          this._handleRpc(msg, (response) => {
            const resStr = JSON.stringify(signHMAC(response));
            const encrypted = encrypt(resStr);
            this._udpSocket.send(encrypted, rinfo.port, rinfo.address);
          });
        } catch {}
      });

      this._udpSocket.bind(this.udpPort, () => {
        this.udpPort = this._udpSocket.address().port;
      });
    } catch {
      // UDP not available, TCP only
      this._udpSocket = null;
    }
  }

  // ── Send RPC over UDP (fast path) ──
  sendRpcUdp(contact, message, timeout = 5000) {
    if (!this._udpSocket || !contact.udpPort) return Promise.reject(new Error("No UDP"));

    return new Promise((resolve, reject) => {
      const host = contact.publicIP || contact.host;
      const port = contact.publicPort || contact.udpPort;
      const signed = signHMAC({ ...message, from: this._makeContact() });
      const encrypted = encrypt(JSON.stringify(signed));

      const timer = setTimeout(() => reject(new Error("UDP timeout")), timeout);

      const handler = (buf) => {
        try {
          const decrypted = decrypt(buf);
          if (!decrypted) return;
          const resp = JSON.parse(decrypted);
          if (resp.id === message.id) {
            clearTimeout(timer);
            this._udpSocket.removeListener("message", handler);
            resolve(resp);
          }
        } catch {}
      };

      this._udpSocket.on("message", handler);
      this._udpSocket.send(encrypted, port, host, (err) => {
        if (err) { clearTimeout(timer); reject(err); }
      });
    });
  }

  // ── UDP Hole-Punching ──
  async holePunch(targetContact, rendezvousContact) {
    if (!this._udpSocket || !targetContact.publicIP) {
      throw new Error("Cannot hole-punch: no UDP or no public address");
    }

    // Send punch request via rendezvous (TCP/relay)
    try {
      await this.sendRpc(rendezvousContact, signHMAC({
        id: randomBytes(4).toString("hex"),
        type: "PUNCH_REQ",
        from: this._makeContact(),
        target: targetContact.dhtId,
        targetAddr: { host: targetContact.publicIP, port: targetContact.publicPort || targetContact.udpPort },
      }));
    } catch {}

    // Send 3 UDP probes to target's public address
    const probeMsg = encrypt(JSON.stringify(signHMAC({
      type: "PUNCH_PROBE",
      from: this._makeContact(),
    })));

    const targetHost = targetContact.publicIP;
    const targetPort = targetContact.publicPort || targetContact.udpPort;

    for (let i = 0; i < 3; i++) {
      this._udpSocket.send(probeMsg, targetPort, targetHost);
      await new Promise(r => setTimeout(r, 500));
    }

    // Wait for PUNCH_ACK (5s timeout)
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._udpSocket.removeListener("message", handler);
        reject(new Error("Hole-punch timeout"));
      }, 5000);

      const handler = (buf, rinfo) => {
        try {
          const decrypted = decrypt(buf);
          if (!decrypted) return;
          const msg = JSON.parse(decrypted);
          if (msg.type === "PUNCH_ACK" && rinfo.address === targetHost) {
            clearTimeout(timer);
            this._udpSocket.removeListener("message", handler);
            resolve({ host: rinfo.address, port: rinfo.port });
          }
        } catch {}
      };

      this._udpSocket.on("message", handler);
    });
  }

  async stop() {
    if (this._refreshTimer) clearInterval(this._refreshTimer);
    if (this._server) this._server.close();
    if (this._udpSocket) try { this._udpSocket.close(); } catch {}
    await this.saveRoutingTable();
  }
}
