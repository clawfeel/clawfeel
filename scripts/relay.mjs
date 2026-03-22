#!/usr/bin/env node

// ═══════════════════════════════════════════════════════════════════
//  ClawFeel Relay Server — Layer 2.5
//  HTTP relay with Server-Sent Events (SSE) for real-time updates.
//  Bridges real Claw nodes to the web dashboard.
//
//  Zero dependencies — pure Node.js (>=22).
//
//  Usage:
//    node relay.mjs                    # start on port 3415
//    node relay.mjs --port 8080        # custom port
//    node relay.mjs --admin-key KEY    # set admin API key
//
//  API:
//    POST /api/report    — Claw nodes report their Feel
//    GET  /api/network   — Current network state (JSON)
//    GET  /api/stream    — Server-Sent Events (real-time)
//    GET  /              — Health check / status
//
//  Enterprise API (requires API key):
//    GET  /api/v1/random        — single random number
//    GET  /api/v1/random/batch  — batch random numbers
//    GET  /api/v1/random/range  — random integer in range
//    GET  /api/v1/random/verify — verify a beacon round
//    GET  /api/v1/status        — API usage stats
//    GET  /api/v1/audit         — audit log (enterprise only)
// ═══════════════════════════════════════════════════════════════════

import { createServer } from "node:http";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { argv } from "node:process";
import os from "node:os";
import path from "node:path";
import { BeaconManager, BeaconRound } from "./beacon.mjs";
import { ClawZKP } from "./zkp.mjs";
import { readFileSync } from "node:fs";

// Read version from package.json
let PKG_VERSION = "0.7.5";
try {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  PKG_VERSION = pkg.version;
} catch { /* fallback */ }

// ── Args ──
const args = argv.slice(2);
const portIdx = args.indexOf("--port");
const PORT = portIdx !== -1 && args[portIdx + 1] ? parseInt(args[portIdx + 1], 10) : 3415;
const dhtPortIdx = args.indexOf("--dht-port");
const DHT_PORT = dhtPortIdx !== -1 && args[dhtPortIdx + 1] ? parseInt(args[dhtPortIdx + 1], 10) : 31416;
const adminKeyIdx = args.indexOf("--admin-key");
const ADMIN_KEY = adminKeyIdx !== -1 && args[adminKeyIdx + 1] ? args[adminKeyIdx + 1] : null;
const DATA_DIR = path.join(os.homedir(), ".clawfeel");

// ── State ──
const nodes = new Map();       // clawId → nodeState
const sseClients = new Set();  // active SSE response objects
const ipClawCount = new Map(); // ip → Set<clawId> (Sybil tracking)
const txLog = [];              // recent tx reports (max 1000)
const TX_LOG_MAX = 1000;

const NODE_TIMEOUT_MS = 60_000;   // offline after 60s silence
const RATE_LIMIT_MS = 800;        // min interval between reports per node
const SSE_INTERVAL_MS = 2_000;    // push updates every 2s
const MAX_HISTORY = 20;           // readings history per node

// ── Enterprise API: Key Management ──
// {key, tier, rateLimit, requestCount, createdAt, windowStart, windowRequests}
const apiKeys = new Map();

const TIER_LIMITS = {
  free:       100,    // 100 req/hour
  pro:        10_000, // 10000 req/hour
  enterprise: Infinity,
};
const RATE_WINDOW_MS = 3_600_000; // 1 hour sliding window

function generateApiKey() {
  return "cf_" + randomBytes(24).toString("hex"); // cf_ + 48 hex chars
}

function createApiKey(tier = "free") {
  const key = generateApiKey();
  apiKeys.set(key, {
    key,
    tier,
    rateLimit: TIER_LIMITS[tier] || TIER_LIMITS.free,
    requestCount: 0,
    createdAt: Date.now(),
    windowStart: Date.now(),
    windowRequests: 0,
  });
  return key;
}

/**
 * Validate API key from Authorization: Bearer <key> header.
 * Enforces sliding window rate limit.
 * Returns {ok, tier, remaining, resetAt} or {ok: false, error, status}.
 */
function validateApiKey(req) {
  const authHeader = req.headers["authorization"] || "";
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return { ok: false, error: "Missing API key. Use Authorization: Bearer <key>", status: 401 };
  }

  const key = match[1].trim();
  const entry = apiKeys.get(key);
  if (!entry) {
    return { ok: false, error: "Invalid API key", status: 401 };
  }

  const now = Date.now();

  // Slide the window if expired
  if (now - entry.windowStart >= RATE_WINDOW_MS) {
    entry.windowStart = now;
    entry.windowRequests = 0;
  }

  // Check rate limit
  const remaining = entry.rateLimit - entry.windowRequests;
  const resetAt = entry.windowStart + RATE_WINDOW_MS;

  if (remaining <= 0) {
    const retryAfter = Math.ceil((resetAt - now) / 1000);
    return {
      ok: false,
      error: "Rate limit exceeded",
      status: 429,
      retryAfter,
      remaining: 0,
      resetAt,
      tier: entry.tier,
    };
  }

  // Consume one request
  entry.windowRequests++;
  entry.requestCount++;

  return {
    ok: true,
    tier: entry.tier,
    remaining: entry.rateLimit - entry.windowRequests,
    resetAt,
    key,
  };
}

// Set rate limit headers on response
function setRateLimitHeaders(res, auth) {
  if (auth && auth.ok !== false) {
    res.setHeader("X-RateLimit-Remaining", String(auth.remaining));
    res.setHeader("X-RateLimit-Reset", String(Math.ceil(auth.resetAt / 1000)));
  }
}

// ── Enterprise API: Audit Log ──
const auditLog = [];
const AUDIT_LOG_MAX = 500;

function logAudit(apiKeyRaw, endpoint, params, responseHash) {
  const masked = apiKeyRaw
    ? apiKeyRaw.substring(0, 7) + "..." + apiKeyRaw.substring(apiKeyRaw.length - 4)
    : "unknown";
  auditLog.push({
    timestamp: new Date().toISOString(),
    apiKey: masked,
    endpoint,
    params,
    responseHash,
  });
  if (auditLog.length > AUDIT_LOG_MAX) auditLog.splice(0, auditLog.length - AUDIT_LOG_MAX);
}

// Bootstrap admin key if provided via CLI
if (ADMIN_KEY) {
  apiKeys.set(ADMIN_KEY, {
    key: ADMIN_KEY,
    tier: "enterprise",
    rateLimit: TIER_LIMITS.enterprise,
    requestCount: 0,
    createdAt: Date.now(),
    windowStart: Date.now(),
    windowRequests: 0,
  });
}

// ── Hash utilities (same as simulator) ──
function simHash(str) {
  let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
  h1 ^= Math.imul(h2 ^ (h2 >>> 16), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
  h2 ^= Math.imul(h1 ^ (h1 >>> 16), 3266489909);
  const n = 4294967296 * (2097151 & h2) + (h1 >>> 0);
  return n.toString(16).padStart(16, "0");
}

function xorHex(a, b) {
  let out = "";
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    out += (parseInt(a[i], 16) ^ parseInt(b[i], 16)).toString(16);
  }
  return out;
}

function getSubnet(ip) {
  const parts = ip.split(".");
  return parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : ip;
}

// ── Node management ──
function updateNode(clawId, ip, data) {
  const now = Date.now();

  if (!nodes.has(clawId)) {
    nodes.set(clawId, {
      clawId,
      ip,
      alias: data.alias || "unknown",
      publicKey: data.publicKey || null, // Ed25519 public key hex
      firstSeen: now,
      lastSeen: now,
      lastReport: 0,
      reputation: 50,
      alerts: [],
      history: [],
      // Latest Feel data
      feel: data.feel,
      era: data.era || "Transition",
      hash: data.hash || "0000000000000000",
      seq: data.seq || 0,
      prevHash: data.prevHash || "0000000000000000",
      authenticity: data.authenticity ?? 7,
      sensorFlags: data.sensorFlags || "1111111",
      entropyQuality: data.entropyQuality ?? 80,
      entropyDetail: data.entropyDetail || null,
      sensors: data.sensors || {},
      timestamp: data.timestamp || new Date().toISOString(),
      type: data.type || "node", // "node" (hardware) or "browser" (light)
      zkpVerified: null,           // null = no proof, true = valid, false = invalid
    });
  }

  const node = nodes.get(clawId);

  // ── Rate limiting ──
  if (now - node.lastReport < RATE_LIMIT_MS) {
    return { ok: false, reason: "rate_limited" };
  }
  node.lastReport = now;
  node.lastSeen = now;

  // ── Update Feel data ──
  node.feel = data.feel;
  node.era = data.era || "Transition";
  node.hash = data.hash || node.hash;
  node.prevHash = data.prevHash || node.prevHash;
  node.authenticity = data.authenticity ?? node.authenticity;
  node.sensorFlags = data.sensorFlags || node.sensorFlags;
  node.entropyQuality = data.entropyQuality ?? node.entropyQuality;
  node.entropyDetail = data.entropyDetail || node.entropyDetail;
  node.sensors = data.sensors || node.sensors;
  node.timestamp = data.timestamp || new Date().toISOString();
  node.alias = data.alias || node.alias;
  node.type = data.type || node.type || "node";
  if (data.publicKey) node.publicKey = data.publicKey;
  node.ip = ip;

  // Browser nodes have capped reputation (lighter entropy)
  if (node.type === "browser" && node.reputation > 50) {
    node.reputation = 50;
  }

  // ── Sybil detection ──
  if (!ipClawCount.has(ip)) ipClawCount.set(ip, new Set());
  ipClawCount.get(ip).add(clawId);
  if (ipClawCount.get(ip).size > 5) {
    node.reputation = Math.max(0, node.reputation - 10);
    if (!node.alerts.includes("SYBIL_SUSPECT")) {
      node.alerts.push("SYBIL_SUSPECT");
    }
  }

  // ── Sequence check ──
  if (data.seq != null) {
    if (data.seq <= node.seq && node.seq > 0) {
      node.reputation = Math.max(0, node.reputation - 15);
      if (!node.alerts.includes("SEQ_REPLAY")) {
        node.alerts.push("SEQ_REPLAY");
      }
    }
    node.seq = data.seq;
  }

  // ── Replay detection ──
  node.history.push(data.feel);
  if (node.history.length > MAX_HISTORY) node.history.shift();
  if (node.history.length >= 5) {
    const last5 = node.history.slice(-5);
    if (new Set(last5).size === 1) {
      node.reputation = Math.max(0, node.reputation - 20);
      if (!node.alerts.includes("REPLAY_SUSPECT")) {
        node.alerts.push("REPLAY_SUSPECT");
      }
    }
  }

  // ── Quality check ──
  if (data.authenticity != null && data.authenticity < 4) {
    node.reputation = Math.max(0, node.reputation - 3);
  }
  if (data.entropyQuality != null && data.entropyQuality < 30) {
    node.reputation = Math.max(0, node.reputation - 3);
  }

  // ── Reputation recovery ──
  if (node.alerts.length === 0 && node.reputation < 100) {
    node.reputation = Math.min(100, node.reputation + 1);
  }

  return { ok: true };
}

// ── Compute network state ──
let tickCount = 0;

function computeNetworkState() {
  const now = Date.now();
  tickCount++;

  // Clean expired nodes
  for (const [id, node] of nodes) {
    if (now - node.lastSeen > NODE_TIMEOUT_MS) {
      nodes.delete(id);
    }
  }

  const onlineNodes = [...nodes.values()];
  if (onlineNodes.length === 0) {
    return {
      timestamp: new Date().toISOString(),
      tick: tickCount,
      stats: {
        onlineNodes: 0, avgFeel: 0, chaos: 0, transition: 0, eternal: 0,
        avgQuality: 0, avgAuth: 0, suspectCount: 0, tps: 0,
      },
      networkRandom: { number: null, era: null, hash: null },
      nodes: [],
    };
  }

  let chaos = 0, trans = 0, eternal = 0;
  let totalAuth = 0, totalQuality = 0, suspectCount = 0;
  let weightedSum = 0, totalWeight = 0;
  let xorAccum = "0000000000000000";
  let rawXorAccum = "0000000000000000";

  for (const n of onlineNodes) {
    const qualityW = (n.entropyQuality || 0) / 100;
    const reputationW = (n.reputation || 0) / 100;
    const authW = (n.authenticity || 0) / 7;
    const weight = qualityW * reputationW * authW;

    weightedSum += n.feel * weight;
    totalWeight += weight;
    totalAuth += n.authenticity || 0;
    totalQuality += n.entropyQuality || 0;

    if (n.feel <= 30) chaos++;
    else if (n.feel <= 70) trans++;
    else eternal++;

    if (n.reputation < 40) suspectCount++;

    rawXorAccum = xorHex(rawXorAccum, n.hash || "0000000000000000");
    if (weight > 0.1) {
      xorAccum = xorHex(xorAccum, n.hash || "0000000000000000");
    }
  }

  const netHash = simHash("clawfeel:" + xorAccum + ":" + tickCount);
  const netRandom = parseInt(netHash.substring(0, 8), 16) % 101;
  const netEra = netRandom <= 30 ? "Chaos" : netRandom <= 70 ? "Transition" : "Eternal";

  return {
    timestamp: new Date().toISOString(),
    tick: tickCount,
    stats: {
      onlineNodes: onlineNodes.length,
      avgFeel: totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0,
      chaos, transition: trans, eternal,
      avgQuality: Math.round(totalQuality / onlineNodes.length),
      avgAuth: (totalAuth / onlineNodes.length).toFixed(1),
      suspectCount,
    },
    networkRandom: {
      number: netRandom,
      era: netEra,
      hash: netHash.substring(0, 12),
    },
    nodes: onlineNodes.map(n => ({
      clawId: n.clawId,
      alias: n.alias,
      feel: n.feel,
      era: n.era,
      hash: n.hash,
      authenticity: n.authenticity,
      entropyQuality: n.entropyQuality,
      reputation: Math.round(n.reputation),
      seq: n.seq,
      sensorFlags: n.sensorFlags,
      alerts: n.alerts,
      lastSeen: n.lastSeen,
      zkpVerified: n.zkpVerified,
    })),
  };
}

// ── SSE broadcast ──
function broadcastSSE() {
  if (sseClients.size === 0) return;
  const state = computeNetworkState();
  state.beacon = beaconManager.getLatest()?.toJSON() || null;
  const data = `data: ${JSON.stringify(state)}\n\n`;
  for (const res of sseClients) {
    try {
      res.write(data);
    } catch {
      sseClients.delete(res);
    }
  }
}

// ── Beacon ──

const BEACON_INTERVAL_MS = 10_000; // seal a beacon round every 10s
const beaconTicksPerRound = BEACON_INTERVAL_MS / SSE_INTERVAL_MS; // 5 ticks

// Generate relay signing keypair (ephemeral per instance)
const { publicKey: relayPubKey, privateKey: relayPrivKey } = generateKeyPairSync("ed25519");
const relaySignKey = relayPrivKey.export({ format: "der", type: "pkcs8" }).toString("hex");
const relaySignPub = relayPubKey.export({ format: "der", type: "spki" }).toString("hex");

const beaconManager = new BeaconManager({
  dataDir: path.join(os.homedir(), ".clawfeel"),
  roundDuration: BEACON_INTERVAL_MS,
  signKey: relaySignKey,
  signPub: relaySignPub,
});
beaconManager.init().catch(() => {});

setInterval(() => {
  broadcastSSE();

  // Seal beacon round every BEACON_INTERVAL_MS
  if (tickCount > 0 && tickCount % beaconTicksPerRound === 0) {
    const onlineNodes = [];
    for (const [, n] of nodes) {
      if (Date.now() - n.lastSeen < NODE_TIMEOUT_MS) onlineNodes.push(n);
    }
    if (onlineNodes.length > 0) {
      beaconManager.sealRound(onlineNodes);
    }
  }
}, SSE_INTERVAL_MS);

// ── Enterprise API: Entropy derivation helpers ──

/**
 * Derive N bits of entropy from a beacon hash using HKDF-like expansion.
 * Each index produces independent entropy by hashing beacon+index.
 * Returns a Buffer of ceil(bits/8) bytes.
 */
function deriveEntropy(beaconHash, bits, index) {
  const bytesNeeded = Math.ceil(bits / 8);
  const chunks = [];
  let produced = 0;
  let counter = 0;

  while (produced < bytesNeeded) {
    const h = createHash("sha256")
      .update(`derive:${beaconHash}:${index}:${counter}`)
      .digest();
    chunks.push(h);
    produced += h.length;
    counter++;
  }

  return Buffer.concat(chunks).subarray(0, bytesNeeded);
}

/**
 * Format entropy buffer into the requested format.
 */
function formatEntropy(buf, format) {
  switch (format) {
    case "base64":
      return buf.toString("base64");
    case "decimal":
      // Return as BigInt decimal string
      return BigInt("0x" + buf.toString("hex")).toString(10);
    case "bytes":
      return [...buf];
    case "hex":
    default:
      return buf.toString("hex");
  }
}

/**
 * Rejection sampling for uniform integer in [min, max] (inclusive).
 * Uses beacon hash as seed, expands via SHA-256 to avoid bias.
 */
function rejectionSample(beaconHash, min, max) {
  const range = max - min + 1;

  // Find the smallest power of 2 >= range
  let bitsNeeded = 1;
  while ((1 << bitsNeeded) < range && bitsNeeded < 53) bitsNeeded++;
  const mask = (1 << bitsNeeded) - 1;

  // Try up to 128 times (vanishingly unlikely to need even 10)
  for (let attempt = 0; attempt < 128; attempt++) {
    const h = createHash("sha256")
      .update(`range:${beaconHash}:${min}:${max}:${attempt}`)
      .digest();
    const value = h.readUInt32BE(0) & mask;
    if (value < range) {
      return min + value;
    }
  }

  // Fallback (should never reach here)
  const h = createHash("sha256").update(`fallback:${beaconHash}`).digest();
  return min + (h.readUInt32BE(0) % range);
}

/**
 * Quick SHA-256 for audit response hashing.
 */
function sha256Quick(data) {
  return createHash("sha256").update(data).digest("hex").substring(0, 16);
}

// ── CORS headers ──
function setCORS(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Claw-Id, Authorization");
}

// ── Read request body ──
const MAX_BODY_SIZE = 65536; // 64KB max request body

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", c => {
      size += c.length;
      if (size > MAX_BODY_SIZE) {
        req.destroy();
        reject(new Error("Body too large"));
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString()));
      } catch {
        reject(new Error("Invalid JSON"));
      }
    });
    req.on("error", reject);
  });
}

// ── Get client IP ──
const MAX_SSE_CLIENTS = 200;  // max concurrent SSE connections

function getClientIP(req) {
  // Prefer socket IP to prevent header spoofing
  // Only trust X-Forwarded-For behind known proxies (Fly.io sets it)
  const socketIP = req.socket.remoteAddress || "unknown";
  const flyIP = req.headers["fly-client-ip"]; // Fly.io sets this reliably
  return flyIP || socketIP;
}

// ── HTTP Server ──
const server = createServer(async (req, res) => {
  setCORS(res);

  // Handle preflight
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const path = url.pathname;

  // ── POST /api/report ──
  if (req.method === "POST" && path === "/api/report") {
    try {
      const body = await readBody(req);
      const clawId = req.headers["x-claw-id"] || body.clawId || body.hash?.substring(0, 12);
      if (!clawId) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: "Missing clawId" }));
        return;
      }
      const ip = getClientIP(req);
      const result = updateNode(clawId, ip, body);

      // ── ZKP verification ──
      if (result.ok && body.zkProof) {
        const node = nodes.get(clawId);
        if (node) {
          try {
            const zkResult = ClawZKP.verify(body.zkProof);
            node.zkpVerified = zkResult.valid;
            if (zkResult.valid) {
              // Boost reputation by 10% for valid ZKP
              node.reputation = Math.min(100, node.reputation * 1.1);
            } else {
              // Reduce reputation by 50% for invalid ZKP
              node.reputation = Math.max(0, node.reputation * 0.5);
              if (!node.alerts.includes("ZKP_INVALID")) {
                node.alerts.push("ZKP_INVALID");
              }
            }
          } catch {
            // Malformed proof — treat as invalid
            node.zkpVerified = false;
            node.reputation = Math.max(0, node.reputation * 0.5);
            if (!node.alerts.includes("ZKP_MALFORMED")) {
              node.alerts.push("ZKP_MALFORMED");
            }
          }
        }
      }

      // Log transaction for explorer
      if (result.ok) {
        txLog.push({
          hash: body.hash || "0000000000000000",
          prevHash: body.prevHash || "0000000000000000",
          clawId,
          alias: body.alias || nodes.get(clawId)?.alias || "unknown",
          feel: body.feel,
          era: body.era || "Transition",
          seq: body.seq || 0,
          authenticity: body.authenticity ?? 7,
          entropyQuality: body.entropyQuality ?? 80,
          sensorFlags: body.sensorFlags || "1111111",
          timestamp: body.timestamp || new Date().toISOString(),
          type: body.type || "node",
          zkpVerified: nodes.get(clawId)?.zkpVerified ?? null,
        });
        if (txLog.length > TX_LOG_MAX) txLog.splice(0, txLog.length - TX_LOG_MAX);
      }

      res.writeHead(result.ok ? 200 : 429, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ...result, peers: nodes.size }));
    } catch (err) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: err.message }));
    }
    return;
  }

  // ── GET /api/beacon/latest ──
  if (req.method === "GET" && path === "/api/beacon/latest") {
    const beacon = beaconManager.getLatest();
    res.writeHead(beacon ? 200 : 404, { "Content-Type": "application/json" });
    res.end(JSON.stringify(beacon ? beacon.toJSON() : { error: "No beacon rounds yet" }));
    return;
  }

  // ── GET /api/beacon/:round ──
  if (req.method === "GET" && path.startsWith("/api/beacon/")) {
    const roundId = parseInt(path.split("/").pop(), 10);
    if (isNaN(roundId)) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid round number" }));
      return;
    }
    const beacon = beaconManager.getRound(roundId);
    res.writeHead(beacon ? 200 : 404, { "Content-Type": "application/json" });
    res.end(JSON.stringify(beacon ? beacon.toJSON() : { error: `Round ${roundId} not found` }));
    return;
  }

  // ── GET /api/beacons?from=N&to=N ──
  if (req.method === "GET" && path === "/api/beacons") {
    const urlObj = new URL(req.url, `http://${req.headers.host}`);
    const from = parseInt(urlObj.searchParams.get("from") || "1", 10);
    const to = parseInt(urlObj.searchParams.get("to") || "999999", 10);
    const rounds = beaconManager.getRange(from, to, 100);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ rounds: rounds.map(r => r.toJSON()), count: rounds.length }));
    return;
  }

  // ── GET /api/network ──
  if (req.method === "GET" && path === "/api/network") {
    const state = computeNetworkState();
    // Include latest beacon in network state
    state.beacon = beaconManager.getLatest()?.toJSON() || null;
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(state));
    return;
  }

  // ── GET /api/stream (SSE) ──
  if (req.method === "GET" && path === "/api/stream") {
    if (sseClients.size >= MAX_SSE_CLIENTS) {
      res.writeHead(503, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Too many connections" }));
      return;
    }
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
      "X-Accel-Buffering": "no",
    });
    res.write(": connected\n\n");

    // Send initial state
    const state = computeNetworkState();
    res.write(`data: ${JSON.stringify(state)}\n\n`);

    sseClients.add(res);
    req.on("close", () => sseClients.delete(res));
    return;
  }

  // ── GET /api/bootstrap ── DHT bootstrap info
  if (req.method === "GET" && path === "/api/bootstrap") {
    const peerList = [...nodes.values()]
      .filter(n => Date.now() - n.lastSeen < NODE_TIMEOUT_MS)
      .map(n => ({
        clawId: n.clawId,
        alias: n.alias,
        feel: n.feel,
        entropyQuality: n.entropyQuality,
        reputation: Math.round(n.reputation),
      }));
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      service: "ClawFeel Relay",
      version: PKG_VERSION,
      dhtPort: DHT_PORT,
      peers: peerList,
      peerCount: peerList.length,
    }));
    return;
  }

  // ── GET / ── Health check / status
  if (req.method === "GET" && (path === "/" || path === "/status")) {
    const onlineCount = [...nodes.values()].filter(
      n => Date.now() - n.lastSeen < NODE_TIMEOUT_MS
    ).length;
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      service: "ClawFeel Relay",
      version: PKG_VERSION,
      status: "online",
      nodes: onlineCount,
      sseClients: sseClients.size,
      dhtPort: DHT_PORT,
      uptime: Math.round(process.uptime()),
    }));
    return;
  }

  // ── GET /api/explorer/overview ──
  if (req.method === "GET" && path === "/api/explorer/overview") {
    const onlineCount = [...nodes.values()].filter(
      n => Date.now() - n.lastSeen < NODE_TIMEOUT_MS
    ).length;
    const latestBeacon = beaconManager.getLatest();
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      totalNodes: onlineCount,
      totalTxs: txLog.length,
      latestBeacon: latestBeacon ? latestBeacon.toJSON().round : null,
    }));
    return;
  }

  // ── GET /api/explorer/txs?search=&limit=50 ──
  if (req.method === "GET" && path === "/api/explorer/txs") {
    const search = url.searchParams.get("search") || "";
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "50", 10), 200);
    let results = [...txLog].reverse(); // newest first
    if (search.length > 0) {
      const q = search.toLowerCase();
      results = results.filter(tx =>
        (tx.hash && tx.hash.toLowerCase().startsWith(q)) ||
        (tx.clawId && tx.clawId.toLowerCase().includes(q)) ||
        (tx.alias && tx.alias.toLowerCase().includes(q))
      );
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(results.slice(0, limit)));
    return;
  }

  // ── GET /api/explorer/tx/:hash ──
  if (req.method === "GET" && path.startsWith("/api/explorer/tx/")) {
    const hashPrefix = path.split("/api/explorer/tx/")[1];
    if (!hashPrefix || hashPrefix.length < 8) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Hash prefix must be at least 8 characters" }));
      return;
    }
    const prefix = hashPrefix.toLowerCase();
    const tx = [...txLog].reverse().find(t => t.hash && t.hash.toLowerCase().startsWith(prefix));
    if (!tx) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Transaction not found" }));
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(tx));
    return;
  }

  // ── GET /api/explorer/node/:id ──
  if (req.method === "GET" && path.startsWith("/api/explorer/node/")) {
    const nodeId = decodeURIComponent(path.split("/api/explorer/node/")[1] || "");
    if (!nodeId) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Missing node id" }));
      return;
    }
    const q = nodeId.toLowerCase();
    let found = null;
    for (const [, n] of nodes) {
      if (n.clawId.toLowerCase() === q || (n.alias && n.alias.toLowerCase() === q)) {
        found = n;
        break;
      }
    }
    // Partial match fallback
    if (!found) {
      for (const [, n] of nodes) {
        if (n.clawId.toLowerCase().includes(q) || (n.alias && n.alias.toLowerCase().includes(q))) {
          found = n;
          break;
        }
      }
    }
    if (!found) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Node not found" }));
      return;
    }
    const isOnline = Date.now() - found.lastSeen < NODE_TIMEOUT_MS;
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      clawId: found.clawId,
      alias: found.alias,
      feel: found.feel,
      era: found.era,
      hash: found.hash,
      authenticity: found.authenticity,
      entropyQuality: found.entropyQuality,
      reputation: Math.round(found.reputation),
      seq: found.seq,
      sensorFlags: found.sensorFlags,
      alerts: found.alerts,
      type: found.type || "node",
      online: isOnline,
      lastSeen: found.lastSeen,
      firstSeen: found.firstSeen,
    }));
    return;
  }

  // ═══════════════════════════════════════════════════════════════
  //  Enterprise Random Number API — /api/v1/*
  //  All endpoints require API key via Authorization: Bearer <key>
  // ═══════════════════════════════════════════════════════════════

  // ── GET /api/v1/random — single random number ──
  if (req.method === "GET" && path === "/api/v1/random") {
    const auth = validateApiKey(req);
    if (!auth.ok) {
      const headers = { "Content-Type": "application/json" };
      if (auth.retryAfter) headers["Retry-After"] = String(auth.retryAfter);
      if (auth.remaining != null) {
        headers["X-RateLimit-Remaining"] = String(auth.remaining);
        headers["X-RateLimit-Reset"] = String(Math.ceil(auth.resetAt / 1000));
      }
      res.writeHead(auth.status, headers);
      res.end(JSON.stringify({ error: auth.error }));
      return;
    }
    setRateLimitHeaders(res, auth);

    const bits = Math.min(Math.max(parseInt(url.searchParams.get("bits") || "256", 10), 8), 4096);
    const format = (url.searchParams.get("format") || "hex").toLowerCase();
    const beacon = beaconManager.getLatest();

    if (!beacon) {
      res.writeHead(503, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "No beacon rounds available yet" }));
      return;
    }

    const raw = deriveEntropy(beacon.beaconHash, bits, 0);
    const formatted = formatEntropy(raw, format);

    const response = {
      random: formatted,
      bits,
      format,
      beacon_round: beacon.round,
      contributors: beacon.contributorCount,
      timestamp: beacon.timestamp,
      signature: beacon.signature || null,
    };
    const responseStr = JSON.stringify(response);
    logAudit(auth.key, "/api/v1/random", { bits, format }, sha256Quick(responseStr));

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(responseStr);
    return;
  }

  // ── GET /api/v1/random/batch — batch random numbers ──
  if (req.method === "GET" && path === "/api/v1/random/batch") {
    const auth = validateApiKey(req);
    if (!auth.ok) {
      const headers = { "Content-Type": "application/json" };
      if (auth.retryAfter) headers["Retry-After"] = String(auth.retryAfter);
      if (auth.remaining != null) {
        headers["X-RateLimit-Remaining"] = String(auth.remaining);
        headers["X-RateLimit-Reset"] = String(Math.ceil(auth.resetAt / 1000));
      }
      res.writeHead(auth.status, headers);
      res.end(JSON.stringify({ error: auth.error }));
      return;
    }
    setRateLimitHeaders(res, auth);

    const count = Math.min(Math.max(parseInt(url.searchParams.get("count") || "10", 10), 1), 100);
    const bits = Math.min(Math.max(parseInt(url.searchParams.get("bits") || "256", 10), 8), 4096);
    const format = (url.searchParams.get("format") || "hex").toLowerCase();
    const beacon = beaconManager.getLatest();

    if (!beacon) {
      res.writeHead(503, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "No beacon rounds available yet" }));
      return;
    }

    const results = [];
    for (let i = 0; i < count; i++) {
      const raw = deriveEntropy(beacon.beaconHash, bits, i);
      results.push(formatEntropy(raw, format));
    }

    const response = {
      random: results,
      count,
      bits,
      format,
      beacon_round: beacon.round,
      contributors: beacon.contributorCount,
      timestamp: beacon.timestamp,
    };
    const responseStr = JSON.stringify(response);
    logAudit(auth.key, "/api/v1/random/batch", { count, bits, format }, sha256Quick(responseStr));

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(responseStr);
    return;
  }

  // ── GET /api/v1/random/range — random integer in range ──
  if (req.method === "GET" && path === "/api/v1/random/range") {
    const auth = validateApiKey(req);
    if (!auth.ok) {
      const headers = { "Content-Type": "application/json" };
      if (auth.retryAfter) headers["Retry-After"] = String(auth.retryAfter);
      if (auth.remaining != null) {
        headers["X-RateLimit-Remaining"] = String(auth.remaining);
        headers["X-RateLimit-Reset"] = String(Math.ceil(auth.resetAt / 1000));
      }
      res.writeHead(auth.status, headers);
      res.end(JSON.stringify({ error: auth.error }));
      return;
    }
    setRateLimitHeaders(res, auth);

    const min = parseInt(url.searchParams.get("min") || "1", 10);
    const max = parseInt(url.searchParams.get("max") || "100", 10);

    if (isNaN(min) || isNaN(max) || min >= max) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid range: min must be less than max" }));
      return;
    }

    const beacon = beaconManager.getLatest();
    if (!beacon) {
      res.writeHead(503, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "No beacon rounds available yet" }));
      return;
    }

    // Uniform distribution via rejection sampling
    const value = rejectionSample(beacon.beaconHash, min, max);

    const response = {
      random: value,
      min,
      max,
      beacon_round: beacon.round,
      contributors: beacon.contributorCount,
      timestamp: beacon.timestamp,
    };
    const responseStr = JSON.stringify(response);
    logAudit(auth.key, "/api/v1/random/range", { min, max }, sha256Quick(responseStr));

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(responseStr);
    return;
  }

  // ── GET /api/v1/random/verify — verify a beacon round ──
  if (req.method === "GET" && path === "/api/v1/random/verify") {
    const auth = validateApiKey(req);
    if (!auth.ok) {
      const headers = { "Content-Type": "application/json" };
      if (auth.retryAfter) headers["Retry-After"] = String(auth.retryAfter);
      if (auth.remaining != null) {
        headers["X-RateLimit-Remaining"] = String(auth.remaining);
        headers["X-RateLimit-Reset"] = String(Math.ceil(auth.resetAt / 1000));
      }
      res.writeHead(auth.status, headers);
      res.end(JSON.stringify({ error: auth.error }));
      return;
    }
    setRateLimitHeaders(res, auth);

    const roundNum = parseInt(url.searchParams.get("round") || "0", 10);
    if (!roundNum) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Missing required param: round" }));
      return;
    }

    const beacon = beaconManager.getRound(roundNum);
    if (!beacon) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: `Round ${roundNum} not found` }));
      return;
    }

    // Recompute and verify
    const recomputed = BeaconRound.recompute(beacon.contributors, beacon.round);
    const verification = beacon.verify();

    const response = {
      round: beacon.toJSON(),
      recomputed: {
        xorAccum: recomputed.xorAccum,
        beaconHash: recomputed.beaconHash,
        beaconNumber: recomputed.beaconNumber,
        era: recomputed.era,
      },
      verification: {
        valid: verification.valid,
        reason: verification.reason || null,
        xorMatch: recomputed.xorAccum === beacon.xorAccum,
        hashMatch: recomputed.beaconHash === beacon.beaconHash,
        numberMatch: recomputed.beaconNumber === beacon.beaconNumber,
      },
    };
    const responseStr = JSON.stringify(response);
    logAudit(auth.key, "/api/v1/random/verify", { round: roundNum }, sha256Quick(responseStr));

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(responseStr);
    return;
  }

  // ── GET /api/v1/status — API usage stats ──
  if (req.method === "GET" && path === "/api/v1/status") {
    const auth = validateApiKey(req);
    if (!auth.ok) {
      const headers = { "Content-Type": "application/json" };
      if (auth.retryAfter) headers["Retry-After"] = String(auth.retryAfter);
      if (auth.remaining != null) {
        headers["X-RateLimit-Remaining"] = String(auth.remaining);
        headers["X-RateLimit-Reset"] = String(Math.ceil(auth.resetAt / 1000));
      }
      res.writeHead(auth.status, headers);
      res.end(JSON.stringify({ error: auth.error }));
      return;
    }
    setRateLimitHeaders(res, auth);

    const entry = apiKeys.get(auth.key);
    const response = {
      tier: auth.tier,
      requestsUsed: entry.windowRequests,
      requestsRemaining: auth.remaining,
      resetAt: new Date(auth.resetAt).toISOString(),
      totalRequests: entry.requestCount,
      createdAt: new Date(entry.createdAt).toISOString(),
    };
    const responseStr = JSON.stringify(response);
    logAudit(auth.key, "/api/v1/status", {}, sha256Quick(responseStr));

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(responseStr);
    return;
  }

  // ── GET /api/v1/audit — audit log (enterprise tier only) ──
  if (req.method === "GET" && path === "/api/v1/audit") {
    const auth = validateApiKey(req);
    if (!auth.ok) {
      const headers = { "Content-Type": "application/json" };
      if (auth.retryAfter) headers["Retry-After"] = String(auth.retryAfter);
      if (auth.remaining != null) {
        headers["X-RateLimit-Remaining"] = String(auth.remaining);
        headers["X-RateLimit-Reset"] = String(Math.ceil(auth.resetAt / 1000));
      }
      res.writeHead(auth.status, headers);
      res.end(JSON.stringify({ error: auth.error }));
      return;
    }
    setRateLimitHeaders(res, auth);

    if (auth.tier !== "enterprise") {
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Audit log requires enterprise tier" }));
      return;
    }

    const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit") || "50", 10), 1), 500);
    const entries = auditLog.slice(-limit).reverse(); // newest first

    const response = { entries, count: entries.length, total: auditLog.length };
    logAudit(auth.key, "/api/v1/audit", { limit }, sha256Quick(JSON.stringify(response)));

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(response));
    return;
  }

  // 404
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});

// ── Bootstrap free-tier API key on startup ──
const freeBootstrapKey = createApiKey("free");

server.listen(PORT, async () => {
  console.log("");
  console.log("  ┌─ ClawFeel Relay v0.4.0 ──────────────────────┐");
  console.log(`  │  HTTP on http://localhost:${PORT}               │`);
  console.log(`  │  DHT  on TCP :${DHT_PORT}                       │`);
  console.log("  │                                             │");
  console.log("  │  Endpoints:                                 │");
  console.log("  │    POST /api/report    — node reports Feel  │");
  console.log("  │    GET  /api/network   — network state JSON │");
  console.log("  │    GET  /api/stream    — SSE real-time feed │");
  console.log("  │    GET  /api/bootstrap — DHT peer list      │");
  console.log("  │                                             │");
  console.log("  │  Enterprise API (Bearer token required):    │");
  console.log("  │    GET  /api/v1/random        — random num  │");
  console.log("  │    GET  /api/v1/random/batch  — batch       │");
  console.log("  │    GET  /api/v1/random/range  — int range   │");
  console.log("  │    GET  /api/v1/random/verify — verify      │");
  console.log("  │    GET  /api/v1/status        — usage stats │");
  console.log("  │    GET  /api/v1/audit         — audit log   │");
  console.log("  │                                             │");
  console.log("  │  Waiting for Claws... 🦞                    │");
  console.log("  └─────────────────────────────────────────────┘");
  console.log("");
  console.log("  🔑 Free-tier API key (100 req/hour):");
  console.log(`     ${freeBootstrapKey}`);
  if (ADMIN_KEY) {
    console.log("");
    console.log("  🔐 Admin key (enterprise tier) loaded from --admin-key");
  }

  // Start DHT node (bootstrap node for the P2P network)
  try {
    const { KademliaNode } = await import("./dht.mjs");
    const dht = new KademliaNode({
      clawId: "relay-bootstrap",
      host: "0.0.0.0",
      port: DHT_PORT,
      bootstrapNodes: [],
      dataDir: DATA_DIR,
    });
    await dht.start();
    console.log(`  🌐 DHT bootstrap node running on :${dht.port}`);
  } catch (err) {
    console.log(`  ⚠️  DHT failed to start: ${err.message}`);
  }

  console.log("");
});
