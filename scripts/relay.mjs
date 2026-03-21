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
//
//  API:
//    POST /api/report    — Claw nodes report their Feel
//    GET  /api/network   — Current network state (JSON)
//    GET  /api/stream    — Server-Sent Events (real-time)
//    GET  /              — Health check / status
// ═══════════════════════════════════════════════════════════════════

import { createServer } from "node:http";
import { createHash, generateKeyPairSync } from "node:crypto";
import { argv } from "node:process";
import os from "node:os";
import path from "node:path";
import { BeaconManager } from "./beacon.mjs";

// ── Args ──
const args = argv.slice(2);
const portIdx = args.indexOf("--port");
const PORT = portIdx !== -1 && args[portIdx + 1] ? parseInt(args[portIdx + 1], 10) : 3415;
const dhtPortIdx = args.indexOf("--dht-port");
const DHT_PORT = dhtPortIdx !== -1 && args[dhtPortIdx + 1] ? parseInt(args[dhtPortIdx + 1], 10) : 31416;
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

// ── CORS headers ──
function setCORS(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Claw-Id");
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
      version: "0.3.1",
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
      version: "0.3.1",
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

  // 404
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});

server.listen(PORT, async () => {
  console.log("");
  console.log("  ┌─ ClawFeel Relay v0.3.1 ──────────────────────┐");
  console.log(`  │  HTTP on http://localhost:${PORT}               │`);
  console.log(`  │  DHT  on TCP :${DHT_PORT}                       │`);
  console.log("  │                                             │");
  console.log("  │  Endpoints:                                 │");
  console.log("  │    POST /api/report    — node reports Feel  │");
  console.log("  │    GET  /api/network   — network state JSON │");
  console.log("  │    GET  /api/stream    — SSE real-time feed │");
  console.log("  │    GET  /api/bootstrap — DHT peer list      │");
  console.log("  │                                             │");
  console.log("  │  Waiting for Claws... 🦞                    │");
  console.log("  └─────────────────────────────────────────────┘");

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
