#!/usr/bin/env node
/**
 * stun.mjs — Pure JS STUN client (RFC 5389)
 * Discovers public IP:port and detects NAT type.
 * Zero dependencies — uses node:dgram + node:crypto only.
 */

import { createSocket } from "node:dgram";
import { randomBytes } from "node:crypto";

// STUN message types
const BINDING_REQUEST = 0x0001;
const BINDING_RESPONSE = 0x0101;
const MAGIC_COOKIE = 0x2112a442;

// Attribute types
const ATTR_MAPPED_ADDRESS = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS = 0x0020;

// Default STUN servers
const DEFAULT_SERVERS = [
  { host: "stun.l.google.com", port: 19302 },
  { host: "stun1.l.google.com", port: 19302 },
  { host: "stun.cloudflare.com", port: 3478 },
];

/**
 * Build a STUN Binding Request (20 bytes header, no attributes).
 * Returns { buffer, transactionId }.
 */
function buildBindingRequest() {
  const txId = randomBytes(12); // 96-bit transaction ID
  const buf = Buffer.alloc(20);
  buf.writeUInt16BE(BINDING_REQUEST, 0);  // Message Type
  buf.writeUInt16BE(0, 2);                 // Message Length (no attributes)
  buf.writeUInt32BE(MAGIC_COOKIE, 4);      // Magic Cookie
  txId.copy(buf, 8);                       // Transaction ID
  return { buffer: buf, transactionId: txId };
}

/**
 * Parse a STUN Binding Response.
 * Extracts XOR-MAPPED-ADDRESS or MAPPED-ADDRESS.
 */
function parseBindingResponse(buf, txId) {
  if (buf.length < 20) return null;

  const type = buf.readUInt16BE(0);
  if (type !== BINDING_RESPONSE) return null;

  const msgLen = buf.readUInt16BE(2);
  const cookie = buf.readUInt32BE(4);
  if (cookie !== MAGIC_COOKIE) return null;

  // Verify transaction ID
  const respTxId = buf.subarray(8, 20);
  if (!txId.equals(respTxId)) return null;

  // Parse attributes
  let offset = 20;
  let result = null;

  while (offset < 20 + msgLen) {
    if (offset + 4 > buf.length) break;
    const attrType = buf.readUInt16BE(offset);
    const attrLen = buf.readUInt16BE(offset + 2);
    const attrData = buf.subarray(offset + 4, offset + 4 + attrLen);

    if (attrType === ATTR_XOR_MAPPED_ADDRESS && attrLen >= 8) {
      result = parseXorMappedAddress(attrData, txId);
    } else if (attrType === ATTR_MAPPED_ADDRESS && attrLen >= 8 && !result) {
      result = parseMappedAddress(attrData);
    }

    // Attributes are padded to 4-byte boundaries
    offset += 4 + Math.ceil(attrLen / 4) * 4;
  }

  return result;
}

function parseXorMappedAddress(data, txId) {
  const family = data[1]; // 0x01 = IPv4, 0x02 = IPv6
  if (family !== 0x01) return null; // Only support IPv4

  const xPort = data.readUInt16BE(2);
  const port = xPort ^ (MAGIC_COOKIE >>> 16);

  const xIP = data.readUInt32BE(4);
  const ip = xIP ^ MAGIC_COOKIE;
  const ipStr = `${(ip >>> 24) & 0xff}.${(ip >>> 16) & 0xff}.${(ip >>> 8) & 0xff}.${ip & 0xff}`;

  return { ip: ipStr, port, family: "IPv4" };
}

function parseMappedAddress(data) {
  const family = data[1];
  if (family !== 0x01) return null;

  const port = data.readUInt16BE(2);
  const ip = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;

  return { ip, port, family: "IPv4" };
}

/**
 * Send a STUN Binding Request and wait for response.
 * @returns {{ ip, port }} or null on timeout
 */
function stunQuery(server, localSocket, timeout = 3000) {
  return new Promise((resolve) => {
    const { buffer, transactionId } = buildBindingRequest();
    let done = false;

    const timer = setTimeout(() => {
      if (!done) { done = true; resolve(null); }
    }, timeout);

    const handler = (msg) => {
      if (done) return;
      const result = parseBindingResponse(msg, transactionId);
      if (result) {
        done = true;
        clearTimeout(timer);
        localSocket.removeListener("message", handler);
        resolve(result);
      }
    };

    localSocket.on("message", handler);
    localSocket.send(buffer, server.port, server.host, (err) => {
      if (err && !done) { done = true; clearTimeout(timer); resolve(null); }
    });
  });
}

/**
 * Discover public IP:port by querying STUN servers.
 * @param {Object} opts
 * @param {Array} opts.servers - STUN servers [{host, port}]
 * @param {number} opts.localPort - local UDP port to bind (0 = random)
 * @param {number} opts.timeout - per-server timeout in ms
 * @returns {{ publicIP, publicPort, localIP, localPort, server }}
 */
export async function stunDiscover({
  servers = DEFAULT_SERVERS,
  localPort = 0,
  timeout = 3000,
} = {}) {
  const socket = createSocket("udp4");

  return new Promise((resolve, reject) => {
    socket.bind(localPort, async () => {
      const addr = socket.address();

      for (const server of servers) {
        try {
          const result = await stunQuery(server, socket, timeout);
          if (result) {
            socket.close();
            resolve({
              publicIP: result.ip,
              publicPort: result.port,
              localIP: addr.address,
              localPort: addr.port,
              server: `${server.host}:${server.port}`,
            });
            return;
          }
        } catch { /* try next server */ }
      }

      socket.close();
      resolve(null); // All servers failed
    });

    socket.on("error", (err) => {
      try { socket.close(); } catch {}
      resolve(null);
    });
  });
}

/**
 * Detect NAT type by comparing STUN results from two different servers.
 * @returns {{ natType, publicIP, publicPort, connectStrategy }}
 * natType: "none" | "full-cone" | "restricted" | "symmetric"
 * connectStrategy: "direct" | "hole-punch" | "relay-only"
 */
export async function detectNATType({
  servers = DEFAULT_SERVERS,
  localPort = 0,
  timeout = 3000,
} = {}) {
  if (servers.length < 2) {
    const result = await stunDiscover({ servers, localPort, timeout });
    if (!result) return { natType: "unknown", connectStrategy: "relay-only" };
    return {
      natType: "unknown",
      publicIP: result.publicIP,
      publicPort: result.publicPort,
      connectStrategy: "hole-punch", // assume best case
    };
  }

  const socket = createSocket("udp4");

  return new Promise((resolve) => {
    socket.bind(localPort, async () => {
      const addr = socket.address();

      // Query two different STUN servers from same local port
      const result1 = await stunQuery(servers[0], socket, timeout);
      const result2 = await stunQuery(servers[1], socket, timeout);

      socket.close();

      if (!result1 && !result2) {
        resolve({ natType: "blocked", connectStrategy: "relay-only" });
        return;
      }

      if (!result1 || !result2) {
        // Only got one result
        const r = result1 || result2;
        resolve({
          natType: "unknown",
          publicIP: r.ip,
          publicPort: r.port,
          connectStrategy: "hole-punch",
        });
        return;
      }

      // Compare: same local port → same public address?
      const localIP = addr.address;
      const isPublic = result1.ip === localIP || result1.ip === "0.0.0.0";

      if (isPublic) {
        // No NAT detected
        resolve({
          natType: "none",
          publicIP: result1.ip,
          publicPort: result1.port,
          connectStrategy: "direct",
        });
      } else if (result1.port === result2.port && result1.ip === result2.ip) {
        // Same mapped address from different servers → full cone or restricted cone
        // (Can't distinguish without additional tests, but both support hole-punching)
        resolve({
          natType: "full-cone",
          publicIP: result1.ip,
          publicPort: result1.port,
          connectStrategy: "hole-punch",
        });
      } else if (result1.ip === result2.ip && result1.port !== result2.port) {
        // Same IP but different ports → port-restricted or symmetric
        // Port changes per destination → symmetric NAT (hole-punch unreliable)
        resolve({
          natType: "symmetric",
          publicIP: result1.ip,
          publicPort: result1.port,
          connectStrategy: "relay-only",
        });
      } else {
        // Different IPs → very unusual, treat as symmetric
        resolve({
          natType: "symmetric",
          publicIP: result1.ip,
          publicPort: result1.port,
          connectStrategy: "relay-only",
        });
      }
    });

    socket.on("error", () => {
      try { socket.close(); } catch {}
      resolve({ natType: "error", connectStrategy: "relay-only" });
    });
  });
}

// ── CLI: run standalone for testing ──
const isDirectRun = process.argv[1]?.endsWith("stun.mjs");
if (isDirectRun) {
  console.log("🔍 Probing NAT via STUN...\n");
  const nat = await detectNATType();
  console.log("  NAT Type:    ", nat.natType || "unknown");
  console.log("  Public IP:   ", nat.publicIP || "n/a");
  console.log("  Public Port: ", nat.publicPort || "n/a");
  console.log("  Strategy:    ", nat.connectStrategy || "unknown");
  console.log("");
}
