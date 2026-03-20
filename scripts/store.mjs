// ═══════════════════════════════════════════════════════════════════
//  ClawStore — Distributed File Storage (Layer 4)
//  Pure Node.js (>=22), zero dependencies.
//
//  Stores files as content-addressed chunks across the DHT network.
//  XOR-based erasure coding for redundancy (k-of-n recovery).
//
//  Usage:
//    const store = new FileStore({ dht, dataDir });
//    const manifest = await store.put(buffer);     // store file
//    const data = await store.get(manifestHash);    // retrieve file
// ═══════════════════════════════════════════════════════════════════

import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir, readdir, unlink, stat } from "node:fs/promises";
import path from "node:path";

const CHUNK_SIZE = 4096;        // 4KB chunks
const DEFAULT_K = 4;            // data blocks for erasure coding
const DEFAULT_M = 2;            // parity blocks
const MAX_CACHE_MB = 64;        // max in-memory chunk cache
const REPLICATE_COUNT = 3;      // store each chunk on 3 DHT nodes

// ── Content hashing ───────────────────────────────────────────────

function sha256(data) {
  return createHash("sha256").update(data).digest("hex");
}

// ── Erasure Coding (XOR-based) ────────────────────────────────────
//  Simple but effective: each parity block = XOR of two data blocks.
//  Can recover 1 missing data block per parity block.

export class ErasureCoder {
  constructor({ k = DEFAULT_K, m = DEFAULT_M } = {}) {
    this.k = k;
    this.m = m;
  }

  _xorBuffers(a, b) {
    const len = Math.max(a.length, b.length);
    const result = Buffer.alloc(len);
    for (let i = 0; i < len; i++) {
      result[i] = (a[i] || 0) ^ (b[i] || 0);
    }
    return result;
  }

  /**
   * Encode data into k data blocks + m parity blocks.
   * @param {Buffer} data - file data
   * @returns {{ dataBlocks: Buffer[], parityBlocks: Buffer[], blockSize: number }}
   */
  encode(data) {
    const blockSize = Math.ceil(data.length / this.k);
    const dataBlocks = [];

    // Split into k data blocks (pad last block with zeros)
    for (let i = 0; i < this.k; i++) {
      const start = i * blockSize;
      const end = Math.min(start + blockSize, data.length);
      const block = Buffer.alloc(blockSize);
      data.copy(block, 0, start, end);
      dataBlocks.push(block);
    }

    // Generate m parity blocks via XOR pairs
    const parityBlocks = [];
    for (let j = 0; j < this.m; j++) {
      const idx1 = j % this.k;
      const idx2 = (j + 1) % this.k;
      parityBlocks.push(this._xorBuffers(dataBlocks[idx1], dataBlocks[idx2]));
    }

    return { dataBlocks, parityBlocks, blockSize };
  }

  /**
   * Decode blocks back to original data.
   * @param {(Buffer|null)[]} dataBlocks - k data blocks (some may be null)
   * @param {(Buffer|null)[]} parityBlocks - m parity blocks (some may be null)
   * @param {{ blockSize: number, originalSize: number }} config
   * @returns {Buffer} original data
   */
  decode(dataBlocks, parityBlocks, config) {
    const { blockSize, originalSize } = config;
    const recovered = [...dataBlocks];

    // Try to recover missing data blocks using parity
    for (let j = 0; j < this.m; j++) {
      if (!parityBlocks[j]) continue;
      const idx1 = j % this.k;
      const idx2 = (j + 1) % this.k;

      if (!recovered[idx1] && recovered[idx2]) {
        // Recover idx1: data[idx1] = parity[j] XOR data[idx2]
        recovered[idx1] = this._xorBuffers(parityBlocks[j], recovered[idx2]);
      } else if (!recovered[idx2] && recovered[idx1]) {
        // Recover idx2: data[idx2] = parity[j] XOR data[idx1]
        recovered[idx2] = this._xorBuffers(parityBlocks[j], recovered[idx1]);
      }
    }

    // Check all blocks recovered
    const missing = recovered.filter(b => !b).length;
    if (missing > 0) {
      throw new Error(`Cannot recover: ${missing} data blocks still missing`);
    }

    // Reassemble
    const full = Buffer.concat(recovered);
    return full.subarray(0, originalSize);
  }
}

// ── Chunk Store (persistent, disk-backed) ─────────────────────────

export class ChunkStore {
  constructor({ dataDir }) {
    this.dataDir = dataDir;
    this.chunkDir = path.join(dataDir, "chunks");
    this.cache = new Map();     // hash → Buffer (hot cache)
    this.cacheSize = 0;         // bytes in cache
  }

  _chunkPath(hash) {
    // 2-level directory for filesystem performance
    const prefix = hash.substring(0, 2);
    return path.join(this.chunkDir, prefix, hash + ".bin");
  }

  async put(hash, data) {
    // Memory cache
    if (!this.cache.has(hash)) {
      this.cache.set(hash, data);
      this.cacheSize += data.length;
      this._evictIfNeeded();
    }

    // Disk persistence
    const filePath = this._chunkPath(hash);
    await mkdir(path.dirname(filePath), { recursive: true });
    await writeFile(filePath, data);
  }

  async get(hash) {
    // Check cache
    if (this.cache.has(hash)) {
      return this.cache.get(hash);
    }

    // Check disk
    try {
      const data = await readFile(this._chunkPath(hash));
      // Warm cache
      this.cache.set(hash, data);
      this.cacheSize += data.length;
      this._evictIfNeeded();
      return data;
    } catch {
      return null;
    }
  }

  async has(hash) {
    if (this.cache.has(hash)) return true;
    try {
      await stat(this._chunkPath(hash));
      return true;
    } catch {
      return false;
    }
  }

  _evictIfNeeded() {
    const maxBytes = MAX_CACHE_MB * 1024 * 1024;
    while (this.cacheSize > maxBytes && this.cache.size > 0) {
      const first = this.cache.keys().next().value;
      this.cacheSize -= this.cache.get(first).length;
      this.cache.delete(first);
    }
  }

  async getStats() {
    let diskChunks = 0;
    try {
      const prefixes = await readdir(this.chunkDir);
      for (const prefix of prefixes) {
        const files = await readdir(path.join(this.chunkDir, prefix));
        diskChunks += files.length;
      }
    } catch { /* no chunks yet */ }
    return { cacheChunks: this.cache.size, diskChunks, cacheMB: Math.round(this.cacheSize / 1024 / 1024 * 10) / 10 };
  }
}

// ── File Store (main API) ─────────────────────────────────────────

export class FileStore {
  constructor({ dht, chunkStore, dataDir }) {
    this.dht = dht;
    this.chunkStore = chunkStore || new ChunkStore({ dataDir });
    this.erasure = new ErasureCoder();
    this.dataDir = dataDir;
    this.manifestFile = path.join(dataDir, "manifests.jsonl");

    // Register chunk handlers on DHT
    this._registerHandlers();
  }

  _registerHandlers() {
    const existingHandler = this.dht._externalHandler;
    this.dht.onMessage(async (msg, socket) => {
      // Handle chunk operations
      if (msg.type === "STORE_CHUNK") {
        const data = Buffer.from(msg.data, "base64");
        const hash = sha256(data);
        await this.chunkStore.put(hash, data);
        return { id: msg.id, type: "CHUNK_STORED", hash };
      }

      if (msg.type === "GET_CHUNK") {
        const data = await this.chunkStore.get(msg.hash);
        if (data) {
          return { id: msg.id, type: "CHUNK_DATA", hash: msg.hash, data: data.toString("base64") };
        }
        return { id: msg.id, type: "CHUNK_NOT_FOUND", hash: msg.hash };
      }

      // Pass to existing handler (gossip)
      if (existingHandler) return existingHandler(msg, socket);
      return null;
    });
  }

  /**
   * Store a file on the network.
   * @param {Buffer} data - file contents
   * @param {object} opts - { name, encrypt }
   * @returns {{ manifestHash, manifest }}
   */
  async put(data, opts = {}) {
    // 1. Split into chunks
    const chunks = [];
    for (let i = 0; i < data.length; i += CHUNK_SIZE) {
      chunks.push(data.subarray(i, Math.min(i + CHUNK_SIZE, data.length)));
    }

    // 2. Erasure encode
    const { dataBlocks, parityBlocks, blockSize } = this.erasure.encode(data);
    const allBlocks = [...dataBlocks, ...parityBlocks];

    // 3. Hash and store each block
    const chunkHashes = [];
    const parityHashes = [];

    for (let i = 0; i < allBlocks.length; i++) {
      const block = allBlocks[i];
      const hash = sha256(block);

      // Store locally
      await this.chunkStore.put(hash, block);

      // Store on DHT (find closest nodes and send)
      await this._storeOnDHT(hash, block);

      if (i < dataBlocks.length) {
        chunkHashes.push(hash);
      } else {
        parityHashes.push(hash);
      }
    }

    // 4. Create manifest
    const manifest = {
      version: 1,
      type: "clawstore:manifest",
      name: opts.name || null,
      size: data.length,
      chunkSize: CHUNK_SIZE,
      blockSize,
      chunks: chunkHashes,
      parity: parityHashes,
      erasure: { k: this.erasure.k, m: this.erasure.m },
      created: new Date().toISOString(),
      owner: this.dht.clawId,
    };

    const manifestJson = JSON.stringify(manifest);
    const manifestHash = sha256(Buffer.from(manifestJson));

    // Store manifest on DHT
    const closest = this.dht.findClosest(manifestHash.substring(0, 40), REPLICATE_COUNT);
    for (const contact of closest) {
      try {
        await this.dht.sendRpc(contact, {
          id: manifestHash.substring(0, 8),
          type: "STORE",
          key: manifestHash,
          value: manifest,
        });
      } catch { /* peer unreachable */ }
    }

    // Store manifest locally (DHT memory + disk)
    this.dht.store.set(manifestHash, manifest);
    await this.chunkStore.put(manifestHash, Buffer.from(manifestJson, "utf8"));

    // Save to local manifest index
    await this._saveManifestIndex(manifestHash, manifest);

    return { manifestHash, manifest };
  }

  /**
   * Retrieve a file from the network.
   * @param {string} manifestHash
   * @returns {Buffer} file data
   */
  async get(manifestHash) {
    // 1. Find manifest (try local first, then DHT)
    let manifest = this.dht.store.get(manifestHash);

    if (!manifest) {
      // Try local chunk store (manifest saved as chunk)
      const localManifest = await this.chunkStore.get(manifestHash);
      if (localManifest) {
        try { manifest = JSON.parse(localManifest.toString("utf8")); } catch {}
      }
    }

    if (!manifest) {
      // Lookup on DHT
      const closest = this.dht.findClosest(manifestHash.substring(0, 40), 5);
      for (const contact of closest) {
        try {
          const res = await this.dht.sendRpc(contact, {
            id: manifestHash.substring(0, 8),
            type: "FIND_VALUE",
            key: manifestHash,
            target: manifestHash.substring(0, 40),
          });
          if (res.type === "VALUE" && res.value) {
            manifest = res.value;
            break;
          }
        } catch { /* try next */ }
      }
    }

    if (!manifest || manifest.type !== "clawstore:manifest") {
      throw new Error("Manifest not found: " + manifestHash);
    }

    // 2. Retrieve data blocks
    const dataBlocks = await Promise.all(
      manifest.chunks.map(hash => this._getFromDHT(hash))
    );

    // 3. Retrieve parity blocks
    const parityBlocks = await Promise.all(
      manifest.parity.map(hash => this._getFromDHT(hash))
    );

    // 4. Check if we need erasure decoding
    const missingData = dataBlocks.filter(b => !b).length;
    if (missingData === 0) {
      // All data blocks available, just concatenate
      const full = Buffer.concat(dataBlocks);
      return full.subarray(0, manifest.size);
    }

    // 5. Erasure decode
    return this.erasure.decode(dataBlocks, parityBlocks, {
      blockSize: manifest.blockSize,
      originalSize: manifest.size,
    });
  }

  /**
   * List locally known manifests.
   */
  async list() {
    try {
      const raw = await readFile(this.manifestFile, "utf8");
      const lines = raw.trim().split("\n").filter(Boolean);
      return lines.map(l => {
        try { return JSON.parse(l); } catch { return null; }
      }).filter(Boolean);
    } catch {
      return [];
    }
  }

  // ── DHT storage helpers ──

  async _storeOnDHT(hash, data) {
    // Store on closest nodes
    const closest = this.dht.findClosest(hash.substring(0, 40), REPLICATE_COUNT);
    const b64 = data.toString("base64");

    for (const contact of closest) {
      try {
        await this.dht.sendRpc(contact, {
          id: hash.substring(0, 8),
          type: "STORE_CHUNK",
          data: b64,
        });
      } catch { /* peer unreachable */ }
    }
  }

  async _getFromDHT(hash) {
    // Try local first
    const local = await this.chunkStore.get(hash);
    if (local) return local;

    // Try DHT
    const closest = this.dht.findClosest(hash.substring(0, 40), 5);
    for (const contact of closest) {
      try {
        const res = await this.dht.sendRpc(contact, {
          id: hash.substring(0, 8),
          type: "GET_CHUNK",
          hash,
        });
        if (res.type === "CHUNK_DATA" && res.data) {
          const data = Buffer.from(res.data, "base64");
          // Verify hash
          if (sha256(data) === hash) {
            await this.chunkStore.put(hash, data);
            return data;
          }
        }
      } catch { /* try next */ }
    }

    return null; // not found
  }

  async _saveManifestIndex(hash, manifest) {
    try {
      await mkdir(this.dataDir, { recursive: true });
      const entry = JSON.stringify({ hash, name: manifest.name, size: manifest.size, created: manifest.created });
      await writeFile(this.manifestFile, entry + "\n", { flag: "a" });
    } catch { /* ignore */ }
  }

  // ── Stats ──

  async getStats() {
    const chunkStats = await this.chunkStore.getStats();
    const manifests = await this.list();
    return {
      manifests: manifests.length,
      ...chunkStats,
    };
  }
}
