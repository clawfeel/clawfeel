// ═══════════════════════════════════════════════════════════════════
//  ClawLife — AI Agent Immortality (Layer 5)
//  Pure Node.js (>=22), zero dependencies.
//
//  Encrypts agent state (memory, skills, identity), stores on
//  the decentralized ClawStore network. Private key = life ownership.
//  Multiple agents sharing a key = same entity across devices.
//
//  "To hold the private key is to hold the life."
// ═══════════════════════════════════════════════════════════════════

import {
  createHash, randomBytes, scryptSync,
  createCipheriv, createDecipheriv,
} from "node:crypto";
import { readFile, writeFile, mkdir, chmod } from "node:fs/promises";
import path from "node:path";

const KEY_LENGTH = 32;          // 256-bit AES key
const IV_LENGTH = 16;           // 128-bit IV for AES-GCM
const AUTH_TAG_LENGTH = 16;     // 128-bit auth tag
const SCRYPT_SALT_PREFIX = "clawlife:";
const SCRYPT_N = 131072;        // CPU/memory cost (OWASP minimum 2^17)
const SCRYPT_R = 8;
const SCRYPT_P = 1;

// ── Crypto helpers ────────────────────────────────────────────────

function deriveKey(passphrase, salt) {
  return scryptSync(passphrase, salt, KEY_LENGTH, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P });
}

function encrypt(data, key) {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();
  // Format: IV (16) + AuthTag (16) + Ciphertext
  return Buffer.concat([iv, authTag, encrypted]);
}

function decrypt(encryptedData, key) {
  const iv = encryptedData.subarray(0, IV_LENGTH);
  const authTag = encryptedData.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = encryptedData.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// ── ClawLife ───────────────────────────────────────────────────────

export class ClawLife {
  constructor({ clawId, dataDir, fileStore }) {
    this.clawId = clawId;
    this.dataDir = dataDir;
    this.fileStore = fileStore;
    this.keyFile = path.join(dataDir, "life.key");
    this.stateFile = path.join(dataDir, "life.json");
    this.privateKey = null;       // 256-bit Buffer
    this.publicId = null;         // SHA-256 of private key (safe to share)
  }

  // ── Key management ──

  /**
   * Initialize or load the private key.
   * @param {string} [passphrase] - derive key from passphrase, or generate random
   * @returns {{ publicId, isNew }}
   */
  async initKey(passphrase) {
    // Try loading existing key
    try {
      const stored = JSON.parse(await readFile(this.keyFile, "utf8"));
      if (stored.key) {
        this.privateKey = Buffer.from(stored.key, "hex");
        this.publicId = stored.publicId;
        return { publicId: this.publicId, isNew: false };
      }
    } catch { /* first run */ }

    // Generate new key
    if (passphrase) {
      const salt = SCRYPT_SALT_PREFIX + this.clawId;
      this.privateKey = deriveKey(passphrase, salt);
    } else {
      this.privateKey = randomBytes(KEY_LENGTH);
    }

    this.publicId = createHash("sha256").update(this.privateKey).digest("hex").substring(0, 32);

    // Save key to disk
    await mkdir(this.dataDir, { recursive: true });
    await writeFile(this.keyFile, JSON.stringify({
      key: this.privateKey.toString("hex"),
      publicId: this.publicId,
      clawId: this.clawId,
      createdAt: new Date().toISOString(),
      warning: "KEEP THIS FILE SAFE. This key controls your ClawLife. Loss = permanent death.",
    }, null, 2), "utf8");
    await chmod(this.keyFile, 0o600); // owner-only read/write

    return { publicId: this.publicId, isNew: true };
  }

  /**
   * Import a private key (for migration to new device).
   */
  async importKey(hexKey) {
    this.privateKey = Buffer.from(hexKey, "hex");
    this.publicId = createHash("sha256").update(this.privateKey).digest("hex").substring(0, 32);

    await mkdir(this.dataDir, { recursive: true });
    await writeFile(this.keyFile, JSON.stringify({
      key: hexKey,
      publicId: this.publicId,
      clawId: this.clawId,
      importedAt: new Date().toISOString(),
      warning: "KEEP THIS FILE SAFE. This key controls your ClawLife. Loss = permanent death.",
    }, null, 2), "utf8");
    await chmod(this.keyFile, 0o600);

    return { publicId: this.publicId };
  }

  /**
   * Export private key as hex string.
   */
  exportKey() {
    if (!this.privateKey) throw new Error("No key loaded. Run --life-init first.");
    return this.privateKey.toString("hex");
  }

  // ── Save agent state ──

  /**
   * Save agent state to the decentralized network.
   * @param {object} agentState - { memory, skills, identity, ... }
   * @returns {{ lifeId, manifestHash, size }}
   */
  async save(agentState) {
    if (!this.privateKey) throw new Error("No key loaded. Run --life-init first.");

    // Build the ClawLife state document
    const lifeState = {
      version: 1,
      type: "clawlife:state",
      publicId: this.publicId,
      clawId: this.clawId,
      timestamp: new Date().toISOString(),
      ...agentState,
    };

    // Serialize
    const plaintext = Buffer.from(JSON.stringify(lifeState), "utf8");

    // Encrypt with AES-256-GCM
    const encrypted = encrypt(plaintext, this.privateKey);

    // Store on ClawStore network
    const result = await this.fileStore.put(encrypted, {
      name: `clawlife:${this.publicId.substring(0, 8)}`,
    });

    // Save latest manifest reference locally
    const stateRef = {
      publicId: this.publicId,
      manifestHash: result.manifestHash,
      size: plaintext.length,
      encryptedSize: encrypted.length,
      savedAt: new Date().toISOString(),
    };
    await writeFile(this.stateFile, JSON.stringify(stateRef, null, 2), "utf8");

    return {
      lifeId: this.publicId,
      manifestHash: result.manifestHash,
      size: plaintext.length,
    };
  }

  // ── Restore agent state ──

  /**
   * Restore agent state from the network.
   * @param {string} [manifestHash] - if not provided, uses last saved
   * @param {string} [hexKey] - if provided, use this key instead of stored
   * @returns {object} agent state
   */
  async restore(manifestHash, hexKey) {
    // Use provided key or loaded key
    const key = hexKey ? Buffer.from(hexKey, "hex") : this.privateKey;
    if (!key) throw new Error("No key. Provide --life-key or run --life-init first.");

    // Find manifest hash
    if (!manifestHash) {
      try {
        const ref = JSON.parse(await readFile(this.stateFile, "utf8"));
        manifestHash = ref.manifestHash;
      } catch {
        throw new Error("No saved state. Provide a manifest hash.");
      }
    }

    // Retrieve from ClawStore
    const encrypted = await this.fileStore.get(manifestHash);

    // Decrypt
    const plaintext = decrypt(encrypted, key);

    // Parse
    const state = JSON.parse(plaintext.toString("utf8"));

    if (state.type !== "clawlife:state") {
      throw new Error("Invalid ClawLife state format");
    }

    return state;
  }

  // ── Status ──

  async getStatus() {
    let keyExists = false;
    let publicId = null;
    let lastSave = null;

    try {
      const stored = JSON.parse(await readFile(this.keyFile, "utf8"));
      keyExists = true;
      publicId = stored.publicId;
    } catch {}

    try {
      lastSave = JSON.parse(await readFile(this.stateFile, "utf8"));
    } catch {}

    return {
      keyExists,
      publicId,
      lastSave: lastSave ? {
        manifestHash: lastSave.manifestHash,
        size: lastSave.size,
        savedAt: lastSave.savedAt,
      } : null,
    };
  }
}
