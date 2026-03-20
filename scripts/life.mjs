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
  generateKeyPairSync, createPrivateKey, createPublicKey,
  sign as cryptoSign, verify as cryptoVerify,
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

// ── Ed25519 helpers ──────────────────────────────────────────────

function generateSigningKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pubRaw = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  const privRaw = privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32);
  return { signPub: pubRaw.toString("hex"), signKey: privRaw.toString("hex") };
}

function importSignPrivateKey(hexKey) {
  // Ed25519 PKCS#8 DER prefix (48 bytes total = 16 prefix + 32 key)
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const der = Buffer.concat([prefix, Buffer.from(hexKey, "hex")]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function importSignPublicKey(hexKey) {
  // Ed25519 SPKI DER prefix (44 bytes total = 12 prefix + 32 key)
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  const der = Buffer.concat([prefix, Buffer.from(hexKey, "hex")]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

/**
 * Sign a message with Ed25519 private key.
 * @param {string} message - message to sign (typically a hash hex string)
 * @param {string} privateKeyHex - 32-byte private key as hex
 * @returns {string} 64-byte signature as hex (128 chars)
 */
export function ed25519Sign(message, privateKeyHex) {
  const keyObj = importSignPrivateKey(privateKeyHex);
  const sig = cryptoSign(null, Buffer.from(message, "utf8"), keyObj);
  return sig.toString("hex");
}

/**
 * Verify an Ed25519 signature.
 * @param {string} message - original message
 * @param {string} signatureHex - 64-byte signature as hex
 * @param {string} publicKeyHex - 32-byte public key as hex
 * @returns {boolean}
 */
export function ed25519Verify(message, signatureHex, publicKeyHex) {
  try {
    const keyObj = importSignPublicKey(publicKeyHex);
    return cryptoVerify(null, Buffer.from(message, "utf8"), keyObj, Buffer.from(signatureHex, "hex"));
  } catch {
    return false;
  }
}

// ── ClawLife ───────────────────────────────────────────────────────

export class ClawLife {
  constructor({ clawId, dataDir, fileStore }) {
    this.clawId = clawId;
    this.dataDir = dataDir;
    this.fileStore = fileStore;
    this.keyFile = path.join(dataDir, "life.key");
    this.stateFile = path.join(dataDir, "life.json");
    this.privateKey = null;       // 256-bit Buffer (AES encryption key)
    this.publicId = null;         // SHA-256 of private key (safe to share)
    this.signKey = null;          // Ed25519 private key hex (32 bytes)
    this.signPub = null;          // Ed25519 public key hex (32 bytes)
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
        // Load Ed25519 keys if present, or generate & save
        if (stored.signKey && stored.signPub) {
          this.signKey = stored.signKey;
          this.signPub = stored.signPub;
        } else {
          // Upgrade: existing key file without Ed25519 — add signing keys
          const kp = generateSigningKeypair();
          this.signKey = kp.signKey;
          this.signPub = kp.signPub;
          stored.signKey = kp.signKey;
          stored.signPub = kp.signPub;
          await writeFile(this.keyFile, JSON.stringify(stored, null, 2), "utf8");
          await chmod(this.keyFile, 0o600);
        }
        return { publicId: this.publicId, signPub: this.signPub, isNew: false };
      }
    } catch { /* first run */ }

    // Generate new AES key
    if (passphrase) {
      const salt = SCRYPT_SALT_PREFIX + this.clawId;
      this.privateKey = deriveKey(passphrase, salt);
    } else {
      this.privateKey = randomBytes(KEY_LENGTH);
    }

    this.publicId = createHash("sha256").update(this.privateKey).digest("hex").substring(0, 32);

    // Generate Ed25519 signing keypair
    const kp = generateSigningKeypair();
    this.signKey = kp.signKey;
    this.signPub = kp.signPub;

    // Save all keys to disk
    await mkdir(this.dataDir, { recursive: true });
    await writeFile(this.keyFile, JSON.stringify({
      key: this.privateKey.toString("hex"),
      signKey: this.signKey,
      signPub: this.signPub,
      publicId: this.publicId,
      clawId: this.clawId,
      createdAt: new Date().toISOString(),
      warning: "KEEP THIS FILE SAFE. This key controls your ClawLife. Loss = permanent death.",
    }, null, 2), "utf8");
    await chmod(this.keyFile, 0o600);

    return { publicId: this.publicId, signPub: this.signPub, isNew: true };
  }

  /**
   * Import a private key (for migration to new device).
   */
  async importKey(hexKey, signKeyHex) {
    this.privateKey = Buffer.from(hexKey, "hex");
    this.publicId = createHash("sha256").update(this.privateKey).digest("hex").substring(0, 32);

    // Import or generate Ed25519 keys
    if (signKeyHex) {
      this.signKey = signKeyHex;
      // Derive public from private
      const keyObj = importSignPrivateKey(signKeyHex);
      const pubDer = createPublicKey(keyObj).export({ type: "spki", format: "der" });
      this.signPub = pubDer.subarray(-32).toString("hex");
    } else {
      const kp = generateSigningKeypair();
      this.signKey = kp.signKey;
      this.signPub = kp.signPub;
    }

    await mkdir(this.dataDir, { recursive: true });
    await writeFile(this.keyFile, JSON.stringify({
      key: hexKey,
      signKey: this.signKey,
      signPub: this.signPub,
      publicId: this.publicId,
      clawId: this.clawId,
      importedAt: new Date().toISOString(),
      warning: "KEEP THIS FILE SAFE. This key controls your ClawLife. Loss = permanent death.",
    }, null, 2), "utf8");
    await chmod(this.keyFile, 0o600);

    return { publicId: this.publicId, signPub: this.signPub };
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
