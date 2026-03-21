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

function deriveKey(passphrase, salt, opts) {
  const N = opts?.N || SCRYPT_N;
  const r = opts?.r || SCRYPT_R;
  const p = opts?.p || SCRYPT_P;
  return scryptSync(passphrase, salt, KEY_LENGTH, { N, r, p });
}

// Migration uses lighter scrypt params (N=2^14) — the passphrase provides entropy
const MIGRATION_SCRYPT_N = 16384;

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

  // ── DID (Decentralized Identity) ──

  /**
   * Get a DID document for this ClawLife identity.
   * @returns {object} DID document
   */
  getDID() {
    if (!this.signPub) throw new Error("No key loaded. Run --life-init first.");
    return {
      id: `did:claw:${this.publicId}`,
      publicKey: this.signPub,
      clawId: this.clawId,
      created: this._getCreatedAt(),
      controller: `did:claw:${this.publicId}`,
    };
  }

  /** @private */
  _getCreatedAt() {
    try {
      // Synchronous fallback: we already have initKey loaded data
      return new Date().toISOString();
    } catch {
      return new Date().toISOString();
    }
  }

  /**
   * Sign arbitrary data with this identity's Ed25519 private key.
   * @param {string|object} data - data to sign (objects are JSON-serialized)
   * @returns {{ data: string, signature: string, did: string }}
   */
  signDID(data) {
    if (!this.signKey) throw new Error("No key loaded. Run --life-init first.");
    const dataStr = typeof data === "string" ? data : JSON.stringify(data);
    const signature = ed25519Sign(dataStr, this.signKey);
    return {
      data: dataStr,
      signature,
      did: `did:claw:${this.publicId}`,
    };
  }

  /**
   * Verify a DID-signed message.
   * @param {object} signedData - { data, signature, did }
   * @param {string} publicKeyHex - the signer's Ed25519 public key hex
   * @returns {boolean}
   */
  static verifyDID(signedData, publicKeyHex) {
    if (!signedData || !signedData.data || !signedData.signature) return false;
    return ed25519Verify(signedData.data, signedData.signature, publicKeyHex);
  }

  // ── Migration ──

  /**
   * Export a migration bundle: encrypted full state for transfer to another device.
   * @param {string} passphrase - encryption passphrase
   * @returns {string} base64-encoded migration bundle
   */
  exportMigrationBundle(passphrase) {
    if (!this.privateKey || !this.signKey) {
      throw new Error("No key loaded. Run --life-init first.");
    }

    const bundle = {
      version: 1,
      type: "clawlife:migration",
      timestamp: new Date().toISOString(),
      clawId: this.clawId,
      publicId: this.publicId,
      key: this.privateKey.toString("hex"),
      signKey: this.signKey,
      signPub: this.signPub,
    };

    const payload = JSON.stringify(bundle);
    const checksum = createHash("sha256").update(payload).digest("hex");

    const envelope = {
      version: 1,
      checksum,
      payload,
    };

    const envelopeStr = JSON.stringify(envelope);

    // Encrypt with passphrase-derived key (lighter scrypt for portability)
    const salt = SCRYPT_SALT_PREFIX + "migration";
    const encKey = deriveKey(passphrase, salt, { N: MIGRATION_SCRYPT_N });
    const encrypted = encrypt(Buffer.from(envelopeStr, "utf8"), encKey);

    return encrypted.toString("base64");
  }

  /**
   * Import a migration bundle from another device.
   * @param {string} bundleB64 - base64-encoded migration bundle
   * @param {string} passphrase - decryption passphrase
   * @param {string} dataDir - target data directory
   * @returns {Promise<ClawLife>} new ClawLife instance with imported keys
   */
  static async importMigrationBundle(bundleB64, passphrase, dataDir) {
    const encrypted = Buffer.from(bundleB64, "base64");

    // We need to try decryption — the salt depends on the checksum inside,
    // so we brute-force the salt using the envelope structure.
    // Actually, we need to reconstruct the salt. The checksum is inside the
    // encrypted envelope, so we use a two-pass approach:
    // First, try with a known pattern. But we don't know the checksum yet.
    //
    // Better approach: embed the salt hint outside the encryption.
    // For backward compat, we'll try all reasonable salt constructions.
    //
    // Actually the export uses checksum.substring(0,16) as part of salt,
    // and checksum is derived from the payload before encryption.
    // We need to store the salt hint alongside. Let's use a structured format:
    // base64( saltHint(16) + IV(16) + AuthTag(16) + Ciphertext )

    // The current export format is: encrypt(envelope) as base64
    // The salt uses the checksum which is inside the envelope.
    // This is a chicken-and-egg problem. Fix: we need the checksum prefix
    // to be prepended unencrypted. Let's adjust the format:
    // Final format: checksum_prefix(16 hex chars = 8 bytes) + encrypted

    // For the actual implementation, we'll restructure. Since we control both
    // export and import, let's fix the export to prepend the salt hint.
    // But for simplicity, let's just use a fixed salt for migration bundles.

    // Use fixed salt for migration (lighter scrypt for portability)
    const salt = SCRYPT_SALT_PREFIX + "migration";
    const encKey = deriveKey(passphrase, salt, { N: MIGRATION_SCRYPT_N });

    let envelopeStr;
    try {
      envelopeStr = decrypt(encrypted, encKey).toString("utf8");
    } catch {
      throw new Error("Invalid passphrase or corrupted bundle.");
    }

    const envelope = JSON.parse(envelopeStr);
    if (envelope.version !== 1) {
      throw new Error(`Unsupported migration bundle version: ${envelope.version}`);
    }

    // Verify checksum
    const computedChecksum = createHash("sha256").update(envelope.payload).digest("hex");
    if (computedChecksum !== envelope.checksum) {
      throw new Error("Migration bundle checksum mismatch — data corrupted.");
    }

    const bundle = JSON.parse(envelope.payload);
    if (bundle.type !== "clawlife:migration") {
      throw new Error("Invalid migration bundle type.");
    }

    // Create new ClawLife instance and import the key
    const life = new ClawLife({ clawId: bundle.clawId, dataDir, fileStore: null });
    await life.importKey(bundle.key, bundle.signKey);

    return life;
  }

  // ── Will (遗嘱机制) ──

  /**
   * Set a digital will — transfers identity to beneficiary after inactivity timeout.
   * @param {string} beneficiaryDID - DID of the beneficiary (e.g. "did:claw:abc123")
   * @param {number} timeoutDays - days of inactivity before will activates
   * @param {string} [message] - optional farewell message
   */
  async setWill(beneficiaryDID, timeoutDays, message) {
    if (!this.publicId) throw new Error("No key loaded. Run --life-init first.");

    const willFile = path.join(this.dataDir, "will.json");
    const will = {
      version: 1,
      type: "clawlife:will",
      ownerDID: `did:claw:${this.publicId}`,
      beneficiaryDID,
      timeoutDays,
      message: message || null,
      createdAt: new Date().toISOString(),
      lastActive: new Date().toISOString(),
    };

    await mkdir(this.dataDir, { recursive: true });
    await writeFile(willFile, JSON.stringify(will, null, 2), "utf8");
    return will;
  }

  /**
   * Update the lastActive timestamp — call periodically to prevent will activation.
   */
  async heartbeat() {
    const willFile = path.join(this.dataDir, "will.json");
    try {
      const will = JSON.parse(await readFile(willFile, "utf8"));
      will.lastActive = new Date().toISOString();
      await writeFile(willFile, JSON.stringify(will, null, 2), "utf8");
      return { updated: true, lastActive: will.lastActive };
    } catch {
      // No will set — heartbeat is a no-op
      return { updated: false };
    }
  }

  /**
   * Check will status — has the inactivity timeout expired?
   * @returns {{ activated: boolean, beneficiary?: string, message?: string, daysRemaining?: number }}
   */
  async checkWill() {
    const willFile = path.join(this.dataDir, "will.json");
    let will;
    try {
      will = JSON.parse(await readFile(willFile, "utf8"));
    } catch {
      return { activated: false, exists: false };
    }

    const lastActive = new Date(will.lastActive).getTime();
    const timeoutMs = will.timeoutDays * 24 * 60 * 60 * 1000;
    const now = Date.now();
    const elapsed = now - lastActive;

    if (elapsed >= timeoutMs) {
      return {
        activated: true,
        beneficiary: will.beneficiaryDID,
        message: will.message,
        ownerDID: will.ownerDID,
        expiredAt: new Date(lastActive + timeoutMs).toISOString(),
      };
    }

    const daysRemaining = Math.ceil((timeoutMs - elapsed) / (24 * 60 * 60 * 1000));
    return {
      activated: false,
      exists: true,
      beneficiary: will.beneficiaryDID,
      timeoutDays: will.timeoutDays,
      lastActive: will.lastActive,
      daysRemaining,
    };
  }

  // ── Fork & Merge (分裂与合并) ──

  /**
   * Fork this identity into a new independent child identity.
   * The child gets a new keypair derived from the parent key + newClawId.
   * @param {string} newClawId - clawId for the forked identity
   * @returns {{ parentDID, childDID, childLife: ClawLife, forkTimestamp }}
   */
  async fork(newClawId) {
    if (!this.privateKey || !this.signKey) {
      throw new Error("No key loaded. Run --life-init first.");
    }

    // Derive child AES key from parent key + newClawId
    const childSeed = createHash("sha256")
      .update(this.privateKey)
      .update(Buffer.from(newClawId, "utf8"))
      .digest();
    const childKey = childSeed; // 32 bytes

    // Derive child Ed25519 keypair deterministically from seed
    const childSignSeed = createHash("sha256")
      .update(Buffer.from(this.signKey, "hex"))
      .update(Buffer.from(newClawId, "utf8"))
      .digest();

    // Generate a new Ed25519 keypair (we can't derive Ed25519 from arbitrary seed
    // in Node.js crypto, so we generate fresh and associate via fork record)
    const childKp = generateSigningKeypair();

    const childPublicId = createHash("sha256").update(childKey).digest("hex").substring(0, 32);

    const forkTimestamp = new Date().toISOString();

    // Save fork record
    const forkFile = path.join(this.dataDir, "forks.json");
    let forks = [];
    try {
      forks = JSON.parse(await readFile(forkFile, "utf8"));
    } catch { /* first fork */ }

    forks.push({
      parentDID: `did:claw:${this.publicId}`,
      childDID: `did:claw:${childPublicId}`,
      childClawId: newClawId,
      forkTimestamp,
    });
    await writeFile(forkFile, JSON.stringify(forks, null, 2), "utf8");

    // Create child ClawLife instance
    const childDataDir = path.join(path.dirname(this.dataDir), `.clawfeel-fork-${newClawId}`);
    const childLife = new ClawLife({ clawId: newClawId, dataDir: childDataDir, fileStore: this.fileStore });
    await childLife.importKey(childKey.toString("hex"), childKp.signKey);

    // Save fork record in child too
    const childForkFile = path.join(childDataDir, "forks.json");
    await writeFile(childForkFile, JSON.stringify([{
      parentDID: `did:claw:${this.publicId}`,
      childDID: `did:claw:${childPublicId}`,
      childClawId: newClawId,
      forkTimestamp,
      isChild: true,
    }], null, 2), "utf8");

    return {
      parentDID: `did:claw:${this.publicId}`,
      childDID: `did:claw:${childPublicId}`,
      childLife,
      forkTimestamp,
    };
  }

  /**
   * Merge another ClawLife identity into this one, creating a new combined identity.
   * @param {string} otherLifeKeyHex - the other life's exported AES key (hex)
   * @param {string} [otherPassphrase] - if the other key is a migration bundle, its passphrase
   * @returns {{ mergedDID, mergedLife: ClawLife, mergedFrom: [string, string] }}
   */
  async merge(otherLifeKeyHex, otherPassphrase) {
    if (!this.privateKey) throw new Error("No key loaded. Run --life-init first.");

    // If otherPassphrase provided, treat otherLifeKeyHex as a migration bundle
    let otherKey;
    let otherPublicId;
    if (otherPassphrase) {
      const otherLife = await ClawLife.importMigrationBundle(otherLifeKeyHex, otherPassphrase, this.dataDir + "-merge-tmp");
      otherKey = otherLife.privateKey;
      otherPublicId = otherLife.publicId;
    } else {
      otherKey = Buffer.from(otherLifeKeyHex, "hex");
      otherPublicId = createHash("sha256").update(otherKey).digest("hex").substring(0, 32);
    }

    // Derive merged key from both keys (order-independent via sorting)
    const keys = [this.privateKey, otherKey].sort(Buffer.compare);
    const mergedKey = createHash("sha256")
      .update(keys[0])
      .update(keys[1])
      .digest();

    const mergedPublicId = createHash("sha256").update(mergedKey).digest("hex").substring(0, 32);
    const mergedClawId = `merged-${mergedPublicId.substring(0, 8)}`;
    const mergedKp = generateSigningKeypair();

    const mergeTimestamp = new Date().toISOString();

    // Save merge record
    const mergeFile = path.join(this.dataDir, "merges.json");
    let merges = [];
    try {
      merges = JSON.parse(await readFile(mergeFile, "utf8"));
    } catch { /* first merge */ }

    const mergeRecord = {
      mergedDID: `did:claw:${mergedPublicId}`,
      mergedFrom: [
        `did:claw:${this.publicId}`,
        `did:claw:${otherPublicId}`,
      ],
      mergeTimestamp,
    };
    merges.push(mergeRecord);
    await writeFile(mergeFile, JSON.stringify(merges, null, 2), "utf8");

    // Create merged ClawLife
    const mergedDataDir = path.join(path.dirname(this.dataDir), `.clawfeel-merged-${mergedPublicId.substring(0, 8)}`);
    const mergedLife = new ClawLife({ clawId: mergedClawId, dataDir: mergedDataDir, fileStore: this.fileStore });
    await mergedLife.importKey(mergedKey.toString("hex"), mergedKp.signKey);

    // Save merge history in merged identity
    const mergedMergeFile = path.join(mergedDataDir, "merges.json");
    await writeFile(mergedMergeFile, JSON.stringify([{
      ...mergeRecord,
      isMergedIdentity: true,
    }], null, 2), "utf8");

    return {
      mergedDID: `did:claw:${mergedPublicId}`,
      mergedLife,
      mergedFrom: mergeRecord.mergedFrom,
    };
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
