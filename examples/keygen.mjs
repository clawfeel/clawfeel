#!/usr/bin/env node
/**
 * ClawFeel Example: Cryptographic Key Generation
 *
 * Generates crypto-grade random keys using hardware entropy
 * from the ClawFeel network. Suitable for:
 * - AES-256 encryption keys
 * - API tokens
 * - Session secrets
 * - Wallet seed phrases
 *
 * Usage: node examples/keygen.mjs
 */

import { ClawRandom } from "clawfeel";

async function generateKeys() {
  console.log("🔐 ClawFeel Cryptographic Key Generator");
  console.log("═".repeat(45));
  console.log("");

  const claw = await ClawRandom.local();

  // AES-256 key (256 bits = 32 bytes)
  const aesKey = await claw.getEntropy(256);
  console.log("   AES-256 Key:");
  console.log(`   ${aesKey}`);
  console.log("");

  // API Token (128 bits)
  const token = await claw.getEntropy(128);
  console.log("   API Token:");
  console.log(`   cf_${token}`);
  console.log("");

  // Session Secret (512 bits)
  const secret = await claw.getEntropy(512);
  console.log("   Session Secret (512-bit):");
  console.log(`   ${secret}`);
  console.log("");

  // Random bytes (Base64)
  const bytes = await claw.randomBytes(32);
  console.log("   Random Bytes (Base64):");
  console.log(`   ${bytes}`);
  console.log("");

  console.log("✅ All keys generated from hardware entropy (7 sensors + SHA-256)");
  console.log("   Entropy quality: crypto-grade (256-bit per reading)");
}

generateKeys().catch(console.error);
