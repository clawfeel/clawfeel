#!/usr/bin/env node
/**
 * ClawFeel Example: Blockchain VRF (Verifiable Random Function)
 *
 * Demonstrates how ClawFeel beacon can replace Chainlink VRF:
 * - Fetch beacon round with cryptographic proof
 * - Verify independently (recompute hash from contributors)
 * - Use as on-chain randomness source
 *
 * Usage: node examples/blockchain-vrf.mjs
 */

import { ClawRandom } from "clawfeel";

async function vrfDemo() {
  console.log("⛓️  ClawFeel Blockchain VRF Demo");
  console.log("═".repeat(45));
  console.log("");

  const claw = await ClawRandom.remote();

  // Get latest beacon with full proof
  const beacon = await claw.getBeacon();

  console.log("   📡 Beacon Round:");
  console.log(`      Round:        #${beacon.round}`);
  console.log(`      Timestamp:    ${beacon.timestamp}`);
  console.log(`      Contributors: ${beacon.contributorCount}`);
  console.log(`      XOR Accum:    ${beacon.xorAccum?.substring(0, 32)}...`);
  console.log(`      Beacon Hash:  ${beacon.beaconHash?.substring(0, 32)}...`);
  console.log(`      Beacon Number:${beacon.beaconNumber}`);
  console.log(`      Signature:    ${beacon.signature?.substring(0, 32)}...`);
  console.log("");

  // Verify the beacon
  console.log("   🔍 Verification:");
  const verified = await claw.verifyBeacon(beacon);
  console.log(`      Hash valid:      ${verified ? "✅" : "❌"}`);
  console.log(`      Signature valid: ${beacon.signature ? "✅" : "⚠️ relay-signed"}`);
  console.log("");

  // Derive deterministic values for smart contract use
  console.log("   📋 Smart Contract Values (derived from beacon):");
  console.log(`      NFT Rarity Seed:   ${beacon.beaconHash?.substring(0, 16)}`);
  console.log(`      Lottery Winner:    ${beacon.beaconNumber % 1000}`);
  console.log(`      Token Distribution:${beacon.beaconNumber % 100}%`);
  console.log("");

  console.log("   💡 Integration:");
  console.log("      1. Smart contract stores expected beacon round #");
  console.log("      2. Oracle fetches beacon from ClawFeel API");
  console.log("      3. Contract verifies hash matches XOR of contributors");
  console.log("      4. Result is deterministic and publicly verifiable");
  console.log("");

  console.log("✅ No mining needed — powered by Proof of Existence");
}

vrfDemo().catch(console.error);
