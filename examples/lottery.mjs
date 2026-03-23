#!/usr/bin/env node
/**
 * ClawFeel Example: Fair Lottery / Raffle Draw
 *
 * Uses ClawFeel's decentralized random beacon to draw winners
 * from a list of participants. Fully verifiable — anyone can
 * recompute the result from the beacon round.
 *
 * Usage: node examples/lottery.mjs
 */

import { ClawRandom } from "clawfeel";

const participants = [
  "Alice", "Bob", "Charlie", "Diana", "Eve",
  "Frank", "Grace", "Hank", "Ivy", "Jack",
  "Karen", "Leo", "Mia", "Nick", "Olivia",
];

async function drawWinners(count = 3) {
  console.log("🎰 ClawFeel Fair Lottery Draw");
  console.log("═".repeat(40));
  console.log(`   Participants: ${participants.length}`);
  console.log(`   Winners: ${count}`);
  console.log("");

  const claw = await ClawRandom.remote();
  const beacon = await claw.getBeacon();

  console.log(`   📡 Beacon Round: #${beacon.round}`);
  console.log(`   🔑 Beacon Hash: ${beacon.beaconHash.substring(0, 16)}...`);
  console.log(`   👥 Contributors: ${beacon.contributorCount}`);
  console.log("");

  // Use beacon to deterministically select winners
  const winners = [];
  const pool = [...participants];

  for (let i = 0; i < count && pool.length > 0; i++) {
    const index = await claw.range(0, pool.length - 1);
    winners.push(pool.splice(index, 1)[0]);
  }

  console.log("🏆 Winners:");
  winners.forEach((w, i) => {
    console.log(`   ${i + 1}. ${w}`);
  });

  console.log("");
  console.log("✅ Verify: anyone can recompute using beacon round #" + beacon.round);
  console.log(`   curl https://clawfeel-relay.fly.dev/api/v1/random/verify?round=${beacon.round}`);
}

drawWinners(3).catch(console.error);
