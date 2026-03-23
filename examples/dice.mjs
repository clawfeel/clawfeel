#!/usr/bin/env node
/**
 * ClawFeel Example: Game Dice & Card Shuffle
 *
 * Uses hardware entropy for provably fair gaming:
 * - Dice rolls (D6, D20, custom)
 * - Coin flips
 * - Card shuffling (Fisher-Yates with hardware RNG)
 *
 * Usage: node examples/dice.mjs
 */

import { ClawRandom } from "clawfeel";

async function gamingDemo() {
  const claw = await ClawRandom.local();

  console.log("🎲 ClawFeel Gaming Random Generator");
  console.log("═".repeat(40));
  console.log("");

  // Roll dice
  console.log("   🎲 Dice Rolls:");
  for (let i = 0; i < 5; i++) {
    const d6 = await claw.range(1, 6);
    const d20 = await claw.range(1, 20);
    console.log(`      Roll ${i + 1}: D6=${d6}  D20=${d20}`);
  }
  console.log("");

  // Coin flips
  console.log("   🪙 Coin Flips:");
  const flips = [];
  for (let i = 0; i < 10; i++) {
    const flip = await claw.range(0, 1);
    flips.push(flip === 0 ? "H" : "T");
  }
  console.log(`      ${flips.join(" ")}`);
  console.log(`      Heads: ${flips.filter(f => f === "H").length} / Tails: ${flips.filter(f => f === "T").length}`);
  console.log("");

  // Shuffle a deck of cards
  console.log("   🃏 Card Shuffle (top 5):");
  const suits = ["♠", "♥", "♦", "♣"];
  const ranks = ["A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K"];
  const deck = [];
  for (const s of suits) for (const r of ranks) deck.push(r + s);

  // Fisher-Yates shuffle with hardware entropy
  for (let i = deck.length - 1; i > 0; i--) {
    const j = await claw.range(0, i);
    [deck[i], deck[j]] = [deck[j], deck[i]];
  }

  console.log(`      ${deck.slice(0, 5).join("  ")}`);
  console.log("");

  // Random color
  const r = await claw.range(0, 255);
  const g = await claw.range(0, 255);
  const b = await claw.range(0, 255);
  console.log(`   🎨 Random Color: rgb(${r}, ${g}, ${b}) = #${r.toString(16).padStart(2,"0")}${g.toString(16).padStart(2,"0")}${b.toString(16).padStart(2,"0")}`);
  console.log("");

  console.log("✅ All random values from hardware entropy — provably fair");
}

gamingDemo().catch(console.error);
