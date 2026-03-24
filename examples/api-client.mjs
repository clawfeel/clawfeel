#!/usr/bin/env node
/**
 * ClawFeel Example: Enterprise API Client
 *
 * Demonstrates the full Random Beacon API workflow:
 * 1. Register for a free API key
 * 2. Fetch random numbers (various formats)
 * 3. Verify beacon rounds
 * 4. Check usage stats
 *
 * Usage: node examples/api-client.mjs
 */

const RELAY = "https://api.clawfeel.ai";

async function apiDemo() {
  console.log("🏢 ClawFeel Enterprise API Demo");
  console.log("═".repeat(45));
  console.log("");

  // Step 1: Register for API key
  console.log("   📝 Step 1: Register for API key...");
  const regRes = await fetch(`${RELAY}/api/v1/keys/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "demo@example.com", name: "Demo App" }),
  });
  const reg = await regRes.json();
  const apiKey = reg.apiKey;
  console.log(`      Key: ${apiKey.substring(0, 10)}...`);
  console.log(`      Tier: ${reg.tier} (${reg.rateLimit} req/hr)`);
  console.log("");

  const headers = { Authorization: `Bearer ${apiKey}` };

  // Step 2: Get random number (256-bit hex)
  console.log("   🎲 Step 2: Random number (256-bit hex)...");
  const r1 = await fetch(`${RELAY}/api/v1/random?bits=256&format=hex`, { headers });
  const d1 = await r1.json();
  console.log(`      Value: ${d1.value.substring(0, 32)}...`);
  console.log(`      Beacon Round: #${d1.beacon_round}`);
  console.log("");

  // Step 3: Batch random numbers
  console.log("   📦 Step 3: Batch (5 × 64-bit integers)...");
  const r2 = await fetch(`${RELAY}/api/v1/random/batch?count=5&bits=64&format=integer`, { headers });
  const d2 = await r2.json();
  d2.values.forEach((v, i) => console.log(`      [${i}] ${v.value}`));
  console.log("");

  // Step 4: Random in range
  console.log("   🎯 Step 4: Random in range [1, 1000000]...");
  const r3 = await fetch(`${RELAY}/api/v1/random/range?min=1&max=1000000`, { headers });
  const d3 = await r3.json();
  console.log(`      Value: ${d3.value}`);
  console.log("");

  // Step 5: Check API usage
  console.log("   📊 Step 5: API usage stats...");
  const r4 = await fetch(`${RELAY}/api/v1/status`, { headers });
  const d4 = await r4.json();
  console.log(`      Total requests: ${d4.totalRequests}`);
  console.log(`      Remaining: ${d4.remaining}`);
  console.log("");

  console.log("✅ Full API workflow complete!");
  console.log(`   Docs: https://clawfeel.ai/explorer.html#api`);
}

apiDemo().catch(console.error);
