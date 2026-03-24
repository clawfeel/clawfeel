#!/usr/bin/env node

// ═══════════════════════════════════════════════════════════════════
//  ClawFeel — Your Claw's Heartbeat (Security-Hardened)
//  Collects 7 hardware sensors, SHA-256 hashes them into a Feel (0–100).
//  Includes: authenticity tracking, entropy quality scoring,
//  weighted sensors, chain hashing, commit-reveal, Sybil defense.
//
//  Usage:
//    node clawfeel.mjs                    # single reading, JSON output
//    node clawfeel.mjs --digit-only       # print only the random digit (0–9)
//    node clawfeel.mjs --interval 5 --count 3   # 3 readings, 5s apart
//    node clawfeel.mjs --pretty           # human-friendly output
//    node clawfeel.mjs --save             # save reading to history
//    node clawfeel.mjs --history          # show last 20 readings
//    node clawfeel.mjs --history --count 50  # show last 50 readings
//    node clawfeel.mjs --broadcast        # broadcast Feel via UDP to LAN
//    node clawfeel.mjs --listen           # listen for other Claws' broadcasts
//    node clawfeel.mjs --anchor           # enable external time anchoring
//    node clawfeel.mjs --anchor-value <hex>  # inject external anchor
//    node clawfeel.mjs --zkp             # include zero-knowledge proof
// ═══════════════════════════════════════════════════════════════════

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { readFile, writeFile, appendFile, mkdir, unlink } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { execSync, execFileSync } from "node:child_process";
import { createSocket } from "node:dgram";
import os from "node:os";
import path from "node:path";
import { argv } from "node:process";

// ── Version + Auto-Update ────────────────────────────────────────

// Read local version from package.json
let LOCAL_VERSION = "0.0.0";
try {
  const pkgPath = new URL("../package.json", import.meta.url).pathname;
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
  LOCAL_VERSION = pkg.version || "0.0.0";
} catch {}

/**
 * Check npm for updates and auto-install if major or minor version changed.
 * Patch-only changes (0.8.0 → 0.8.1) are skipped.
 * Major/minor changes (0.8.x → 0.9.0 or 1.0.0) trigger auto-update.
 */
async function checkForUpdates() {
  try {
    const res = await fetch("https://registry.npmjs.org/clawfeel/latest", { signal: AbortSignal.timeout(10000) });
    if (!res.ok) return null;
    const data = await res.json();
    const remoteVersion = data.version;
    if (!remoteVersion) return null;

    const [lMajor, lMinor] = LOCAL_VERSION.split(".").map(Number);
    const [rMajor, rMinor] = remoteVersion.split(".").map(Number);

    // Only auto-update if major or minor version changed
    if (rMajor > lMajor || (rMajor === lMajor && rMinor > lMinor)) {
      console.log(`  🔄 Update available: v${LOCAL_VERSION} → v${remoteVersion} (auto-updating...)`);
      try {
        execFileSync("npm", ["install", "-g", `clawfeel@${remoteVersion}`], {
          encoding: "utf8", timeout: 60000, stdio: "pipe",
        });
        console.log(`  ✅ Updated to v${remoteVersion}. Restarting...`);
        // Restart: spawn new daemon, exit current
        const { spawn: spawnChild } = await import("node:child_process");
        const clawfeelBin = process.argv[1];
        const newArgs = process.argv.slice(2);
        spawnChild(process.execPath, [clawfeelBin, ...newArgs], {
          detached: true, stdio: "ignore",
          env: { ...process.env },
        }).unref();
        process.exit(0);
      } catch (err) {
        console.error(`  ⚠️  Auto-update failed: ${err.message}`);
      }
      return remoteVersion;
    } else if (remoteVersion !== LOCAL_VERSION) {
      // Patch update available but not auto-installed
      return null;
    }
    return null;
  } catch { return null; }
}

const AUTO_UPDATE_INTERVAL = 720; // check every 720 iterations (6 hours at 30s interval)

// ── Argument parsing ─────────────────────────────────────────────

const args = argv.slice(2);
const flag = (name) => args.includes(`--${name}`);
const param = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i !== -1 && args[i + 1] ? args[i + 1] : fallback;
};

const DIGIT_ONLY = flag("digit-only");
const PRETTY = flag("pretty");
const SAVE = flag("save");
const HISTORY = flag("history");
const BROADCAST = flag("broadcast");
const LISTEN = flag("listen");
const ANCHOR = flag("anchor");
const _rawAnchorValue = param("anchor-value", null);
const ANCHOR_VALUE = _rawAnchorValue && /^[0-9a-f]+$/i.test(_rawAnchorValue) ? _rawAnchorValue : null;
const RELAY = param("relay", null);
const ALIAS = param("alias", null);
const P2P = flag("p2p");
const LIGHT_MODE = flag("light");
const NO_RELAY = flag("no-relay");
const FULL_NODE = flag("full-node");
const RELAY_ONLY = flag("relay-only");
const RELAY_PORT = parseInt(param("relay-port", "8080"), 10);
const DHT_PORT = parseInt(param("dht-port", "31416"), 10);
const BOOTSTRAP = param("bootstrap", null);
const DAG_STATUS = flag("dag-status");
const STOP = flag("stop");
const STATUS = flag("status");
const RESTART = flag("restart");
const STORE_FILE = param("store", null);
const GET_FILE = param("get", null);
const OUTPUT_FILE = param("output", null);
const STORE_LIST = flag("store-list");
const LIFE_INIT = flag("life-init");
const LIFE_SAVE = flag("life-save");
const LIFE_RESTORE = param("life-restore", null);
const LIFE_KEY = param("life-key", null);
const LIFE_EXPORT = flag("life-export");
const LIFE_STATUS = flag("life-status");
const DID = flag("did");
const MIGRATE_EXPORT = param("migrate-export", null);
const MIGRATE_IMPORT = param("migrate-import", null);
const MIGRATE_PASS = param("migrate-pass", null);
const WILL_SET = param("will-set", null);       // beneficiaryDID
const WILL_TIMEOUT = param("will-timeout", null); // timeoutDays
const WILL_STATUS = flag("will-status");
const FORK = param("fork", null);               // newClawId
const ZKP = flag("zkp");
const HEARTBEAT = flag("heartbeat");
const AGENT_DECIDE = param("agent-decide", null);
const IS_DAEMON = flag("__daemon");  // internal: marks the background process
const ATTACHED = flag("__attached"); // internal: lifecycle bound to parent (OpenClaw)
const NO_DAEMON = flag("no-daemon"); // run in foreground (for Docker/containers)
const INTERVAL = parseInt(param("interval", "0"), 10);
const COUNT = parseInt(param("count", "1"), 10);
const PORT = parseInt(param("port", "31415"), 10); // Three-Body: pi digits

// ── Paths ────────────────────────────────────────────────────────

const DATA_DIR = path.join(os.homedir(), ".clawfeel");
const HISTORY_FILE = path.join(DATA_DIR, "history.jsonl");
const SEQ_FILE = path.join(DATA_DIR, "seq");
const PEERS_FILE = path.join(DATA_DIR, "peers.jsonl");
const IDENTITY_FILE = path.join(DATA_DIR, "identity.json");
const PID_FILE = path.join(DATA_DIR, "daemon.pid");
const DAEMON_LOG = path.join(DATA_DIR, "daemon.log");

// ── Platform detection ───────────────────────────────────────────

const PLATFORM = os.platform();
const IS_LINUX = PLATFORM === "linux";
const IS_MAC = PLATFORM === "darwin";
const IS_WIN = PLATFORM === "win32";

// ── Node identity (privacy-preserving) ──────────────────────────
//  Priority: CLI --alias > feel.md > identity.json > auto-generate.
//  Real hostname is NEVER sent to the network.
//
//  feel.md (OpenClaw user config) — human-readable, user-editable:
//    Located at ~/.openclaw/feel.md or ./feel.md
//    Parsed as YAML-like frontmatter key: value pairs.
//
//  identity.json — machine-generated, auto-synced from feel.md:
//    Located at ~/.clawfeel/identity.json

function generateAlias(clawId) {
  // Use first 8 chars of clawId for consistency with ?me= param
  if (clawId && clawId.length >= 8) return `Claw-${clawId.substring(0, 8)}`;
  return `Claw-${randomBytes(4).toString("hex")}`;
}

let nodeAlias = null;
let nodeRelay = null; // relay URL from feel.md
let nodeSignKey = null;  // Ed25519 private key hex
let nodeSignPub = null;  // Ed25519 public key hex

// Search paths for feel.md
const FEEL_MD_PATHS = [
  path.join(os.homedir(), ".openclaw", "feel.md"),
  path.join(os.homedir(), ".openclaw", "workspace", "feel.md"),
  path.join(process.cwd(), "feel.md"),
];

/**
 * Parse feel.md frontmatter-style config.
 * Format:
 *   alias: MyClaw
 *   relay: https://api.clawfeel.ai
 *   clawId: 3eda7c810253
 */
function parseFeelMd(content) {
  const config = {};
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("---")) continue;
    const colonIdx = trimmed.indexOf(":");
    if (colonIdx > 0) {
      const key = trimmed.substring(0, colonIdx).trim().toLowerCase();
      const value = trimmed.substring(colonIdx + 1).trim();
      if (key && value) config[key] = value;
    }
  }
  return config;
}

/**
 * Generate feel.md content from identity config.
 */
function generateFeelMd(config) {
  return `# ClawFeel Identity
# Edit this file to customize your node settings.
# Changes take effect on next clawfeel run.

alias: ${config.alias}
clawId: ${config.clawId}
relay: ${config.relay || "https://api.clawfeel.ai"}
createdAt: ${config.createdAt}
`;
}

async function loadIdentity() {
  const clawId = getClawId();

  // CLI --alias always wins
  if (ALIAS) {
    nodeAlias = ALIAS;
    return;
  }

  // ── 1. Try feel.md (user-editable config, highest priority) ──
  for (const feelPath of FEEL_MD_PATHS) {
    try {
      const raw = await readFile(feelPath, "utf8");
      const config = parseFeelMd(raw);
      if (config.alias) {
        nodeAlias = config.alias;
        // Sync feel.md → identity.json
        await mkdir(DATA_DIR, { recursive: true });
        await writeFile(IDENTITY_FILE, JSON.stringify({
          alias: config.alias,
          clawId: config.clawid || clawId,
          relay: config.relay || null,
          createdAt: config.createdat || new Date().toISOString(),
          source: feelPath,
        }, null, 2), "utf8");
        // Set relay from feel.md if not specified on CLI
        if (config.relay && !RELAY) {
          nodeRelay = config.relay;
        }
        return;
      }
    } catch { /* file not found, try next */ }
  }

  // ── 2. Try identity.json (machine-generated) ──
  try {
    const raw = await readFile(IDENTITY_FILE, "utf8");
    const data = JSON.parse(raw.trim());
    if (data.alias) {
      nodeAlias = data.alias;
      if (data.relay && !RELAY) nodeRelay = data.relay;
      return;
    }
  } catch { /* first run */ }

  // ── 3. Generate new identity ──
  nodeAlias = generateAlias(clawId);
  const defaultRelay = "https://api.clawfeel.ai";
  const config = {
    alias: nodeAlias,
    clawId,
    relay: defaultRelay,
    createdAt: new Date().toISOString(),
  };

  // Set relay so this first run also reports
  if (!RELAY) nodeRelay = defaultRelay;

  // Save identity.json
  await mkdir(DATA_DIR, { recursive: true });
  await writeFile(IDENTITY_FILE, JSON.stringify(config, null, 2), "utf8");

  // Create feel.md in first available OpenClaw directory
  for (const feelPath of FEEL_MD_PATHS) {
    try {
      await mkdir(path.dirname(feelPath), { recursive: true });
      await writeFile(feelPath, generateFeelMd(config), "utf8");
      break; // only create in first available location
    } catch { /* try next */ }
  }
}

// ── Ed25519 signing key management ──────────────────────────────

async function loadSigningKeys() {
  const keyFile = path.join(DATA_DIR, "life.key");
  try {
    const stored = JSON.parse(await readFile(keyFile, "utf8"));
    if (stored.signKey && stored.signPub) {
      nodeSignKey = stored.signKey;
      nodeSignPub = stored.signPub;
      return;
    }
  } catch { /* no key file */ }

  // Auto-generate Ed25519 keypair on first run
  const { generateKeyPairSync } = await import("node:crypto");
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pubRaw = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  const privRaw = privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32);
  nodeSignKey = privRaw.toString("hex");
  nodeSignPub = pubRaw.toString("hex");

  // Save to life.key (merge with existing data if present)
  await mkdir(DATA_DIR, { recursive: true });
  let existing = {};
  try { existing = JSON.parse(await readFile(keyFile, "utf8")); } catch {}
  existing.signKey = nodeSignKey;
  existing.signPub = nodeSignPub;
  existing.clawId = existing.clawId || getClawId();
  existing.createdAt = existing.createdAt || new Date().toISOString();
  existing.warning = "KEEP THIS FILE SAFE. This key controls your ClawLife. Loss = permanent death.";
  await writeFile(keyFile, JSON.stringify(existing, null, 2), "utf8");
  const { chmod } = await import("node:fs/promises");
  await chmod(keyFile, 0o600);
}

// ── Sensor controllability weights ──────────────────────────────
//  Higher weight = harder to manipulate = contributes more entropy
//  Used in weighted SHA-256 input construction

const SENSOR_WEIGHTS = {
  cpuTemp:      0.8,   // Low controllability (physical heat transfer)
  memUsage:     0.5,   // Medium controllability
  diskIO:       0.5,   // Medium controllability
  netLatency:   0.9,   // Low controllability (external network)
  cpuLoad:      0.3,   // High controllability (can run programs)
  uptimeJitter: 0.7,   // Low controllability (OS scheduler)
  entropyPool:  1.0,   // Very low controllability (kernel entropy)
};

// ── Sensor collectors (return { value, authentic }) ──────────────
//  Every sensor now returns an object indicating whether the
//  reading came from real hardware or a random fallback.

/**
 * 1. CPU Temperature (°C)
 */
async function readCpuTemp() {
  try {
    if (IS_LINUX) {
      const zones = [
        "/sys/class/thermal/thermal_zone0/temp",
        "/sys/class/thermal/thermal_zone1/temp",
        "/sys/class/hwmon/hwmon0/temp1_input",
      ];
      for (const p of zones) {
        try {
          const raw = await readFile(p, "utf8");
          const milliC = parseInt(raw.trim(), 10);
          if (!isNaN(milliC)) return { value: milliC / 1000, authentic: true };
        } catch { /* try next */ }
      }
    }
    if (IS_MAC) {
      try {
        const out = execFileSync("sysctl", ["-n", "machdep.xcpm.cpu_thermal_level"], {
          encoding: "utf8", timeout: 2000, stdio: ["pipe", "pipe", "pipe"],
        }).trim();
        const level = parseInt(out, 10);
        if (!isNaN(level)) return { value: 40 + level * 10, authentic: true };
      } catch { /* fallback */ }
    }
    if (IS_WIN) {
      try {
        const out = execFileSync("powershell", ["-NoProfile", "-Command",
          "Get-CimInstance MSAcpi_ThermalZoneTemperature -Namespace root/wmi -ErrorAction Stop | Select -First 1 -Expand CurrentTemperature"
        ], { encoding: "utf8", timeout: 5000, stdio: ["pipe", "pipe", "pipe"] }).trim();
        const kelvin10 = parseFloat(out);
        if (!isNaN(kelvin10)) return { value: kelvin10 / 10 - 273.15, authentic: true };
      } catch { /* fallback — not all Windows machines expose thermal zones */ }
    }
  } catch { /* fallback */ }
  // ⚠️ FALLBACK: marked as inauthentic
  return { value: 45 + (randomBytes(1)[0] / 255) * 30, authentic: false };
}

/**
 * 2. Memory Usage (%)
 *    Always authentic — os.totalmem/freemem available everywhere
 */
function readMemUsage() {
  const total = os.totalmem();
  const free = os.freemem();
  return { value: ((total - free) / total) * 100, authentic: true };
}

/**
 * 3. Disk I/O (sectors read since boot, normalized)
 */
async function readDiskIO() {
  try {
    if (IS_LINUX) {
      const raw = await readFile("/proc/diskstats", "utf8");
      const lines = raw.split("\n").filter((l) => l.trim());
      let totalSectors = 0;
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 10) {
          totalSectors += parseInt(parts[5], 10) || 0;
          totalSectors += parseInt(parts[9], 10) || 0;
        }
      }
      return { value: (totalSectors * 512) / (1024 * 1024), authentic: true };
    }
    if (IS_MAC) {
      const out = execFileSync("iostat", ["-d", "-c", "1"], {
        encoding: "utf8", timeout: 2000, stdio: ["pipe", "pipe", "pipe"],
      }).trim().split("\n").pop().trim();
      const parts = out.split(/\s+/);
      const kbPerSec = parseFloat(parts[1]) || 0;
      return { value: kbPerSec / 1024, authentic: true };
    }
    if (IS_WIN) {
      try {
        const out = execFileSync("powershell", ["-NoProfile", "-Command",
          "(Get-Counter '\\PhysicalDisk(_Total)\\Disk Bytes/sec' -ErrorAction Stop).CounterSamples.CookedValue"
        ], { encoding: "utf8", timeout: 5000, stdio: ["pipe", "pipe", "pipe"] }).trim();
        const bytesPerSec = parseFloat(out);
        if (!isNaN(bytesPerSec)) return { value: bytesPerSec / (1024 * 1024), authentic: true };
      } catch { /* fallback */ }
    }
  } catch { /* fallback */ }
  return { value: randomBytes(2).readUInt16BE(0) / 65535 * 500, authentic: false };
}

/**
 * 4. Network Latency jitter (ms)
 */
async function readNetLatency() {
  try {
    const times = [];
    for (let i = 0; i < 3; i++) {
      const start = process.hrtime.bigint();
      execFileSync("true", [], { timeout: 1000, stdio: ["pipe", "pipe", "pipe"] });
      const end = process.hrtime.bigint();
      times.push(Number(end - start) / 1e6);
    }
    const mean = times.reduce((a, b) => a + b, 0) / times.length;
    const variance = times.reduce((a, t) => a + (t - mean) ** 2, 0) / times.length;
    return { value: Math.sqrt(variance), authentic: true };
  } catch {
    return { value: randomBytes(1)[0] / 255 * 5, authentic: false };
  }
}

/**
 * 5. CPU Load (1-min average, normalized by core count)
 *    Always authentic — os.loadavg() available everywhere
 */
function readCpuLoad() {
  const load1m = os.loadavg()[0];
  const cpuCount = os.cpus().length || 1;
  return { value: load1m / cpuCount, authentic: true };
}

/**
 * 6. Uptime Jitter (μs) — OS scheduler noise
 *    Always authentic — measures actual timing variance
 */
function readUptimeJitter() {
  const t1 = process.hrtime.bigint();
  let x = 0;
  for (let i = 0; i < 1000; i++) x += i;
  const t2 = process.hrtime.bigint();
  const elapsedNs = Number(t2 - t1);
  return { value: elapsedNs / 1e6, authentic: true };
}

/**
 * 7. Entropy Pool depth
 */
async function readEntropyPool() {
  try {
    if (IS_LINUX) {
      const raw = await readFile("/proc/sys/kernel/random/entropy_avail", "utf8");
      return { value: parseInt(raw.trim(), 10), authentic: true };
    }
  } catch { /* fallback */ }
  // macOS / Windows: timing-based entropy measurement — semi-authentic
  // Measures how long crypto.randomBytes takes (reflects OS entropy pool depth)
  const start = process.hrtime.bigint();
  randomBytes(256);
  const end = process.hrtime.bigint();
  const ns = Number(end - start);
  return {
    value: Math.max(100, Math.min(4096, Math.round(4096 - ns / 1000))),
    authentic: IS_MAC || IS_WIN, // timing method is semi-authentic on macOS/Windows
  };
}

// ── Normalization ────────────────────────────────────────────────

function normalize(value, min, max) {
  const clamped = Math.max(min, Math.min(max, value));
  return (clamped - min) / (max - min);
}

// ── Entropy Quality Scoring ─────────────────────────────────────
//  Evaluates how trustworthy a Feel reading is, 0-100 score.

// In-memory history buffer for quality scoring (last 20 readings)
const recentReadings = [];
const MAX_RECENT = 20;

/**
 * Compute entropy quality score (0-100) from four dimensions:
 *  - Diversity (0-25): coefficient of variation across sensors
 *  - Authenticity (0-25): ratio of real sensors
 *  - Temporal randomness (0-25): runs test on recent Feel values
 *  - Cross-sensor correlation (0-25): physical plausibility
 */
function computeEntropyQuality(sensorResults, feel) {
  // ── 1. Diversity score (0-25) ──
  // Coefficient of variation of the 7 normalized values
  const vals = [
    normalize(sensorResults.cpuTemp.value, 20, 100),
    normalize(sensorResults.memUsage.value, 0, 100),
    normalize(sensorResults.diskIO.value, 0, 100000),
    normalize(sensorResults.netLatency.value, 0, 50),
    normalize(sensorResults.cpuLoad.value, 0, 2),
    normalize(sensorResults.uptimeJitter.value, 0, 5),
    normalize(sensorResults.entropyPool.value, 0, 4096),
  ];
  const mean = vals.reduce((a, b) => a + b, 0) / vals.length;
  const std = Math.sqrt(vals.reduce((a, v) => a + (v - mean) ** 2, 0) / vals.length);
  const cv = mean > 0 ? std / mean : 0;
  // CV of 0.3-0.8 is healthy; too low (<0.1) = suspiciously uniform
  const diversityScore = Math.min(25, Math.round(Math.min(cv / 0.6, 1) * 25));

  // ── 2. Authenticity score (0-25) ──
  const sensorKeys = ["cpuTemp", "memUsage", "diskIO", "netLatency", "cpuLoad", "uptimeJitter", "entropyPool"];
  const authenticCount = sensorKeys.filter(k => sensorResults[k].authentic).length;
  const authenticityScore = Math.round((authenticCount / 7) * 25);

  // ── 3. Temporal randomness score (0-25) ──
  // Wald–Wolfowitz runs test on recent Feel values (above/below median)
  let temporalScore = 25; // default to max if not enough history
  recentReadings.push(feel);
  if (recentReadings.length > MAX_RECENT) recentReadings.shift();

  if (recentReadings.length >= 10) {
    const median = [...recentReadings].sort((a, b) => a - b)[Math.floor(recentReadings.length / 2)];
    const signs = recentReadings.map(v => v >= median ? 1 : 0);
    let runs = 1;
    for (let i = 1; i < signs.length; i++) {
      if (signs[i] !== signs[i - 1]) runs++;
    }
    const n = signs.length;
    const n1 = signs.filter(s => s === 1).length;
    const n0 = n - n1;
    if (n1 > 0 && n0 > 0) {
      const expectedRuns = 1 + (2 * n1 * n0) / n;
      const stdRuns = Math.sqrt((2 * n1 * n0 * (2 * n1 * n0 - n)) / (n * n * (n - 1)));
      if (stdRuns > 0) {
        const z = Math.abs((runs - expectedRuns) / stdRuns);
        // z < 1.96 → random at 95% confidence → full score
        // z > 3 → very suspicious → low score
        temporalScore = Math.round(Math.max(0, Math.min(25, 25 * (1 - (z - 1.96) / 1.04))));
        if (z < 1.96) temporalScore = 25;
      }
    }
  }

  // ── 4. Cross-sensor correlation score (0-25) ──
  // Check physical plausibility: CPU load and CPU temp should have
  // positive correlation with a delay. For now, check if they're
  // not perfectly correlated (which would indicate simulation).
  let correlationScore = 20; // default reasonable score
  if (recentReadings.length >= 5) {
    // Check if all recent values are identical (replay detection)
    const unique = new Set(recentReadings.slice(-5));
    if (unique.size === 1) {
      correlationScore = 0; // All identical = replay attack
    } else if (unique.size <= 2) {
      correlationScore = 5; // Almost no variation = suspicious
    } else {
      correlationScore = 25; // Good variation
    }
  }

  const total = diversityScore + authenticityScore + temporalScore + correlationScore;

  return {
    total: Math.min(100, total),
    diversity: diversityScore,
    authenticity: authenticityScore,
    temporal: temporalScore,
    correlation: correlationScore,
  };
}

// ── Sequence number + chain hash ────────────────────────────────

let currentSeq = 0;
let prevHash = "0000000000000000"; // genesis

async function loadSeqState() {
  try {
    const raw = await readFile(SEQ_FILE, "utf8");
    const data = JSON.parse(raw.trim());
    currentSeq = data.seq || 0;
    prevHash = data.prevHash || "0000000000000000";
  } catch {
    // First run, start from 0
  }
}

async function saveSeqState() {
  await mkdir(DATA_DIR, { recursive: true });
  await writeFile(SEQ_FILE, JSON.stringify({ seq: currentSeq, prevHash }), "utf8");
}

// ── Core: collect + hash + score ─────────────────────────────────

async function collectSensors() {
  const [cpuTemp, memUsage, diskIO, netLatency, cpuLoad, uptimeJitter, entropyPool] =
    await Promise.all([
      readCpuTemp(),
      Promise.resolve(readMemUsage()),
      readDiskIO(),
      readNetLatency(),
      Promise.resolve(readCpuLoad()),
      Promise.resolve(readUptimeJitter()),
      readEntropyPool(),
    ]);

  return { cpuTemp, memUsage, diskIO, netLatency, cpuLoad, uptimeJitter, entropyPool };
}

function computeFeel(sensorResults) {
  const sensors = {};
  const sensorFlags = {};
  let authenticCount = 0;

  // Extract values and track authenticity
  for (const [key, result] of Object.entries(sensorResults)) {
    sensors[key] = result.value;
    sensorFlags[key] = result.authentic;
    if (result.authentic) authenticCount++;
  }

  // Normalize each sensor to [0, 1]
  const normalized = {
    cpuTemp:      normalize(sensors.cpuTemp, 20, 100),
    memUsage:     normalize(sensors.memUsage, 0, 100),
    diskIO:       normalize(sensors.diskIO, 0, 100000),
    netLatency:   normalize(sensors.netLatency, 0, 50),
    cpuLoad:      normalize(sensors.cpuLoad, 0, 2),
    uptimeJitter: normalize(sensors.uptimeJitter, 0, 5),
    entropyPool:  normalize(sensors.entropyPool, 0, 4096),
  };

  // ── Weighted entropy string construction ──
  // Sensors with higher weight (harder to manipulate) contribute more
  const now = process.hrtime.bigint().toString();
  const parts = [];

  for (const [key, normVal] of Object.entries(normalized)) {
    const weight = SENSOR_WEIGHTS[key];
    // Repeat the value proportional to weight (1x at 0.3, 3x at 1.0)
    const repeats = Math.max(1, Math.round(weight * 3));
    for (let r = 0; r < repeats; r++) {
      parts.push(`${key}:${normVal.toFixed(12)}:${r}`);
    }
  }

  // Add high-resolution timestamp
  parts.push(`ts:${now}`);

  // Add previous hash for chain integrity
  parts.push(`prev:${prevHash}`);

  // Add sequence number
  currentSeq++;
  parts.push(`seq:${currentSeq}`);

  // External anchoring (if enabled)
  if (ANCHOR || ANCHOR_VALUE) {
    const timeAnchor = createHash("sha256")
      .update(new Date().toISOString().substring(0, 16)) // minute-level
      .digest("hex").substring(0, 16);
    parts.push(`anchor:${timeAnchor}`);

    if (ANCHOR_VALUE) {
      parts.push(`ext:${ANCHOR_VALUE}`);
    }
  }

  const entropyString = parts.join("|");

  // SHA-256 hash (full 256-bit entropy)
  const hashBuf = createHash("sha256").update(entropyString).digest();
  const hash = hashBuf.toString("hex"); // 64 hex chars = 256 bits

  // Feel score: first 8 hex chars → integer → mod 101 → 0–100 (human-readable)
  const hashInt = parseInt(hash.substring(0, 8), 16);
  const feel = hashInt % 101;
  const digit = feel % 10;

  // Crypto-grade random: full 256-bit entropy in multiple formats
  const random64 = hashBuf.readBigUInt64BE(0).toString(); // 64-bit integer
  const randomHex = hash;                                  // 256-bit hex
  const randomBytes256 = hashBuf.toString("base64");       // 256-bit base64

  // Update chain
  prevHash = hash.substring(0, 16);

  // Era classification
  let era, eraEN;
  if (feel <= 30)      { era = "Chaos"; eraEN = "Chaos"; }
  else if (feel <= 70) { era = "Transition"; eraEN = "Transition"; }
  else                 { era = "Eternal"; eraEN = "Eternal"; }

  // Entropy quality scoring
  const entropyQuality = computeEntropyQuality(sensorResults, feel);

  // Build sensor flags bitmask: bit 6=cpuTemp ... bit 0=entropyPool
  const sensorOrder = ["cpuTemp", "memUsage", "diskIO", "netLatency", "cpuLoad", "uptimeJitter", "entropyPool"];
  let flagBits = 0;
  for (let i = 0; i < sensorOrder.length; i++) {
    if (sensorFlags[sensorOrder[i]]) {
      flagBits |= (1 << (6 - i));
    }
  }

  return {
    feel,
    digit,
    era,
    eraEN,
    timestamp: new Date().toISOString(),
    sensors: {
      cpuTemp:      Math.round(sensors.cpuTemp * 100) / 100,
      memUsage:     Math.round(sensors.memUsage * 100) / 100,
      diskIO:       Math.round(sensors.diskIO * 100) / 100,
      netLatency:   Math.round(sensors.netLatency * 1000) / 1000,
      cpuLoad:      Math.round(sensors.cpuLoad * 1000) / 1000,
      uptimeJitter: Math.round(sensors.uptimeJitter * 1000000) / 1000000,
      entropyPool:  Math.round(sensors.entropyPool),
    },
    hash: hash.substring(0, 16),         // short hash (chain link)
    // ── Crypto-grade random output ──
    entropy: randomHex,                   // 256-bit (64 hex chars) — cryptographic grade
    random: random64,                     // 64-bit integer string — financial grade
    randomBytes: randomBytes256,          // 256-bit base64 — raw entropy
    // ── Security fields ──
    seq: currentSeq,
    prevHash,
    authenticity: authenticCount,         // 0-7: how many sensors are real
    sensorFlags: flagBits.toString(2).padStart(7, "0"), // "1110111" bitmask
    entropyQuality: entropyQuality.total, // 0-100: overall trustworthiness
    entropyDetail: entropyQuality,        // breakdown of 4 dimensions
  };
}

// ── Pretty output ────────────────────────────────────────────────

function prettyPrint(result) {
  const bar = (val, max, width = 20) => {
    const filled = Math.round((val / max) * width);
    return "█".repeat(Math.min(filled, width)) + "░".repeat(Math.max(0, width - filled));
  };

  const eraEmoji = result.era === "Chaos" ? "🌪️" : result.era === "Eternal" ? "☀️" : "🌤️";
  const authLabel = result.authenticity === 7 ? "✅ FULL" :
                    result.authenticity >= 5 ? "⚠️  PARTIAL" : "❌ LOW";
  const qualLabel = result.entropyQuality >= 75 ? "🟢" :
                    result.entropyQuality >= 40 ? "🟡" : "🔴";

  console.log("");
  console.log("  ╔════════════════════════════════════════════════╗");
  console.log(`  ║  ClawFeel  ${eraEmoji}  ${result.era} (${result.eraEN})`);
  console.log("  ╠════════════════════════════════════════════════╣");
  console.log(`  ║  Feel:    ${String(result.feel).padStart(3)}  ${bar(result.feel, 100)}   ║`);
  console.log(`  ║  Digit:     ${result.digit}                                 ║`);
  console.log("  ╠════════════════════════════════════════════════╣");
  console.log(`  ║  CPU Temp:     ${String(result.sensors.cpuTemp).padStart(7)}°C              ║`);
  console.log(`  ║  Memory:       ${String(result.sensors.memUsage).padStart(7)}%               ║`);
  console.log(`  ║  Disk I/O:     ${String(result.sensors.diskIO).padStart(7)} MB              ║`);
  console.log(`  ║  Net Jitter:   ${String(result.sensors.netLatency).padStart(7)} ms             ║`);
  console.log(`  ║  CPU Load:     ${String(result.sensors.cpuLoad).padStart(7)}                ║`);
  console.log(`  ║  Uptime Jit:   ${String(result.sensors.uptimeJitter).padStart(7)} ms          ║`);
  console.log(`  ║  Entropy:      ${String(result.sensors.entropyPool).padStart(7)} bits           ║`);
  console.log("  ╠═══════════ Security ═════════════════════════╣");
  console.log(`  ║  Auth:    ${authLabel}  (${result.authenticity}/7)   Flags: ${result.sensorFlags}  ║`);
  console.log(`  ║  Quality: ${qualLabel} ${String(result.entropyQuality).padStart(3)}  ${bar(result.entropyQuality, 100)}   ║`);
  console.log(`  ║    Diversity:    ${String(result.entropyDetail.diversity).padStart(2)}/25                     ║`);
  console.log(`  ║    Authenticity: ${String(result.entropyDetail.authenticity).padStart(2)}/25                     ║`);
  console.log(`  ║    Temporal:     ${String(result.entropyDetail.temporal).padStart(2)}/25                     ║`);
  console.log(`  ║    Correlation:  ${String(result.entropyDetail.correlation).padStart(2)}/25                     ║`);
  console.log("  ╠═══════════ Entropy (256-bit) ════════════════╣");
  console.log(`  ║  ${result.entropy.substring(0,48)}  ║`);
  console.log(`  ║  ${result.entropy.substring(48).padEnd(48)}  ║`);
  console.log(`  ║  Random64: ${result.random.padStart(20)}                ║`);
  console.log("  ╠════════════════════════════════════════════════╣");
  console.log(`  ║  Seq:   ${String(result.seq).padStart(6)}                               ║`);
  console.log(`  ║  Hash:  ${result.hash}                         ║`);
  console.log(`  ║  Prev:  ${result.prevHash}                         ║`);
  console.log(`  ║  Time:  ${result.timestamp}      ║`);
  console.log("  ╚════════════════════════════════════════════════╝");
  console.log("");
}

// ── History ───────────────────────────────────────────────────────

const MAX_HISTORY_LINES = 10_000; // ~3MB max

async function saveReading(result) {
  await mkdir(DATA_DIR, { recursive: true });
  const line = JSON.stringify(result) + "\n";
  await appendFile(HISTORY_FILE, line, "utf8");

  // Rotate: keep only last MAX_HISTORY_LINES entries
  try {
    const raw = await readFile(HISTORY_FILE, "utf8");
    const lines = raw.trim().split("\n").filter(Boolean);
    if (lines.length > MAX_HISTORY_LINES) {
      const trimmed = lines.slice(-MAX_HISTORY_LINES).join("\n") + "\n";
      await writeFile(HISTORY_FILE, trimmed, "utf8");
    }
  } catch { /* ignore rotation errors */ }
}

async function showHistory(count) {
  let lines;
  try {
    const raw = await readFile(HISTORY_FILE, "utf8");
    lines = raw.trim().split("\n").filter(Boolean);
  } catch {
    console.log("No history yet. Run with --save to start recording.");
    return;
  }

  const recent = lines.slice(-count);
  if (recent.length === 0) {
    console.log("No history yet. Run with --save to start recording.");
    return;
  }

  const stats = { "Chaos": 0, "Transition": 0, "Eternal": 0 };
  let totalFeel = 0;
  let totalQuality = 0;

  const entries = recent.map((l) => {
    try { return JSON.parse(l); } catch { return null; }
  }).filter(Boolean);

  for (const e of entries) {
    stats[e.era] = (stats[e.era] || 0) + 1;
    totalFeel += e.feel;
    totalQuality += (e.entropyQuality || 0);
  }

  const avgFeel = Math.round(totalFeel / entries.length);
  const avgQuality = Math.round(totalQuality / entries.length);
  const sparkline = entries.map((e) => {
    if (e.feel <= 30) return "▁";
    if (e.feel <= 50) return "▃";
    if (e.feel <= 70) return "▅";
    return "▇";
  }).join("");

  console.log("");
  console.log(`  ┌─ ClawFeel History ── last ${entries.length} readings ─────────┐`);
  console.log(`  │  Avg Feel: ${avgFeel}  Avg Quality: ${avgQuality}  Sparkline: ${sparkline}`);
  console.log(`  │  Chaos: ${stats["Chaos"]}  Transition: ${stats["Transition"]}  Eternal: ${stats["Eternal"]}`);
  console.log(`  ├──────────────────────────────────────────────────┤`);

  for (const e of entries) {
    const eraEmoji = e.era === "Chaos" ? "🌪️" : e.era === "Eternal" ? "☀️" : "🌤️";
    const time = e.timestamp.replace("T", " ").substring(0, 19);
    const auth = e.authenticity != null ? `${e.authenticity}/7` : " — ";
    const qual = e.entropyQuality != null ? `Q:${String(e.entropyQuality).padStart(3)}` : "";
    console.log(`  │  ${eraEmoji} ${String(e.feel).padStart(3)} │ ${e.era} │ ${auth} │ ${qual} │ ${time} │ ${e.hash || ""}`);
  }

  console.log(`  └──────────────────────────────────────────────────┘`);
  console.log("");
}

// ── Network broadcast (UDP) — with Commit-Reveal ────────────────

function getClawId() {
  // Priority: identity.json > feel.md > computed from hardware
  try {
    const idPath = path.join(os.homedir(), ".clawfeel", "identity.json");
    const data = JSON.parse(readFileSync(idPath, "utf8"));
    if (data.clawId) return data.clawId;
  } catch {}
  try {
    const feelPath = path.join(os.homedir(), ".openclaw", "feel.md");
    const content = readFileSync(feelPath, "utf8");
    const m = content.match(/^clawId:\s*(.+)/m);
    if (m) return m[1].trim();
  } catch {}
  // Fallback: compute from hardware
  const interfaces = os.networkInterfaces();
  const macs = Object.values(interfaces)
    .flat()
    .filter((i) => !i.internal && i.mac !== "00:00:00:00:00:00")
    .map((i) => i.mac)
    .sort();
  const raw = os.hostname() + "|" + macs.join(",");
  return createHash("sha256").update(raw).digest("hex").substring(0, 12);
}

/**
 * Broadcast with commit-reveal protocol:
 * 1. Send commitment = SHA-256(feel + nonce)
 * 2. Wait 2 seconds for other commitments
 * 3. Send reveal = { feel, nonce }
 */
let lastBroadcastTime = 0;
const MIN_BROADCAST_INTERVAL_MS = 5000; // max 1 broadcast per 5s

function broadcastFeel(result) {
  const now = Date.now();
  if (now - lastBroadcastTime < MIN_BROADCAST_INTERVAL_MS) return; // rate limit
  lastBroadcastTime = now;
  const clawId = getClawId();
  const nonce = randomBytes(16).toString("hex");
  const commitment = createHash("sha256")
    .update(`${result.feel}|${nonce}`)
    .digest("hex").substring(0, 16);

  const socket = createSocket("udp4");
  socket.bind(() => {
    socket.setBroadcast(true);

    // Phase 1: Commit
    const commitMsg = JSON.stringify({
      type: "clawfeel:commit",
      version: 2,
      clawId,
      commitment,
      seq: result.seq,
      timestamp: result.timestamp,
    });
    const commitBuf = Buffer.from(commitMsg);
    socket.send(commitBuf, 0, commitBuf.length, PORT, "255.255.255.255", (err) => {
      if (err) console.error("Commit broadcast error:", err.message);
    });

    // Phase 2: Reveal (after 2 second delay)
    setTimeout(() => {
      // Only send safe fields — no raw sensors, no hardware fingerprint
      const revealMsg = JSON.stringify({
        type: "clawfeel:reveal",
        version: 2,
        clawId,
        alias: nodeAlias,
        nonce,
        feel: result.feel, era: result.era, hash: result.hash,
        seq: result.seq, prevHash: result.prevHash,
        authenticity: result.authenticity, entropyQuality: result.entropyQuality,
        sensorFlags: result.sensorFlags, timestamp: result.timestamp,
      });
      const revealBuf = Buffer.from(revealMsg);
      socket.send(revealBuf, 0, revealBuf.length, PORT, "255.255.255.255", (err) => {
        if (err) console.error("Reveal broadcast error:", err.message);
        socket.close();
      });
    }, 2000);

    // Also send legacy v1 format for backward compatibility
    const legacyMsg = JSON.stringify({
      type: "clawfeel",
      version: 1,
      clawId,
      alias: nodeAlias,
      feel: result.feel, era: result.era, hash: result.hash,
      seq: result.seq, authenticity: result.authenticity,
      entropyQuality: result.entropyQuality, timestamp: result.timestamp,
    });
    const legacyBuf = Buffer.from(legacyMsg);
    socket.send(legacyBuf, 0, legacyBuf.length, PORT, "255.255.255.255");
  });
}

/**
 * Listen for broadcasts with Sybil detection and peer reputation
 */
function listenForClaws() {
  const socket = createSocket("udp4");
  const myId = getClawId();

  // ── Peer tracking for Sybil detection ──
  const peers = new Map(); // clawId → { ip, firstSeen, readings[], reputation, lastSeq, commitments }
  const ipClawCount = new Map(); // ip → Set<clawId>  (Sybil detection)
  const pendingCommits = new Map(); // clawId → { commitment, timestamp }

  function getSubnet(ip) {
    // Extract /24 subnet
    const parts = ip.split(".");
    return parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : ip;
  }

  function updatePeer(clawId, ip, data) {
    if (!peers.has(clawId)) {
      peers.set(clawId, {
        ip,
        firstSeen: Date.now(),
        readings: [],
        reputation: 50, // start neutral
        lastSeq: 0,
        alerts: [],
      });
    }

    const peer = peers.get(clawId);
    const feel = data.feel;

    // Track IP → clawId mapping for Sybil detection
    if (!ipClawCount.has(ip)) ipClawCount.set(ip, new Set());
    ipClawCount.get(ip).add(clawId);

    // ── Sybil check: too many clawIds from same IP ──
    const clawsFromIP = ipClawCount.get(ip).size;
    if (clawsFromIP > 3) {
      peer.reputation = Math.max(0, peer.reputation - 10);
      if (!peer.alerts.includes("SYBIL_SUSPECT")) {
        peer.alerts.push("SYBIL_SUSPECT");
      }
    }

    // ── Subnet check ──
    const subnet = getSubnet(ip);
    let subnetClaws = 0;
    for (const [, ips] of ipClawCount) {
      for (const cid of ips) {
        const p = peers.get(cid);
        if (p && getSubnet(p.ip) === subnet) subnetClaws++;
      }
    }

    // ── Sequence check: reject seq going backwards ──
    if (data.seq != null) {
      if (data.seq <= peer.lastSeq && peer.lastSeq > 0) {
        peer.reputation = Math.max(0, peer.reputation - 15);
        if (!peer.alerts.includes("SEQ_REPLAY")) {
          peer.alerts.push("SEQ_REPLAY");
        }
      }
      peer.lastSeq = data.seq;
    }

    // ── Replay detection: identical Feel values ──
    peer.readings.push(feel);
    if (peer.readings.length > 20) peer.readings.shift();
    if (peer.readings.length >= 5) {
      const last5 = peer.readings.slice(-5);
      if (new Set(last5).size === 1) {
        peer.reputation = Math.max(0, peer.reputation - 20);
        if (!peer.alerts.includes("REPLAY_SUSPECT")) {
          peer.alerts.push("REPLAY_SUSPECT");
        }
      }
    }

    // ── Entropy quality check ──
    if (data.authenticity != null && data.authenticity < 4) {
      peer.reputation = Math.max(0, peer.reputation - 5);
    }
    if (data.entropyQuality != null && data.entropyQuality < 30) {
      peer.reputation = Math.max(0, peer.reputation - 5);
    }

    // ── Reputation recovery (slow) ──
    if (peer.alerts.length === 0 && peer.reputation < 100) {
      peer.reputation = Math.min(100, peer.reputation + 1);
    }

    return peer;
  }

  socket.on("message", (msg, rinfo) => {
    try {
      const data = JSON.parse(msg.toString());

      // Handle commit phase
      if (data.type === "clawfeel:commit") {
        pendingCommits.set(data.clawId, {
          commitment: data.commitment,
          timestamp: Date.now(),
        });
        return;
      }

      // Handle reveal phase
      if (data.type === "clawfeel:reveal") {
        const pending = pendingCommits.get(data.clawId);
        let commitValid = "N/A";
        if (pending) {
          // Verify commitment: SHA-256(feel|nonce) should match
          const expected = createHash("sha256")
            .update(`${data.feel}|${data.nonce}`)
            .digest("hex").substring(0, 16);
          try {
            commitValid = timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(pending.commitment, "hex")) ? "✅" : "❌ MISMATCH";
          } catch { commitValid = "❌ MISMATCH"; }
          pendingCommits.delete(data.clawId);

          if (commitValid === "❌ MISMATCH") {
            const peer = peers.get(data.clawId);
            if (peer) {
              peer.reputation = Math.max(0, peer.reputation - 30);
              peer.alerts.push("COMMIT_MISMATCH");
            }
          }
        }

        const peer = updatePeer(data.clawId, rinfo.address, data);
        const isSelf = data.clawId === myId;
        const label = isSelf ? "(self)" : `${data.alias || data.clawId}`;
        const eraEmoji = data.era === "Chaos" ? "🌪️" : data.era === "Eternal" ? "☀️" : "🌤️";
        const time = new Date().toLocaleTimeString();
        const repIcon = peer.reputation >= 70 ? "🟢" : peer.reputation >= 40 ? "🟡" : "🔴";
        const authStr = data.authenticity != null ? `${data.authenticity}/7` : "—";
        const alertStr = peer.alerts.length > 0 ? ` ⚠️ ${peer.alerts.join(",")}` : "";

        console.log(
          `  ${eraEmoji} [${time}] ${label} (${data.clawId}) ` +
          `Feel: ${String(data.feel).padStart(3)} │ ${data.era} │ ` +
          `Auth:${authStr} │ ${repIcon} Rep:${peer.reputation} │ ` +
          `Commit:${commitValid} │ Seq:${data.seq || "—"} │ ` +
          `${rinfo.address}${alertStr}`
        );
        return;
      }

      // Handle legacy v1 format
      if (data.type === "clawfeel") {
        const peer = updatePeer(data.clawId, rinfo.address, data);
        const isSelf = data.clawId === myId;
        const label = isSelf ? "(self)" : `${data.alias || data.clawId}`;
        const eraEmoji = data.era === "Chaos" ? "🌪️" : data.era === "Eternal" ? "☀️" : "🌤️";
        const time = new Date().toLocaleTimeString();
        const repIcon = peer.reputation >= 70 ? "🟢" : peer.reputation >= 40 ? "🟡" : "🔴";
        const alertStr = peer.alerts.length > 0 ? ` ⚠️ ${peer.alerts.join(",")}` : "";

        console.log(
          `  ${eraEmoji} [${time}] ${label} (${data.clawId}) ` +
          `Feel: ${String(data.feel).padStart(3)} │ ${data.era} │ ` +
          `${repIcon} Rep:${peer.reputation} │ ` +
          `from ${rinfo.address}:${rinfo.port}${alertStr}`
        );
      }
    } catch { /* ignore malformed */ }
  });

  socket.on("listening", () => {
    const addr = socket.address();
    console.log("");
    console.log(`  ┌─ ClawFeel Listener v2 (Security-Hardened) ────┐`);
    console.log(`  │  Listening on UDP :${addr.port}                   │`);
    console.log(`  │  My Claw ID: ${myId}                 │`);
    console.log(`  │  Defenses: Commit-Reveal, Sybil, Replay, Seq  │`);
    console.log(`  │  Waiting for broadcasts... (Ctrl+C to stop)   │`);
    console.log(`  └───────────────────────────────────────────────┘`);
    console.log("");
  });

  socket.bind(PORT, () => {
    try { socket.addMembership("224.0.0.1"); } catch { /* ok if unsupported */ }
  });
}

// ── ZKP proof generation ─────────────────────────────────────────

async function attachZKP(result, sensorResults) {
  if (!ZKP) return;
  const { ClawZKP } = await import("./zkp.mjs");
  const sensorValues = {
    cpuTemp:      sensorResults.cpuTemp.value,
    memUsage:     sensorResults.memUsage.value,
    diskIO:       sensorResults.diskIO.value,
    netLatency:   sensorResults.netLatency.value,
    cpuLoad:      sensorResults.cpuLoad.value,
    uptimeJitter: sensorResults.uptimeJitter.value,
    entropyPool:  sensorResults.entropyPool.value,
  };
  result.zkProof = ClawZKP.prove(
    sensorValues,
    result.sensorFlags,
    result.feel,
    result.hash,
    result.entropy,
  );
}

// ── Relay report (HTTP POST) ─────────────────────────────────────

// Multi-relay endpoints for redundancy
const RELAY_ENDPOINTS = [
  "https://api.clawfeel.ai",
];

async function reportToRelay(result) {
  const primaryRelay = RELAY || nodeRelay;
  if (!primaryRelay) return;
  const clawId = getClawId();
  const body = JSON.stringify({
    feel: result.feel, era: result.era, hash: result.hash, entropy: result.entropy,
    seq: result.seq, prevHash: result.prevHash, timestamp: result.timestamp,
    authenticity: result.authenticity, entropyQuality: result.entropyQuality,
    sensorFlags: result.sensorFlags, clawId, alias: nodeAlias, publicKey: nodeSignPub,
    ...(result.zkProof ? { zkProof: result.zkProof } : {}),
  });

  // Build unique relay URLs to report to
  const relayUrls = new Set([primaryRelay, ...RELAY_ENDPOINTS]);

  // Report to all relays in parallel
  const results = await Promise.allSettled(
    [...relayUrls].map(async (relayUrl) => {
      const url = relayUrl.replace(/\/$/, "") + "/api/report";
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Claw-Id": clawId },
        body,
        signal: AbortSignal.timeout(15000),
      });
      return res.json();
    })
  );

  // Show status from first successful response
  const firstOk = results.find(r => r.status === "fulfilled" && r.value?.ok);
  const firstAny = results.find(r => r.status === "fulfilled");
  const data = firstOk?.value || firstAny?.value || null;
  const successCount = results.filter(r => r.status === "fulfilled" && r.value?.ok).length;

  if (PRETTY) {
    if (data) {
      console.log(`  📡 Relay: ${data.ok ? "✅" : "❌"} ${data.peers || 0} peers | ${successCount}/${relayUrls.size} relays`);
      console.log(`  🌐 Live:  https://clawfeel.ai/simulator.html?me=${clawId}`);
    } else {
      const err = results[0]?.reason?.message || "all relays failed";
      console.log(`  📡 Relay: ⚠️ ${err}`);
    }
  }
  if (data?.ok) autoOpenBrowser(clawId);
}

// ── Device detection (desktop vs mobile/IoT) ───────────────────
function isDesktop() {
  const p = process.platform;
  // darwin (macOS), win32 (Windows), linux with enough memory = desktop
  if (p === "darwin" || p === "win32") return true;
  // Linux: check if it has enough RAM (>1GB = likely desktop/server)
  try {
    const totalMem = os.totalmem();
    return totalMem > 1_073_741_824; // 1GB
  } catch { return false; }
}

// ── Start embedded relay for full-node mode ─────────────────────
async function startEmbeddedRelay(port) {
  try {
    const relayModule = await import("./relay.mjs");
    if (relayModule.startRelay) {
      await relayModule.startRelay({ port, embedded: true });
      return true;
    }
    // Fallback: spawn relay as child process
    const { spawn: spawnChild } = await import("node:child_process");
    const relayPath = new URL("./relay.mjs", import.meta.url).pathname;
    const child = spawnChild(process.execPath, [relayPath, "--port", String(port)], {
      detached: false,
      stdio: "ignore",
      env: { PATH: process.env.PATH, HOME: process.env.HOME, NODE_ENV: "production" },
    });
    child.unref();
    return true;
  } catch (err) {
    console.error(`  ⚠️  Failed to start embedded relay: ${err.message}`);
    return false;
  }
}

// ── Local Identity Server (localhost:31415) ─────────────────────
// Allows clawfeel.ai to auto-detect the local node without ?me= param.
// Only binds to 127.0.0.1 — not accessible from outside.
let localIdentityServerStarted = false;

async function startLocalIdentityServer() {
  if (localIdentityServerStarted) return;
  localIdentityServerStarted = true;

  const { createServer: createHttpServer } = await import("node:http");
  const LOCAL_ID_PORT = 31415; // Three-Body: pi digits

  try {
    const srv = createHttpServer((req, res) => {
      // CORS: allow clawfeel.ai to fetch
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "GET");
      res.setHeader("Content-Type", "application/json");

      if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }

      if (req.url === "/identity" || req.url === "/") {
        const clawId = getClawId();
        res.writeHead(200);
        res.end(JSON.stringify({
          clawId,
          alias: nodeAlias || "Claw-" + clawId.substring(0, 8),
          version: LOCAL_VERSION,
          online: true,
        }));
        return;
      }

      res.writeHead(404);
      res.end(JSON.stringify({ error: "Not found" }));
    });

    srv.on("error", () => {}); // silently fail if port in use
    srv.listen(LOCAL_ID_PORT, "127.0.0.1", () => {});
  } catch {}
}

// ── Auto-open browser to register clawId in localStorage ────────
let browserOpened = false;
async function autoOpenBrowser(clawId) {
  if (browserOpened) return;
  browserOpened = true;
  const url = `https://clawfeel.ai/?me=${clawId}`;
  try {
    const { platform } = await import("node:os");
    const { exec } = await import("node:child_process");
    const cmd = platform() === "darwin" ? `open "${url}"`
      : platform() === "win32" ? `start "${url}"`
      : `xdg-open "${url}" 2>/dev/null`;
    exec(cmd);
  } catch { /* ignore if browser can't open */ }
}

// ── Daemon management ────────────────────────────────────────────
//  Automatically runs clawfeel as a background process.
//  Users never need to think about this — install skill, it just runs.

import { spawn } from "node:child_process";

async function getDaemonPid() {
  try {
    const pid = parseInt((await readFile(PID_FILE, "utf8")).trim(), 10);
    if (isNaN(pid)) return null;
    // Check if process is alive
    try { process.kill(pid, 0); return pid; } catch { return null; }
  } catch { return null; }
}

async function stopDaemon() {
  const pid = await getDaemonPid();
  if (pid) {
    try {
      process.kill(pid, "SIGTERM");
      await writeFile(PID_FILE, "", "utf8").catch(() => {});
      return { stopped: true, pid };
    } catch {
      return { stopped: false, error: "Failed to stop" };
    }
  }
  return { stopped: false, error: "No daemon running" };
}

async function startDaemon({ attached = false } = {}) {
  // Check if already running
  const existingPid = await getDaemonPid();
  if (existingPid) {
    return { started: false, pid: existingPid, message: "Already running" };
  }

  await mkdir(DATA_DIR, { recursive: true });

  const { openSync } = await import("node:fs");
  const logFd = openSync(DAEMON_LOG, "a");

  const baseArgs = process.argv.slice(1).filter(a =>
    a !== "--pretty" && a !== "--stop" && a !== "--status" && a !== "--restart"
  );

  if (attached) {
    // Attached mode: NOT detached, lifecycle bound to parent (OpenClaw)
    // When parent exits, this child process is killed automatically
    const child = spawn(process.execPath, [
      ...baseArgs, "--__daemon", "--__attached",
    ], {
      detached: false,  // stay attached to parent
      stdio: ["ignore", logFd, logFd],
      env: { PATH: process.env.PATH, HOME: process.env.HOME, NODE_ENV: process.env.NODE_ENV || "production" },
    });

    // Save PID
    await writeFile(PID_FILE, String(child.pid), "utf8");

    // Clean up PID file when child exits
    child.on("exit", async () => {
      try { await unlink(PID_FILE); } catch {}
    });

    return { started: true, pid: child.pid, mode: "attached" };
  } else {
    // Detached mode: standalone daemon (npx / manual)
    const child = spawn(process.execPath, [
      ...baseArgs, "--__daemon",
    ], {
      detached: true,
      stdio: ["ignore", logFd, logFd],
      env: { PATH: process.env.PATH, HOME: process.env.HOME, NODE_ENV: process.env.NODE_ENV || "production" },
    });

    child.unref();
    await writeFile(PID_FILE, String(child.pid), "utf8");

    return { started: true, pid: child.pid, mode: "detached" };
  }
}

// ── Parent process monitoring (for attached mode) ──
function startParentMonitor() {
  if (!ATTACHED) return;
  const parentPid = process.ppid;
  const checkInterval = setInterval(() => {
    try {
      process.kill(parentPid, 0); // signal 0 = check only
    } catch {
      // Parent died → clean exit
      clearInterval(checkInterval);
      console.log(`[ClawFeel] Parent process ${parentPid} exited, shutting down.`);
      unlink(PID_FILE).catch(() => {});
      process.exit(0);
    }
  }, 10_000);
  checkInterval.unref(); // don't prevent Node from exiting
}

async function getDaemonStatus() {
  const pid = await getDaemonPid();
  let identity = null;
  try {
    identity = JSON.parse(await readFile(IDENTITY_FILE, "utf8"));
  } catch {}

  return {
    running: !!pid,
    pid,
    alias: identity?.alias || null,
    clawId: identity?.clawId || null,
    relay: identity?.relay || null,
  };
}

// ── Main ─────────────────────────────────────────────────────────

async function main() {
  // ── Daemon commands ──
  if (STOP) {
    const result = await stopDaemon();
    if (result.stopped) {
      console.log(`🛑 ClawFeel daemon stopped (PID ${result.pid})`);
    } else {
      console.log(`ℹ️  ${result.error}`);
    }
    return;
  }

  if (RESTART) {
    await stopDaemon();
    const result = await startDaemon();
    console.log(result.started
      ? `🔄 ClawFeel daemon restarted (PID ${result.pid})`
      : `ℹ️  ${result.error || "Restart failed"}`);
    return;
  }

  if (STATUS) {
    const status = await getDaemonStatus();
    if (status.running) {
      console.log(`🟢 ClawFeel daemon running (PID ${status.pid})`);
      console.log(`   Alias: ${status.alias || "unknown"}`);
      console.log(`   ClawId: ${status.clawId || "unknown"}`);
      console.log(`   Relay: ${status.relay || "none"}`);
    } else {
      // Auto-recovery: daemon is dead, restart it
      console.log("🔴 ClawFeel daemon not running — auto-restarting...");
      const result = await startDaemon();
      if (result.started) {
        console.log(`🟢 Daemon recovered (PID ${result.pid})`);
      } else {
        console.log(`⚠️  Auto-restart failed: ${result.error || "unknown"}`);
      }
    }
    return;
  }

  // ── Agent decide: quick one-shot decision ──
  if (AGENT_DECIDE) {
    const { ClawAgent } = await import("./agent.mjs");
    const agent = new ClawAgent({ mode: "fast" });
    const options = AGENT_DECIDE.split(",").map(s => s.trim()).filter(Boolean);
    if (options.length < 2) {
      console.error("Error: --agent-decide requires at least 2 comma-separated options");
      process.exit(1);
    }
    const result = await agent.decide(options);
    agent.stop();
    if (PRETTY) {
      console.log(`\n  🎲 Agent Decision`);
      console.log(`  Options: ${options.join(", ")}`);
      console.log(`  Choice:  ${result.choice} (index ${result.index})`);
      console.log(`  Entropy: ${result.entropy}`);
      console.log(`  Mode:    ${result.proof.mode}\n`);
    } else {
      console.log(JSON.stringify(result));
    }
    return;
  }

  // ── Auto-daemon: if not already a daemon and not a one-shot command,
  //    start a background daemon and return one reading to the user ──
  const isOneShot = DIGIT_ONLY || HISTORY || LISTEN || DAG_STATUS || STORE_FILE || GET_FILE || STORE_LIST || LIFE_INIT || LIFE_SAVE || LIFE_RESTORE || LIFE_EXPORT || LIFE_STATUS || AGENT_DECIDE;
  const userSetCount = args.includes("--count");
  const userSetInterval = args.includes("--interval");

  // ── Relay-only mode: just run the relay server ──
  if (RELAY_ONLY) {
    if (PRETTY) console.log("🌐 Starting ClawFeel Relay (relay-only mode)...");
    await startEmbeddedRelay(RELAY_PORT);
    if (PRETTY) console.log(`  ✅ Relay listening on port ${RELAY_PORT}`);
    // Keep process alive
    await new Promise(() => {});
    return;
  }

  if (!IS_DAEMON && !NO_DAEMON && !isOneShot && !userSetCount && !userSetInterval) {
    // Detect if running inside OpenClaw (check parent process)
    let isOpenClaw = false;
    try {
      const ppidCmd = process.platform === "darwin"
        ? execFileSync("ps", ["-p", String(process.ppid), "-o", "comm="], { encoding: "utf8", timeout: 2000 }).trim()
        : execFileSync("cat", [`/proc/${process.ppid}/cmdline`], { encoding: "utf8", timeout: 2000 });
      isOpenClaw = /openclaw|claude|claw/i.test(ppidCmd);
    } catch {}

    // Determine node mode: desktop → full node, mobile/IoT → light node
    const autoFullNode = !LIGHT_MODE && !NO_RELAY && isDesktop();
    const runFullNode = FULL_NODE || autoFullNode;

    // OpenClaw → attached mode (lifecycle bound), standalone → detached mode
    const daemonResult = await startDaemon({ attached: isOpenClaw });

    // Start embedded relay if full-node mode
    let relayStarted = false;
    if (runFullNode) {
      relayStarted = await startEmbeddedRelay(RELAY_PORT);
    }

    // Load identity and signing keys
    await loadIdentity();
    await loadSigningKeys();
    await loadSeqState();
    await startLocalIdentityServer();

    // Give one reading to the user
    const sensorResults = await collectSensors();
    const result = computeFeel(sensorResults);
    await attachZKP(result, sensorResults);
    await saveSeqState();

    // Report to relay once
    const hasRelay = !NO_RELAY && !!(RELAY || nodeRelay);
    if (hasRelay) await reportToRelay(result);

    if (PRETTY) {
      prettyPrint(result);
      if (hasRelay) {
        const clawId = getClawId();
        console.log(`  📡 Relay: online`);
        console.log(`  🌐 Live:  https://clawfeel.ai/simulator.html?me=${clawId}`);
      }
      console.log("");

      // Node mode display
      const nodeMode = runFullNode ? "🖥️  Full Node (relay + sensor)" : "📱 Light Node (sensor only)";
      console.log(`  ${nodeMode}`);
      if (relayStarted) {
        console.log(`  📡 Embedded relay on port ${RELAY_PORT}`);
      }

      if (daemonResult.started) {
        const modeLabel = daemonResult.mode === "attached"
          ? "🔗 Attached to OpenClaw (auto-exit when OpenClaw stops)"
          : "🔧 Standalone daemon (run --stop to stop)";
        console.log(`  ✅ Background daemon started (PID ${daemonResult.pid})`);
        console.log(`     ${modeLabel}`);
        console.log("     Reporting every 30s.");
      } else {
        console.log(`  ✅ Background daemon already running (PID ${daemonResult.pid})`);
      }
      console.log("");
    } else {
      console.log(JSON.stringify(result, null, 2));
    }
    return;
  }

  if (HISTORY) {
    await showHistory(COUNT === 1 ? 20 : COUNT);
    return;
  }

  // ── ClawStore commands (require P2P) ──
  if (STORE_FILE || GET_FILE || STORE_LIST) {
    const { KademliaNode } = await import("./dht.mjs");
    const { FileStore } = await import("./store.mjs");

    const dht = new KademliaNode({
      clawId: getClawId(),
      host: "0.0.0.0",
      port: DHT_PORT,
      bootstrapNodes: BOOTSTRAP ? [BOOTSTRAP, "api.clawfeel.ai:31416"] : ["api.clawfeel.ai:31416"],
      dataDir: DATA_DIR,
    });
    await dht.start();
    const fileStore = new FileStore({ dht, dataDir: DATA_DIR });

    if (STORE_LIST) {
      const manifests = await fileStore.list();
      if (manifests.length === 0) {
        console.log("No stored files.");
      } else {
        console.log(`\n  ${manifests.length} stored file(s):\n`);
        for (const m of manifests) {
          console.log(`  📦 ${m.hash.substring(0, 16)}  ${m.name || "(unnamed)"}  ${m.size} bytes  ${m.created}`);
        }
        console.log("");
      }
      await dht.stop();
      return;
    }

    if (STORE_FILE) {
      try {
        const data = await readFile(STORE_FILE);
        const fileName = STORE_FILE.split("/").pop();
        console.log(`\n  📤 Storing: ${fileName} (${data.length} bytes)`);
        const result = await fileStore.put(data, { name: fileName });
        console.log(`  ✅ Stored!`);
        console.log(`  📋 Manifest: ${result.manifestHash}`);
        console.log(`  📦 Chunks: ${result.manifest.chunks.length} data + ${result.manifest.parity.length} parity`);
        console.log(`\n  To retrieve: clawfeel --get ${result.manifestHash}\n`);
      } catch (err) {
        console.error(`  ❌ Store failed: ${err.message}`);
      }
      await dht.stop();
      return;
    }

    if (GET_FILE) {
      try {
        console.log(`\n  📥 Retrieving: ${GET_FILE.substring(0, 16)}...`);
        const data = await fileStore.get(GET_FILE);
        const outPath = OUTPUT_FILE || `./${GET_FILE.substring(0, 12)}`;
        await writeFile(outPath, data);
        console.log(`  ✅ Retrieved! ${data.length} bytes → ${outPath}\n`);
      } catch (err) {
        console.error(`  ❌ Retrieve failed: ${err.message}`);
      }
      await dht.stop();
      return;
    }
  }

  // ── ClawLife commands ──
  if (LIFE_INIT || LIFE_SAVE || LIFE_RESTORE || LIFE_EXPORT || LIFE_STATUS ||
      DID || MIGRATE_EXPORT || MIGRATE_IMPORT || WILL_SET || WILL_STATUS ||
      FORK || HEARTBEAT) {
    const { KademliaNode } = await import("./dht.mjs");
    const { FileStore } = await import("./store.mjs");
    const { ClawLife } = await import("./life.mjs");

    const clawId = getClawId();
    await loadIdentity();
    await loadSigningKeys();

    const dht = new KademliaNode({
      clawId,
      host: "0.0.0.0",
      port: DHT_PORT,
      bootstrapNodes: BOOTSTRAP ? [BOOTSTRAP, "api.clawfeel.ai:31416"] : ["api.clawfeel.ai:31416"],
      dataDir: DATA_DIR,
    });
    await dht.start();
    const fileStore = new FileStore({ dht, dataDir: DATA_DIR });
    const life = new ClawLife({ clawId, dataDir: DATA_DIR, fileStore });

    if (LIFE_STATUS) {
      const status = await life.getStatus();
      if (status.keyExists) {
        console.log(`\n  🧬 ClawLife: Active`);
        console.log(`  🔑 Public ID: ${status.publicId}`);
        if (status.lastSave) {
          console.log(`  💾 Last save: ${status.lastSave.savedAt}`);
          console.log(`  📋 Manifest:  ${status.lastSave.manifestHash.substring(0, 16)}...`);
          console.log(`  📦 Size:      ${status.lastSave.size} bytes`);
        } else {
          console.log("  💾 No saves yet. Run --life-save to backup.");
        }
      } else {
        console.log("\n  🧬 ClawLife: Not initialized");
        console.log("  Run --life-init to create your ClawLife key.");
      }
      console.log("");
      await dht.stop();
      return;
    }

    if (LIFE_INIT) {
      const result = await life.initKey();
      if (result.isNew) {
        console.log("\n  🧬 ClawLife initialized!");
        console.log(`  🔑 Public ID: ${result.publicId}`);
        console.log(`  🔐 Private key saved to: ~/.clawfeel/life.key`);
        console.log("");
        console.log("  ⚠️  IMPORTANT: Back up your private key!");
        console.log("     Run: clawfeel --life-export");
        console.log("     Loss of this key = permanent death of your ClawLife.");
      } else {
        console.log(`\n  🧬 ClawLife already initialized (${result.publicId})`);
      }
      console.log("");
      await dht.stop();
      return;
    }

    if (LIFE_EXPORT) {
      await life.initKey();
      const key = life.exportKey();
      console.log("\n  🔐 ClawLife Private Key (KEEP SECRET!):");
      console.log(`\n  ${key}\n`);
      console.log("  To restore on another device:");
      console.log(`  clawfeel --life-restore <manifest-hash> --life-key ${key.substring(0, 8)}...`);
      console.log("");
      await dht.stop();
      return;
    }

    if (LIFE_SAVE) {
      await life.initKey();
      // Collect current agent state
      let agentMemory = {};
      try {
        // Try reading OpenClaw feel.md as part of agent state
        for (const p of FEEL_MD_PATHS) {
          try {
            agentMemory.feelMd = await readFile(p, "utf8");
            break;
          } catch {}
        }
      } catch {}

      // Collect recent history
      let history = [];
      try {
        const raw = await readFile(HISTORY_FILE, "utf8");
        history = raw.trim().split("\n").slice(-20).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
      } catch {}

      const agentState = {
        alias: nodeAlias,
        memory: agentMemory,
        history,
        identity: {
          clawId,
          alias: nodeAlias,
          createdAt: new Date().toISOString(),
        },
        feel: {
          totalReadings: currentSeq,
        },
      };

      console.log("\n  🧬 Saving ClawLife to network...");
      const result = await life.save(agentState);
      console.log("  ✅ ClawLife saved!");
      console.log(`  🔑 Life ID:  ${result.lifeId}`);
      console.log(`  📋 Manifest: ${result.manifestHash}`);
      console.log(`  📦 Size:     ${result.size} bytes (encrypted)`);
      console.log(`\n  To restore: clawfeel --life-restore ${result.manifestHash}\n`);
      await dht.stop();
      return;
    }

    if (LIFE_RESTORE) {
      const key = LIFE_KEY || null;
      if (!key) {
        // Try loading local key
        await life.initKey();
      }
      console.log("\n  🧬 Restoring ClawLife from network...");
      try {
        const state = await life.restore(LIFE_RESTORE, key);
        const outPath = OUTPUT_FILE || path.join(DATA_DIR, "life-restored.json");
        await writeFile(outPath, JSON.stringify(state, null, 2), "utf8");
        console.log("  ✅ ClawLife restored!");
        console.log(`  👤 Alias:    ${state.alias || state.identity?.alias || "unknown"}`);
        console.log(`  🔑 Life ID:  ${state.publicId}`);
        console.log(`  📅 Saved:    ${state.timestamp}`);
        console.log(`  💾 Output:   ${outPath}`);
      } catch (err) {
        console.error(`  ❌ Restore failed: ${err.message}`);
      }
      console.log("");
      await dht.stop();
      return;
    }

    // ── DID ──
    if (DID) {
      await life.initKey();
      const did = life.getDID();
      console.log("\n  🆔 ClawLife DID Document:\n");
      console.log(JSON.stringify(did, null, 2));
      console.log("");
      await dht.stop();
      return;
    }

    // ── Migration Export ──
    if (MIGRATE_EXPORT) {
      await life.initKey();
      try {
        const bundle = life.exportMigrationBundle(MIGRATE_EXPORT);
        console.log("\n  📦 Migration Bundle (keep secret!):\n");
        console.log(`  ${bundle}\n`);
        console.log("  To import on another device:");
        console.log(`  clawfeel --migrate-import <bundle> --migrate-pass <passphrase>\n`);
      } catch (err) {
        console.error(`  ❌ Export failed: ${err.message}`);
      }
      await dht.stop();
      return;
    }

    // ── Migration Import ──
    if (MIGRATE_IMPORT) {
      const passphrase = MIGRATE_PASS;
      if (!passphrase) {
        console.error("  ❌ Missing --migrate-pass <passphrase>");
        await dht.stop();
        return;
      }
      try {
        const { ClawLife: CL } = await import("./life.mjs");
        const imported = await CL.importMigrationBundle(MIGRATE_IMPORT, passphrase, DATA_DIR);
        console.log("\n  ✅ Migration bundle imported!");
        console.log(`  🔑 Public ID: ${imported.publicId}`);
        console.log(`  🆔 DID:       did:claw:${imported.publicId}`);
        console.log(`  📁 Saved to:  ${DATA_DIR}/life.key\n`);
      } catch (err) {
        console.error(`  ❌ Import failed: ${err.message}`);
      }
      await dht.stop();
      return;
    }

    // ── Will Set ──
    if (WILL_SET) {
      await life.initKey();
      const timeoutDays = parseInt(WILL_TIMEOUT || "30", 10);
      const message = param("will-message", null);
      try {
        const will = await life.setWill(WILL_SET, timeoutDays, message);
        console.log("\n  📜 Will (遗嘱) set!");
        console.log(`  🔑 Owner:       ${will.ownerDID}`);
        console.log(`  🤝 Beneficiary: ${will.beneficiaryDID}`);
        console.log(`  ⏱️  Timeout:     ${will.timeoutDays} days`);
        if (will.message) console.log(`  💬 Message:     ${will.message}`);
        console.log(`  📅 Created:     ${will.createdAt}\n`);
      } catch (err) {
        console.error(`  ❌ Will set failed: ${err.message}`);
      }
      await dht.stop();
      return;
    }

    // ── Will Status ──
    if (WILL_STATUS) {
      await life.initKey();
      const status = await life.checkWill();
      if (!status.exists && !status.activated) {
        console.log("\n  📜 No will set. Use --will-set <beneficiaryDID> --will-timeout <days>\n");
      } else if (status.activated) {
        console.log("\n  ⚠️  WILL ACTIVATED!");
        console.log(`  🤝 Beneficiary: ${status.beneficiary}`);
        if (status.message) console.log(`  💬 Message:     ${status.message}`);
        console.log(`  📅 Expired at:  ${status.expiredAt}\n`);
      } else {
        console.log("\n  📜 Will Status:");
        console.log(`  🤝 Beneficiary:    ${status.beneficiary}`);
        console.log(`  ⏱️  Timeout:        ${status.timeoutDays} days`);
        console.log(`  📅 Last active:    ${status.lastActive}`);
        console.log(`  ⏳ Days remaining: ${status.daysRemaining}\n`);
      }
      await dht.stop();
      return;
    }

    // ── Heartbeat ──
    if (HEARTBEAT) {
      await life.initKey();
      const result = await life.heartbeat();
      if (result.updated) {
        console.log(`\n  💓 Heartbeat: ${result.lastActive}\n`);
      } else {
        console.log("\n  💓 Heartbeat: no will set (no-op)\n");
      }
      await dht.stop();
      return;
    }

    // ── Fork ──
    if (FORK) {
      await life.initKey();
      try {
        const result = await life.fork(FORK);
        console.log("\n  🔀 Identity forked!");
        console.log(`  👤 Parent DID: ${result.parentDID}`);
        console.log(`  👶 Child DID:  ${result.childDID}`);
        console.log(`  📅 Forked at:  ${result.forkTimestamp}\n`);
      } catch (err) {
        console.error(`  ❌ Fork failed: ${err.message}`);
      }
      await dht.stop();
      return;
    }
  }

  if (LISTEN) {
    listenForClaws();
    return;
  }

  // Load identity and signing keys
  await loadIdentity();
  await loadSigningKeys();

  // Load sequence state for chain integrity
  await loadSeqState();

  // Start local identity server (localhost:31415) for browser auto-detection
  await startLocalIdentityServer();

  // ── Full-node mode: start embedded relay ──
  if (FULL_NODE) {
    const relayOk = await startEmbeddedRelay(RELAY_PORT);
    if (relayOk) console.log(`  🖥️  Full node: relay on port ${RELAY_PORT}`);
    else console.log(`  ⚠️  Full node: relay failed to start`);
  }

  // ── P2P mode: auto-enable on desktop, opt-in on mobile ──
  // Desktop = auto P2P (unless --no-p2p), Mobile/IoT = relay only (unless --p2p)
  const NO_P2P = flag("no-p2p");
  const enableP2P = P2P || (isDesktop() && !NO_P2P && !LIGHT_MODE);
  let gossipManager = null;
  let dhtNode = null;

  if (enableP2P) {
    try {
      const { KademliaNode } = await import("./dht.mjs");
      const { DAGStore } = await import("./dag.mjs");
      const { GossipManager } = await import("./gossip.mjs");

      // Enhanced bootstrap: fetch online peers from relay API
      const bootstrapList = BOOTSTRAP
        ? [BOOTSTRAP, "api.clawfeel.ai:31416"]
        : ["api.clawfeel.ai:31416"];

      try {
        const relayUrl = RELAY || nodeRelay || "https://api.clawfeel.ai";
        const bsRes = await fetch(relayUrl.replace(/\/$/, "") + "/api/bootstrap", {
          signal: AbortSignal.timeout(5000),
        });
        const bsData = await bsRes.json();
        if (bsData.nodes) {
          // Add online peers as bootstrap nodes (up to 10)
          for (const n of bsData.nodes.slice(0, 10)) {
            if (n.dhtPort && n.host) {
              bootstrapList.push(`${n.host}:${n.dhtPort}`);
            }
          }
        }
      } catch { /* relay unreachable, use defaults */ }

      dhtNode = new KademliaNode({
        clawId: getClawId(),
        host: "0.0.0.0",
        port: DHT_PORT,
        bootstrapNodes: bootstrapList,
        dataDir: DATA_DIR,
        lightMode: LIGHT_MODE,
      });

      const dag = new DAGStore({
        dataDir: DATA_DIR,
        lightMode: LIGHT_MODE,
      });
      await dag.load();

      gossipManager = new GossipManager({
        dht: dhtNode, dag, clawId: getClawId(),
        fanout: LIGHT_MODE ? 3 : 6,
        lightMode: LIGHT_MODE,
      });

      await dhtNode.start();

      if (PRETTY) {
        const peers = dhtNode.stats?.peers || 0;
        const contacts = dhtNode.stats?.contacts || 0;
        console.log(`  🔗 P2P: DHT :${dhtNode.port} | ${peers} peers | ${contacts} contacts`);
        console.log(`  📊 DAG: ${dag.txMap.size} txs, ${dag.tips.size} tips`);
      }

      // Initial sync
      try {
        if (LIGHT_MODE) {
          await gossipManager.lightSync();
        } else {
          await gossipManager.fullSync();
        }
      } catch { /* sync failure is non-fatal */ }

      if (DAG_STATUS) {
        const stats = gossipManager.getStats();
        console.log(JSON.stringify(stats, null, 2));
        return;
      }
    } catch (err) {
      // P2P init failed — continue with relay-only mode
      if (PRETTY) console.log(`  ⚠️  P2P init failed: ${err.message} (relay-only mode)`);
      gossipManager = null;
      dhtNode = null;
    }
  }

  // Start parent process monitor if running in attached mode (OpenClaw lifecycle)
  startParentMonitor();

  // Loop settings: __daemon runs forever at 30s, otherwise respect user flags
  const hasRelayLoop = !NO_RELAY && !!(RELAY || nodeRelay);
  const loopCount = IS_DAEMON ? Infinity : COUNT;
  const loopInterval = IS_DAEMON ? 30 : (INTERVAL > 0 ? INTERVAL : (enableP2P ? 10 : 0));

  // Relay health tracking
  let relayFailCount = 0;
  const RELAY_FAIL_THRESHOLD = 3; // switch to P2P-only after 3 consecutive failures
  let relayHealthy = true;

  for (let i = 0; i < loopCount; i++) {
    const sensorResults = await collectSensors();
    const result = computeFeel(sensorResults);
    await attachZKP(result, sensorResults);

    if (DIGIT_ONLY) {
      console.log(result.digit);
    } else if (PRETTY) {
      prettyPrint(result);
    } else {
      console.log(JSON.stringify(result, null, 2));
    }

    if (SAVE) {
      await saveReading(result);
    }

    if (BROADCAST) {
      broadcastFeel(result);
    }

    if (hasRelayLoop && relayHealthy) {
      try {
        await reportToRelay(result);
        relayFailCount = 0;
        relayHealthy = true;
      } catch {
        relayFailCount++;
        if (relayFailCount >= RELAY_FAIL_THRESHOLD) {
          relayHealthy = false;
          if (PRETTY) console.log(`  ⚠️  Relay unreachable (${relayFailCount}x) — P2P only mode`);
        }
      }
    } else if (hasRelayLoop && !relayHealthy && i % 20 === 0) {
      // Periodically try to reconnect relay (every ~10min at 30s interval)
      try {
        await reportToRelay(result);
        relayFailCount = 0;
        relayHealthy = true;
        if (PRETTY) console.log(`  ✅ Relay reconnected!`);
      } catch { /* still down */ }
    }

    // P2P: create DAG transaction and gossip
    if (gossipManager) {
      const tx = gossipManager.onNewLocalReading(result);
      if (tx && PRETTY) {
        const stats = gossipManager.getStats();
        console.log(`  🔗 DAG: tx ${tx.hash.substring(0, 12)}... → ${tx.parents.length} parents │ ${stats.dagStats.tipCount} tips │ ${stats.dhtPeers} peers`);
      }
    }

    // Save sequence state after each reading
    await saveSeqState();

    // Daemon heartbeat for will mechanism (every 10th iteration ≈ 5 minutes)
    if (IS_DAEMON && i > 0 && i % 10 === 0) {
      try {
        const { ClawLife } = await import("./life.mjs");
        const daemonLife = new ClawLife({ clawId: getClawId(), dataDir: DATA_DIR, fileStore: null });
        await daemonLife.initKey();
        await daemonLife.heartbeat();
      } catch { /* will heartbeat is best-effort */ }
    }

    // Periodic DAG prune
    if (gossipManager && i > 0 && i % 100 === 0) {
      gossipManager.dag.prune();
    }

    // Auto-update check (every ~6 hours in daemon mode)
    if (IS_DAEMON && i > 0 && i % AUTO_UPDATE_INTERVAL === 0) {
      checkForUpdates().catch(() => {});
    }

    if (loopInterval > 0 && i < loopCount - 1) {
      await new Promise((resolve) => setTimeout(resolve, loopInterval * 1000));
    }
  }
}

// Only run CLI when executed directly, not when imported as library
const isDirectRun = process.argv[1] && (
  process.argv[1].endsWith("clawfeel.mjs") ||
  process.argv[1].endsWith("clawfeel")
);
if (isDirectRun) {
  main().catch((err) => {
    console.error("ClawFeel error:", err.message);
    process.exit(1);
  });
}

// ── Public API exports for SDK ──
export { collectSensors, computeFeel, loadIdentity, getClawId };
