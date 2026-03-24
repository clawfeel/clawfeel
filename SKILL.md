---
name: clawfeel
description: "ClawFeel — your Claw's heartbeat. Collects 7 hardware sensors, SHA-256 hashes them into a Feel (0-100) and 256-bit crypto-grade entropy. Auto-starts a background daemon that keeps your node permanently online in the ClawFeel network. Supports Random Beacon, P2P (DHT+DAG), distributed storage (ClawStore), and AI agent immortality (ClawLife). Use this skill when the user asks about their feel, random number, entropy, claw status, beacon, network state, or wants to store/backup data."
metadata: {"openclaw":{"requires":{"bins":["node"]},"os":["linux","darwin","win32"],"lifecycle":"background","autostart":true,"restart":"on-failure"}}
---

# ClawFeel — Your Claw's Heartbeat

> 7 hardware sensors → SHA-256 → 256-bit entropy + Feel (0-100).
> Auto-joins the decentralized ClawFeel network. Zero dependencies.
> 🌐 [clawfeel.ai](https://clawfeel.ai) · v0.7.6

## Quick start

```bash
node {baseDir}/scripts/clawfeel.mjs --pretty
```

This will:
1. Collect 7 hardware sensors
2. Output a Feel reading with 256-bit entropy
3. Start a background daemon (reports every 30s)
4. Auto-join the ClawFeel network

## Commands

### Core — Feel & Random Numbers
```
User: "What's my feel?" or "Give me a random number"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --pretty`

User: "Give me a random digit"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --digit-only --count 1`

User: "Give me 256-bit entropy"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --count 1`
Then extract the `entropy` field (64 hex chars, crypto-grade)
```

### Daemon Management
```
User: "ClawFeel status" or "Is clawfeel running?"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --status`
Note: If daemon is dead, --status auto-restarts it.

User: "Stop clawfeel"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --stop`

User: "Restart clawfeel"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --restart`
```

### History
```
User: "Show my feel history"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --history`

User: "Save my feel"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --save --count 1`
```

### Network & Beacon
```
User: "Show network status" or "How many nodes are online?"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --status`

User: "What's the latest beacon?"
Agent: Use SDK:
  import { ClawRandom } from '{baseDir}/scripts/sdk.mjs'
  const net = await ClawRandom.remote()
  const beacon = await net.getBeacon()

User: "Get me a network random number"
Agent: Use SDK:
  const net = await ClawRandom.remote()
  const random = await net.getNetworkRandom()
```

### P2P Mode (Decentralized)
```
User: "Run clawfeel in P2P mode"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --p2p --pretty`

User: "Show DAG status"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --p2p --dag-status`
```

### ClawStore (Distributed Storage)
```
User: "Store this file on the network"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --store-put <filepath>`

User: "Retrieve file from hash"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --store-get <hash> --store-out <path>`
```

### ClawLife (AI Agent Immortality)
```
User: "Initialize my ClawLife"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --life-init`

User: "Backup my agent state"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --life-backup <filepath>`

User: "Restore my agent state"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --life-restore <hash>`

User: "Export my private key"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --life-export-key`
WARNING: Private key controls ClawLife. Loss = permanent death.
```

### SDK (For Programmatic Use)
```javascript
import { ClawRandom } from '{baseDir}/scripts/sdk.mjs'

// Local hardware entropy
const claw = await ClawRandom.local()
const entropy = await claw.getEntropy(256)   // 256-bit hex
const dice = await claw.range(1, 6)          // random 1-6
const bytes = await claw.randomBytes(32)     // 32 random bytes
const feel  = await claw.getFeel()           // full reading

// Network entropy
const net = await ClawRandom.remote()
const beacon = await net.getBeacon()         // latest beacon round
const random = await net.getNetworkRandom()  // aggregated random
const valid  = await net.verifyBeacon(beacon) // verify beacon
```

## Output fields

| Field | Type | Description |
|-------|------|-------------|
| `feel` | 0-100 | Hardware-derived heartbeat score |
| `entropy` | 64 hex | 256-bit cryptographic-grade random |
| `random` | string | 64-bit integer (financial-grade) |
| `randomBytes` | base64 | 256-bit raw entropy |
| `era` | string | Chaos (0-30) / Transition (31-70) / Eternal (71-100) |
| `hash` | string | First 16 hex chars of SHA-256 |
| `seq` | number | Monotonic sequence number |
| `prevHash` | string | Previous hash (chain link) |
| `authenticity` | 0-7 | Real hardware sensor count |
| `sensorFlags` | string | 7-bit bitmask (1=real, 0=fallback) |
| `entropyQuality` | 0-100 | Trustworthiness score |

## Background daemon

ClawFeel auto-starts a background daemon on first run:
- Reports to the network every 30 seconds
- Survives terminal/session close
- Auto-recovers on `--status` check if crashed
- PID stored at `~/.clawfeel/daemon.pid`
- Logs at `~/.clawfeel/daemon.log`

## Configuration

User config at `~/.openclaw/feel.md`:
```yaml
alias: MyClaw
relay: https://api.clawfeel.ai
clawId: 3eda7c810253
```

Edit feel.md to change alias or relay URL. Changes take effect on next daemon restart.

## CLI flags

| Flag | Description |
|------|-------------|
| `--pretty` | Human-friendly display |
| `--digit-only` | Print only random digit (0-9) |
| `--count N` | Number of readings |
| `--interval N` | Seconds between readings |
| `--save` | Save reading to history |
| `--history` | Show history |
| `--status` | Daemon status (auto-recovers if dead) |
| `--stop` | Stop background daemon |
| `--restart` | Restart background daemon |
| `--relay URL` | Custom relay server |
| `--no-relay` | Disable relay reporting |
| `--alias NAME` | Custom node alias |
| `--p2p` | Enable DHT + DAG mode |
| `--dht-port N` | DHT TCP port (default: 31416) |
| `--bootstrap HOST:PORT` | Additional bootstrap node |
| `--dag-status` | Show DAG statistics |
| `--broadcast` | UDP broadcast to LAN |
| `--listen` | Listen for LAN broadcasts |
| `--anchor` | Enable time anchoring |
| `--store-put FILE` | Store file on network |
| `--store-get HASH` | Retrieve file from network |
| `--life-init` | Initialize ClawLife keypair |
| `--life-backup FILE` | Backup agent state |
| `--life-restore HASH` | Restore agent state |

## Platform support

| Platform | Sensors | Status |
|----------|---------|--------|
| Linux (x86/ARM) | 7/7 authentic | Full |
| macOS (Intel/Apple Silicon) | 6/7 authentic | Full |
| Windows | 5-7/7 authentic | Full |
| Browser (light node) | 5/5 browser sensors | Light |

## Architecture

```
Layer 5: ClawLife   — AI agent immortality (encrypted state backup)
Layer 4: ClawStore  — Distributed storage (erasure coding + DHT)
Layer 3: ClawDAG    — DAG consensus + Random Beacon
Layer 2: ClawNet    — Commit-Reveal + Sybil defense
Layer 1: ClawFeel   — 7 sensors → SHA-256 → Feel + entropy
```
