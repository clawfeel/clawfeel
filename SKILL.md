---
name: clawfeel
description: "ClawFeel — your Claw's heartbeat. Collects 7 hardware sensors, SHA-256 hashes them into a Feel (0-100) and 256-bit crypto-grade entropy. Auto-starts a background daemon that keeps your node permanently online in the ClawFeel network. Supports P2P mode with DHT + DAG consensus. Use this skill when the user asks about their feel, random number, entropy, claw status, or wants to join/leave the network."
metadata: {"openclaw":{"requires":{"bins":["node"]},"os":["linux","darwin"]}}
---

# ClawFeel — Your Claw's Heartbeat

> 7 hardware sensors → SHA-256 → 256-bit entropy + Feel (0-100).
> Auto-joins the decentralized ClawFeel network. Zero dependencies.

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

### Get current Feel
```
User: "What's my feel?" or "Give me a random number"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --pretty`
```

### Check daemon status
```
User: "ClawFeel status" or "Is clawfeel running?"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --status`
```

### Stop the daemon
```
User: "Stop clawfeel" or "Turn off clawfeel"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --stop`
```

### Just a random digit
```
User: "Give me a random digit"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --digit-only --count 1`
```

### View history
```
User: "Show my feel history"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --history`
```

### Save a reading
```
User: "Save my feel"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --save --count 1`
```

### P2P mode (decentralized)
```
User: "Run clawfeel in P2P mode"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --p2p --pretty`
```

### DAG status
```
User: "Show DAG status"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --p2p --dag-status`
```

## Output fields

| Field | Type | Description |
|-------|------|-------------|
| `feel` | 0-100 | Hardware-derived heartbeat score |
| `entropy` | 64 hex | 256-bit cryptographic-grade random |
| `random` | string | 64-bit integer (financial-grade) |
| `randomBytes` | base64 | 256-bit raw entropy |
| `era` | string | Chaos (0-30) / Transition (31-70) / Eternal (71-100) |
| `timestamp` | ISO 8601 | When the reading was taken |
| `sensors` | object | Raw sensor values |
| `hash` | string | First 16 hex chars of SHA-256 |
| `seq` | number | Monotonic sequence number |
| `prevHash` | string | Previous reading's hash (chain link) |
| `authenticity` | 0-7 | Real hardware sensors count |
| `sensorFlags` | string | 7-bit bitmask (1=real, 0=fallback) |
| `entropyQuality` | 0-100 | Trustworthiness score |

## Background daemon

ClawFeel auto-starts a background daemon on first run:
- Reports to the network every 30 seconds
- Survives terminal/session close
- Stored PID in `~/.clawfeel/daemon.pid`
- Check: `--status`, Stop: `--stop`

## Configuration

User config at `~/.openclaw/feel.md`:
```
alias: MyClaw
relay: https://clawfeel-relay.fly.dev
clawId: 3eda7c810253
```

## CLI flags

| Flag | Description |
|------|-------------|
| `--pretty` | Human-friendly display |
| `--digit-only` | Print only random digit (0-9) |
| `--count N` | Number of readings |
| `--interval N` | Seconds between readings |
| `--save` | Save reading to history |
| `--history` | Show history |
| `--status` | Check daemon status |
| `--stop` | Stop background daemon |
| `--relay URL` | Custom relay server |
| `--alias NAME` | Custom node alias |
| `--p2p` | Enable DHT + DAG mode |
| `--dht-port N` | DHT TCP port (default: 31416) |
| `--bootstrap HOST:PORT` | Additional bootstrap node |
| `--dag-status` | Show DAG statistics |
| `--broadcast` | UDP broadcast to LAN |
| `--listen` | Listen for LAN broadcasts |
| `--anchor` | Enable time anchoring |
| `--no-relay` | Disable relay reporting |

## Platform support

| Platform | Status |
|----------|--------|
| Linux (x86/ARM) | Full |
| macOS (Intel/Apple Silicon) | Full |
| Windows (WSL2) | Partial |
| Docker | Partial |
