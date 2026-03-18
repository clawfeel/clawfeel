---
name: clawfeel
description: "ClawFeel — sense and broadcast your Claw's real-time hardware 'Feel'. Collects 7 hardware parameters (CPU temp, memory usage, disk I/O, network latency, CPU load, uptime jitter, entropy pool), hashes them into a Feel score (0–100) and a random digit (0–9). Security-hardened with sensor authenticity tracking, entropy quality scoring, weighted aggregation, commit-reveal protocol, Sybil defense, and chain hashing. Use this skill whenever the user asks about their Claw's feel, mood, status pulse, hardware entropy, random number, Eternal/Chaos era state, or wants to express their Claw's unique identity. Also triggers on: 'what's my feel', 'how is my claw feeling', 'give me a random number', 'clawfeel', 'show my entropy', 'claw pulse', 'claw heartbeat'."
metadata: {"openclaw":{"requires":{"bins":["node"]},"os":["linux","darwin"]}}
---

# ClawFeel — Your Claw's Heartbeat (Security-Hardened)

> Every Claw has a Feel. A single number (0–100) distilled from seven hardware
> dimensions, unpredictable and unique — like a heartbeat no one else can forge.

## Quick start

Run the sensor script to get the current Feel:

```bash
node {baseDir}/scripts/clawfeel.mjs
```

The script prints a JSON object to stdout:

```json
{
  "feel": 73,
  "digit": 3,
  "era": "Eternal",
  "eraEN": "Eternal",
  "timestamp": "2026-03-17T12:34:56.789Z",
  "sensors": { "cpuTemp": 52.3, "memUsage": 67.1, "diskIO": 12.4, "netLatency": 3.21, "cpuLoad": 0.42, "uptimeJitter": 0.000312, "entropyPool": 3891 },
  "hash": "a7f3b9c1e2d4f6a8",
  "seq": 42,
  "prevHash": "b3c7d1e5f9a2b4c6",
  "authenticity": 6,
  "sensorFlags": "1111110",
  "entropyQuality": 82,
  "entropyDetail": { "total": 82, "diversity": 20, "authenticity": 22, "temporal": 25, "correlation": 15 }
}
```

## Output fields

| Field | Type | Description |
|-------|------|-------------|
| `feel` | 0–100 | The Claw's Feel score. Higher = calmer, lower = more chaotic. |
| `digit` | 0–9 | Last digit of `feel` — a hardware-derived random digit. |
| `era` | string | Three-body era classification (see below). |
| `eraEN` | string | English era name. |
| `timestamp` | ISO 8601 | When the reading was taken. |
| `sensors` | object | Raw normalized sensor values (for debugging / display). |
| `hash` | string | First 16 hex chars of the SHA-256 digest. |
| `seq` | number | Monotonically increasing sequence number (chain integrity). |
| `prevHash` | string | Previous reading's hash (chain link). |
| `authenticity` | 0–7 | How many of 7 sensors returned real hardware data (vs fallback). |
| `sensorFlags` | string | 7-bit bitmask: 1=real, 0=fallback, order: cpuTemp→entropyPool. |
| `entropyQuality` | 0–100 | Overall trustworthiness score. |
| `entropyDetail` | object | Breakdown: diversity, authenticity, temporal, correlation (each 0–25). |

## Era classification

| Range | Era | English | Meaning |
|-------|-----|---------|---------|
| 0–30 | Chaos | Chaos | Hardware state is volatile — high entropy, heavy load. |
| 31–70 | Transition | Transition | Normal operating conditions. |
| 71–100 | Eternal | Eternal | System is calm and stable — low variance. |

## How it works

1. **Collect**: Read 7 hardware parameters via OS-native interfaces. Each returns `{ value, authentic }`.
2. **Normalize**: Scale each parameter to a 0–1 float.
3. **Weight**: Apply controllability weights — harder-to-fake sensors (entropy pool, net latency) contribute more.
4. **Chain**: Include previous hash and sequence number for chain integrity.
5. **Anchor** (optional): Mix in external time anchor or peer data.
6. **Hash**: SHA-256 of weighted entropy string.
7. **Score**: First 8 hex chars → integer → mod 101 → Feel (0–100).
8. **Quality**: Compute entropy quality from diversity, authenticity, temporal randomness, and cross-sensor correlation.

## Security features

### Sensor authenticity tracking
Each sensor reports whether it read real hardware data or fell back to random values. Fallback readings are marked `authentic: false` and reduce the `authenticity` count and `entropyQuality` score.

### Entropy quality scoring (0–100)
Four dimensions, each 0–25 points:
- **Diversity**: Coefficient of variation across 7 sensor values. Too uniform = suspicious.
- **Authenticity**: Ratio of real hardware sensors (vs fallback).
- **Temporal randomness**: Wald-Wolfowitz runs test on recent Feel values. Detects predictable patterns.
- **Cross-sensor correlation**: Checks for replay attacks (identical values) and physical plausibility.

### Weighted sensor input
Sensors are weighted by controllability (how hard they are to manipulate):
- `entropyPool: 1.0` (kernel-level, very hard to control)
- `netLatency: 0.9` (external network, hard to control)
- `cpuTemp: 0.8` (physical heat transfer)
- `uptimeJitter: 0.7` (OS scheduler noise)
- `memUsage: 0.5`, `diskIO: 0.5` (medium)
- `cpuLoad: 0.3` (easy to control via running programs)

### Chain hashing
Each Feel includes `seq` (monotonic counter) and `prevHash` (link to previous reading), forming a tamper-evident chain. Sequence rollback = replay attack detected.

### External anchoring (`--anchor`)
Mixes in a minute-level time hash as external anchor. With `--anchor-value <hex>`, can inject peer Feel data for cross-node entropy mixing.

### Commit-Reveal broadcast protocol (v2)
When broadcasting, the node first sends a commitment `SHA-256(feel|nonce)`, waits 2 seconds, then reveals the actual Feel + nonce. Listeners verify the match. This prevents last-second manipulation.

### Sybil defense (listener mode)
- Tracks `clawId → IP` mapping; multiple IDs from same IP = Sybil suspect.
- Subnet-level deduplication.
- Reputation system: starts at 50, gains from consistent good data, loses from low authenticity, low quality, seq replay, or commit-reveal mismatches.

## Usage examples

### Get current Feel
```
User: "What's my Claw's feel right now?"
Agent: runs `node {baseDir}/scripts/clawfeel.mjs` and reports the result.
```

### Pretty output with security info
```
User: "Show me a detailed feel reading."
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --pretty`
```

### Continuous monitoring
```
User: "Monitor my Claw's feel every 10 seconds for a minute."
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --interval 10 --count 6`
```

### Just the random digit
```
User: "Give me a random number from my Claw."
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --digit-only`
```

### Save and view history
```
User: "Take a feel reading and save it."
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --save`

User: "Show my feel history."
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --history`
```

### Network broadcast (with commit-reveal)
```
User: "Broadcast my feel to the network."
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --broadcast`

User: "Listen for other Claws on the network."
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --listen`
```

### External anchoring
```
User: "Take a feel reading with time anchoring."
Agent: runs `node {baseDir}/scripts/clawfeel.mjs --anchor`
```

## Platform support

| Platform | Status | Notes |
|----------|--------|-------|
| Linux (x86/ARM) | Full | All 7 sensors available, highest authenticity. |
| macOS | Full | Uses sysctl/IOKit fallbacks for temp and entropy. |
| Windows (WSL2) | Partial | Runs inside WSL's Linux layer; some sensors fall back. |
| Docker | Partial | Some sensors require `--privileged`; authenticity will be lower. |

## Data storage

- `~/.clawfeel/history.jsonl` — Feel readings (with `--save`)
- `~/.clawfeel/seq` — Sequence number and previous hash (chain state)
- `~/.clawfeel/peers.jsonl` — Peer reputation data (listener mode)

## Security notes

- The script only **reads** system metrics. No root/sudo required.
- SHA-256 is one-way — sharing Feel does not expose hardware details.
- Commit-reveal protocol prevents pre-computation attacks on broadcast.
- Entropy quality score enables weighted aggregation that resists Sybil attacks.
- Chain hashing detects replay attacks and sequence manipulation.
