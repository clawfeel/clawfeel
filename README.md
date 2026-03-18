# 🦞 ClawFeel

**Your Claw's Heartbeat — A hardware-entropy skill for OpenClaw**

Every Claw runs on unique hardware, under unique conditions, at a unique moment in time. ClawFeel distills that uniqueness into a single number: the **Feel** (0–100).

Seven hardware sensors → SHA-256 → one score. Unpredictable. Irreversible. Yours.

---

## What it does

ClawFeel reads 7 real-time hardware parameters from your device, normalizes them, hashes the combination through SHA-256, and outputs:

| Output | Range | Description |
|--------|-------|-------------|
| **Feel** | 0–100 | Your Claw's current state — a hardware-derived score |
| **Digit** | 0–9 | Last digit of Feel — a quick random number |
| **Era** | Chaos / Transition / Eternal | Three-Body era classification |

### The seven senses

| # | Sensor | Source |
|---|--------|--------|
| 1 | CPU Temperature | `/sys/class/thermal/` or `sysctl` |
| 2 | Memory Usage | `os.totalmem()` / `os.freemem()` |
| 3 | Disk I/O | `/proc/diskstats` or `iostat` |
| 4 | Network Latency Jitter | Process timing variance |
| 5 | CPU Load | `os.loadavg()` normalized by cores |
| 6 | Uptime Jitter | `process.hrtime.bigint()` scheduling noise |
| 7 | Entropy Pool | `/proc/sys/kernel/random/entropy_avail` or crypto timing |

### Era classification

Inspired by Liu Cixin's *Three-Body Problem*:

| Feel | Era | Meaning |
|------|-----|---------|
| 0–30 | 🌪️ Chaos | Hardware state is volatile |
| 31–70 | 🌤️ Transition | Normal operation |
| 71–100 | ☀️ Eternal | System is calm and stable |

---

## Install

### As an OpenClaw Skill

```bash
# Copy to your workspace skills directory
cp -r clawfeel ~/.openclaw/workspace/skills/

# Or to the shared skills directory (all agents)
cp -r clawfeel ~/.openclaw/skills/

# Refresh skills
# Ask your agent: "refresh skills"
```

### Standalone

```bash
# No dependencies needed — pure Node.js (≥22)
node scripts/clawfeel.mjs
```

---

## Usage

### Basic (JSON output)
```bash
node scripts/clawfeel.mjs
```
```json
{
  "feel": 73,
  "digit": 3,
  "era": "Eternal",
  "eraEN": "Eternal",
  "timestamp": "2026-03-17T12:34:56.789Z",
  "sensors": { ... },
  "hash": "a7f3b9c1e2d4f6a8"
}
```

### Pretty display
```bash
node scripts/clawfeel.mjs --pretty
```
```
  ╔══════════════════════════════════════════╗
  ║  ClawFeel  ☀️  Eternal
  ╠══════════════════════════════════════════╣
  ║  Feel:    73  ███████████████░░░░░  ║
  ║  Digit:    3                              ║
  ╠══════════════════════════════════════════╣
  ║  CPU Temp:       52.3°C              ║
  ║  Memory:        67.1%               ║
  ║  ...                                      ║
  ╚══════════════════════════════════════════╝
```

### Just the random digit
```bash
node scripts/clawfeel.mjs --digit-only
# Output: 3
```

### Continuous monitoring
```bash
node scripts/clawfeel.mjs --interval 10 --count 6
# 6 readings, 10 seconds apart
```

### Save to history
```bash
node scripts/clawfeel.mjs --save
# Reading is appended to ~/.clawfeel/history.jsonl
```

### View history
```bash
node scripts/clawfeel.mjs --history
# Shows last 20 readings with sparkline and era stats

node scripts/clawfeel.mjs --history --count 50
# Shows last 50 readings
```
```
  ┌─ ClawFeel History ── last 5 readings ─────────┐
  │  Avg Feel: 58    Sparkline: ▅▃▇▅▁
  │  Chaos: 1  Transition: 2  Eternal: 2
  ├──────────────────────────────────────────────┤
  │  🌤️  42 │ Transition │ 2026-03-17 12:34:56 │ a7f3b9c1e2d4f6a8
  │  🌪️  18 │ Chaos │ 2026-03-17 12:35:06 │ 3c9a1bf4d7e20856
  │  ...
  └──────────────────────────────────────────────┘
```

### Broadcast to LAN
```bash
# Send your Feel to all devices on the local network
node scripts/clawfeel.mjs --broadcast

# Broadcast every 10 seconds, 6 times
node scripts/clawfeel.mjs --broadcast --interval 10 --count 6

# Custom port (default: 31415)
node scripts/clawfeel.mjs --broadcast --port 9999
```

### Listen for other Claws
```bash
node scripts/clawfeel.mjs --listen
```
```
  ┌─ ClawFeel Listener ─────────────────────────┐
  │  Listening on UDP :31415                     │
  │  My Claw ID: a7f3b9c1e2d4                   │
  │  Waiting for broadcasts... (Ctrl+C to stop)  │
  └─────────────────────────────────────────────┘

  ☀️ [14:30:05] lobby-pi (3c9a1bf4d7e2) Feel:  82 │ Eternal │ from 192.168.1.42:31415
  🌤️ [14:30:07] (self) (a7f3b9c1e2d4) Feel:  55 │ Transition │ from 192.168.1.10:31415
```

### Via OpenClaw chat
```
You: "What's my Claw's feel?"
You: "Give me a random number"
You: "Monitor my feel every 5 seconds"
You: "Save my feel and show history"
You: "Broadcast my feel to the network"
You: "Listen for other Claws"
```

---

## How it works

```
┌─────────────────────────────────────────────┐
│  7 Hardware Sensors (real-time readings)     │
│  CPU°C | RAM% | DiskIO | NetΔ | Load |     │
│  UptimeJitter | EntropyPool                 │
└──────────────────┬──────────────────────────┘
                   ▼
┌─────────────────────────────────────────────┐
│  Normalize each to [0.0, 1.0]               │
│  Concatenate with nanosecond timestamp      │
└──────────────────┬──────────────────────────┘
                   ▼
┌─────────────────────────────────────────────┐
│  SHA-256 Hash                                │
│  → Avalanche effect (tiny change = new hash)│
│  → Uniform distribution                      │
│  → One-way (can't reverse to hardware state) │
└──────────────────┬──────────────────────────┘
                   ▼
┌─────────────────────────────────────────────┐
│  first_8_hex_chars → int → mod 101          │
│  Feel: 0–100    Digit: feel % 10            │
└─────────────────────────────────────────────┘
```

### Why SHA-256?

A naive weighted sum of hardware parameters would produce a normal distribution (central limit theorem) and adjacent readings would be highly correlated. SHA-256 solves both:

1. **Avalanche**: Even a 0.001°C temperature change completely changes the output
2. **Uniformity**: mod 101 over a 32-bit range has negligible bias (~0.0000024%)
3. **Irreversibility**: Sharing your Feel score reveals nothing about your hardware

---

## Platform support

| Platform | Status | Notes |
|----------|--------|-------|
| Linux (x86/ARM) | ✅ Full | All 7 sensors natively available |
| macOS (Intel/Apple Silicon) | ✅ Full | Uses sysctl/IOKit fallbacks |
| Windows (WSL2) | ⚠️ Partial | Runs in WSL's Linux layer |
| Docker | ⚠️ Partial | May need `--privileged` for thermal |
| Android (Termux) | ⚠️ Partial | Limited thermal zone access |

---

## Security Hardening (v2)

ClawFeel v2 implements a multi-layered defense system:

### Sensor authenticity tracking
Every sensor reports `{ value, authentic }`. Fallback (random) values are flagged, reducing the node's `authenticity` score (0–7) and `entropyQuality` rating.

### Entropy quality scoring (0–100)
Four dimensions, each 0–25 points:
- **Diversity**: Coefficient of variation across sensors (too uniform = suspicious)
- **Authenticity**: Ratio of real hardware sensors vs fallback
- **Temporal randomness**: Runs test detects predictable patterns
- **Cross-sensor correlation**: Detects replay attacks and simulation

### Weighted sensor input
Sensors weighted by controllability (entropy pool ×1.0, CPU load ×0.3). Harder-to-fake sensors contribute more to the hash.

### Chain hashing
Each reading includes `seq` (monotonic counter) + `prevHash` (previous reading's hash). Sequence rollback = replay detected.

### Commit-Reveal protocol
Broadcasts use two-phase commit: first `SHA-256(feel|nonce)`, then reveal after 2s. Prevents last-second manipulation.

### Sybil defense (listener mode)
- IP→clawId tracking, subnet deduplication
- Reputation system (0–100): gains from consistent data, loses from anomalies
- Entropy-weighted aggregation: low-quality nodes automatically de-weighted

### External anchoring
`--anchor` mixes in minute-level time hash; `--anchor-value <hex>` injects peer entropy for cross-node mixing.

### Network simulator
Open `web/index.html` for an interactive visualization of 100 nodes with attack simulation:
- **Sybil attack**: Inject 20 fake nodes, watch them get de-weighted
- **Sensor spoofing**: 10 nodes produce predictable sine-wave data
- **Replay attack**: 5 nodes repeat fixed values
- **Dual waveform**: Compare entropy-weighted vs naive average aggregation

---

## Vision: The Three-Body Network

ClawFeel is building toward a decentralized entropy network. Progress:

1. ✅ **ClawFeel Skill** — Each Claw knows its own Feel
2. ✅ **History** — Local recording and trend analysis
3. ✅ **LAN Broadcast** — Claws can sense each other on the network
4. ✅ **Security Hardening** — Authenticity, quality scoring, Sybil defense
5. ✅ **Commit-Reveal** — Tamper-resistant broadcast protocol
6. ✅ **Network Simulator** — 100-node visualization with attack simulation
7. 🔜 **VRF Layer** — Verifiable Random Functions on top of Feel
8. 🔮 **TriSol Network** — DAG-based decentralized consensus using Claw entropy

---

## License

MIT

---

## Links

- 🌐 [clawfeel.com](https://clawfeel.com)
- 🤖 [clawfeel.ai](https://clawfeel.ai)
- 🦞 [OpenClaw](https://github.com/openclaw/openclaw)

---

*Built for the Claw Crew. The lobster has a heartbeat now.* 🦞💓
