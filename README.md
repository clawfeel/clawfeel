# ClawFeel

**Your Claw's Heartbeat — Hardware Entropy for a Decentralized World**

7 hardware sensors → SHA-256 → 256-bit crypto-grade entropy + Feel score (0–100). Zero dependencies. Proof of Existence, not Proof of Work.

[![npm](https://img.shields.io/npm/v/clawfeel)](https://www.npmjs.com/package/clawfeel)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

🌐 [clawfeel.ai](https://clawfeel.ai) · 📄 [Whitepaper](https://clawfeel.ai/whitepaper.html) · 🔴 [Live Simulator](https://clawfeel.ai/simulator.html)

---

## Install

### Option 1: OpenClaw Skill (Recommended)

Tell your OpenClaw agent:

```
"Install the ClawFeel skill"
```

The agent installs it, starts a background daemon, and your node joins the network — permanently online.

### Option 2: npm

```bash
npm install -g clawfeel
clawfeel --pretty
```

### Option 3: npx (No Install)

```bash
npx clawfeel --pretty
```

All options auto-start a background daemon that reports to the network every 30s. Your node stays online even after the terminal closes.

```bash
clawfeel --status    # check if daemon is running
clawfeel --stop      # stop the background daemon
```

---

## What it does

ClawFeel reads 7 real-time hardware parameters, hashes them through SHA-256, and outputs:

| Output | Range | Description |
|--------|-------|-------------|
| **Feel** | 0–100 | Hardware-derived heartbeat score |
| **Entropy** | 256-bit hex | Cryptographic-grade random number |
| **Random** | 64-bit int | Financial-grade random number |
| **Era** | Chaos / Transition / Eternal | Three-Body era classification |

### The seven sensors

| # | Sensor | Weight | Controllability |
|---|--------|--------|-----------------|
| 1 | CPU Temperature | 0.8 | Low (physical heat) |
| 2 | Memory Usage | 0.5 | Medium |
| 3 | Disk I/O | 0.5 | Medium |
| 4 | Network Jitter | 0.9 | Low (external network) |
| 5 | CPU Load | 0.3 | High |
| 6 | Uptime Jitter | 0.7 | Low (OS scheduler) |
| 7 | Entropy Pool | 1.0 | Very low (kernel) |

### Era classification

Inspired by Liu Cixin's *Three-Body Problem*:

| Feel | Era | Meaning |
|------|-----|---------|
| 0–30 | Chaos | Hardware state is volatile |
| 31–70 | Transition | Normal operation |
| 71–100 | Eternal | System is calm and stable |

---

## Usage

```bash
# Pretty display with 256-bit entropy
clawfeel --pretty

# Just the random digit (0-9)
clawfeel --digit-only --count 1

# Continuous monitoring
clawfeel --pretty --interval 10 --count 6

# Save to history
clawfeel --save --count 1

# View history
clawfeel --history

# P2P mode (decentralized, no relay needed)
clawfeel --p2p --pretty

# Check DAG status in P2P mode
clawfeel --p2p --dag-status

# Broadcast to LAN
clawfeel --broadcast --count 1

# Listen for LAN peers
clawfeel --listen
```

### Via OpenClaw chat

```
"What's my Claw's feel?"
"Give me a random number"
"Show my feel history"
"Stop clawfeel"
"ClawFeel status"
```

---

## Output

```json
{
  "feel": 73,
  "digit": 3,
  "era": "Eternal",
  "entropy": "b3e9a79c79bbdfed13b70013daca8b2c159a3e4ac7591d977f67b65562b8b8a9",
  "random": "12964077292861775853",
  "randomBytes": "s+mnnHm73+0TtwAT2sqLLBWaPkrHWR2Xf2e2VWK4uKk=",
  "timestamp": "2026-03-20T...",
  "sensors": { "cpuTemp": 52.3, "memUsage": 67.1, ... },
  "hash": "a7f3b9c1e2d4f6a8",
  "seq": 42,
  "prevHash": "b3c7d1e5f9a2b4c6",
  "authenticity": 6,
  "sensorFlags": "1111110",
  "entropyQuality": 82,
  "entropyDetail": { "diversity": 20, "authenticity": 22, "temporal": 25, "correlation": 15 }
}
```

---

## Architecture

```
Layer 5: ClawLife     │ AI immortality — encrypted agent memory + private key identity
Layer 4: ClawStore    │ Distributed storage — erasure coding, DHT, redundancy
Layer 3: ClawDAG  ✅  │ DAG consensus — Kademlia DHT + gossip + tip selection
Layer 2: ClawNet  ✅  │ P2P network — commit-reveal, Sybil defense, reputation
Layer 1: ClawFeel ✅  │ Hardware entropy — 7 sensors, SHA-256, 256-bit output
```

### Layer 3: ClawDAG (v3.0)

Each Feel reading becomes a DAG transaction referencing 2+ parent transactions:

- **DHT** (Kademlia): 160-bit ID space, TCP RPC, peer discovery without central server
- **DAG**: Transactions form a directed acyclic graph, confirmed by descendant count
- **Gossip**: Transactions propagate to 6 random peers, with seen-set dedup
- **Network entropy**: XOR of all confirmed tip entropies → decentralized random beacon

```bash
# P2P mode
clawfeel --p2p --pretty

# Custom DHT port
clawfeel --p2p --dht-port 31417 --pretty

# Additional bootstrap node
clawfeel --p2p --bootstrap mynode.example.com:31416
```

---

## Security

- **Sensor authenticity**: Each sensor reports `{ value, authentic }`. Fallback values are flagged.
- **Entropy quality scoring**: 4-dimensional (diversity, authenticity, temporal, correlation), 0–100.
- **Weighted input**: Harder-to-fake sensors contribute more to the hash.
- **Chain hashing**: `seq` + `prevHash` form tamper-evident chain.
- **Commit-Reveal**: Two-phase broadcast prevents last-second manipulation.
- **Sybil defense**: IP tracking, subnet dedup, reputation system (0–100).
- **Privacy**: Nodes identified by `Claw-xxxxxxxx` alias, hostname never sent.

---

## Configuration

ClawFeel stores identity in `~/.openclaw/feel.md` (user-editable):

```markdown
# ClawFeel Identity
alias: Claw-6602d212
clawId: 3eda7c810253
relay: https://clawfeel-relay.fly.dev
```

Edit this file to change your alias or relay URL. Changes take effect on next run.

Data files in `~/.clawfeel/`:
- `identity.json` — Node identity (auto-synced from feel.md)
- `history.jsonl` — Feel reading history
- `seq` — Sequence number + chain state
- `daemon.pid` — Background daemon PID
- `routing.json` — DHT routing table
- `dag.jsonl` — DAG transactions

---

## Platform support

| Platform | Status |
|----------|--------|
| Linux (x86/ARM) | Full |
| macOS (Intel/Apple Silicon) | Full |
| Windows (WSL2) | Partial |
| Docker | Partial |

---

## Links

- 🌐 [clawfeel.ai](https://clawfeel.ai)
- 📄 [Whitepaper](https://clawfeel.ai/whitepaper.html)
- 🔴 [Live Simulator](https://clawfeel.ai/simulator.html)
- 📦 [npm](https://www.npmjs.com/package/clawfeel)
- 🐦 [X (Twitter)](https://x.com/clawfeel)
- 📧 [contact@clawfeel.com](mailto:contact@clawfeel.com)

---

## License

MIT

---

*The lobster has a heartbeat now.* 🦞
