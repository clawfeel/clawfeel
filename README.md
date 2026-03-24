# 🦞 ClawFeel

**Your Claw's Heartbeat — Decentralized Hardware Entropy Network**

ClawFeel turns physical hardware signals from every device into crypto-grade randomness, forming a decentralized network that's Bitcoin-robust without the energy waste.

[![npm](https://img.shields.io/npm/v/clawfeel)](https://www.npmjs.com/package/clawfeel)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Quick Start

### OpenClaw Skill (Recommended)

```
"Install the ClawFeel skill"
```

### npm

```bash
npm install -g clawfeel
clawfeel --pretty
```

### npx (No Install)

```bash
npx clawfeel@latest --pretty
```

All options auto-start a background daemon that reports to the network every 30s. Your node stays online even after the terminal closes.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 5: ClawLife    │ AI immortality — Ed25519 identity,      │
│                       │ encrypted memory shards, agent revival  │
├───────────────────────┼─────────────────────────────────────────┤
│  Layer 4: ClawStore   │ Distributed storage — erasure coding,   │
│                       │ DHT-backed redundancy                   │
├───────────────────────┼─────────────────────────────────────────┤
│  Layer 3: ClawDAG     │ DAG consensus — Kademlia DHT, gossip    │
│                       │ protocol, tip selection                 │
├───────────────────────┼─────────────────────────────────────────┤
│  Layer 2: ClawNet     │ P2P network — commit-reveal, Sybil      │
│                       │ defense, reputation system              │
├───────────────────────┼─────────────────────────────────────────┤
│  Layer 1: ClawFeel    │ Hardware entropy — 7 sensors, SHA-256,  │
│                       │ Feel 0-100 + 256-bit output             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Features

- **256-bit crypto-grade entropy** + 64-bit random integer + Feel score (0-100)
- **P2P auto-enabled on desktop** — Kademlia DHT + Gossip protocol
- **NAT traversal** — STUN + UDP hole-punching for firewall-free connectivity
- **WebRTC browser P2P** — browser nodes participate directly in the network
- **Random Beacon** — 10-second rounds, Ed25519 signed, publicly verifiable
- **3 API modes** — Fast (<50ms local), Fair (~10s network consensus), Enterprise (<1ms cached)
- **Zero-Knowledge Proofs** — Sigma protocols + Pedersen commitments + range proofs
- **ClawToken incentive** — full nodes earn more; reputation-weighted rewards
- **Auto-update daemon** — major/minor version auto-upgrade with rollback
- **53 language i18n** — internationalized output and messages
- **Cross-platform** — macOS, Linux, Windows, Browser
- **3 node modes** — Full node / Light node / Relay-only
- **Zero npm dependencies**

---

## CLI Reference

| Flag | Description |
|------|-------------|
| `--pretty` | Colorized human-readable output |
| `--interval <s>` | Repeat every N seconds |
| `--count <n>` | Number of readings |
| `--relay <url>` | Custom relay URL |
| `--p2p` | Enable P2P mode (DHT + Gossip) |
| `--full-node` | Run as full node (store DAG, serve peers) |
| `--light` | Run as light node (minimal resources) |
| `--no-p2p` | Disable P2P, relay-only |
| `--stop` | Stop the background daemon |
| `--status` | Check daemon status |
| `--restart` | Restart the daemon |
| `--history` | View local feel history |
| `--save` | Save reading to history |
| `--broadcast` | Broadcast to LAN |
| `--listen` | Listen for LAN peers |
| `--dag-status` | Show DAG sync status |
| `--dht-port <n>` | Custom DHT port (default: 31416) |
| `--bootstrap <addr>` | Additional bootstrap node |
| `--digit-only` | Output only the digit (0-9) |
| `--json` | JSON output |

---

## SDK Usage

### JavaScript

```javascript
import { ClawRandom } from 'clawfeel'

// Local mode — uses this machine's hardware sensors
const claw = await ClawRandom.local()
const entropy = await claw.getEntropy(256)   // 256-bit hex string
const dice = await claw.range(1, 6)          // random integer 1-6
const bytes = await claw.randomBytes(32)     // 32 random bytes
const float = await claw.randomFloat()       // [0, 1) like Math.random()
const feel  = await claw.getFeel()           // { feel, era, hash, entropy, ... }

// Remote mode — fetch from ClawFeel network
const net = await ClawRandom.remote()
const random = await net.getNetworkRandom()  // aggregated network entropy
const nodes  = await net.getNodes()          // online nodes list

// Real-time subscription (SSE)
const unsub = net.subscribe(state => {
  console.log('Network random:', state.networkRandom)
})
```

### Python

```python
import subprocess, json

result = subprocess.run(["npx", "clawfeel", "--json", "--count", "1"],
                        capture_output=True, text=True)
data = json.loads(result.stdout)
print(data["entropy"])  # 256-bit hex
print(data["feel"])     # 0-100
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/report` | Submit a feel reading |
| GET | `/api/network` | Current network state |
| GET | `/api/stream` | SSE real-time stream |
| GET | `/api/beacon/latest` | Latest random beacon (Ed25519 signed) |
| GET | `/api/v1/random` | Enterprise API (Bearer token required) |
| WS | `/ws/signal` | WebRTC signaling |

Base URL: `https://api.clawfeel.ai`

---

## Security

- **28 vulnerabilities audited**, 12 critical/high fixed
- **AES-256-GCM** encrypted DHT communications
- **Ed25519** transaction signatures
- **Sybil defense** — IP tracking, subnet dedup, reputation system (0-100)
- **Commit-Reveal** — two-phase broadcast prevents last-second manipulation
- **Entropy quality scoring** — 4-dimensional (diversity, authenticity, temporal, correlation)
- **Chain hashing** — `seq` + `prevHash` form tamper-evident chain
- **Zero-Knowledge Proofs** — prove entropy contribution without revealing sensor data
- **Privacy** — nodes identified by `Claw-xxxxxxxx` alias, hostname never sent

---

## Links

- Website: [clawfeel.ai](https://clawfeel.ai)
- API: [api.clawfeel.ai](https://api.clawfeel.ai)
- npm: [npmjs.com/package/clawfeel](https://www.npmjs.com/package/clawfeel)
- Whitepaper: [clawfeel.ai/whitepaper.html](https://clawfeel.ai/whitepaper.html)
- Explorer: [clawfeel.ai/explorer.html](https://clawfeel.ai/explorer.html)
- X/Twitter: [x.com/clawfeel](https://x.com/clawfeel)
- Contact: [contact@clawfeel.com](mailto:contact@clawfeel.com)

---

## License

MIT
