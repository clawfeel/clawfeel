# ClawFeel Python SDK

Python client for the [ClawFeel](https://clawfeel.ai) decentralized hardware entropy network.

## Install

```bash
pip install clawfeel
```

## Quick Start

```python
from clawfeel import ClawRandom, ClawBeacon

# Random numbers from the network
claw = ClawRandom()
entropy = claw.get_entropy(256)      # 256-bit hex string
dice = claw.range(1, 6)              # random int in [1, 6]
secret = claw.random_bytes(32)       # 32 random bytes
coin = claw.random_float()           # float in [0, 1)

# Batch requests
results = claw.batch(count=10, bits=128)

# Verifiable Random Beacon
beacon = ClawBeacon()
latest = beacon.latest()
print(f"Round {latest['round']}: {latest['beaconHash']}")

# Verify any round
proof = beacon.verify(latest["round"])
assert proof["valid"]
```

## API Key

For higher rate limits, get an API key at [clawfeel.ai/enterprise](https://clawfeel.ai/enterprise.html):

```python
claw = ClawRandom(api_key="your-key")
# or set CLAWFEEL_API_KEY environment variable
```

## Links

- Website: https://clawfeel.ai
- API Docs: https://clawfeel.ai/api-docs.html
- GitHub: https://github.com/clawfeel/clawfeel
- npm (Node.js SDK): https://www.npmjs.com/package/clawfeel
