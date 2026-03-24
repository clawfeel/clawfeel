"""ClawFeel Python SDK — Client for the ClawFeel random number network."""

import hashlib
import json
import os
import struct
import time
import urllib.request
import urllib.error
from typing import Optional, List, Dict, Any

DEFAULT_RELAY = "https://clawfeel-relay.fly.dev"


class ClawRandom:
    """Client for ClawFeel decentralized random numbers.

    Usage:
        from clawfeel import ClawRandom

        # Remote mode (fetch from network)
        claw = ClawRandom()
        entropy = claw.get_entropy(256)
        dice = claw.range(1, 6)
        password_bytes = claw.random_bytes(32)

        # With API key (higher rate limits)
        claw = ClawRandom(api_key="your-key")
    """

    def __init__(self, relay: str = DEFAULT_RELAY, api_key: Optional[str] = None):
        self.relay = relay.rstrip("/")
        self.api_key = api_key or os.environ.get("CLAWFEEL_API_KEY")

    def _request(self, path: str, headers: Optional[Dict] = None) -> Dict:
        """Make authenticated request to relay API."""
        url = f"{self.relay}{path}"
        hdrs = {"Accept": "application/json"}
        if self.api_key:
            hdrs["Authorization"] = f"Bearer {self.api_key}"
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            raise RuntimeError(f"ClawFeel API error {e.code}: {body}") from e
        except urllib.error.URLError as e:
            raise ConnectionError(f"Cannot reach relay: {e.reason}") from e

    def get_entropy(self, bits: int = 256) -> str:
        """Get cryptographic entropy as hex string.

        Args:
            bits: Number of bits (64, 128, 256, 512). Default 256.

        Returns:
            Hex string of the requested bit length.
        """
        data = self._request(f"/api/v1/random?bits={bits}")
        return data.get("entropy", data.get("hex", ""))

    def range(self, min_val: int, max_val: int) -> int:
        """Get a random integer in [min, max] range.

        Args:
            min_val: Minimum value (inclusive).
            max_val: Maximum value (inclusive).

        Returns:
            Random integer in the specified range.
        """
        data = self._request(f"/api/v1/random/range?min={min_val}&max={max_val}")
        return data.get("value", data.get("number", 0))

    def random_bytes(self, n: int = 32) -> bytes:
        """Get n random bytes.

        Args:
            n: Number of bytes. Default 32.

        Returns:
            Random bytes.
        """
        hex_str = self.get_entropy(n * 8)
        return bytes.fromhex(hex_str[:n * 2])

    def random_float(self) -> float:
        """Get a random float in [0, 1).

        Returns:
            Random float.
        """
        hex_str = self.get_entropy(64)
        val = int(hex_str[:16], 16)
        return val / (2**64)

    def batch(self, count: int = 10, bits: int = 256) -> List[Dict]:
        """Get multiple random numbers in one call.

        Args:
            count: Number of random values. Default 10.
            bits: Bits per value. Default 256.

        Returns:
            List of random number objects.
        """
        data = self._request(f"/api/v1/random/batch?count={count}&bits={bits}")
        return data.get("results", [])

    def get_network(self) -> Dict:
        """Get current network state (nodes, random number, stats).

        Returns:
            Network state dictionary.
        """
        return self._request("/api/network")

    def get_nodes(self) -> List[Dict]:
        """Get list of online nodes.

        Returns:
            List of node dictionaries.
        """
        data = self.get_network()
        return data.get("nodes", [])


class ClawBeacon:
    """Client for ClawFeel Random Beacon — verifiable randomness.

    Usage:
        from clawfeel import ClawBeacon

        beacon = ClawBeacon()
        latest = beacon.latest()
        print(latest["round"], latest["beaconHash"])

        # Verify a round
        verification = beacon.verify(latest["round"])
        assert verification["valid"]
    """

    def __init__(self, relay: str = DEFAULT_RELAY, api_key: Optional[str] = None):
        self.relay = relay.rstrip("/")
        self.api_key = api_key or os.environ.get("CLAWFEEL_API_KEY")

    def _request(self, path: str) -> Dict:
        url = f"{self.relay}{path}"
        hdrs = {"Accept": "application/json"}
        if self.api_key:
            hdrs["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(url, headers=hdrs)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())

    def latest(self) -> Dict:
        """Get the latest beacon round.

        Returns:
            Beacon round with hash, number, signature, contributors.
        """
        return self._request("/api/beacon/latest")

    def get_round(self, round_number: int) -> Dict:
        """Get a specific beacon round by number.

        Args:
            round_number: The round number to fetch.

        Returns:
            Beacon round data.
        """
        return self._request(f"/api/beacon/{round_number}")

    def get_range(self, from_round: int, to_round: int) -> List[Dict]:
        """Get a range of beacon rounds.

        Args:
            from_round: Start round (inclusive).
            to_round: End round (inclusive).

        Returns:
            List of beacon rounds.
        """
        data = self._request(f"/api/beacons?from={from_round}&to={to_round}")
        return data.get("rounds", [])

    def verify(self, round_number: int) -> Dict:
        """Verify a beacon round (recompute and check signature).

        Args:
            round_number: The round number to verify.

        Returns:
            Verification result with valid flag and details.
        """
        return self._request(f"/api/v1/random/verify?round={round_number}")
