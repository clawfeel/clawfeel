import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { BeaconRound, BeaconManager } from "../scripts/beacon.mjs";

describe("Beacon", () => {
  describe("BeaconRound.recompute()", () => {
    const contributors = [
      { clawId: "aaa111", hash: "a".repeat(64), feel: 42 },
      { clawId: "bbb222", hash: "b".repeat(64), feel: 73 },
      { clawId: "ccc333", hash: "c".repeat(64), feel: 15 },
    ];

    it("should produce deterministic output for same inputs", () => {
      const r1 = BeaconRound.recompute(contributors, 1);
      const r2 = BeaconRound.recompute(contributors, 1);
      assert.equal(r1.beaconHash, r2.beaconHash);
      assert.equal(r1.beaconNumber, r2.beaconNumber);
    });

    it("should produce different output for different round numbers", () => {
      const r1 = BeaconRound.recompute(contributors, 1);
      const r2 = BeaconRound.recompute(contributors, 2);
      assert.notEqual(r1.beaconHash, r2.beaconHash);
    });

    it("should return 64-char hex beacon hash", () => {
      const r = BeaconRound.recompute(contributors, 1);
      assert.equal(r.beaconHash.length, 64);
      assert.ok(/^[0-9a-f]{64}$/.test(r.beaconHash));
    });

    it("should classify era correctly", () => {
      const r = BeaconRound.recompute(contributors, 1);
      assert.ok(["Chaos", "Transition", "Eternal"].includes(r.era));
    });

    it("should handle single contributor", () => {
      const r = BeaconRound.recompute([{ clawId: "solo", hash: "f".repeat(64), feel: 50 }], 1);
      assert.ok(typeof r.beaconHash === "string");
      assert.equal(r.beaconHash.length, 64);
    });
  });

  describe("BeaconManager", () => {
    it("should seal rounds and retrieve them", () => {
      const mgr = new BeaconManager({ persist: false });
      const nodes = [
        { clawId: "aaa", hash: "a".repeat(16), feel: 50 },
      ];
      mgr.sealRound(nodes);
      mgr.sealRound(nodes);

      const latest = mgr.getLatest();
      assert.ok(latest !== null);
      assert.equal(latest.round, 2);

      const round1 = mgr.getRound(1);
      assert.ok(round1 !== null);
      assert.equal(round1.round, 1);
    });

    it("should return null for non-existent round", () => {
      const mgr = new BeaconManager({ persist: false });
      assert.equal(mgr.getRound(999), null);
    });

    it("should return range of rounds", () => {
      const mgr = new BeaconManager({ persist: false });
      const c = [{ clawId: "x", hash: "f".repeat(16), feel: 50 }];
      for (let i = 0; i < 5; i++) mgr.sealRound(c);

      const range = mgr.getRange(2, 4, 10);
      assert.ok(range.length >= 3);
      // Check that rounds 2-4 are included
      const roundNums = range.map(r => r.round);
      assert.ok(roundNums.includes(2));
      assert.ok(roundNums.includes(3));
      assert.ok(roundNums.includes(4));
    });

    it("should produce verifiable rounds", () => {
      const mgr = new BeaconManager({ persist: false });
      mgr.sealRound([
        { clawId: "aaa", hash: "a".repeat(16), feel: 50 },
        { clawId: "bbb", hash: "b".repeat(16), feel: 75 },
      ]);
      const round = mgr.getLatest();
      const recomputed = BeaconRound.recompute(round.contributors, round.round);
      assert.equal(recomputed.beaconHash, round.beaconHash);
    });
  });
});
