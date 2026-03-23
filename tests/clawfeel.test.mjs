import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { collectSensors, computeFeel, getClawId } from "../scripts/clawfeel.mjs";

describe("ClawFeel Core", () => {
  let sensors;

  before(async () => {
    sensors = await collectSensors();
  });

  describe("collectSensors()", () => {
    it("should return 7 sensor readings", () => {
      assert.equal(Object.keys(sensors).length, 7);
    });

    it("should have {value, authentic} structure for each sensor", () => {
      for (const [name, reading] of Object.entries(sensors)) {
        assert.ok(typeof reading.value === "number", `${name}.value should be number`);
        assert.ok(typeof reading.authentic === "boolean", `${name}.authentic should be boolean`);
      }
    });

    it("should return numeric values in valid ranges", () => {
      for (const [name, reading] of Object.entries(sensors)) {
        assert.ok(isFinite(reading.value), `${name}.value should be finite`);
      }
    });
  });

  describe("computeFeel()", () => {
    it("should return a result object with required fields", () => {
      const result = computeFeel(sensors);
      assert.ok(result.feel >= 0 && result.feel <= 100, "feel should be 0-100");
      assert.ok(["Chaos", "Transition", "Eternal"].includes(result.era), "era should be valid");
      assert.ok(typeof result.hash === "string", "hash should be string");
      assert.ok(result.hash.length === 16, "hash should be 16 hex chars");
      assert.ok(typeof result.entropy === "string", "entropy should be string");
      assert.ok(result.entropy.length === 64, "entropy should be 64 hex chars (256-bit)");
      assert.ok(typeof result.random === "string" || typeof result.random === "bigint" || typeof result.random === "number", "random should exist");
      assert.ok(typeof result.randomBytes === "string", "randomBytes should be base64 string");
    });

    it("should classify eras correctly", () => {
      // Run multiple times, verify era matches feel
      for (let i = 0; i < 10; i++) {
        const result = computeFeel(sensors);
        if (result.feel <= 30) assert.equal(result.era, "Chaos");
        else if (result.feel <= 70) assert.equal(result.era, "Transition");
        else assert.equal(result.era, "Eternal");
      }
    });

    it("should produce different hashes for different sensor inputs", () => {
      const result1 = computeFeel(sensors);
      // Modify one sensor
      const modified = { ...sensors };
      const firstKey = Object.keys(modified)[0];
      modified[firstKey] = { value: modified[firstKey].value + 1, authentic: true };
      const result2 = computeFeel(modified);
      assert.notEqual(result1.hash, result2.hash, "different inputs should produce different hashes");
    });

    it("should include authenticity count (0-7)", () => {
      const result = computeFeel(sensors);
      assert.ok(result.authenticity >= 0 && result.authenticity <= 7);
    });

    it("should include entropy quality score (0-100)", () => {
      const result = computeFeel(sensors);
      assert.ok(result.entropyQuality >= 0 && result.entropyQuality <= 100);
    });

    it("should include 7-bit sensor flags", () => {
      const result = computeFeel(sensors);
      assert.ok(typeof result.sensorFlags === "string");
      assert.equal(result.sensorFlags.length, 7);
      assert.ok(/^[01]{7}$/.test(result.sensorFlags));
    });

    it("should include seq and prevHash for chain hashing", () => {
      const result = computeFeel(sensors);
      assert.ok(typeof result.seq === "number");
      assert.ok(typeof result.prevHash === "string");
    });
  });

  describe("getClawId()", () => {
    it("should return a 12-char hex string", () => {
      const id = getClawId();
      assert.ok(typeof id === "string");
      assert.equal(id.length, 12);
      assert.ok(/^[0-9a-f]{12}$/.test(id));
    });

    it("should be deterministic (same machine = same id)", () => {
      const id1 = getClawId();
      const id2 = getClawId();
      assert.equal(id1, id2);
    });
  });
});
