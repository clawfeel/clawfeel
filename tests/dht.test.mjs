import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { makeDhtId } from "../scripts/dht.mjs";

describe("DHT", () => {
  describe("makeDhtId()", () => {
    it("should return a 40-char hex string", () => {
      const id = makeDhtId("test-claw-id");
      assert.ok(typeof id === "string");
      assert.equal(id.length, 40);
      assert.ok(/^[0-9a-f]{40}$/.test(id));
    });

    it("should be deterministic", () => {
      assert.equal(makeDhtId("same"), makeDhtId("same"));
    });

    it("should produce different IDs for different inputs", () => {
      assert.notEqual(makeDhtId("alice"), makeDhtId("bob"));
    });
  });

  // KademliaNode tests skipped - requires network (port binding)
  // Full integration tests would need a test harness with mock sockets
});
