import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { ErasureCoder } from "../scripts/store.mjs";

describe("ClawStore", () => {
  describe("ErasureCoder", () => {
    it("should split data into k data blocks + m parity blocks", () => {
      const ec = new ErasureCoder({ k: 3, m: 2 });
      const data = Buffer.from("Hello, ClawFeel distributed storage!");
      const { dataBlocks, parityBlocks, blockSize } = ec.encode(data);
      assert.equal(dataBlocks.length, 3);
      assert.equal(parityBlocks.length, 2);
      assert.ok(blockSize > 0);
    });

    it("should reconstruct from all blocks", () => {
      const ec = new ErasureCoder({ k: 3, m: 2 });
      const original = Buffer.from("Reconstruct me perfectly!");
      const { dataBlocks, parityBlocks, blockSize } = ec.encode(original);
      const recovered = ec.decode(dataBlocks, parityBlocks, {
        blockSize,
        originalSize: original.length,
      });
      assert.ok(recovered.slice(0, original.length).equals(original));
    });

    it("should reconstruct with one missing data block", () => {
      const ec = new ErasureCoder({ k: 3, m: 2 });
      const original = Buffer.from("Survive missing shards!!");
      const { dataBlocks, parityBlocks, blockSize } = ec.encode(original);
      // Remove first data block
      dataBlocks[0] = null;
      const recovered = ec.decode(dataBlocks, parityBlocks, {
        blockSize,
        originalSize: original.length,
      });
      assert.ok(recovered.slice(0, original.length).equals(original));
    });

    it("should handle large data", () => {
      const ec = new ErasureCoder({ k: 4, m: 2 });
      const data = Buffer.alloc(10000, 0x42);
      const { dataBlocks, parityBlocks, blockSize } = ec.encode(data);
      assert.equal(dataBlocks.length, 4);
      assert.equal(parityBlocks.length, 2);
      const recovered = ec.decode(dataBlocks, parityBlocks, {
        blockSize,
        originalSize: data.length,
      });
      assert.ok(recovered.slice(0, data.length).equals(data));
    });
  });
});
