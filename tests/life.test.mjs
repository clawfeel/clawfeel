import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { ed25519Sign, ed25519Verify } from "../scripts/life.mjs";
import { randomBytes, createPrivateKey, createPublicKey } from "node:crypto";

// Helper: generate an Ed25519 raw 32-byte private key hex
function genPrivateKeyHex() {
  return randomBytes(32).toString("hex");
}

// Helper: derive public key hex from private key hex
function derivePublicKeyHex(privateKeyHex) {
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const der = Buffer.concat([prefix, Buffer.from(privateKeyHex, "hex")]);
  const keyObj = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const pubDer = createPublicKey(keyObj).export({ type: "spki", format: "der" });
  return pubDer.subarray(-32).toString("hex");
}

describe("ClawLife Crypto", () => {
  describe("Ed25519 Sign/Verify", () => {
    it("should sign and verify a message", () => {
      const privHex = genPrivateKeyHex();
      const pubHex = derivePublicKeyHex(privHex);
      const message = "Hello ClawFeel";
      const sigHex = ed25519Sign(message, privHex);

      assert.ok(typeof sigHex === "string");
      assert.equal(sigHex.length, 128); // 64 bytes = 128 hex
      assert.ok(ed25519Verify(message, sigHex, pubHex));
    });

    it("should reject tampered message", () => {
      const privHex = genPrivateKeyHex();
      const pubHex = derivePublicKeyHex(privHex);
      const sigHex = ed25519Sign("original", privHex);
      assert.ok(!ed25519Verify("tampered", sigHex, pubHex));
    });

    it("should reject wrong public key", () => {
      const key1 = genPrivateKeyHex();
      const key2 = genPrivateKeyHex();
      const sigHex = ed25519Sign("test", key1);
      const wrongPub = derivePublicKeyHex(key2);
      assert.ok(!ed25519Verify("test", sigHex, wrongPub));
    });

    it("should produce deterministic signatures for same key+message", () => {
      const privHex = genPrivateKeyHex();
      const sig1 = ed25519Sign("deterministic test", privHex);
      const sig2 = ed25519Sign("deterministic test", privHex);
      assert.equal(sig1, sig2);
    });
  });
});
