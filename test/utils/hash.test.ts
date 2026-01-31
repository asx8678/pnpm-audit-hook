import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { sha256Hex, isSha512Integrity } from "../../src/utils/hash";

describe("sha256Hex", () => {
  it("produces consistent hash", () => {
    const hash1 = sha256Hex("test");
    const hash2 = sha256Hex("test");
    assert.equal(hash1, hash2);
  });

  it("produces different hash for different input", () => {
    const hash1 = sha256Hex("test1");
    const hash2 = sha256Hex("test2");
    assert.notEqual(hash1, hash2);
  });

  it("produces 64-character hex string", () => {
    const hash = sha256Hex("test");
    assert.equal(hash.length, 64);
    assert.match(hash, /^[a-f0-9]+$/);
  });
});

describe("isSha512Integrity", () => {
  it("returns true for sha512 prefix", () => {
    assert.equal(isSha512Integrity("sha512-abc123"), true);
  });

  it("returns false for other prefixes", () => {
    assert.equal(isSha512Integrity("sha256-abc123"), false);
    assert.equal(isSha512Integrity("md5-abc123"), false);
  });
});
