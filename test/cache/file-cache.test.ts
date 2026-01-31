import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { FileCache } from "../../src/cache/file-cache";

describe("FileCache", () => {
  let tempDir: string;
  let cache: FileCache<string>;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "file-cache-test-"));
    cache = new FileCache<string>({ dir: tempDir });
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  describe("set and get", () => {
    it("stores and retrieves a value", async () => {
      await cache.set("test-key", "test-value", 60);
      const result = await cache.get("test-key");
      
      assert.ok(result !== null);
      assert.equal(result.value, "test-value");
    });

    it("stores complex objects", async () => {
      const objectCache = new FileCache<{ foo: string; bar: number }>({ dir: tempDir });
      const value = { foo: "hello", bar: 42 };
      
      await objectCache.set("obj-key", value, 60);
      const result = await objectCache.get("obj-key");
      
      assert.ok(result !== null);
      assert.deepEqual(result.value, value);
    });

    it("stores arrays", async () => {
      const arrayCache = new FileCache<string[]>({ dir: tempDir });
      const value = ["a", "b", "c"];
      
      await arrayCache.set("arr-key", value, 60);
      const result = await arrayCache.get("arr-key");
      
      assert.ok(result !== null);
      assert.deepEqual(result.value, value);
    });
  });

  describe("TTL expiration", () => {
    it("returns entry before expiration", async () => {
      await cache.set("ttl-key", "value", 60);
      const result = await cache.get("ttl-key");
      
      assert.ok(result !== null);
      assert.equal(result.value, "value");
    });

    it("returns null after expiration", async () => {
      await cache.set("expire-key", "value", 0); // 0 second TTL = immediate expiration
      
      // Small delay to ensure expiration
      await new Promise(resolve => setTimeout(resolve, 10));
      
      const result = await cache.get("expire-key");
      assert.equal(result, null);
    });

    it("includes storedAt and expiresAt timestamps", async () => {
      const before = Date.now();
      await cache.set("time-key", "value", 60);
      const after = Date.now();
      
      const result = await cache.get("time-key");
      
      assert.ok(result !== null);
      assert.ok(result.storedAt >= before);
      assert.ok(result.storedAt <= after);
      assert.ok(result.expiresAt > result.storedAt);
      assert.ok(result.expiresAt <= after + 60 * 1000);
    });
  });

  describe("missing keys", () => {
    it("returns null for non-existent key", async () => {
      const result = await cache.get("non-existent-key");
      assert.equal(result, null);
    });

    it("returns null for different keys with same prefix", async () => {
      await cache.set("key-abc", "value1", 60);
      
      const result = await cache.get("key-abcd");
      assert.equal(result, null);
    });
  });

  describe("directory creation", () => {
    it("creates cache directory if not exists", async () => {
      const newDir = path.join(tempDir, "nested", "cache", "dir");
      const nestedCache = new FileCache<string>({ dir: newDir });
      
      await nestedCache.set("nested-key", "nested-value", 60);
      
      const result = await nestedCache.get("nested-key");
      assert.ok(result !== null);
      assert.equal(result.value, "nested-value");
      
      // Verify directory was created
      const stat = await fs.stat(newDir);
      assert.ok(stat.isDirectory());
    });

    it("creates two-level fanout directories", async () => {
      await cache.set("fanout-key", "value", 60);

      // Check that subdirectories exist
      const entries = await fs.readdir(tempDir);
      assert.ok(entries.length > 0);

      // First level should be 2-character hex directory
      const firstLevel = entries[0]!;
      assert.equal(firstLevel.length, 2);
      assert.ok(/^[0-9a-f]{2}$/.test(firstLevel));
    });
  });

  describe("key isolation", () => {
    it("different keys have different values", async () => {
      await cache.set("key1", "value1", 60);
      await cache.set("key2", "value2", 60);
      
      const result1 = await cache.get("key1");
      const result2 = await cache.get("key2");
      
      assert.ok(result1 !== null);
      assert.ok(result2 !== null);
      assert.equal(result1.value, "value1");
      assert.equal(result2.value, "value2");
    });

    it("overwrites existing value for same key", async () => {
      await cache.set("overwrite-key", "original", 60);
      await cache.set("overwrite-key", "updated", 60);
      
      const result = await cache.get("overwrite-key");
      
      assert.ok(result !== null);
      assert.equal(result.value, "updated");
    });
  });

  describe("special characters in keys", () => {
    it("handles keys with special characters", async () => {
      const specialKeys = [
        "key/with/slashes",
        "key:with:colons",
        "@scoped/package@1.0.0",
        "key with spaces",
        "key\nwith\nnewlines",
      ];
      
      for (const key of specialKeys) {
        await cache.set(key, `value-for-${key}`, 60);
        const result = await cache.get(key);
        
        assert.ok(result !== null, `Failed to retrieve key: ${key}`);
        assert.equal(result.value, `value-for-${key}`);
      }
    });
  });

  describe("concurrent operations", () => {
    it("handles concurrent writes to different keys", async () => {
      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(cache.set(`concurrent-key-${i}`, `value-${i}`, 60));
      }
      
      await Promise.all(promises);
      
      for (let i = 0; i < 10; i++) {
        const result = await cache.get(`concurrent-key-${i}`);
        assert.ok(result !== null);
        assert.equal(result.value, `value-${i}`);
      }
    });
  });
});
