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
      await cache.set("expire-key", "value", 0.001); // 1ms TTL = near-immediate expiration

      // Small delay to ensure expiration
      await new Promise(resolve => setTimeout(resolve, 10));

      const result = await cache.get("expire-key");
      assert.equal(result, null);
    });

    it("throws error for invalid TTL values", async () => {
      await assert.rejects(
        cache.set("zero-ttl", "value", 0),
        { message: "Invalid TTL: 0" }
      );
      await assert.rejects(
        cache.set("negative-ttl", "value", -1),
        { message: "Invalid TTL: -1" }
      );
      await assert.rejects(
        cache.set("infinity-ttl", "value", Infinity),
        { message: "Invalid TTL: Infinity" }
      );
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

  describe("prune", () => {
    it("removes expired entries", async () => {
      // Create an entry that will expire immediately
      await cache.set("expire-soon", "value", 0.001);
      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 10));

      const result = await cache.prune();

      assert.equal(result.pruned, 1);
      assert.equal(result.failed, 0);

      // Verify entry is gone
      const entry = await cache.get("expire-soon");
      assert.equal(entry, null);
    });

    it("does not remove non-expired entries", async () => {
      await cache.set("still-valid", "value", 3600); // 1 hour TTL

      const result = await cache.prune();

      assert.equal(result.pruned, 0);
      assert.equal(result.failed, 0);

      // Verify entry still exists
      const entry = await cache.get("still-valid");
      assert.ok(entry !== null);
      assert.equal(entry.value, "value");
    });

    it("handles corrupted cache files (deletes them)", async () => {
      // First create a valid entry to get the directory structure
      await cache.set("valid-key", "value", 3600);

      // Find the subdirectory
      const subdirs = await fs.readdir(tempDir);
      const subdir = subdirs[0]!;
      const subdirPath = path.join(tempDir, subdir);

      // Write a corrupted file
      await fs.writeFile(
        path.join(subdirPath, "corrupted.json"),
        "not valid json {"
      );

      const result = await cache.prune();

      // Corrupted file should be deleted (counted as pruned)
      assert.equal(result.pruned, 1);
      assert.equal(result.failed, 0);
    });

    it("handles non-existent cache directory", async () => {
      const nonExistentDir = path.join(tempDir, "does-not-exist");
      const emptyCache = new FileCache<string>({ dir: nonExistentDir });

      const result = await emptyCache.prune();

      assert.equal(result.pruned, 0);
      assert.equal(result.failed, 0);
    });

    it("returns correct counts (pruned and failed)", async () => {
      // Create multiple entries with different expiration states
      await cache.set("expired-1", "value", 0.001);
      await cache.set("expired-2", "value", 0.001);
      await cache.set("valid-1", "value", 3600);
      await cache.set("valid-2", "value", 3600);

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 10));

      const result = await cache.prune();

      assert.equal(result.pruned, 2);
      assert.equal(result.failed, 0);

      // Verify valid entries still exist
      const valid1 = await cache.get("valid-1");
      const valid2 = await cache.get("valid-2");
      assert.ok(valid1 !== null);
      assert.ok(valid2 !== null);
    });

    it("handles empty cache directory", async () => {
      // tempDir exists but has no cache entries
      const result = await cache.prune();

      assert.equal(result.pruned, 0);
      assert.equal(result.failed, 0);
    });

    it("handles entries with invalid structure (missing expiresAt)", async () => {
      // Create a valid entry first to ensure directory structure
      await cache.set("setup-key", "value", 3600);

      // Find the subdirectory
      const subdirs = await fs.readdir(tempDir);
      const subdir = subdirs[0]!;
      const subdirPath = path.join(tempDir, subdir);

      // Write file with invalid structure (missing expiresAt)
      await fs.writeFile(
        path.join(subdirPath, "invalid-structure.json"),
        JSON.stringify({ value: "test", storedAt: Date.now() })
      );

      const result = await cache.prune();

      // Invalid structure should be deleted
      assert.ok(result.pruned >= 1);
      assert.equal(result.failed, 0);
    });
  });

  describe("Enhanced Features", () => {
    describe("LRU eviction in path cache", () => {
      it("should evict oldest entries when path cache exceeds limit", async () => {
        const lruCache = new FileCache<string>({ 
          dir: tempDir, 
          maxPathCacheEntries: 2 // Very small limit for testing
        });

        // Add 3 entries
        await lruCache.set("key1", "value1", 3600);
        await lruCache.set("key2", "value2", 3600);
        await lruCache.set("key3", "value3", 3600);

        // Access key1 to make it recently used
        await lruCache.get("key1");

        // Add another entry to trigger eviction
        await lruCache.set("key4", "value4", 3600);

        // All values should still be retrievable from disk
        const val1 = await lruCache.get("key1");
        const val2 = await lruCache.get("key2");
        const val3 = await lruCache.get("key3");
        const val4 = await lruCache.get("key4");

        assert.equal(val1?.value, "value1");
        assert.equal(val2?.value, "value2");
        assert.equal(val3?.value, "value3");
        assert.equal(val4?.value, "value4");

        // Check that evictions happened in memory
        const stats = lruCache.getStatistics();
        assert.ok(stats.evictions > 0, "Should have evicted some entries");
      });

      it("should maintain access order for LRU behavior", async () => {
        const lruCache = new FileCache<string>({ 
          dir: tempDir, 
          maxPathCacheEntries: 2
        });

        await lruCache.set("key1", "value1", 3600);
        await lruCache.set("key2", "value2", 3600);

        // Access key1 to make it recently used
        await lruCache.get("key1");

        // Add key3 - should evict key2 (least recently used)
        await lruCache.set("key3", "value3", 3600);

        // key1 should be in memory cache (recently accessed)
        // key2 and key3 might need disk reads
        const val1 = await lruCache.get("key1");
        assert.equal(val1?.value, "value1");
      });
    });

    describe("Cache statistics", () => {
      it("should track hit/miss ratios", async () => {
        const statsCache = new FileCache<string>({ dir: tempDir });

        // Initially all misses
        await statsCache.get("nonexistent1");
        await statsCache.get("nonexistent2");

        let stats = statsCache.getStatistics();
        assert.equal(stats.hits, 0);
        assert.equal(stats.misses, 2);

        // Add an entry
        await statsCache.set("existing", "value", 3600);

        // Hit
        await statsCache.get("existing");
        stats = statsCache.getStatistics();
        assert.equal(stats.hits, 1);
        assert.equal(stats.misses, 2);
      });

      it("should track cache size", async () => {
        const statsCache = new FileCache<string>({ dir: tempDir });

        await statsCache.set("key1", "value1", 3600);
        await statsCache.set("key2", "value2", 3600);

        const stats = statsCache.getStatistics();
        assert.ok(stats.totalSizeBytes > 0, "Should track total size");
        assert.ok(stats.sets >= 2, "Should track sets");
      });

      it("should track performance metrics", async () => {
        const statsCache = new FileCache<string>({ dir: tempDir });

        await statsCache.set("key1", "value1", 3600);
        await statsCache.get("key1");

        const stats = statsCache.getStatistics();
        assert.ok(stats.averageReadTimeMs >= 0, "Should track read performance");
        assert.ok(stats.averageWriteTimeMs >= 0, "Should track write performance");
      });
    });

    describe("Smart invalidation", () => {
      it("should support version-aware caching", async () => {
        const versionCache = new FileCache<string>({ dir: tempDir });

        // Store with version
        await versionCache.set("key1", "value1", 3600, { version: "1.0" });

        // Retrieve
        const entry = await versionCache.get("key1");
        assert.equal(entry?.version, "1.0");
        assert.equal(entry?.value, "value1");
      });

      it("should support dependency tracking", async () => {
        const depCache = new FileCache<string>({ dir: tempDir });

        // Store with dependencies
        await depCache.set("key1", "value1", 3600, { 
          dependencies: ["dep1", "dep2"] 
        });

        // Retrieve
        const entry = await depCache.get("key1");
        assert.deepEqual(entry?.dependencies, ["dep1", "dep2"]);
      });
    });

    describe("Cache operations", () => {
      it("should delete entries", async () => {
        const opCache = new FileCache<string>({ dir: tempDir });

        await opCache.set("key1", "value1", 3600);
        const deleted = await opCache.delete("key1");
        assert.equal(deleted, true);

        const entry = await opCache.get("key1");
        assert.equal(entry, null);
      });

      it("should check if key exists", async () => {
        const opCache = new FileCache<string>({ dir: tempDir });

        await opCache.set("key1", "value1", 3600);

        assert.equal(await opCache.has("key1"), true);
        assert.equal(await opCache.has("nonexistent"), false);
      });

      it("should clear all entries", async () => {
        const opCache = new FileCache<string>({ dir: tempDir });

        await opCache.set("key1", "value1", 3600);
        await opCache.set("key2", "value2", 3600);

        await opCache.clear();

        assert.equal(await opCache.has("key1"), false);
        assert.equal(await opCache.has("key2"), false);
      });
    });

    describe("Cache health", () => {
      it("should report healthy status for good cache", async () => {
        const healthCache = new FileCache<string>({ dir: tempDir });

        // Add some entries and access them
        await healthCache.set("key1", "value1", 3600);
        await healthCache.set("key2", "value2", 3600);
        await healthCache.get("key1");
        await healthCache.get("key2");

        const health = healthCache.getHealth();
        assert.equal(health.status, "healthy");
        assert.ok(health.hitRate > 0.5, "Should have good hit rate");
        assert.ok(health.entryCount >= 2, "Should track entry count");
      });

      it("should provide recommendations", async () => {
        const healthCache = new FileCache<string>({ dir: tempDir });

        // Create poor cache performance
        for (let i = 0; i < 10; i++) {
          await healthCache.get(`nonexistent${i}`);
        }

        const health = healthCache.getHealth();
        assert.ok(health.recommendations.length > 0, "Should have recommendations");
      });
    });

    describe("Size-based pruning", () => {
      it("should enforce entry count limits", async () => {
        const limitCache = new FileCache<string>({ 
          dir: tempDir, 
          maxEntries: 2 
        });

        // Add 3 entries - should trigger pruning
        await limitCache.set("key1", "value1", 3600);
        await limitCache.set("key2", "value2", 3600);
        await limitCache.set("key3", "value3", 3600);

        // At least some entries should have been pruned
        const stats = limitCache.getStatistics();
        assert.ok(stats.evictions > 0, "Should have evicted entries");
      });
    });

    describe("Pruning updates statistics", () => {
      it("should update statistics after pruning", async () => {
        const pruneStatsCache = new FileCache<string>({ dir: tempDir });

        await pruneStatsCache.set("key1", "value1", 0.001); // 1ms TTL
        await new Promise(resolve => setTimeout(resolve, 10));

        const beforeStats = pruneStatsCache.getStatistics();
        await pruneStatsCache.prune();
        const afterStats = pruneStatsCache.getStatistics();

        assert.ok(afterStats.prunedEntries >= beforeStats.prunedEntries + 1, 
          "Should update prunedEntries count");
        assert.ok(afterStats.lastPruneTime, "Should update lastPruneTime");
      });
    });
  });
});
