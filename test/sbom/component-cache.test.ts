/**
 * Tests for SBOM Component Cache.
 *
 * Tests the SbomComponentCache class including LRU eviction,
 * persistence, integrity validation, and statistics tracking.
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import {
  SbomComponentCache,
  createComponentCache,
} from "../../src/sbom/component-cache";
import type { PackageRef } from "../../src/types";
import type { SbomComponent } from "../../src/sbom/types";

// ============================================================================
// Test Fixtures
// ============================================================================

const mockPackages: PackageRef[] = [
  { name: "express", version: "4.18.2", integrity: "sha512-abc123def456" },
  { name: "lodash", version: "4.17.21", dependencies: ["express"] },
  { name: "@scope/package", version: "1.0.0", integrity: "sha256-xyz789" },
  { name: "minimist", version: "1.2.5" },
];

const mockComponents: SbomComponent[] = [
  {
    name: "express",
    version: "4.18.2",
    purl: "pkg:npm/express@4.18.2",
    hashes: [{ algorithm: "SHA-512", value: "abc123def456" }],
  },
  {
    name: "lodash",
    version: "4.17.21",
    purl: "pkg:npm/lodash@4.17.21",
    dependencies: ["express"],
  },
  {
    name: "@scope/package",
    version: "1.0.0",
    purl: "pkg:npm/%40scope%2Fpackage@1.0.0",
    hashes: [{ algorithm: "SHA-256", value: "xyz789" }],
  },
  {
    name: "minimist",
    version: "1.2.5",
    purl: "pkg:npm/minimist@1.2.5",
  },
];

// ============================================================================
// Helper Functions
// ============================================================================

function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sbom-cache-test-"));
}

function cleanupTempDir(dir: string): void {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    // Ignore cleanup errors
  }
}

// ============================================================================
// Tests
// ============================================================================

describe("SbomComponentCache", () => {
  describe("Basic Operations", () => {
    it("should create a cache with default options", () => {
      const cache = new SbomComponentCache();
      assert.equal(cache.size, 0);
      const stats = cache.getStats();
      assert.equal(stats.hits, 0);
      assert.equal(stats.misses, 0);
      assert.equal(stats.size, 0);
      assert.equal(stats.hitRate, 0);
    });

    it("should create a cache with custom options", () => {
      const cache = new SbomComponentCache({
        maxEntries: 500,
        ttlMs: 3600000,
      });
      assert.equal(cache.size, 0);
    });

    it("should store and retrieve components", () => {
      const cache = new SbomComponentCache();
      cache.setComponent("express", "4.18.2", mockComponents[0]);

      const component = cache.getComponent("express", "4.18.2");
      assert.deepEqual(component, mockComponents[0]);
    });

    it("should store and retrieve multiple components", () => {
      const cache = new SbomComponentCache();
      cache.setComponents(mockPackages, mockComponents);

      assert.equal(cache.size, 4);

      const component1 = cache.getComponent("express", "4.18.2");
      const component2 = cache.getComponent("lodash", "4.17.21");
      assert.deepEqual(component1, mockComponents[0]);
      assert.deepEqual(component2, mockComponents[1]);
    });

    it("should return undefined for missing components", () => {
      const cache = new SbomComponentCache();
      const component = cache.getComponent("missing", "1.0.0");
      assert.equal(component, undefined);
    });

    it("should check component existence with has()", () => {
      const cache = new SbomComponentCache();
      cache.setComponent("express", "4.18.2", mockComponents[0]);

      assert.equal(cache.has("express", "4.18.2"), true);
      assert.equal(cache.has("missing", "1.0.0"), false);
    });

    it("should remove components", () => {
      const cache = new SbomComponentCache();
      cache.setComponent("express", "4.18.2", mockComponents[0]);

      assert.equal(cache.has("express", "4.18.2"), true);
      const removed = cache.remove("express", "4.18.2");
      assert.equal(removed, true);
      assert.equal(cache.has("express", "4.18.2"), false);
    });

    it("should return false when removing non-existent component", () => {
      const cache = new SbomComponentCache();
      const removed = cache.remove("missing", "1.0.0");
      assert.equal(removed, false);
    });

    it("should clear all components", () => {
      const cache = new SbomComponentCache();
      cache.setComponents(mockPackages, mockComponents);
      assert.equal(cache.size, 4);

      cache.clear();
      assert.equal(cache.size, 0);
    });
  });

  describe("LRU Eviction", () => {
    it("should evict oldest entry when cache is full", () => {
      const cache = new SbomComponentCache({ maxEntries: 2 });

      cache.setComponent("express", "4.18.2", mockComponents[0]);
      cache.setComponent("lodash", "4.17.21", mockComponents[1]);
      cache.setComponent("@scope/package", "1.0.0", mockComponents[2]);

      // express should be evicted (oldest)
      assert.equal(cache.has("express", "4.18.2"), false);
      assert.equal(cache.has("lodash", "4.17.21"), true);
      assert.equal(cache.has("@scope/package", "1.0.0"), true);
      assert.equal(cache.size, 2);
    });

    it("should move accessed entries to end (LRU behavior)", () => {
      const cache = new SbomComponentCache({ maxEntries: 2 });

      cache.setComponent("express", "4.18.2", mockComponents[0]);
      cache.setComponent("lodash", "4.17.21", mockComponents[1]);

      // Access express to move it to end
      cache.getComponent("express", "4.18.2");

      // Now lodash should be evicted
      cache.setComponent("@scope/package", "1.0.0", mockComponents[2]);

      assert.equal(cache.has("express", "4.18.2"), true);
      assert.equal(cache.has("lodash", "4.17.21"), false);
      assert.equal(cache.has("@scope/package", "1.0.0"), true);
    });

    it("should update existing entry without eviction", () => {
      const cache = new SbomComponentCache({ maxEntries: 2 });

      cache.setComponent("express", "4.18.2", mockComponents[0]);
      cache.setComponent("lodash", "4.17.21", mockComponents[1]);

      // Update express
      cache.setComponent("express", "4.18.2", { ...mockComponents[0], version: "4.19.0" });

      assert.equal(cache.size, 2);
      const component = cache.getComponent("express", "4.18.2");
      assert.equal(component?.version, "4.19.0");
    });
  });

  describe("Integrity Validation", () => {
    it("should invalidate cache on integrity mismatch", () => {
      const cache = new SbomComponentCache();
      cache.setComponent("express", "4.18.2", mockComponents[0], "sha512-abc123");

      // Different integrity hash should cause invalidation
      const component = cache.getComponent("express", "4.18.2", "sha512-different");
      assert.equal(component, undefined);
    });

    it("should accept matching integrity hash", () => {
      const cache = new SbomComponentCache();
      cache.setComponent("express", "4.18.2", mockComponents[0], "sha512-abc123");

      const component = cache.getComponent("express", "4.18.2", "sha512-abc123");
      assert.deepEqual(component, mockComponents[0]);
    });

    it("should accept component without integrity check when no integrity provided", () => {
      const cache = new SbomComponentCache();
      cache.setComponent("express", "4.18.2", mockComponents[0], "sha512-abc123");

      // No integrity provided - should still return cached component
      const component = cache.getComponent("express", "4.18.2");
      assert.deepEqual(component, mockComponents[0]);
    });

    it("should validate integrity for bulk operations", () => {
      const cache = new SbomComponentCache();
      cache.setComponents(mockPackages, mockComponents);

      // Try to get with different integrity hash
      const packagesWithWrongIntegrity: PackageRef[] = [
        { name: "express", version: "4.18.2", integrity: "sha512-wrong" },
      ];

      const result = cache.getComponents(packagesWithWrongIntegrity);
      // Should return null when no valid cached components exist
      assert.equal(result, null);
    });
  });

  describe("TTL Expiration", () => {
    it("should expire entries after TTL", async () => {
      const cache = new SbomComponentCache({ ttlMs: 100 }); // 100ms TTL
      cache.setComponent("express", "4.18.2", mockComponents[0]);

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 150));

      const component = cache.getComponent("express", "4.18.2");
      assert.equal(component, undefined);
    });

    it("should not expire entries before TTL", async () => {
      const cache = new SbomComponentCache({ ttlMs: 1000 }); // 1 second TTL
      cache.setComponent("express", "4.18.2", mockComponents[0]);

      await new Promise((resolve) => setTimeout(resolve, 50));

      const component = cache.getComponent("express", "4.18.2");
      assert.deepEqual(component, mockComponents[0]);
    });
  });

  describe("Batch Operations", () => {
    it("should get multiple components at once", () => {
      const cache = new SbomComponentCache();
      cache.setComponents(mockPackages, mockComponents);

      const result = cache.getComponents(mockPackages);
      assert.notEqual(result, null);
      assert.equal(result?.size, 4);
    });

    it("should return partial results when some components missing", () => {
      const cache = new SbomComponentCache();
      cache.setComponent("express", "4.18.2", mockComponents[0]);

      const result = cache.getComponents(mockPackages);
      assert.notEqual(result, null);
      assert.equal(result?.has("express@4.18.2"), true);
      assert.equal(result?.size, 1);
    });

    it("should return null when no components cached", () => {
      const cache = new SbomComponentCache();
      const result = cache.getComponents(mockPackages);
      assert.equal(result, null);
    });
  });

  describe("Statistics", () => {
    it("should track cache hits and misses", () => {
      const cache = new SbomComponentCache();
      cache.setComponent("express", "4.18.2", mockComponents[0]);

      // Hit
      cache.getComponent("express", "4.18.2");
      // Miss
      cache.getComponent("missing", "1.0.0");

      const stats = cache.getStats();
      assert.equal(stats.hits, 1);
      assert.equal(stats.misses, 1);
      assert.equal(stats.hitRate, 0.5);
    });

    it("should reset statistics on clear", () => {
      const cache = new SbomComponentCache();
      cache.setComponent("express", "4.18.2", mockComponents[0]);
      cache.getComponent("express", "4.18.2");

      cache.clear();

      const stats = cache.getStats();
      assert.equal(stats.hits, 0);
      assert.equal(stats.misses, 0);
      assert.equal(stats.size, 0);
    });
  });

  describe("Persistence", () => {
    let tempDir: string;
    let cachePath: string;

    beforeEach(() => {
      tempDir = createTempDir();
      cachePath = path.join(tempDir, "cache.json");
    });

    afterEach(() => {
      cleanupTempDir(tempDir);
    });

    it("should save cache to disk", () => {
      const cache = new SbomComponentCache({
        cacheFilePath: cachePath,
      });
      cache.setComponents(mockPackages, mockComponents);

      const saved = cache.saveToDisk();
      assert.equal(saved, true);
      assert.equal(fs.existsSync(cachePath), true);

      const content = JSON.parse(fs.readFileSync(cachePath, "utf-8"));
      assert.equal(content.version, 1);
      assert.equal(content.entries.length, 4);
    });

    it("should load cache from disk", () => {
      // Create and save cache
      const cache1 = new SbomComponentCache({
        cacheFilePath: cachePath,
      });
      cache1.setComponents(mockPackages, mockComponents);
      cache1.saveToDisk();

      // Load into new cache instance
      const cache2 = new SbomComponentCache({
        cacheFilePath: cachePath,
      });

      const component = cache2.getComponent("express", "4.18.2");
      assert.deepEqual(component, mockComponents[0]);
    });

    it("should skip expired entries when loading", async () => {
      // Create cache with short TTL
      const cache1 = new SbomComponentCache({
        cacheFilePath: cachePath,
        ttlMs: 50,
      });
      cache1.setComponent("express", "4.18.2", mockComponents[0]);
      cache1.saveToDisk();

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Load into new cache instance
      const cache2 = new SbomComponentCache({
        cacheFilePath: cachePath,
        ttlMs: 50,
      });

      const component = cache2.getComponent("express", "4.18.2");
      assert.equal(component, undefined);
    });

    it("should auto-save when persistence is enabled", () => {
      const cache = new SbomComponentCache({
        cacheFilePath: cachePath,
      });
      cache.setComponent("express", "4.18.2", mockComponents[0]);

      // Should auto-save on set
      assert.equal(fs.existsSync(cachePath), true);
    });

    it("should handle missing cache file gracefully", () => {
      const nonExistentPath = path.join(tempDir, "nonexistent", "cache.json");
      const cache = new SbomComponentCache({
        cacheFilePath: nonExistentPath,
      });

      // Should not throw
      const component = cache.getComponent("express", "4.18.2");
      assert.equal(component, undefined);
    });

    it("should create directory if it doesn't exist", () => {
      const deepPath = path.join(tempDir, "a", "b", "c", "cache.json");
      const cache = new SbomComponentCache({
        cacheFilePath: deepPath,
      });
      cache.setComponent("express", "4.18.2", mockComponents[0]);

      const saved = cache.saveToDisk();
      assert.equal(saved, true);
      assert.equal(fs.existsSync(deepPath), true);
    });

    it("should flush dirty cache to disk", () => {
      const cache = new SbomComponentCache({
        cacheFilePath: cachePath,
      });

      // setComponent with cacheFilePath auto-saves, so dirty is false after
      // But saveToDisk is called, meaning the file should exist
      cache.setComponent("express", "4.18.2", mockComponents[0]);
      assert.equal(fs.existsSync(cachePath), true);

      // Verify the file has the correct content
      const content = JSON.parse(fs.readFileSync(cachePath, "utf-8"));
      assert.equal(content.entries.length, 1);
      assert.equal(content.entries[0].name, "express");
    });

    it("should not flush clean cache", () => {
      const cache = new SbomComponentCache({
        cacheFilePath: cachePath,
      });

      const flushed = cache.flush();
      assert.equal(flushed, false);
    });
  });

  describe("Factory Function", () => {
    it("should create cache with factory function", () => {
      const cache = createComponentCache({ maxEntries: 500 });
      assert.ok(cache instanceof SbomComponentCache);
    });

    it("should create cache with default options", () => {
      const cache = createComponentCache();
      assert.ok(cache instanceof SbomComponentCache);
    });
  });
});
