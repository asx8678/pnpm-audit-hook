import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { LazyStaticDbReader } from "../../src/static-db/lazy-reader";

const fixturesPath = path.join(__dirname, "../fixtures/static-db");

describe("LazyStaticDbReader", () => {
  describe("initialization", () => {
    it("does not initialize until getInstance is called", () => {
      const reader = new LazyStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      // Should not be ready yet (no initialization triggered)
      assert.equal(reader.isReady(), false);
    });

    it("initializes successfully when getInstance is called", async () => {
      const reader = new LazyStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      const instance = await reader.getInstance();
      assert.ok(instance);
      assert.equal(reader.isReady(), true);
    });

    it("fails gracefully with invalid data path", async () => {
      const reader = new LazyStaticDbReader({
        dataPath: "/nonexistent/path",
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      const instance = await reader.getInstance();
      assert.equal(instance, null);
      assert.equal(reader.isReady(), false);
      assert.equal(reader.hasInitializationError(), true);
      assert.ok(reader.getInitializationError());
    });

    it("returns same instance on multiple getInstance calls", async () => {
      const reader = new LazyStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      const instance1 = await reader.getInstance();
      const instance2 = await reader.getInstance();
      assert.strictEqual(instance1, instance2);
    });

    it("handles concurrent getInstance calls", async () => {
      const reader = new LazyStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      // Start multiple concurrent getInstance calls
      const [instance1, instance2, instance3] = await Promise.all([
        reader.getInstance(),
        reader.getInstance(),
        reader.getInstance(),
      ]);

      // All should return the same instance
      assert.strictEqual(instance1, instance2);
      assert.strictEqual(instance2, instance3);
      assert.ok(instance1);
    });
  });

  describe("metadata methods", () => {
    it("returns config cutoff date before initialization", () => {
      const reader = new LazyStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      assert.equal(reader.getCutoffDate(), "2025-01-01T00:00:00Z");
    });

    it("returns empty string for getDbVersion before initialization", () => {
      const reader = new LazyStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      assert.equal(reader.getDbVersion(), "");
    });

    it("returns null for getIndex before initialization", () => {
      const reader = new LazyStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      assert.equal(reader.getIndex(), null);
    });

    it("returns correct cutoff date after initialization", async () => {
      const reader = new LazyStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      await reader.getInstance();
      // getCutoffDate should now return the index's cutoff date
      const cutoffDate = reader.getCutoffDate();
      assert.ok(cutoffDate);
    });

    it("returns db version after initialization", async () => {
      const reader = new LazyStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      await reader.getInstance();
      const dbVersion = reader.getDbVersion();
      assert.ok(dbVersion);
    });

    it("returns index after initialization", async () => {
      const reader = new LazyStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      await reader.getInstance();
      const index = reader.getIndex();
      assert.ok(index);
      assert.equal(index.schemaVersion, 1);
    });
  });

  describe("query methods", () => {
    it("triggers initialization on queryPackage call", async () => {
      const reader = new LazyStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      assert.equal(reader.isReady(), false);
      await reader.queryPackage("lodash");
      assert.equal(reader.isReady(), true);
    });

    it("triggers initialization on queryPackageWithOptions call", async () => {
      const reader = new LazyStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      assert.equal(reader.isReady(), false);
      await reader.queryPackageWithOptions("lodash", { version: "4.17.0" });
      assert.equal(reader.isReady(), true);
    });

    it("triggers initialization on hasVulnerabilities call", async () => {
      const reader = new LazyStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      assert.equal(reader.isReady(), false);
      await reader.hasVulnerabilities("lodash");
      assert.equal(reader.isReady(), true);
    });

    it("returns empty array when initialization fails", async () => {
      const reader = new LazyStaticDbReader({
        dataPath: "/nonexistent/path",
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      const findings = await reader.queryPackage("lodash");
      assert.deepEqual(findings, []);
    });

    it("returns false for hasVulnerabilities when initialization fails", async () => {
      const reader = new LazyStaticDbReader({
        dataPath: "/nonexistent/path",
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      const result = await reader.hasVulnerabilities("lodash");
      assert.equal(result, false);
    });
  });

  describe("reset", () => {
    it("allows re-initialization after reset", async () => {
      const reader = new LazyStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      // Initialize
      const instance1 = await reader.getInstance();
      assert.ok(instance1);
      assert.equal(reader.isReady(), true);

      // Reset
      reader.reset();
      assert.equal(reader.isReady(), false);

      // Re-initialize
      const instance2 = await reader.getInstance();
      assert.ok(instance2);
      assert.equal(reader.isReady(), true);
    });

    it("clears initialization error after reset", async () => {
      const reader = new LazyStaticDbReader({
        dataPath: "/nonexistent/path",
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      // Trigger initialization failure
      await reader.getInstance();
      assert.equal(reader.hasInitializationError(), true);

      // Reset
      reader.reset();
      assert.equal(reader.hasInitializationError(), false);
      assert.equal(reader.getInitializationError(), null);
    });
  });

  describe("concurrent queries", () => {
    it("handles concurrent queries before initialization", async () => {
      const reader = new LazyStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      // Start multiple concurrent queries before initialization
      const [findings1, findings2, findings3] = await Promise.all([
        reader.queryPackage("lodash"),
        reader.queryPackage("react"),
        reader.hasVulnerabilities("@angular/core"),
      ]);

      // All should work correctly
      assert.ok(findings1.length > 0);
      assert.ok(findings2.length > 0);
      assert.equal(findings3, true);

      // Reader should be ready
      assert.equal(reader.isReady(), true);
    });
  });
});
