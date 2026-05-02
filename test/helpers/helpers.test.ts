/**
 * Tests for the test helpers themselves.
 * Ensures our mock factories, assertions, and utilities work correctly.
 */
import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import {
  createMockCache,
  createMockHttpClient,
  createMockFinding,
  createMockFindings,
  createMockConfig,
  assertValidAuditResult,
  assertValidFinding,
  assertLength,
  assertNotEmpty,
  assertThrowsAsync,
} from "./index.js";
import {
  setupTempDir,
  setupTempDirWithConfig,
  setupTestProject,
  setupConsoleSpy,
} from "./setup.js";
import { safeRemove, createTeardown } from "./teardown.js";

// ─── Mock Cache Tests ────────────────────────────────────────────────────────

describe("createMockCache", () => {
  it("should set and get values", async () => {
    const cache = createMockCache();
    await cache.set("key1", { data: "value1" }, 3600);

    const entry = await cache.get("key1");
    assert(entry !== null);
    assert.deepEqual(entry.value, { data: "value1" });
  });

  it("should return null for missing keys", async () => {
    const cache = createMockCache();
    const entry = await cache.get("nonexistent");
    assert.equal(entry, null);
  });

  it("should expire entries after TTL", async () => {
    const cache = createMockCache();
    // Set with 0 TTL (expires immediately)
    await cache.set("key1", "value1", 0);

    // Wait a bit
    await new Promise((r) => setTimeout(r, 10));

    const entry = await cache.get("key1");
    assert.equal(entry, null);
  });

  it("should delete entries", async () => {
    const cache = createMockCache();
    await cache.set("key1", "value1", 3600);

    const deleted = await cache.delete("key1");
    assert.equal(deleted, true);

    const entry = await cache.get("key1");
    assert.equal(entry, null);
  });

  it("should clear all entries", async () => {
    const cache = createMockCache();
    await cache.set("key1", "value1", 3600);
    await cache.set("key2", "value2", 3600);

    await cache.clear();

    assert.equal(cache.store.size, 0);
  });

  it("should expose store for assertions", async () => {
    const cache = createMockCache();
    await cache.set("key1", "value1", 3600);

    assert.equal(cache.store.size, 1);
    assert(cache.store.has("key1"));
  });

  it("should track statistics", async () => {
    const cache = createMockCache();
    await cache.set("key1", "value1", 3600);

    await cache.get("key1"); // hit
    await cache.get("missing"); // miss

    const stats = cache.getStatistics();
    assert.equal(stats.hits, 1);
    assert.equal(stats.misses, 1);

    cache.resetStats();
    const resetStats = cache.getStatistics();
    assert.equal(resetStats.hits, 0);
    assert.equal(resetStats.misses, 0);
  });

  it("should store version and dependencies", async () => {
    const cache = createMockCache();
    await cache.set("key1", "value1", 3600, {
      version: "1.0.0",
      dependencies: ["dep1", "dep2"],
    });

    const entry = await cache.get("key1");
    assert(entry !== null);
    assert.equal(entry.version, "1.0.0");
    assert.deepEqual(entry.dependencies, ["dep1", "dep2"]);
  });
});

// ─── Mock HTTP Client Tests ──────────────────────────────────────────────────

describe("createMockHttpClient", () => {
  it("should return mock response", async () => {
    const http = createMockHttpClient();
    http.mockResponse("https://api.test.com", {
      status: 200,
      data: { results: [] },
      headers: {},
    });

    const response = await http.get("https://api.test.com/data");
    assert.equal(response.status, 200);
    assert.deepEqual(response.data, { results: [] });
  });

  it("should match URL patterns", async () => {
    const http = createMockHttpClient();
    http.mockResponse(/api\.test\.com/, {
      status: 200,
      data: "matched",
      headers: {},
    });

    const response = await http.get("https://api.test.com/anything");
    assert.equal(response.status, 200);
  });

  it("should throw for unmocked URLs", async () => {
    const http = createMockHttpClient();

    await assertThrowsAsync(
      () => http.get("https://unmocked.test.com"),
      /No mock response configured/
    );
  });

  it("should mock errors", async () => {
    const http = createMockHttpClient();
    http.mockError("https://api.test.com", new Error("Network error"));

    await assertThrowsAsync(
      () => http.get("https://api.test.com"),
      /Network error/
    );
  });

  it("should record requests", async () => {
    const http = createMockHttpClient();
    http.mockResponse("https://api.test.com", {
      status: 200,
      data: null,
      headers: {},
    });

    await http.get("https://api.test.com");
    await http.post("https://api.test.com", { key: "value" });

    assert.equal(http.requests.length, 2);
    assert.equal(http.requests[0].method, "GET");
    assert.equal(http.requests[1].method, "POST");
  });

  it("should reset state", async () => {
    const http = createMockHttpClient();
    http.mockResponse("test", { status: 200, data: null, headers: {} });
    await http.get("test");

    http.reset();

    assert.equal(http.requests.length, 0);
    await assertThrowsAsync(() => http.get("test"), /No mock response/);
  });
});

// ─── Mock Finding Tests ──────────────────────────────────────────────────────

describe("createMockFinding", () => {
  it("should create a finding with defaults", () => {
    const finding = createMockFinding();
    assert.equal(typeof finding.id, "string");
    assert.equal(finding.source, "github");
    assert.equal(typeof finding.packageName, "string");
    assert.equal(typeof finding.packageVersion, "string");
    assert.equal(finding.severity, "high");
  });

  it("should allow overrides", () => {
    const finding = createMockFinding({
      packageName: "lodash",
      severity: "critical",
      id: "GHSA-custom",
    });

    assert.equal(finding.packageName, "lodash");
    assert.equal(finding.severity, "critical");
    assert.equal(finding.id, "GHSA-custom");
  });

  assertValidFinding(createMockFinding());
});

describe("createMockFindings", () => {
  it("should create multiple findings", () => {
    const findings = createMockFindings(5);
    assert.equal(findings.length, 5);

    // Each should have a unique ID
    const ids = new Set(findings.map((f) => f.id));
    assert.equal(ids.size, 5);
  });

  it("should apply base overrides to all", () => {
    const findings = createMockFindings(3, { severity: "critical" });
    for (const f of findings) {
      assert.equal(f.severity, "critical");
    }
  });
});

// ─── Mock Config Tests ───────────────────────────────────────────────────────

describe("createMockConfig", () => {
  it("should create a valid config", () => {
    const config = createMockConfig();
    assert.deepEqual(config.policy.block, ["critical", "high"]);
    assert.deepEqual(config.policy.warn, ["medium", "low", "unknown"]);
    assert.equal(config.sources.github.enabled, true);
    assert.equal(config.sources.nvd.enabled, true);
    assert.equal(config.sources.osv.enabled, true);
  });

  it("should allow overrides", () => {
    const config = createMockConfig({
      policy: {
        block: ["critical"],
        warn: ["high"],
        allowlist: [],
      },
    });
    assert.deepEqual(config.policy.block, ["critical"]);
    assert.deepEqual(config.policy.warn, ["high"]);
  });
});

// ─── Assertion Tests ─────────────────────────────────────────────────────────

describe("assertValidAuditResult", () => {
  it("should pass for valid result", () => {
    const result = {
      blocked: true,
      warnings: false,
      decisions: [],
      exitCode: 1,
      findings: [],
      sourceStatus: {},
      totalPackages: 5,
      durationMs: 100,
    };
    assertValidAuditResult(result); // Should not throw
  });

  it("should throw for invalid result", () => {
    assert.throws(() => assertValidAuditResult(null), /not be null/);
    assert.throws(() => assertValidAuditResult("string"), /object/);
    assert.throws(
      () => assertValidAuditResult({ blocked: true }),
      /missing required field/
    );
  });
});

// ─── Setup/Teardown Tests ────────────────────────────────────────────────────

describe("setupTempDir", () => {
  let ctx: Awaited<ReturnType<typeof setupTempDir>>;

  beforeEach(async () => {
    ctx = await setupTempDir("test-helpers-");
  });

  it("should create a temp directory", async () => {
    const fs = await import("node:fs/promises");
    const stat = await fs.stat(ctx.tempDir);
    assert(stat.isDirectory());
  });

  it("should clean up temp directory", async () => {
    await ctx.cleanup();
    const fs = await import("node:fs/promises");
    await assert.rejects(() => fs.stat(ctx.tempDir), /ENOENT/);
  });
});

describe("setupTestProject", () => {
  it("should create config and lockfile", async () => {
    const project = await setupTestProject({
      packages: [{ name: "lodash", version: "4.17.21" }],
    });

    try {
      const fs = await import("node:fs/promises");
      const yaml = await import("yaml");

      const configContent = await fs.readFile(project.configPath, "utf-8");
      const config = yaml.parse(configContent);
      assert.deepEqual(config.policy.block, ["critical", "high"]);

      const lockContent = await fs.readFile(project.lockfilePath, "utf-8");
      const lockfile = yaml.parse(lockContent);
      assert("/lodash@4.17.21" in lockfile.packages);
    } finally {
      await project.cleanup();
    }
  });
});

describe("setupConsoleSpy", () => {
  it("should capture console output", () => {
    const spy = setupConsoleSpy();

    console.log("test log");
    console.error("test error");
    console.warn("test warn");

    assert.deepEqual(spy.logs, ["test log"]);
    assert.deepEqual(spy.errors, ["test error"]);
    assert.deepEqual(spy.warnings, ["test warn"]);

    spy.restore();
  });

  it("should restore original console", () => {
    const originalLog = console.log;
    const spy = setupConsoleSpy();

    spy.restore();

    assert.equal(console.log, originalLog);
  });
});

// ─── Teardown Tests ──────────────────────────────────────────────────────────

describe("createTeardown", () => {
  it("should run cleanups in reverse order", async () => {
    const order: number[] = [];
    const teardown = createTeardown();

    teardown.add(() => { order.push(1); });
    teardown.add(() => { order.push(2); });
    teardown.add(() => { order.push(3); });

    await teardown.run();

    assert.deepEqual(order, [3, 2, 1]);
  });

  it("should handle async cleanups", async () => {
    const order: number[] = [];
    const teardown = createTeardown();

    teardown.add(async () => {
      await new Promise((r) => setTimeout(r, 10));
      order.push(1);
    });
    teardown.add(() => { order.push(2); });

    await teardown.run();

    assert.deepEqual(order, [2, 1]);
  });
});

describe("safeRemove", () => {
  it("should not throw for non-existent paths", async () => {
    await safeRemove("/nonexistent/path/that/does/not/exist");
    // Should not throw
  });
});
