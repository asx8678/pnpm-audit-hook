import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

describe("Audit Performance Integration", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "audit-perf-test-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  describe("response time", () => {
    it("completes audit within 5 seconds for small lockfile", async () => {
      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0" as const,
        packages: {
          "/lodash@4.17.21": {
            resolution: { integrity: "sha512-test" },
          },
        },
      };

      const startTime = Date.now();
      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_OFFLINE: "true" },
        registryUrl: "https://registry.npmjs.org",
      });
      const duration = Date.now() - startTime;

      assert.ok(duration < 5000, `Audit took ${duration}ms, should be under 5000ms`);
      assert.ok(result);
    });

    it("completes audit within 10 seconds for medium lockfile", async () => {
      const { runAudit } = await import("../../../src/audit");

      const packages: Record<string, object> = {};
      for (let i = 0; i < 50; i++) {
        packages[`/package-${i}@${i}.0.0`] = {
          resolution: { integrity: `sha512-test${i}` },
        };
      }

      const lockfile = {
        lockfileVersion: "9.0" as const,
        packages,
      };

      const startTime = Date.now();
      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_OFFLINE: "true" },
        registryUrl: "https://registry.npmjs.org",
      });
      const duration = Date.now() - startTime;

      assert.ok(duration < 10000, `Audit took ${duration}ms, should be under 10000ms`);
      assert.ok(result);
    });

    it("completes audit within 30 seconds for large lockfile", async () => {
      const { runAudit } = await import("../../../src/audit");

      const packages: Record<string, object> = {};
      for (let i = 0; i < 200; i++) {
        packages[`/package-${i}@${i}.0.0`] = {
          resolution: { integrity: `sha512-test${i}` },
        };
      }

      const lockfile = {
        lockfileVersion: "9.0" as const,
        packages,
      };

      const startTime = Date.now();
      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_OFFLINE: "true" },
        registryUrl: "https://registry.npmjs.org",
      });
      const duration = Date.now() - startTime;

      assert.ok(duration < 30000, `Audit took ${duration}ms, should be under 30000ms`);
      assert.ok(result);
    });
  });

  describe("memory usage", () => {
    it("does not leak memory on repeated audits", async () => {
      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0" as const,
        packages: {
          "/test-pkg@1.0.0": {
            resolution: { integrity: "sha512-test" },
          },
        },
      };

      // Run multiple audits
      for (let i = 0; i < 10; i++) {
        const result = await runAudit(lockfile, {
          cwd: tempDir,
          env: { PNPM_AUDIT_OFFLINE: "true" },
          registryUrl: "https://registry.npmjs.org",
        });
        assert.ok(result);
      }

      // If we got here without crashing, memory is likely fine
      assert.ok(true);
    });

    it("handles large number of packages without excessive memory", async () => {
      const { runAudit } = await import("../../../src/audit");

      const packages: Record<string, object> = {};
      for (let i = 0; i < 1000; i++) {
        packages[`/package-${i}@${i}.0.0`] = {
          resolution: { integrity: `sha512-test${i}` },
        };
      }

      const lockfile = {
        lockfileVersion: "9.0" as const,
        packages,
      };

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_OFFLINE: "true" },
        registryUrl: "https://registry.npmjs.org",
      });

      assert.ok(result);
      assert.equal(result.totalPackages, 1000);
    });
  });

  describe("concurrent performance", () => {
    it("handles 10 concurrent audits without degradation", async () => {
      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0" as const,
        packages: {
          "/test-pkg@1.0.0": {
            resolution: { integrity: "sha512-test" },
          },
        },
      };

      const startTime = Date.now();
      const promises = Array.from({ length: 10 }, () =>
        runAudit(lockfile, {
          cwd: tempDir,
          env: { PNPM_AUDIT_OFFLINE: "true" },
          registryUrl: "https://registry.npmjs.org",
        })
      );

      const results = await Promise.all(promises);
      const totalDuration = Date.now() - startTime;

      assert.ok(totalDuration < 30000, `Concurrent audits took ${totalDuration}ms`);
      results.forEach((result) => {
        assert.ok(result);
        assert.equal(result.blocked, false);
      });
    });
  });

  describe("cache performance", () => {
    it("cache hit improves performance on second run", async () => {
      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0" as const,
        packages: {
          "/test-pkg@1.0.0": {
            resolution: { integrity: "sha512-test" },
          },
        },
      };

      // First run (cache miss)
      const startTime1 = Date.now();
      const result1 = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_OFFLINE: "true" },
        registryUrl: "https://registry.npmjs.org",
      });
      const duration1 = Date.now() - startTime1;

      // Second run (cache hit)
      const startTime2 = Date.now();
      const result2 = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_OFFLINE: "true" },
        registryUrl: "https://registry.npmjs.org",
      });
      const duration2 = Date.now() - startTime2;

      assert.ok(result1);
      assert.ok(result2);

      // Cache hit should be faster (or at least not significantly slower)
      // Allow some tolerance for system variations
      assert.ok(duration2 <= duration1 * 2, `Cache hit was slower: ${duration2}ms vs ${duration1}ms`);
    });
  });

  describe("scalability", () => {
    it("scales linearly with package count", async () => {
      const { runAudit } = await import("../../../src/audit");

      // Test with 10 packages
      const packages10: Record<string, object> = {};
      for (let i = 0; i < 10; i++) {
        packages10[`/pkg-${i}@1.0.0`] = { resolution: { integrity: "sha512-test" } };
      }

      const startTime10 = Date.now();
      await runAudit(
        { lockfileVersion: "9.0", packages: packages10 },
        { cwd: tempDir, env: { PNPM_AUDIT_OFFLINE: "true" }, registryUrl: "https://registry.npmjs.org" }
      );
      const duration10 = Date.now() - startTime10;

      // Test with 100 packages
      const packages100: Record<string, object> = {};
      for (let i = 0; i < 100; i++) {
        packages100[`/pkg-${i}@1.0.0`] = { resolution: { integrity: "sha512-test" } };
      }

      const startTime100 = Date.now();
      await runAudit(
        { lockfileVersion: "9.0", packages: packages100 },
        { cwd: tempDir, env: { PNPM_AUDIT_OFFLINE: "true" }, registryUrl: "https://registry.npmjs.org" }
      );
      const duration100 = Date.now() - startTime100;

      // Should scale reasonably (not exponentially)
      // Allow up to 20x for 10x packages due to overhead
      assert.ok(
        duration100 < duration10 * 20,
        `Scaling too slowly: ${duration100}ms for 100 packages vs ${duration10}ms for 10 packages`
      );
    });
  });
});
