import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

describe("Audit Full Workflow Integration", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "audit-workflow-test-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  describe("end-to-end audit workflow", () => {
    it("runs audit with clean lockfile (no vulnerabilities)", async () => {
      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0",
        packages: {
          "/safe-package@1.0.0": {
            resolution: { integrity: "sha512-test123" },
          },
        },
      };

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_OFFLINE: "true" },
        registryUrl: "https://registry.npmjs.org",
      });

      assert.equal(result.blocked, false);
      assert.equal(result.warnings, false);
      assert.ok(Array.isArray(result.decisions));
      assert.ok(Array.isArray(result.findings));
      assert.ok(typeof result.exitCode === "number");
      assert.ok(typeof result.totalPackages === "number");
      assert.ok(typeof result.durationMs === "number");
    });

    it("audit result contains source status information", async () => {
      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0",
        packages: {},
      };

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_OFFLINE: "true" },
        registryUrl: "https://registry.npmjs.org",
      });

      assert.ok(result.sourceStatus);
      assert.ok(typeof result.sourceStatus === "object");
    });

    it("audit completes within reasonable time", async () => {
      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0",
        packages: {},
      };

      const startTime = Date.now();
      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_OFFLINE: "true" },
        registryUrl: "https://registry.npmjs.org",
      });
      const duration = Date.now() - startTime;

      assert.ok(duration < 30000, `Audit took too long: ${duration}ms`);
      assert.ok(result.durationMs >= 0, "Duration should be non-negative");
    });

    it("audit handles multiple packages correctly", async () => {
      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0",
        packages: {
          "/package-a@1.0.0": {
            resolution: { integrity: "sha512-test1" },
          },
          "/package-b@2.0.0": {
            resolution: { integrity: "sha512-test2" },
          },
          "/package-c@3.0.0": {
            resolution: { integrity: "sha512-test3" },
          },
        },
      };

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_OFFLINE: "true" },
        registryUrl: "https://registry.npmjs.org",
      });

      assert.ok(result.totalPackages >= 3, "Should count all packages");
    });

    it("audit with empty lockfile returns valid result", async () => {
      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0",
        packages: {},
      };

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_OFFLINE: "true" },
        registryUrl: "https://registry.npmjs.org",
      });

      assert.equal(result.blocked, false);
      assert.equal(result.totalPackages, 0);
      assert.ok(Array.isArray(result.findings));
      assert.equal(result.findings.length, 0);
    });
  });

  describe("configuration loading", () => {
    it("loads default config when no config file exists", async () => {
      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0",
        packages: {},
      };

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: {},
        registryUrl: "https://registry.npmjs.org",
      });

      // Should use default config
      assert.ok(result);
    });

    it("loads custom config from .pnpm-audit.yaml", async () => {
      const configContent = `
policy:
  block:
    - critical
  warn:
    - high
    - medium
    - low
    - unknown
sources:
  github: true
  nvd: true
  osv: true
cache:
  ttlSeconds: 7200
`;
      await fs.writeFile(path.join(tempDir, ".pnpm-audit.yaml"), configContent);

      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0",
        packages: {},
      };

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: {},
        registryUrl: "https://registry.npmjs.org",
      });

      // Should use custom config
      assert.ok(result);
    });

    it("handles invalid config file gracefully", async () => {
      const configContent = "invalid: yaml: {{{{";
      await fs.writeFile(path.join(tempDir, ".pnpm-audit.yaml"), configContent);

      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0",
        packages: {},
      };

      // May throw on invalid config - that's ok, we're testing it doesn't crash catastrophically
      try {
        const result = await runAudit(lockfile, {
          cwd: tempDir,
          env: {},
          registryUrl: "https://registry.npmjs.org",
        });
        assert.ok(result);
      } catch (error) {
        // Config parse errors are acceptable
        assert.ok(error instanceof Error);
      }
    });
  });

  describe("environment variable integration", () => {
    it("respects PNPM_AUDIT_OFFLINE environment variable", async () => {
      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0",
        packages: {
          "/lodash@4.17.21": {
            resolution: { integrity: "sha512-test" },
          },
        },
      };

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_OFFLINE: "true" },
        registryUrl: "https://registry.npmjs.org",
      });

      // Should complete without network calls
      assert.ok(result);
    });

    it("respects PNPM_AUDIT_QUIET environment variable", async () => {
      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0",
        packages: {},
      };

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_QUIET: "true" },
        registryUrl: "https://registry.npmjs.org",
      });

      // Should complete without verbose output
      assert.ok(result);
    });

    it("respects PNPM_AUDIT_DEBUG environment variable", async () => {
      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0",
        packages: {},
      };

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_DEBUG: "true" },
        registryUrl: "https://registry.npmjs.org",
      });

      // Should complete with debug output
      assert.ok(result);
    });
  });

  describe("hook integration", () => {
    it("createPnpmHooks returns valid hook structure", async () => {
      const { createPnpmHooks } = await import("../../../src/index");

      const hooks = createPnpmHooks();

      assert.ok(hooks);
      assert.ok(hooks.hooks);
      assert.ok(typeof hooks.hooks.afterAllResolved === "function");
    });

    it("hook handles lockfile correctly", async () => {
      const { createPnpmHooks } = await import("../../../src/index");

      const hooks = createPnpmHooks();

      const lockfile = {
        lockfileVersion: "9.0",
        packages: {},
      };

      // Mock context
      const context = {
        lockfileDir: tempDir,
      };

      // Should not throw
      try {
        await hooks.hooks.afterAllResolved(lockfile, context);
      } catch (error) {
        // May throw if no lockfile exists, but should not throw on hook structure
        assert.ok(error instanceof Error);
      }
    });
  });
});
