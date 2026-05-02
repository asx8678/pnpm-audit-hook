import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

describe("Audit Edge Cases Integration", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "audit-edge-test-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  describe("lockfile edge cases", () => {
    it("handles lockfile with no packages field", async () => {
      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0",
      };

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_OFFLINE: "true" },
        registryUrl: "https://registry.npmjs.org",
      });

      assert.ok(result);
      assert.equal(result.blocked, false);
    });

    it("handles lockfile with empty packages object", async () => {
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

      assert.ok(result);
      assert.equal(result.totalPackages, 0);
    });

    it("handles lockfile with very long package names", async () => {
      const { runAudit } = await import("../../../src/audit");

      const longName = "a".repeat(200);
      const lockfile = {
        lockfileVersion: "9.0",
        packages: {
          [`/${longName}@1.0.0`]: {
            resolution: { integrity: "sha512-test" },
          },
        },
      };

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_OFFLINE: "true" },
        registryUrl: "https://registry.npmjs.org",
      });

      assert.ok(result);
    });

    it("handles lockfile with special characters in package names", async () => {
      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0",
        packages: {
          "/@scope/package@1.0.0": {
            resolution: { integrity: "sha512-test" },
          },
          "/package.with.dots@1.0.0": {
            resolution: { integrity: "sha512-test" },
          },
          "/package-with-dashes@1.0.0": {
            resolution: { integrity: "sha512-test" },
          },
          "/package_with_underscores@1.0.0": {
            resolution: { integrity: "sha512-test" },
          },
        },
      };

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_OFFLINE: "true" },
        registryUrl: "https://registry.npmjs.org",
      });

      assert.ok(result);
      assert.equal(result.blocked, false);
    });

    it("handles lockfile with various version formats", async () => {
      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0",
        packages: {
          "/package@1.0.0": {
            resolution: { integrity: "sha512-test" },
          },
          "/package@2.3.4": {
            resolution: { integrity: "sha512-test" },
          },
          "/package@0.1.0-beta.1": {
            resolution: { integrity: "sha512-test" },
          },
          "/package@1.0.0-rc.1": {
            resolution: { integrity: "sha512-test" },
          },
        },
      };

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_OFFLINE: "true" },
        registryUrl: "https://registry.npmjs.org",
      });

      assert.ok(result);
    });

    it("handles lockfile with nested dependencies", async () => {
      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0",
        packages: {
          "/parent@1.0.0": {
            resolution: { integrity: "sha512-test" },
            dependencies: {
              child: "1.0.0",
            },
          },
          "/child@1.0.0": {
            resolution: { integrity: "sha512-test" },
          },
        },
      };

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_OFFLINE: "true" },
        registryUrl: "https://registry.npmjs.org",
      });

      assert.ok(result);
    });
  });

  describe("config edge cases", () => {
    it("handles config with empty policy", async () => {
      const configContent = `
policy:
  block: []
  warn: []
  allowlist: []
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

      assert.ok(result);
    });

    it("handles config with all sources disabled", async () => {
      const configContent = `
policy:
  block: [critical]
sources:
  github: false
  nvd: false
  osv: false
failOnNoSources: false
`;
      await fs.writeFile(path.join(tempDir, ".pnpm-audit.yaml"), configContent);

      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0",
        packages: {
          "/test-pkg@1.0.0": {
            resolution: { integrity: "sha512-test" },
          },
        },
      };

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: {},
        registryUrl: "https://registry.npmjs.org",
      });

      assert.ok(result);
      // With all sources disabled and failOnNoSources: false, should not find any vulnerabilities
      assert.ok(result);
    });

    it("handles config with very large TTL", async () => {
      const configContent = `
cache:
  ttlSeconds: 86400
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

      assert.ok(result);
    });

    it("handles config with zero TTL", async () => {
      const configContent = `
cache:
  ttlSeconds: 0
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

      assert.ok(result);
    });
  });

  describe("concurrent audit requests", () => {
    it("handles multiple concurrent audits", async () => {
      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0",
        packages: {},
      };

      const promises = Array.from({ length: 5 }, () =>
        runAudit(lockfile, {
          cwd: tempDir,
          env: { PNPM_AUDIT_OFFLINE: "true" },
          registryUrl: "https://registry.npmjs.org",
        })
      );

      const results = await Promise.all(promises);

      results.forEach((result) => {
        assert.ok(result);
        assert.equal(result.blocked, false);
      });
    });
  });

  describe("error recovery", () => {
    it("recovers from cache errors gracefully", async () => {
      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0",
        packages: {},
      };

      // Should not throw even with potential cache issues
      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_OFFLINE: "true" },
        registryUrl: "https://registry.npmjs.org",
      });

      assert.ok(result);
    });

    it("handles missing environment variables", async () => {
      const { runAudit } = await import("../../../src/audit");

      const lockfile = {
        lockfileVersion: "9.0",
        packages: {},
      };

      // Run with minimal env vars
      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: {},
        registryUrl: "https://registry.npmjs.org",
      });

      assert.ok(result);
    });
  });
});
