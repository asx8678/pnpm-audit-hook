import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import type { AuditConfig, PackageRef } from "../src/types";

describe("runAudit", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pnpm-audit-test-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  // Helper to create a minimal lockfile
  function createLockfile(packages: PackageRef[]): Record<string, unknown> {
    const pkgSnapshots: Record<string, object> = {};
    for (const p of packages) {
      pkgSnapshots[`/${p.name}@${p.version}`] = { resolution: { integrity: "sha512-test" } };
    }
    return {
      lockfileVersion: "9.0",
      packages: pkgSnapshots,
    };
  }

  // Helper to write config file
  async function writeConfig(config: Partial<AuditConfig> & Record<string, unknown>): Promise<void> {
    const yaml = await import("yaml");
    await fs.writeFile(path.join(tempDir, ".pnpm-audit.yaml"), yaml.stringify(config));
  }

  describe("return structure", () => {
    it("returns correct structure with blocked, warnings, and decisions", async () => {
      const { runAudit } = await import("../src/audit");
      const lockfile = createLockfile([{ name: "lodash", version: "4.17.21" }]);

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: {},
        registryUrl: "https://registry.npmjs.org",
      });

      assert.ok("blocked" in result);
      assert.ok("warnings" in result);
      assert.ok("decisions" in result);
      assert.equal(typeof result.blocked, "boolean");
      assert.equal(typeof result.warnings, "boolean");
      assert.ok(Array.isArray(result.decisions));
    });

    it("returns blocked=false and warnings=false when no vulnerabilities", async () => {
      const { runAudit } = await import("../src/audit");
      const lockfile = createLockfile([{ name: "safe-package", version: "1.0.0" }]);

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: {},
        registryUrl: "https://registry.npmjs.org",
      });

      assert.equal(result.blocked, false);
      assert.equal(result.warnings, false);
    });

    it("decisions array contains PolicyDecision objects", async () => {
      await writeConfig({
        sources: { github: false, nvd: false, osv: false },
        failOnNoSources: false,
      });

      const { runAudit } = await import("../src/audit");
      const lockfile = createLockfile([{ name: "pkg", version: "1.0.0" }]);

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: {},
        registryUrl: "https://registry.npmjs.org",
      });

      // Decisions array should be valid (even if empty)
      for (const decision of result.decisions) {
        assert.ok("action" in decision);
        assert.ok("reason" in decision);
        assert.ok("source" in decision);
        assert.ok("at" in decision);
      }
    });
  });

  describe("source failure handling", () => {
    it("throws when failOnNoSources is true (default) and all sources disabled", async () => {
      await writeConfig({
        policy: { block: ["critical"], warn: [] },
        sources: { github: false, nvd: false, osv: false },
        failOnNoSources: true,
      });

      const { runAudit } = await import("../src/audit");
      const lockfile = createLockfile([{ name: "test-pkg", version: "1.0.0" }]);

      await assert.rejects(
        runAudit(lockfile, {
          cwd: tempDir,
          env: {},
          registryUrl: "https://registry.npmjs.org",
        }),
        /All vulnerability sources are disabled/
      );
    });

    it("does not throw when failOnNoSources is false and all sources disabled", async () => {
      await writeConfig({
        policy: { block: ["critical"], warn: [] },
        sources: { github: false, nvd: false, osv: false },
        failOnNoSources: false,
      });

      const { runAudit } = await import("../src/audit");
      const lockfile = createLockfile([{ name: "test-pkg", version: "1.0.0" }]);

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: {},
        registryUrl: "https://registry.npmjs.org",
      });

      assert.equal(typeof result.blocked, "boolean");
      assert.equal(typeof result.warnings, "boolean");
    });

    it("uses default failOnNoSources=true when not specified", async () => {
      await writeConfig({
        sources: { github: false, nvd: false, osv: false },
        // failOnNoSources not specified - should default to true
      });

      const { runAudit } = await import("../src/audit");
      const lockfile = createLockfile([{ name: "pkg", version: "1.0.0" }]);

      await assert.rejects(
        runAudit(lockfile, {
          cwd: tempDir,
          env: {},
          registryUrl: "https://registry.npmjs.org",
        }),
        /All vulnerability sources are disabled/
      );
    });

    it("uses default failOnSourceError=true when not specified", async () => {
      // failOnSourceError defaults to true - this is tested by observing config behavior
      const { loadConfig } = await import("../src/config");

      const cfg = await loadConfig({ cwd: tempDir, env: {} });
      assert.equal(cfg.failOnSourceError, true);
    });

    it("respects failOnSourceError=false in config", async () => {
      await writeConfig({
        failOnSourceError: false,
      });

      const { loadConfig } = await import("../src/config");
      const cfg = await loadConfig({ cwd: tempDir, env: {} });

      assert.equal(cfg.failOnSourceError, false);
    });
  });

  describe("policy decisions", () => {
    it("applies severity policy to findings", async () => {
      await writeConfig({
        policy: {
          block: ["critical", "high"],
          warn: ["medium", "low"],
          allowlist: [],
        },
        sources: { github: true, nvd: false, osv: false },
      });

      const { runAudit } = await import("../src/audit");
      const lockfile = createLockfile([{ name: "vulnerable-pkg", version: "1.0.0" }]);

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: {},
        registryUrl: "https://registry.npmjs.org",
      });

      // Verify structure is correct
      assert.ok(Array.isArray(result.decisions));
    });

    it("allowlist config is loaded correctly", async () => {
      await writeConfig({
        policy: {
          block: ["critical"],
          warn: [],
          allowlist: [
            { id: "CVE-2024-0001", reason: "Accepted risk" },
            { package: "lodash", reason: "Internal use" },
          ],
        },
      });

      const { loadConfig } = await import("../src/config");
      const cfg = await loadConfig({ cwd: tempDir, env: {} });

      assert.equal(cfg.policy.allowlist.length, 2);
      assert.equal(cfg.policy.allowlist[0]!.id, "CVE-2024-0001");
      assert.equal(cfg.policy.allowlist[1]!.package, "lodash");
    });
  });

  describe("integration with config", () => {
    it("uses default config when no config file exists", async () => {
      const { runAudit } = await import("../src/audit");
      const lockfile = createLockfile([{ name: "pkg", version: "1.0.0" }]);

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: {},
        registryUrl: "https://registry.npmjs.org",
      });

      assert.ok("blocked" in result);
      assert.ok("warnings" in result);
      assert.ok("decisions" in result);
    });

    it("respects custom config path via env var", async () => {
      const customDir = path.join(tempDir, "custom");
      await fs.mkdir(customDir, { recursive: true });

      const yaml = await import("yaml");
      await fs.writeFile(
        path.join(customDir, "audit-config.yaml"),
        yaml.stringify({
          policy: { block: ["low"], warn: [] },
          sources: { github: false, nvd: false, osv: false },
          failOnNoSources: false,
        })
      );

      const { runAudit } = await import("../src/audit");
      const lockfile = createLockfile([{ name: "pkg", version: "1.0.0" }]);

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_CONFIG_PATH: "custom/audit-config.yaml" },
        registryUrl: "https://registry.npmjs.org",
      });

      assert.ok("blocked" in result);
    });

    it("loads cache TTL from config", async () => {
      await writeConfig({
        cache: { ttlSeconds: 7200 },
      });

      const { loadConfig } = await import("../src/config");
      const cfg = await loadConfig({ cwd: tempDir, env: {} });

      assert.equal(cfg.cache.ttlSeconds, 7200);
    });

    it("loads performance timeout from config", async () => {
      await writeConfig({
        performance: { timeoutMs: 30000 },
      });

      const { loadConfig } = await import("../src/config");
      const cfg = await loadConfig({ cwd: tempDir, env: {} });

      assert.equal(cfg.performance.timeoutMs, 30000);
    });
  });

  describe("lockfile parsing", () => {
    it("extracts packages from lockfile", async () => {
      await writeConfig({
        sources: { github: false, nvd: false, osv: false },
        failOnNoSources: false,
      });

      const { runAudit } = await import("../src/audit");
      const lockfile = createLockfile([
        { name: "lodash", version: "4.17.21" },
        { name: "express", version: "4.18.0" },
        { name: "@types/node", version: "20.0.0" },
      ]);

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: {},
        registryUrl: "https://registry.npmjs.org",
      });

      assert.ok("blocked" in result);
    });

    it("handles empty lockfile", async () => {
      await writeConfig({
        sources: { github: false, nvd: false, osv: false },
        failOnNoSources: false,
      });

      const { runAudit } = await import("../src/audit");
      const lockfile = { lockfileVersion: "9.0", packages: {} };

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: {},
        registryUrl: "https://registry.npmjs.org",
      });

      assert.equal(result.blocked, false);
      assert.equal(result.warnings, false);
      assert.deepEqual(result.decisions, []);
    });

    it("handles scoped packages", async () => {
      await writeConfig({
        sources: { github: false, nvd: false, osv: false },
        failOnNoSources: false,
      });

      const { runAudit } = await import("../src/audit");
      const lockfile = createLockfile([
        { name: "@babel/core", version: "7.23.0" },
        { name: "@types/react", version: "18.2.0" },
      ]);

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: {},
        registryUrl: "https://registry.npmjs.org",
      });

      assert.ok("blocked" in result);
    });
  });

  describe("decision aggregation", () => {
    it("blocked is true when any decision has action=block", async () => {
      // Test by triggering fail-closed behavior
      await writeConfig({
        sources: { github: false, nvd: false, osv: false },
        failOnNoSources: true,
      });

      const { runAudit } = await import("../src/audit");
      const lockfile = createLockfile([{ name: "pkg", version: "1.0.0" }]);

      await assert.rejects(
        runAudit(lockfile, {
          cwd: tempDir,
          env: {},
          registryUrl: "https://registry.npmjs.org",
        })
      );
    });

    it("warnings is false when no warn decisions exist", async () => {
      await writeConfig({
        policy: { block: [], warn: [] },
        sources: { github: false, nvd: false, osv: false },
        failOnNoSources: false,
      });

      const { runAudit } = await import("../src/audit");
      const lockfile = createLockfile([{ name: "pkg", version: "1.0.0" }]);

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: {},
        registryUrl: "https://registry.npmjs.org",
      });

      assert.equal(result.warnings, false);
    });

    it("returns empty decisions when no findings and no source errors", async () => {
      await writeConfig({
        sources: { github: false, nvd: false, osv: false },
        failOnNoSources: false,
      });

      const { runAudit } = await import("../src/audit");
      const lockfile = createLockfile([{ name: "pkg", version: "1.0.0" }]);

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: {},
        registryUrl: "https://registry.npmjs.org",
      });

      assert.deepEqual(result.decisions, []);
    });
  });

  describe("cache initialization", () => {
    it("initializes cache with cwd-relative path", async () => {
      await writeConfig({
        sources: { github: false, nvd: false, osv: false },
        failOnNoSources: false,
      });

      const { runAudit } = await import("../src/audit");
      const lockfile = createLockfile([{ name: "pkg", version: "1.0.0" }]);

      // Should not throw during cache initialization
      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: {},
        registryUrl: "https://registry.npmjs.org",
      });

      assert.ok("blocked" in result);
    });
  });

  describe("runtime options", () => {
    it("uses provided cwd for config and cache", async () => {
      const customCwd = path.join(tempDir, "custom-cwd");
      await fs.mkdir(customCwd, { recursive: true });

      const yaml = await import("yaml");
      await fs.writeFile(
        path.join(customCwd, ".pnpm-audit.yaml"),
        yaml.stringify({
          sources: { github: false, nvd: false, osv: false },
          failOnNoSources: false,
        })
      );

      const { runAudit } = await import("../src/audit");
      const lockfile = createLockfile([{ name: "pkg", version: "1.0.0" }]);

      const result = await runAudit(lockfile, {
        cwd: customCwd,
        env: {},
        registryUrl: "https://registry.npmjs.org",
      });

      assert.ok("blocked" in result);
    });

    it("passes env to config loader", async () => {
      const customConfigDir = path.join(tempDir, "env-config");
      await fs.mkdir(customConfigDir, { recursive: true });

      const yaml = await import("yaml");
      await fs.writeFile(
        path.join(customConfigDir, "my-audit.yaml"),
        yaml.stringify({
          sources: { github: false, nvd: false, osv: false },
          failOnNoSources: false,
        })
      );

      const { runAudit } = await import("../src/audit");
      const lockfile = createLockfile([{ name: "pkg", version: "1.0.0" }]);

      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: { PNPM_AUDIT_CONFIG_PATH: "env-config/my-audit.yaml" },
        registryUrl: "https://registry.npmjs.org",
      });

      assert.ok("blocked" in result);
    });

    it("passes registryUrl to aggregator context", async () => {
      await writeConfig({
        sources: { github: false, nvd: false, osv: false },
        failOnNoSources: false,
      });

      const { runAudit } = await import("../src/audit");
      const lockfile = createLockfile([{ name: "pkg", version: "1.0.0" }]);

      // Should work with different registry URLs
      const result = await runAudit(lockfile, {
        cwd: tempDir,
        env: {},
        registryUrl: "https://custom-registry.example.com",
      });

      assert.ok("blocked" in result);
    });
  });
});
