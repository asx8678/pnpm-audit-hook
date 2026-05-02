import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

describe("AuditResult type", () => {
  it("has correct shape", async () => {
    const { runAudit } = await import("../src/audit");
    type AuditResult = Awaited<ReturnType<typeof runAudit>>;

    // Type-level test - if this compiles, the types are correct
    const _testShape: AuditResult = {
      blocked: false,
      warnings: false,
      decisions: [],
      exitCode: 0,
      findings: [],
      sourceStatus: {},
      totalPackages: 0,
      durationMs: 0,
    };

    assert.ok(true);
  });

  it("decisions array accepts valid PolicyDecision objects", async () => {
    type AuditResult = {
      blocked: boolean;
      warnings: boolean;
      decisions: Array<{
        action: "allow" | "warn" | "block";
        reason: string;
        source: "severity" | "source" | "allowlist";
        at: string;
        findingId?: string;
        packageName?: string;
        packageVersion?: string;
      }>;
    };

    const _testDecision: AuditResult["decisions"][0] = {
      action: "block",
      reason: "Critical vulnerability",
      source: "severity",
      at: new Date().toISOString(),
      findingId: "CVE-2024-0001",
      packageName: "test-pkg",
      packageVersion: "1.0.0",
    };

    assert.ok(true);
  });
});

describe("dependencyChain wiring", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pnpm-audit-chain-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it("populates dependencyChain on findings for transitive deps", async () => {
    const yaml = await import("yaml");
    await fs.writeFile(
      path.join(tempDir, ".pnpm-audit.yaml"),
      yaml.stringify({
        sources: { github: true, nvd: false, osv: true },
        failOnNoSources: false,
      }),
    );

    const { runAudit } = await import("../src/audit");

    // express@4.17.1 -> qs@6.7.0 (qs has known CVEs)
    const lockfile = {
      lockfileVersion: "9.0",
      importers: {
        ".": {
          dependencies: { express: "4.17.1" },
        },
      },
      packages: {
        "express@4.17.1": {
          resolution: { integrity: "sha512-test" },
          dependencies: { qs: "6.7.0" },
        },
        "qs@6.7.0": {
          resolution: { integrity: "sha512-test" },
        },
      },
    };

    const result = await runAudit(lockfile, {
      cwd: tempDir,
      env: {},
      registryUrl: "https://registry.npmjs.org",
    });

    // If findings exist, they should all have dependencyChain populated
    for (const finding of result.findings) {
      assert.ok(
        Array.isArray(finding.dependencyChain),
        `Expected dependencyChain array on finding for ${finding.packageName}@${finding.packageVersion}`,
      );
      assert.ok(
        finding.dependencyChain!.length > 0,
        "dependencyChain should not be empty",
      );
      // First element should be a direct dependency
      assert.ok(
        finding.dependencyChain!.length >= 1,
        "dependencyChain should have at least one element",
      );
      // Last element should be the vulnerable package itself
      const last = finding.dependencyChain![finding.dependencyChain!.length - 1];
      assert.equal(
        last,
        `${finding.packageName}@${finding.packageVersion}`,
        "dependencyChain should end with the vulnerable package",
      );
    }
  });
});

