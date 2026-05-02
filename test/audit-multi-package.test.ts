import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import type { PackageRef } from "../src/types";

describe("multiple package decision accumulation", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pnpm-audit-multi-pkg-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  async function writeConfig(config: Record<string, unknown>): Promise<void> {
    const yaml = await import("yaml");
    await fs.writeFile(path.join(tempDir, ".pnpm-audit.yaml"), yaml.stringify(config));
  }

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

  it("processes multiple packages and accumulates all decisions", async () => {
    await writeConfig({
      sources: { github: false, nvd: false, osv: false },
      failOnNoSources: false,
    });

    const { runAudit } = await import("../src/audit");
    const lockfile = createLockfile([
      { name: "lodash", version: "4.17.21" },
      { name: "express", version: "4.18.0" },
      { name: "react", version: "18.2.0" },
      { name: "@babel/core", version: "7.23.0" },
    ]);

    const result = await runAudit(lockfile, {
      cwd: tempDir,
      env: {},
      registryUrl: "https://registry.npmjs.org",
    });

    // With disabled sources and no findings, decisions should be empty
    assert.ok(Array.isArray(result.decisions));
    assert.equal(result.blocked, false);
    assert.equal(result.warnings, false);
  });

  it("accumulates decisions from policy engine for multiple packages with findings", async () => {
    const { evaluatePackagePolicies } = await import("../src/policies/policy-engine");

    const cfg = {
      policy: { block: ["critical", "high"], warn: ["medium"], allowlist: [] },
      sources: { github: { enabled: true }, nvd: { enabled: true }, osv: { enabled: false } },
      performance: { timeoutMs: 15000 },
      cache: { ttlSeconds: 3600 },
      failOnNoSources: true,
      failOnSourceError: true,
    } as const;

    // Simulate multiple packages with varying findings
    const packages = [
      {
        pkg: { name: "lodash", version: "4.17.0" },
        findings: [
          { id: "CVE-2021-23337", source: "github" as const, packageName: "lodash", packageVersion: "4.17.0", severity: "critical" as const },
        ],
      },
      {
        pkg: { name: "express", version: "4.17.0" },
        findings: [
          { id: "CVE-2022-24999", source: "github" as const, packageName: "express", packageVersion: "4.17.0", severity: "high" as const },
          { id: "CVE-2022-24998", source: "github" as const, packageName: "express", packageVersion: "4.17.0", severity: "medium" as const },
        ],
      },
      {
        pkg: { name: "react", version: "18.2.0" },
        findings: [], // No vulnerabilities
      },
      {
        pkg: { name: "axios", version: "0.21.0" },
        findings: [
          { id: "CVE-2021-3749", source: "github" as const, packageName: "axios", packageVersion: "0.21.0", severity: "medium" as const },
        ],
      },
    ];

    // Accumulate decisions like audit.ts does
    const allDecisions: Array<{
      action: "allow" | "warn" | "block";
      reason: string;
      source: "severity" | "source" | "allowlist";
      at: string;
      findingId?: string;
      packageName?: string;
      packageVersion?: string;
    }> = [];

    for (const pkgResult of packages) {
      allDecisions.push(...evaluatePackagePolicies(pkgResult, cfg));
    }

    // Verify total decisions (1 from lodash + 2 from express + 0 from react + 1 from axios)
    assert.equal(allDecisions.length, 4);

    // Verify lodash has 1 block decision
    const lodashDecisions = allDecisions.filter((d) => d.packageName === "lodash");
    assert.equal(lodashDecisions.length, 1);
    assert.equal(lodashDecisions[0]!.action, "block");
    assert.equal(lodashDecisions[0]!.findingId, "CVE-2021-23337");

    // Verify express has 2 decisions (1 block, 1 warn)
    const expressDecisions = allDecisions.filter((d) => d.packageName === "express");
    assert.equal(expressDecisions.length, 2);
    assert.ok(expressDecisions.some((d) => d.action === "block" && d.findingId === "CVE-2022-24999"));
    assert.ok(expressDecisions.some((d) => d.action === "warn" && d.findingId === "CVE-2022-24998"));

    // Verify react has no decisions
    const reactDecisions = allDecisions.filter((d) => d.packageName === "react");
    assert.equal(reactDecisions.length, 0);

    // Verify axios has 1 warn decision
    const axiosDecisions = allDecisions.filter((d) => d.packageName === "axios");
    assert.equal(axiosDecisions.length, 1);
    assert.equal(axiosDecisions[0]!.action, "warn");

    // Verify blocked/warnings flags
    const blocked = allDecisions.some((d) => d.action === "block");
    const warnings = allDecisions.some((d) => d.action === "warn");
    assert.equal(blocked, true);
    assert.equal(warnings, true);
  });

  it("handles scoped packages in multi-package accumulation", async () => {
    const { evaluatePackagePolicies } = await import("../src/policies/policy-engine");

    const cfg = {
      policy: { block: ["critical"], warn: ["high", "medium", "low"], allowlist: [] },
      sources: { github: { enabled: true }, nvd: { enabled: true }, osv: { enabled: false } },
      performance: { timeoutMs: 15000 },
      cache: { ttlSeconds: 3600 },
      failOnNoSources: true,
      failOnSourceError: true,
    } as const;

    const packages = [
      {
        pkg: { name: "@babel/core", version: "7.20.0" },
        findings: [
          { id: "GHSA-test-1", source: "github" as const, packageName: "@babel/core", packageVersion: "7.20.0", severity: "high" as const },
        ],
      },
      {
        pkg: { name: "@types/node", version: "18.0.0" },
        findings: [],
      },
    ];

    const allDecisions: Array<{
      action: "allow" | "warn" | "block";
      packageName?: string;
    }> = [];

    for (const pkgResult of packages) {
      allDecisions.push(...evaluatePackagePolicies(pkgResult, cfg));
    }

    // Verify scoped package decision is recorded correctly
    assert.equal(allDecisions.length, 1);
    assert.equal(allDecisions[0]!.packageName, "@babel/core");
    assert.equal(allDecisions[0]!.action, "warn"); // high severity maps to warn
  });

  it("combines vulnerability decisions with source failure decisions", async () => {
    const { evaluatePackagePolicies } = await import("../src/policies/policy-engine");

    const cfg = {
      policy: { block: ["critical"], warn: ["high"], allowlist: [] },
      sources: { github: { enabled: true }, nvd: { enabled: true }, osv: { enabled: false } },
      performance: { timeoutMs: 15000 },
      cache: { ttlSeconds: 3600 },
      failOnNoSources: true,
      failOnSourceError: true,
    } as const;

    // Simulate package with findings
    const pkgResult = {
      pkg: { name: "lodash", version: "4.17.0" },
      findings: [
        { id: "CVE-2021-23337", source: "github" as const, packageName: "lodash", packageVersion: "4.17.0", severity: "high" as const },
      ],
    };

    // Simulate aggregator result with partial source failure
    const mockSources = {
      github: { ok: true, durationMs: 500 },
      nvd: { ok: false, error: "timeout", durationMs: 15000 },
    };

    // Accumulate decisions like audit.ts does
    type PolicyDecision = {
      action: "allow" | "warn" | "block";
      reason: string;
      source: "severity" | "source" | "allowlist";
      at: string;
      findingId?: string;
      packageName?: string;
      packageVersion?: string;
    };
    const decisions: PolicyDecision[] = [];

    // Add vulnerability decisions
    decisions.push(...evaluatePackagePolicies(pkgResult, cfg));

    // Add source failure decisions
    const failOnSourceError = true;
    const failedSources = Object.entries(mockSources).filter(([, v]) => !v.ok);
    if (failedSources.length) {
      const srcList = failedSources.map(([k, v]) => `${k}: ${v.error ?? "unknown"}`).join("; ");
      const action = failOnSourceError ? "block" : "warn";
      decisions.push({
        action,
        reason: `Source failure: ${srcList}`,
        source: "source",
        at: new Date().toISOString(),
      });
    }

    // Verify both vulnerability and source failure decisions are present
    assert.equal(decisions.length, 2);

    // Verify vulnerability decision
    const vulnDecision = decisions.find((d) => d.source === "severity");
    assert.ok(vulnDecision);
    assert.equal(vulnDecision.action, "warn");
    assert.equal(vulnDecision.findingId, "CVE-2021-23337");

    // Verify source failure decision
    const sourceDecision = decisions.find((d) => d.source === "source");
    assert.ok(sourceDecision);
    assert.equal(sourceDecision.action, "block");
    assert.ok(sourceDecision.reason.includes("nvd: timeout"));

    // Combined result should be blocked (source failure with failOnSourceError=true)
    const blocked = decisions.some((d) => d.action === "block");
    const warnings = decisions.some((d) => d.action === "warn");
    assert.equal(blocked, true);
    assert.equal(warnings, true);
  });
});
