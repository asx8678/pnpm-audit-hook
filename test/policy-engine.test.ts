import test from "node:test";
import assert from "node:assert/strict";
import { evaluatePackagePolicies } from "../src/policies/policy-engine";
import type { AuditConfig, PackageAuditResult, VulnerabilityFinding } from "../src/types";

function baseConfig(): AuditConfig {
  return {
    policy: {
      block: ["critical", "high"],
      warn: ["medium", "low", "unknown"],
      allowlist: [],
    },
    sources: {
      github: { enabled: true },
      nvd: { enabled: true },
    },
    performance: { timeoutMs: 15000 },
    cache: { ttlSeconds: 3600 },
    failOnNoSources: true,
  };
}

function pkgResult(
  name = "a",
  version = "1.0.0",
  findings: VulnerabilityFinding[] = [],
): PackageAuditResult {
  return {
    pkg: { name, version },
    findings,
    decisions: [],
  };
}

test("high severity blocks", () => {
  const cfg = baseConfig();
  const f: VulnerabilityFinding = {
    id: "CVE-2025-0001",
    source: "github",
    packageName: "a",
    packageVersion: "1.0.0",
    severity: "high",
  };

  const res = evaluatePackagePolicies(pkgResult("a", "1.0.0", [f]), cfg);
  assert.ok(res.decisions.some((d) => d.action === "block" && d.findingId === "CVE-2025-0001"));
});

test("low severity warns", () => {
  const cfg = baseConfig();
  const f: VulnerabilityFinding = {
    id: "CVE-2025-0002",
    source: "github",
    packageName: "a",
    packageVersion: "1.0.0",
    severity: "low",
  };

  const res = evaluatePackagePolicies(pkgResult("a", "1.0.0", [f]), cfg);
  assert.ok(res.decisions.some((d) => d.action === "warn" && d.findingId === "CVE-2025-0002"));
});

test("no findings means no decisions added", () => {
  const cfg = baseConfig();
  const p: PackageAuditResult = {
    pkg: { name: "a", version: "1.0.0" },
    findings: [],
    decisions: [],
  };

  const res = evaluatePackagePolicies(p, cfg);
  assert.strictEqual(res.decisions.length, 0);
});

test("allowlist by CVE ID suppresses finding", () => {
  const cfg: AuditConfig = {
    ...baseConfig(),
    policy: {
      block: ["critical", "high"],
      warn: ["medium", "low"],
      allowlist: [{ id: "CVE-2024-001", reason: "accepted risk" }],
    },
  };
  const f: VulnerabilityFinding = {
    id: "CVE-2024-001",
    source: "github",
    packageName: "some-package",
    packageVersion: "1.0.0",
    severity: "critical",
    title: "Test vuln",
  };

  const res = evaluatePackagePolicies(pkgResult("some-package", "1.0.0", [f]), cfg);
  assert.equal(res.decisions.length, 1);
  assert.equal(res.decisions[0].action, "allow");
});

test("allowlist by package name suppresses all findings for that package", () => {
  const cfg: AuditConfig = {
    ...baseConfig(),
    policy: {
      block: ["critical"],
      warn: [],
      allowlist: [{ package: "lodash", reason: "we accept lodash risks" }],
    },
  };
  const f: VulnerabilityFinding = {
    id: "CVE-2024-001",
    source: "github",
    packageName: "lodash",
    packageVersion: "4.17.0",
    severity: "critical",
    title: "Prototype pollution",
  };

  const res = evaluatePackagePolicies(pkgResult("lodash", "4.17.0", [f]), cfg);
  assert.equal(res.decisions[0].action, "allow");
});

test("expired allowlist entries are ignored", () => {
  const cfg: AuditConfig = {
    ...baseConfig(),
    policy: {
      block: ["critical"],
      warn: [],
      allowlist: [{ id: "CVE-2024-001", expires: "2020-01-01" }],
    },
  };
  const f: VulnerabilityFinding = {
    id: "CVE-2024-001",
    source: "github",
    packageName: "test",
    packageVersion: "1.0.0",
    severity: "critical",
    title: "Test",
  };

  const res = evaluatePackagePolicies(pkgResult("test", "1.0.0", [f]), cfg);
  assert.equal(res.decisions[0].action, "block");
});

test("invalid expires date is treated as expired (fail-closed)", () => {
  const cfg: AuditConfig = {
    ...baseConfig(),
    policy: {
      block: ["critical"],
      warn: [],
      allowlist: [{ id: "CVE-2024-001", expires: "not-a-date" }],
    },
  };
  const f: VulnerabilityFinding = {
    id: "CVE-2024-001",
    source: "github",
    packageName: "test",
    packageVersion: "1.0.0",
    severity: "critical",
    title: "Test",
  };

  const res = evaluatePackagePolicies(pkgResult("test", "1.0.0", [f]), cfg);
  assert.equal(res.decisions[0].action, "block");
});

test("case-insensitive ID matching", () => {
  const cfg: AuditConfig = {
    ...baseConfig(),
    policy: {
      block: ["critical"],
      warn: [],
      allowlist: [{ id: "cve-2024-001" }],
    },
  };
  const f: VulnerabilityFinding = {
    id: "CVE-2024-001",
    source: "github",
    packageName: "test",
    packageVersion: "1.0.0",
    severity: "critical",
    title: "Test",
  };

  const res = evaluatePackagePolicies(pkgResult("test", "1.0.0", [f]), cfg);
  assert.equal(res.decisions[0].action, "allow");
});
