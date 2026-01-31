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
    failOnSourceError: true,
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

test("allowlist entry with both id and package requires both to match", () => {
  const cfg: AuditConfig = {
    ...baseConfig(),
    policy: {
      block: ["critical"],
      warn: [],
      allowlist: [{ id: "CVE-2024-001", package: "lodash" }],
    },
  };
  const f: VulnerabilityFinding = {
    id: "CVE-2024-001",
    source: "github",
    packageName: "other",
    packageVersion: "1.0.0",
    severity: "critical",
    title: "Test",
  };

  const res = evaluatePackagePolicies(pkgResult("other", "1.0.0", [f]), cfg);
  assert.equal(res.decisions[0].action, "block");
});

test("allowlist entry with both id and package matches when both align", () => {
  const cfg: AuditConfig = {
    ...baseConfig(),
    policy: {
      block: ["critical"],
      warn: [],
      allowlist: [{ id: "CVE-2024-001", package: "lodash" }],
    },
  };
  const f: VulnerabilityFinding = {
    id: "CVE-2024-001",
    source: "github",
    packageName: "lodash",
    packageVersion: "4.17.0",
    severity: "critical",
    title: "Test",
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

test("allowlist entry with version constraint only matches specified versions", () => {
  const cfg: AuditConfig = {
    ...baseConfig(),
    policy: {
      block: ["critical"],
      warn: [],
      allowlist: [{ id: "CVE-2024-001", version: ">=2.0.0", reason: "fixed in v2+" }],
    },
  };
  const f: VulnerabilityFinding = {
    id: "CVE-2024-001",
    source: "github",
    packageName: "test",
    packageVersion: "2.5.0",
    severity: "critical",
    title: "Test vuln",
  };

  const res = evaluatePackagePolicies(pkgResult("test", "2.5.0", [f]), cfg);
  assert.equal(res.decisions[0].action, "allow");
  assert.ok(res.decisions[0].reason.includes("fixed in v2+"));
});

test("allowlist entry with version >=2.0.0 does not match version 1.5.0", () => {
  const cfg: AuditConfig = {
    ...baseConfig(),
    policy: {
      block: ["critical"],
      warn: [],
      allowlist: [{ id: "CVE-2024-001", version: ">=2.0.0" }],
    },
  };
  const f: VulnerabilityFinding = {
    id: "CVE-2024-001",
    source: "github",
    packageName: "test",
    packageVersion: "1.5.0",
    severity: "critical",
    title: "Test vuln",
  };

  const res = evaluatePackagePolicies(pkgResult("test", "1.5.0", [f]), cfg);
  // Should block because version 1.5.0 doesn't satisfy >=2.0.0, so allowlist doesn't apply
  assert.equal(res.decisions[0].action, "block");
});

test("allowlist entry with version <1.0.0 matches version 0.9.0 but not 1.0.0", () => {
  const cfg: AuditConfig = {
    ...baseConfig(),
    policy: {
      block: ["critical"],
      warn: [],
      allowlist: [{ id: "CVE-2024-001", version: "<1.0.0" }],
    },
  };
  const findingV09: VulnerabilityFinding = {
    id: "CVE-2024-001",
    source: "github",
    packageName: "test",
    packageVersion: "0.9.0",
    severity: "critical",
    title: "Test vuln",
  };
  const findingV10: VulnerabilityFinding = {
    id: "CVE-2024-001",
    source: "github",
    packageName: "test",
    packageVersion: "1.0.0",
    severity: "critical",
    title: "Test vuln",
  };

  // Version 0.9.0 should be allowed (matches <1.0.0)
  const resV09 = evaluatePackagePolicies(pkgResult("test", "0.9.0", [findingV09]), cfg);
  assert.equal(resV09.decisions[0].action, "allow");

  // Version 1.0.0 should be blocked (doesn't match <1.0.0)
  const resV10 = evaluatePackagePolicies(pkgResult("test", "1.0.0", [findingV10]), cfg);
  assert.equal(resV10.decisions[0].action, "block");
});

test("invalid version constraint in allowlist is handled gracefully (fails closed)", () => {
  const cfg: AuditConfig = {
    ...baseConfig(),
    policy: {
      block: ["critical"],
      warn: [],
      allowlist: [{ id: "CVE-2024-001", version: "not-a-valid-range!!!" }],
    },
  };
  const f: VulnerabilityFinding = {
    id: "CVE-2024-001",
    source: "github",
    packageName: "test",
    packageVersion: "1.0.0",
    severity: "critical",
    title: "Test vuln",
  };

  // Should block because invalid version range returns false from satisfiesStrict()
  const res = evaluatePackagePolicies(pkgResult("test", "1.0.0", [f]), cfg);
  assert.equal(res.decisions[0].action, "block");
});

test("critical severity blocks", () => {
  const cfg = baseConfig();
  const f: VulnerabilityFinding = {
    id: "CVE-2025-0003",
    source: "github",
    packageName: "a",
    packageVersion: "1.0.0",
    severity: "critical",
  };

  const res = evaluatePackagePolicies(pkgResult("a", "1.0.0", [f]), cfg);
  assert.ok(res.decisions.some((d) => d.action === "block" && d.findingId === "CVE-2025-0003"));
});

test("medium severity warns", () => {
  const cfg = baseConfig();
  const f: VulnerabilityFinding = {
    id: "CVE-2025-0004",
    source: "github",
    packageName: "a",
    packageVersion: "1.0.0",
    severity: "medium",
  };

  const res = evaluatePackagePolicies(pkgResult("a", "1.0.0", [f]), cfg);
  assert.ok(res.decisions.some((d) => d.action === "warn" && d.findingId === "CVE-2025-0004"));
});

test("unknown severity warns per baseConfig", () => {
  const cfg = baseConfig();
  const f: VulnerabilityFinding = {
    id: "CVE-2025-0005",
    source: "github",
    packageName: "a",
    packageVersion: "1.0.0",
    severity: "unknown",
  };

  const res = evaluatePackagePolicies(pkgResult("a", "1.0.0", [f]), cfg);
  assert.ok(res.decisions.some((d) => d.action === "warn" && d.findingId === "CVE-2025-0005"));
});

test("multiple findings on same package get individual decisions", () => {
  const cfg = baseConfig();
  const findings: VulnerabilityFinding[] = [
    { id: "CVE-2025-0010", source: "github", packageName: "a", packageVersion: "1.0.0", severity: "critical" },
    { id: "CVE-2025-0011", source: "nvd", packageName: "a", packageVersion: "1.0.0", severity: "high" },
    { id: "CVE-2025-0012", source: "github", packageName: "a", packageVersion: "1.0.0", severity: "low" },
  ];

  const res = evaluatePackagePolicies(pkgResult("a", "1.0.0", findings), cfg);
  assert.equal(res.decisions.length, 3);
  assert.ok(res.decisions.some((d) => d.findingId === "CVE-2025-0010" && d.action === "block"));
  assert.ok(res.decisions.some((d) => d.findingId === "CVE-2025-0011" && d.action === "block"));
  assert.ok(res.decisions.some((d) => d.findingId === "CVE-2025-0012" && d.action === "warn"));
});
