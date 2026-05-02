import test from "node:test";
import assert from "node:assert/strict";
import { evaluatePackagePolicies } from "../src/policies/policy-engine";
import type { AuditConfig, DependencyGraph, DependencyNode, VulnerabilityFinding } from "../src/types";

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
      osv: { enabled: true },
    },
    performance: { timeoutMs: 15000 },
    cache: { ttlSeconds: 3600 },
    failOnNoSources: true,
    failOnSourceError: true,
  };
}

function pkg(name = "a", version = "1.0.0", findings: VulnerabilityFinding[] = []) {
  return { pkg: { name, version }, findings };
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

  const res = evaluatePackagePolicies(pkg("a", "1.0.0", [f]), cfg);
  assert.ok(res.some((d) => d.action === "block" && d.findingId === "CVE-2025-0001"));
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

  const res = evaluatePackagePolicies(pkg("a", "1.0.0", [f]), cfg);
  assert.ok(res.some((d) => d.action === "warn" && d.findingId === "CVE-2025-0002"));
});

test("no findings means no decisions added", () => {
  const cfg = baseConfig();

  const res = evaluatePackagePolicies(pkg(), cfg);
  assert.strictEqual(res.length, 0);
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

  const res = evaluatePackagePolicies(pkg("some-package", "1.0.0", [f]), cfg);
  assert.equal(res.length, 1);
  assert.equal(res[0].action, "allow");
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

  const res = evaluatePackagePolicies(pkg("lodash", "4.17.0", [f]), cfg);
  assert.equal(res[0].action, "allow");
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

  const res = evaluatePackagePolicies(pkg("other", "1.0.0", [f]), cfg);
  assert.equal(res[0].action, "block");
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

  const res = evaluatePackagePolicies(pkg("lodash", "4.17.0", [f]), cfg);
  assert.equal(res[0].action, "allow");
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

  const res = evaluatePackagePolicies(pkg("test", "1.0.0", [f]), cfg);
  assert.equal(res[0].action, "block");
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

  const res = evaluatePackagePolicies(pkg("test", "1.0.0", [f]), cfg);
  assert.equal(res[0].action, "block");
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

  const res = evaluatePackagePolicies(pkg("test", "1.0.0", [f]), cfg);
  assert.equal(res[0].action, "allow");
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

  const res = evaluatePackagePolicies(pkg("test", "2.5.0", [f]), cfg);
  assert.equal(res[0].action, "allow");
  assert.ok(res[0].reason.includes("fixed in v2+"));
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

  const res = evaluatePackagePolicies(pkg("test", "1.5.0", [f]), cfg);
  // Should block because version 1.5.0 doesn't satisfy >=2.0.0, so allowlist doesn't apply
  assert.equal(res[0].action, "block");
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
  const resV09 = evaluatePackagePolicies(pkg("test", "0.9.0", [findingV09]), cfg);
  assert.equal(resV09[0].action, "allow");

  // Version 1.0.0 should be blocked (doesn't match <1.0.0)
  const resV10 = evaluatePackagePolicies(pkg("test", "1.0.0", [findingV10]), cfg);
  assert.equal(resV10[0].action, "block");
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
  const res = evaluatePackagePolicies(pkg("test", "1.0.0", [f]), cfg);
  assert.equal(res[0].action, "block");
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

  const res = evaluatePackagePolicies(pkg("a", "1.0.0", [f]), cfg);
  assert.ok(res.some((d) => d.action === "block" && d.findingId === "CVE-2025-0003"));
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

  const res = evaluatePackagePolicies(pkg("a", "1.0.0", [f]), cfg);
  assert.ok(res.some((d) => d.action === "warn" && d.findingId === "CVE-2025-0004"));
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

  const res = evaluatePackagePolicies(pkg("a", "1.0.0", [f]), cfg);
  assert.ok(res.some((d) => d.action === "warn" && d.findingId === "CVE-2025-0005"));
});

test("multiple findings on same package get individual decisions", () => {
  const cfg = baseConfig();
  const findings: VulnerabilityFinding[] = [
    { id: "CVE-2025-0010", source: "github", packageName: "a", packageVersion: "1.0.0", severity: "critical" },
    { id: "CVE-2025-0011", source: "nvd", packageName: "a", packageVersion: "1.0.0", severity: "high" },
    { id: "CVE-2025-0012", source: "github", packageName: "a", packageVersion: "1.0.0", severity: "low" },
  ];

  const res = evaluatePackagePolicies(pkg("a", "1.0.0", findings), cfg);
  assert.equal(res.length, 3);
  assert.ok(res.some((d) => d.findingId === "CVE-2025-0010" && d.action === "block"));
  assert.ok(res.some((d) => d.findingId === "CVE-2025-0011" && d.action === "block"));
  assert.ok(res.some((d) => d.findingId === "CVE-2025-0012" && d.action === "warn"));
});

// ── Helper: build a minimal DependencyGraph for testing ──

function makeGraph(directPkgs: Array<{ name: string; version: string }>, transitivePkgs: Array<{ name: string; version: string }> = []): DependencyGraph {
  const nodes = new Map<string, DependencyNode>();
  const byName = new Map<string, string[]>();
  const dependents = new Map<string, Set<string>>();
  const directKeys = new Set<string>();

  const addNode = (name: string, version: string, isDirect: boolean) => {
    const key = `${name}@${version}`;
    nodes.set(key, { name, version, isDirect, isDev: false, dependencies: [] });
    const existing = byName.get(name);
    if (existing) {
      existing.push(key);
    } else {
      byName.set(name, [key]);
    }
    dependents.set(key, new Set());
    if (isDirect) directKeys.add(key);
  };

  for (const p of directPkgs) addNode(p.name, p.version, true);
  for (const p of transitivePkgs) addNode(p.name, p.version, false);

  return { nodes, byName, dependents, directKeys };
}

// ── Transitive severity downgrade tests ──

test("transitive downgrade: critical becomes high for transitive dep", () => {
  const cfg: AuditConfig = {
    ...baseConfig(),
    policy: {
      ...baseConfig().policy,
      transitiveSeverityOverride: "downgrade-by-one",
    },
  };
  const graph = makeGraph(
    [{ name: "direct-pkg", version: "1.0.0" }],
    [{ name: "transitive-pkg", version: "2.0.0" }],
  );

  const f: VulnerabilityFinding = {
    id: "CVE-2025-9999",
    source: "github",
    packageName: "transitive-pkg",
    packageVersion: "2.0.0",
    severity: "critical",
  };

  const res = evaluatePackagePolicies(pkg("transitive-pkg", "2.0.0", [f]), cfg, graph);
  // critical → high, which is still in block list → block action
  assert.equal(res[0].action, "block");
  assert.ok(res[0].reason.includes("downgraded to high"));
});

test("transitive downgrade: high becomes medium for transitive dep", () => {
  const cfg: AuditConfig = {
    ...baseConfig(),
    policy: {
      block: ["critical", "high"],
      warn: ["medium", "low", "unknown"],
      allowlist: [],
      transitiveSeverityOverride: "downgrade-by-one",
    },
  };
  const graph = makeGraph(
    [{ name: "direct-pkg", version: "1.0.0" }],
    [{ name: "transitive-pkg", version: "2.0.0" }],
  );

  const f: VulnerabilityFinding = {
    id: "CVE-2025-9998",
    source: "github",
    packageName: "transitive-pkg",
    packageVersion: "2.0.0",
    severity: "high",
  };

  const res = evaluatePackagePolicies(pkg("transitive-pkg", "2.0.0", [f]), cfg, graph);
  // high → medium, which is in warn list
  assert.equal(res[0].action, "warn");
  assert.ok(res[0].reason.includes("downgraded to medium"));
});

test("transitive downgrade: direct dep is NOT downgraded", () => {
  const cfg: AuditConfig = {
    ...baseConfig(),
    policy: {
      ...baseConfig().policy,
      transitiveSeverityOverride: "downgrade-by-one",
    },
  };
  const graph = makeGraph(
    [{ name: "direct-pkg", version: "1.0.0" }],
    [{ name: "transitive-pkg", version: "2.0.0" }],
  );

  const f: VulnerabilityFinding = {
    id: "CVE-2025-9997",
    source: "github",
    packageName: "direct-pkg",
    packageVersion: "1.0.0",
    severity: "critical",
  };

  const res = evaluatePackagePolicies(pkg("direct-pkg", "1.0.0", [f]), cfg, graph);
  // Should remain critical (block) — no downgrade for direct deps
  assert.equal(res[0].action, "block");
  assert.ok(!res[0].reason.includes("downgraded"));
});

test("no override: transitive deps are evaluated normally without downgrade", () => {
  const cfg = baseConfig(); // no transitiveSeverityOverride
  const graph = makeGraph(
    [{ name: "direct-pkg", version: "1.0.0" }],
    [{ name: "transitive-pkg", version: "2.0.0" }],
  );

  const f: VulnerabilityFinding = {
    id: "CVE-2025-9996",
    source: "github",
    packageName: "transitive-pkg",
    packageVersion: "2.0.0",
    severity: "critical",
  };

  const res = evaluatePackagePolicies(pkg("transitive-pkg", "2.0.0", [f]), cfg, graph);
  // Should still be block — no downgrade without config
  assert.equal(res[0].action, "block");
  assert.ok(!res[0].reason.includes("downgraded"));
});

// ── directOnly allowlist tests ──

test("directOnly allowlist matches direct dependency", () => {
  const cfg: AuditConfig = {
    ...baseConfig(),
    policy: {
      block: ["critical"],
      warn: [],
      allowlist: [{ id: "CVE-2025-5555", directOnly: true, reason: "direct allowlist" }],
    },
  };
  const graph = makeGraph(
    [{ name: "direct-pkg", version: "1.0.0" }],
    [{ name: "transitive-pkg", version: "2.0.0" }],
  );

  const f: VulnerabilityFinding = {
    id: "CVE-2025-5555",
    source: "github",
    packageName: "direct-pkg",
    packageVersion: "1.0.0",
    severity: "critical",
  };

  const res = evaluatePackagePolicies(pkg("direct-pkg", "1.0.0", [f]), cfg, graph);
  assert.equal(res[0].action, "allow");
  assert.ok(res[0].reason.includes("direct allowlist"));
});

test("directOnly allowlist does NOT match transitive dependency", () => {
  const cfg: AuditConfig = {
    ...baseConfig(),
    policy: {
      block: ["critical"],
      warn: [],
      allowlist: [{ id: "CVE-2025-5555", directOnly: true, reason: "direct allowlist" }],
    },
  };
  const graph = makeGraph(
    [{ name: "direct-pkg", version: "1.0.0" }],
    [{ name: "transitive-pkg", version: "2.0.0" }],
  );

  const f: VulnerabilityFinding = {
    id: "CVE-2025-5555",
    source: "github",
    packageName: "transitive-pkg",
    packageVersion: "2.0.0",
    severity: "critical",
  };

  const res = evaluatePackagePolicies(pkg("transitive-pkg", "2.0.0", [f]), cfg, graph);
  // Should NOT be allowlisted — it's transitive
  assert.equal(res[0].action, "block");
});

test("directOnly allowlist without graph: conservative no-match", () => {
  const cfg: AuditConfig = {
    ...baseConfig(),
    policy: {
      block: ["critical"],
      warn: [],
      allowlist: [{ id: "CVE-2025-5555", directOnly: true, reason: "direct allowlist" }],
    },
  };
  // No graph provided
  const f: VulnerabilityFinding = {
    id: "CVE-2025-5555",
    source: "github",
    packageName: "some-pkg",
    packageVersion: "1.0.0",
    severity: "critical",
  };

  const res = evaluatePackagePolicies(pkg("some-pkg", "1.0.0", [f]), cfg);
  // Without graph, directOnly entries should not match (conservative)
  assert.equal(res[0].action, "block");
});

test("non-directOnly allowlist matches both direct and transitive", () => {
  const cfg: AuditConfig = {
    ...baseConfig(),
    policy: {
      block: ["critical"],
      warn: [],
      allowlist: [{ id: "CVE-2025-6666", reason: "applies to all" }],
    },
  };
  const graph = makeGraph(
    [{ name: "direct-pkg", version: "1.0.0" }],
    [{ name: "transitive-pkg", version: "2.0.0" }],
  );

  const fDirect: VulnerabilityFinding = {
    id: "CVE-2025-6666",
    source: "github",
    packageName: "direct-pkg",
    packageVersion: "1.0.0",
    severity: "critical",
  };
  const fTransitive: VulnerabilityFinding = {
    id: "CVE-2025-6666",
    source: "github",
    packageName: "transitive-pkg",
    packageVersion: "2.0.0",
    severity: "critical",
  };

  const resDirect = evaluatePackagePolicies(pkg("direct-pkg", "1.0.0", [fDirect]), cfg, graph);
  assert.equal(resDirect[0].action, "allow");

  const resTransitive = evaluatePackagePolicies(pkg("transitive-pkg", "2.0.0", [fTransitive]), cfg, graph);
  assert.equal(resTransitive[0].action, "allow");
});

test("combined: downgrade + directOnly allowlist — transitive gets downgraded, directOnly allowlist doesn't apply", () => {
  const cfg: AuditConfig = {
    ...baseConfig(),
    policy: {
      block: ["critical", "high"],
      warn: ["medium", "low", "unknown"],
      allowlist: [{ id: "CVE-2025-7777", directOnly: true, reason: "direct only" }],
      transitiveSeverityOverride: "downgrade-by-one",
    },
  };
  const graph = makeGraph(
    [{ name: "direct-pkg", version: "1.0.0" }],
    [{ name: "transitive-pkg", version: "2.0.0" }],
  );

  const f: VulnerabilityFinding = {
    id: "CVE-2025-7777",
    source: "github",
    packageName: "transitive-pkg",
    packageVersion: "2.0.0",
    severity: "critical",
  };

  const res = evaluatePackagePolicies(pkg("transitive-pkg", "2.0.0", [f]), cfg, graph);
  // directOnly allowlist should NOT match (it's transitive)
  // critical → high (downgrade), high is in block list → block
  assert.equal(res[0].action, "block");
  assert.ok(res[0].reason.includes("downgraded to high"));
});

test("transitive downgrade: medium becomes low", () => {
  const cfg: AuditConfig = {
    ...baseConfig(),
    policy: {
      block: ["critical", "high"],
      warn: ["medium", "low", "unknown"],
      allowlist: [],
      transitiveSeverityOverride: "downgrade-by-one",
    },
  };
  const graph = makeGraph(
    [{ name: "direct-pkg", version: "1.0.0" }],
    [{ name: "transitive-pkg", version: "2.0.0" }],
  );

  const f: VulnerabilityFinding = {
    id: "CVE-2025-8888",
    source: "github",
    packageName: "transitive-pkg",
    packageVersion: "2.0.0",
    severity: "medium",
  };

  const res = evaluatePackagePolicies(pkg("transitive-pkg", "2.0.0", [f]), cfg, graph);
  // medium → low, which is in warn list
  assert.equal(res[0].action, "warn");
  assert.ok(res[0].reason.includes("downgraded to low"));
});

test("transitive downgrade: low stays low", () => {
  const cfg: AuditConfig = {
    ...baseConfig(),
    policy: {
      block: ["critical", "high"],
      warn: ["medium", "low", "unknown"],
      allowlist: [],
      transitiveSeverityOverride: "downgrade-by-one",
    },
  };
  const graph = makeGraph(
    [{ name: "direct-pkg", version: "1.0.0" }],
    [{ name: "transitive-pkg", version: "2.0.0" }],
  );

  const f: VulnerabilityFinding = {
    id: "CVE-2025-8889",
    source: "github",
    packageName: "transitive-pkg",
    packageVersion: "2.0.0",
    severity: "low",
  };

  const res = evaluatePackagePolicies(pkg("transitive-pkg", "2.0.0", [f]), cfg, graph);
  // low → low (no further downgrade)
  assert.equal(res[0].action, "warn");
  assert.ok(!res[0].reason.includes("downgraded")); // stays low, no downgrade message
});
