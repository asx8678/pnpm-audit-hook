import test from "node:test";
import assert from "node:assert/strict";
import { evaluatePackagePolicies } from "../src/policies/policy-engine";
import type { AuditConfig, PackageAuditResult, VulnerabilityFinding } from "../src/types";

function baseConfig(): AuditConfig {
  return {
    policy: {
      block: ["critical", "high"],
      warn: ["medium", "low", "unknown"],
    },
    sources: { osv: { enabled: true } },
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
    source: "osv",
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
    source: "osv",
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
