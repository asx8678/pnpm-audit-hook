import test from "node:test";
import assert from "node:assert/strict";
import { evaluatePackagePolicies } from "../src/policies/policy-engine";
import type {
  AuditConfig,
  PackageAuditResult,
  VulnerabilityFinding,
} from "../src/types";

function baseConfig(): AuditConfig {
  return {
    version: 1,
    policies: {
      block: ["critical", "high"],
      warn: ["medium", "low"],
      gracePeriod: 7,
      unknownVulnData: "warn",
      networkPolicy: "fail-open",
      allowlist: [],
      blocklist: [],
    },
    sources: { osv: { enabled: true } },
    integrity: { requireSha512Integrity: true },
    performance: { concurrency: 4, timeoutMs: 1000, earlyExitOnBlock: true },
    cache: { ttlSeconds: 3600, dir: ".cache", allowStale: true },
    reporting: { formats: ["json"], outputDir: ".", basename: "x" },
  };
}

function pkgResult(
  name = "a",
  version = "1.0.0",
  findings: VulnerabilityFinding[] = [],
): PackageAuditResult {
  return {
    pkg: { name, version, integrity: "sha512-abc" },
    findings,
    decisions: [],
  };
}

test("blocklist blocks package", () => {
  const cfg = baseConfig();
  cfg.policies.blocklist = ["event-stream"];

  const res = evaluatePackagePolicies(
    pkgResult("event-stream", "1.2.3"),
    cfg,
    {},
  );

  assert.ok(
    res.decisions.some((d) => d.action === "block" && d.source === "blocklist"),
  );
});

test("severity policy blocks high and allows allowlisted", () => {
  const cfg = baseConfig();
  cfg.policies.allowlist = [
    {
      id: "CVE-2023-0001",
      package: "lodash",
      expires: "2999-01-01",
      reason: "No exploit path",
      approvedBy: "security",
    },
  ];

  const f1: VulnerabilityFinding = {
    id: "CVE-2023-0001",
    source: "npm",
    packageName: "lodash",
    packageVersion: "4.17.21",
    severity: "high",
    publishedAt: new Date("2023-01-01").toISOString(),
  };

  const f2: VulnerabilityFinding = {
    id: "CVE-2023-9999",
    source: "osv",
    packageName: "lodash",
    packageVersion: "4.17.21",
    severity: "high",
    publishedAt: new Date("2023-01-01").toISOString(),
  };

  const res = evaluatePackagePolicies(
    pkgResult("lodash", "4.17.21", [f1, f2]),
    cfg,
    {},
  );

  // allowlisted finding should be allow
  assert.ok(
    res.decisions.some(
      (d) =>
        d.action === "allow" &&
        d.source === "allowlist" &&
        d.findingId === "CVE-2023-0001",
    ),
  );
  // non-allowlisted high should be block
  assert.ok(
    res.decisions.some(
      (d) =>
        d.action === "block" &&
        d.source === "severity" &&
        d.findingId === "CVE-2023-9999",
    ),
  );
});

test("grace period downgrades non-critical block to warn when newly published", () => {
  const cfg = baseConfig();
  cfg.policies.gracePeriod = 30;

  const now = new Date("2025-01-31T00:00:00.000Z");
  const published = new Date("2025-01-15T00:00:00.000Z"); // 16 days old

  const f: VulnerabilityFinding = {
    id: "CVE-2025-1111",
    source: "npm",
    packageName: "a",
    packageVersion: "1.0.0",
    severity: "high",
    publishedAt: published.toISOString(),
  };

  const res = evaluatePackagePolicies(
    pkgResult("a", "1.0.0", [f]),
    cfg,
    {},
    now,
  );

  assert.ok(
    res.decisions.some(
      (d) => d.action === "warn" && d.findingId === "CVE-2025-1111",
    ),
  );
  assert.ok(
    !res.decisions.some(
      (d) => d.action === "block" && d.findingId === "CVE-2025-1111",
    ),
  );
});

test("critical is not downgraded by grace period", () => {
  const cfg = baseConfig();
  cfg.policies.gracePeriod = 365;

  const now = new Date("2025-01-31T00:00:00.000Z");
  const published = new Date("2025-01-30T00:00:00.000Z");

  const f: VulnerabilityFinding = {
    id: "CVE-2025-2222",
    source: "osv",
    packageName: "a",
    packageVersion: "1.0.0",
    severity: "critical",
    publishedAt: published.toISOString(),
  };

  const res = evaluatePackagePolicies(
    pkgResult("a", "1.0.0", [f]),
    cfg,
    {},
    now,
  );

  assert.ok(
    res.decisions.some(
      (d) => d.action === "block" && d.findingId === "CVE-2025-2222",
    ),
  );
});

test("unknown data policy creates decision", () => {
  const cfg = baseConfig();
  cfg.policies.unknownVulnData = "block";

  const res = evaluatePackagePolicies(pkgResult("a", "1.0.0"), cfg, {
    unknownData: true,
  });

  assert.ok(
    res.decisions.some((d) => d.source === "unknown" && d.action === "block"),
  );
});

test("sha512 integrity required blocks non-sha512 integrity", () => {
  const cfg = baseConfig();
  const p: PackageAuditResult = {
    pkg: { name: "a", version: "1.0.0", integrity: "sha1-deadbeef" },
    findings: [],
    decisions: [],
  };

  const res = evaluatePackagePolicies(p, cfg, {});
  assert.ok(
    res.decisions.some((d) => d.action === "block" && d.source === "integrity"),
  );
});

test("expired allowlist does not apply (blocks by severity)", () => {
  const cfg = baseConfig();
  cfg.policies.allowlist = [
    {
      cve: "CVE-2020-0001",
      package: "a",
      expires: "2000-01-01",
      reason: "expired",
      approvedBy: "sec",
    },
  ];

  const f: VulnerabilityFinding = {
    id: "CVE-2020-0001",
    source: "npm",
    packageName: "a",
    packageVersion: "1.0.0",
    severity: "high",
    publishedAt: new Date("2020-01-01").toISOString(),
  };

  const res = evaluatePackagePolicies(pkgResult("a", "1.0.0", [f]), cfg, {});

  assert.ok(
    res.decisions.some(
      (d) => d.action === "block" && d.findingId === "CVE-2020-0001",
    ),
  );
  assert.ok(
    !res.decisions.some(
      (d) => d.action === "allow" && d.findingId === "CVE-2020-0001",
    ),
  );
});
