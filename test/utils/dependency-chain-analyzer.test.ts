import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  propagateSeverity,
  analyzeVulnerability,
  analyzeAllVulnerabilities,
  sortByRisk,
} from "../../src/utils/lockfile/dependency-chain-analyzer";
import { buildDependencyGraph } from "../../src/utils/lockfile/graph-builder";
import type { VulnerabilityFinding } from "../../src/types";

/** Helper to create a lockfile and graph for testing */
function makeGraph(importers: Record<string, Record<string, string>>, packages: Record<string, { dependencies?: Record<string, string>; resolution?: Record<string, string> }>) {
  const lockfile = {
    importers: Object.fromEntries(
      Object.entries(importers).map(([k, v]) => [k, { dependencies: v }])
    ),
    packages: Object.fromEntries(
      Object.entries(packages).map(([k, v]) => [
        k,
        { resolution: { integrity: "sha512-test" }, ...v },
      ])
    ),
  };
  return buildDependencyGraph(lockfile as any);
}

/** Helper to create a basic finding */
function makeFinding(overrides: Partial<VulnerabilityFinding> = {}): VulnerabilityFinding {
  return {
    id: "CVE-2024-0001",
    source: "github",
    packageName: "test-pkg",
    packageVersion: "1.0.0",
    severity: "high",
    ...overrides,
  };
}

describe("propagateSeverity", () => {
  it("returns full severity for direct dependencies", () => {
    assert.equal(propagateSeverity("critical", 0, true, false), "critical");
    assert.equal(propagateSeverity("high", 0, true, false), "high");
    assert.equal(propagateSeverity("medium", 0, true, false), "medium");
  });

  it("returns full severity for shallow transitive deps (depth <= 2)", () => {
    assert.equal(propagateSeverity("critical", 1, false, false), "critical");
    assert.equal(propagateSeverity("high", 2, false, false), "high");
    assert.equal(propagateSeverity("medium", 1, false, false), "medium");
  });

  it("downgrades by 1 for medium-depth transitive deps (depth 3-5)", () => {
    assert.equal(propagateSeverity("critical", 3, false, false), "high");
    assert.equal(propagateSeverity("high", 4, false, false), "medium");
    assert.equal(propagateSeverity("medium", 5, false, false), "low");
  });

  it("downgrades by 1 for deep transitive deps (depth > 5)", () => {
    assert.equal(propagateSeverity("critical", 10, false, false), "high");
    assert.equal(propagateSeverity("high", 8, false, false), "medium");
  });

  it("applies extra downgrade for dev-only dependencies", () => {
    // Dev-only: depth 4 transitive, critical -> high (depth) -> medium (dev-only)
    assert.equal(propagateSeverity("critical", 4, false, true), "medium");
    // Dev-only: depth 4 transitive, high -> medium (depth) -> low (dev-only)
    assert.equal(propagateSeverity("high", 4, false, true), "low");
  });

  it("never goes below 'low'", () => {
    assert.equal(propagateSeverity("low", 10, false, true), "low");
    assert.equal(propagateSeverity("medium", 10, false, true), "low");
  });

  it("does not downgrade 'unknown' severity", () => {
    assert.equal(propagateSeverity("unknown", 10, false, false), "unknown");
    assert.equal(propagateSeverity("unknown", 10, false, true), "unknown");
  });

  it("does not downgrade 'low' severity", () => {
    assert.equal(propagateSeverity("low", 10, false, false), "low");
  });
});

describe("analyzeVulnerability", () => {
  it("enriches a direct dependency finding", () => {
    const graph = makeGraph(
      { ".": { "express": "4.18.0" } },
      { "express@4.18.0": {} }
    );
    const finding = makeFinding({
      packageName: "express",
      packageVersion: "4.18.0",
      severity: "critical",
    });

    const result = analyzeVulnerability(finding, graph);
    assert.ok(result.chainContext);
    assert.equal(result.chainContext.isDirect, true);
    assert.equal(result.chainContext.chainDepth, 0);
    assert.equal(result.chainContext.propagatedSeverity, "critical");
    assert.equal(result.chainContext.isDevOnly, false);
    assert.equal(result.chainContext.totalAffected, 0);
  });

  it("enriches a transitive dependency finding", () => {
    const graph = makeGraph(
      { ".": { "app": "1.0.0" } },
      {
        "app@1.0.0": { dependencies: { lib: "2.0.0" } },
        "lib@2.0.0": { dependencies: { util: "3.0.0" } },
        "util@3.0.0": {},
      }
    );
    const finding = makeFinding({
      packageName: "util",
      packageVersion: "3.0.0",
      severity: "high",
    });

    const result = analyzeVulnerability(finding, graph);
    assert.ok(result.chainContext);
    assert.equal(result.chainContext.isDirect, false);
    assert.equal(result.chainContext.chainDepth, 2);
    assert.equal(result.chainContext.propagatedSeverity, "high"); // depth 2, no downgrade
    assert.equal(result.chainContext.directAncestors.length, 1);
    assert.ok(result.chainContext.directAncestors.includes("app@1.0.0"));
  });

  it("propagates severity for deep transitive deps", () => {
    const graph = makeGraph(
      { ".": { "a": "1.0.0" } },
      {
        "a@1.0.0": { dependencies: { b: "1.0.0" } },
        "b@1.0.0": { dependencies: { c: "1.0.0" } },
        "c@1.0.0": { dependencies: { d: "1.0.0" } },
        "d@1.0.0": {},
      }
    );
    const finding = makeFinding({
      packageName: "d",
      packageVersion: "1.0.0",
      severity: "critical",
    });

    const result = analyzeVulnerability(finding, graph);
    assert.ok(result.chainContext);
    assert.equal(result.chainContext.chainDepth, 3);
    assert.equal(result.chainContext.propagatedSeverity, "high"); // depth 3, downgrade by 1
  });

  it("computes CVSS details when vector is available", () => {
    const graph = makeGraph(
      { ".": { "pkg": "1.0.0" } },
      { "pkg@1.0.0": {} }
    );
    const finding = makeFinding({
      packageName: "pkg",
      packageVersion: "1.0.0",
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      cvssScore: 9.8,
    });

    const result = analyzeVulnerability(finding, graph);
    assert.ok(result.cvssDetails);
    assert.equal(result.cvssDetails.score, 9.8);
    assert.equal(result.cvssDetails.severity, "critical");
    assert.equal(result.cvssDetails.attackVector, "N");
    assert.equal(result.cvssDetails.attackComplexity, "L");
    assert.ok(result.cvssDetails.exploitabilityLabel.includes("remotely exploitable"));
  });

  it("computes risk factors with correct structure", () => {
    const graph = makeGraph(
      { ".": { "pkg": "1.0.0" } },
      { "pkg@1.0.0": {} }
    );
    const finding = makeFinding({
      packageName: "pkg",
      packageVersion: "1.0.0",
      severity: "critical",
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      fixedVersion: "1.0.1",
    });

    const result = analyzeVulnerability(finding, graph);
    assert.ok(result.chainContext);
    assert.ok(result.chainContext.riskFactors.length > 0);

    const riskNames = result.chainContext.riskFactors.map(f => f.name);
    assert.ok(riskNames.includes("cvss-base"));
    assert.ok(riskNames.includes("chain-depth"));
    assert.ok(riskNames.includes("blast-radius"));
    assert.ok(riskNames.includes("fix-availability"));
    assert.ok(riskNames.includes("exploitability"));

    assert.ok(result.chainContext.compositeRiskScore > 0);
    assert.ok(result.chainContext.compositeRiskScore <= 10);
  });

  it("reduces risk score when fix is available", () => {
    const graph = makeGraph(
      { ".": { "pkg": "1.0.0" } },
      { "pkg@1.0.0": {} }
    );

    const withFix = analyzeVulnerability(
      makeFinding({
        packageName: "pkg",
        packageVersion: "1.0.0",
        severity: "high",
        cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        fixedVersion: "1.0.1",
      }),
      graph,
    );

    const withoutFix = analyzeVulnerability(
      makeFinding({
        packageName: "pkg",
        packageVersion: "1.0.0",
        severity: "high",
        cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      }),
      graph,
    );

    assert.ok(withFix.chainContext!.compositeRiskScore < withoutFix.chainContext!.compositeRiskScore,
      `With fix (${withFix.chainContext!.compositeRiskScore}) should be less than without fix (${withoutFix.chainContext!.compositeRiskScore})`);
  });

  it("reduces risk for dev-only dependencies", () => {
    const graph = makeGraph(
      { ".": { "app": "1.0.0" } },
      {
        "app@1.0.0": { dependencies: { "dev-tool": "1.0.0" } },
        "dev-tool@1.0.0": {},
      }
    );
    // Mark dev-tool as dev-only via the importer
    const lockfile = {
      importers: {
        ".": {
          dependencies: { app: "1.0.0" },
          devDependencies: { "dev-tool": "1.0.0" },
        },
      },
      packages: {
        "app@1.0.0": { resolution: { integrity: "sha512-test" }, dependencies: { "dev-tool": "1.0.0" } },
        "dev-tool@1.0.0": { resolution: { integrity: "sha512-test" } },
      },
    };
    const graphWithDev = buildDependencyGraph(lockfile as any);

    const finding = makeFinding({
      packageName: "dev-tool",
      packageVersion: "1.0.0",
      severity: "high",
    });

    const result = analyzeVulnerability(finding, graphWithDev);
    assert.ok(result.chainContext);
    assert.equal(result.chainContext.isDevOnly, true);
  });

  it("traces chain from dependencyChain if already set on finding", () => {
    const graph = makeGraph(
      { ".": { "a": "1.0.0" } },
      {
        "a@1.0.0": { dependencies: { b: "1.0.0" } },
        "b@1.0.0": {},
      }
    );
    const finding = makeFinding({
      packageName: "b",
      packageVersion: "1.0.0",
      dependencyChain: ["a@1.0.0", "b@1.0.0"],
    });

    const result = analyzeVulnerability(finding, graph);
    assert.ok(result.chainContext);
    assert.equal(result.chainContext.chainDepth, 1);
  });
});

describe("analyzeAllVulnerabilities", () => {
  it("processes all findings", () => {
    const graph = makeGraph(
      { ".": { "a": "1.0.0" } },
      {
        "a@1.0.0": { dependencies: { b: "1.0.0" } },
        "b@1.0.0": {},
      }
    );

    const findings = [
      makeFinding({ packageName: "a", packageVersion: "1.0.0", severity: "high" }),
      makeFinding({ packageName: "b", packageVersion: "1.0.0", severity: "critical" }),
    ];

    const results = analyzeAllVulnerabilities(findings, graph);
    assert.equal(results.length, 2);
    assert.ok(results[0]!.chainContext);
    assert.ok(results[1]!.chainContext);
    assert.equal(results[0]!.chainContext!.isDirect, true);
    assert.equal(results[1]!.chainContext!.isDirect, false);
  });
});

describe("sortByRisk", () => {
  it("sorts by composite risk score descending", () => {
    const findings = [
      makeFinding({ packageName: "low-pkg", severity: "low", chainContext: { compositeRiskScore: 2 } as any }),
      makeFinding({ packageName: "high-pkg", severity: "high", chainContext: { compositeRiskScore: 8 } as any }),
      makeFinding({ packageName: "med-pkg", severity: "medium", chainContext: { compositeRiskScore: 5 } as any }),
    ];

    const sorted = sortByRisk(findings);
    assert.equal(sorted[0]!.packageName, "high-pkg");
    assert.equal(sorted[1]!.packageName, "med-pkg");
    assert.equal(sorted[2]!.packageName, "low-pkg");
  });

  it("does not mutate the original array", () => {
    const findings = [
      makeFinding({ packageName: "a", chainContext: { compositeRiskScore: 5 } as any }),
      makeFinding({ packageName: "b", chainContext: { compositeRiskScore: 8 } as any }),
    ];

    const originalFirst = findings[0]!.packageName;
    sortByRisk(findings);
    assert.equal(findings[0]!.packageName, originalFirst);
  });

  it("falls back to severity rank when no chainContext", () => {
    const findings = [
      makeFinding({ packageName: "low-pkg", severity: "low" }),
      makeFinding({ packageName: "high-pkg", severity: "high" }),
    ];

    const sorted = sortByRisk(findings);
    assert.equal(sorted[0]!.packageName, "high-pkg");
    assert.equal(sorted[1]!.packageName, "low-pkg");
  });
});
