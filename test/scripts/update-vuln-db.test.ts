/**
 * Unit tests for pure helper functions in scripts/utils/update-vuln-db-helpers.ts
 *
 * Covers:
 *   - mapSeverity()      — GitHub severity → canonical Severity mapping
 *   - SEVERITY_RANK       — rank ordering constant
 *   - convertAdvisory()  — GitHub Advisory → StaticVulnerability conversion
 *   - normalizePackageData() — raw JSON → StaticPackageData normalization
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import "./update-vuln-db-cli-cases";

import {
  mapSeverity,
  SEVERITY_RANK,
  convertAdvisory,
  normalizePackageData,
} from "../../scripts/utils/update-vuln-db-helpers";
import type { GitHubAdvisory } from "../../scripts/utils/update-vuln-db-helpers";
import type { Severity } from "../../src/types";

// ---------------------------------------------------------------------------
// mapSeverity
// ---------------------------------------------------------------------------

describe("mapSeverity", () => {
  it("maps canonical GitHub severities correctly", () => {
    assert.equal(mapSeverity("critical"), "critical");
    assert.equal(mapSeverity("high"), "high");
    assert.equal(mapSeverity("medium"), "medium");
    assert.equal(mapSeverity("low"), "low");
  });

  it("maps 'moderate' to 'medium' (GitHub's older terminology)", () => {
    assert.equal(mapSeverity("moderate"), "medium");
  });

  it("is case-insensitive", () => {
    assert.equal(mapSeverity("CRITICAL"), "critical");
    assert.equal(mapSeverity("High"), "high");
    assert.equal(mapSeverity("MODERATE"), "medium");
    assert.equal(mapSeverity("Low"), "low");
  });

  it("returns 'unknown' for unrecognised values", () => {
    assert.equal(mapSeverity("severe"), "unknown");
    assert.equal(mapSeverity("warning"), "unknown");
    assert.equal(mapSeverity("info"), "unknown");
    assert.equal(mapSeverity(""), "unknown");
  });
});

// ---------------------------------------------------------------------------
// SEVERITY_RANK
// ---------------------------------------------------------------------------

describe("SEVERITY_RANK", () => {
  it("covers all severity levels", () => {
    const expected: Severity[] = ["critical", "high", "medium", "low", "unknown"];
    assert.deepEqual(
      Object.keys(SEVERITY_RANK).sort(),
      [...expected].sort(),
    );
  });

  it("preserves correct ordering: critical > high > medium > low > unknown", () => {
    assert.ok(SEVERITY_RANK.critical > SEVERITY_RANK.high);
    assert.ok(SEVERITY_RANK.high > SEVERITY_RANK.medium);
    assert.ok(SEVERITY_RANK.medium > SEVERITY_RANK.low);
    assert.ok(SEVERITY_RANK.low > SEVERITY_RANK.unknown);
  });
});

// ---------------------------------------------------------------------------
// convertAdvisory
// ---------------------------------------------------------------------------

describe("convertAdvisory", () => {
  const baseAdvisory: GitHubAdvisory = {
    ghsaId: "GHSA-35jh-r3h4-6jhm",
    summary: "Prototype Pollution in lodash",
    description: "A long description that is definitely under 500 chars.",
    severity: "high",
    publishedAt: "2020-07-15T19:15:00Z",
    updatedAt: "2023-09-13T19:54:00Z",
    permalink: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
    identifiers: [
      { type: "GHSA", value: "GHSA-35jh-r3h4-6jhm" },
      { type: "CVE", value: "CVE-2020-8203" },
    ],
    vulnerabilities: {
      nodes: [],
    },
  };

  const baseVulnNode: GitHubAdvisory["vulnerabilities"]["nodes"][0] = {
    package: { name: "lodash", ecosystem: "NPM" },
    vulnerableVersionRange: "<4.17.19",
    firstPatchedVersion: { identifier: "4.17.19" },
  };

  it("converts a GitHub Advisory + vuln node to {packageName, entry}", () => {
    const result = convertAdvisory(baseAdvisory, baseVulnNode);
    assert.equal(result.packageName, "lodash");
    assert.equal(result.entry.id, "GHSA-35jh-r3h4-6jhm");
    assert.equal(result.entry.packageName, "lodash");
  });

  it("maps severity via mapSeverity", () => {
    const result = convertAdvisory(baseAdvisory, baseVulnNode);
    assert.equal(result.entry.severity, "high");
  });

  it("maps 'moderate' severity to 'medium'", () => {
    const moderate = { ...baseAdvisory, severity: "moderate" };
    const result = convertAdvisory(moderate, baseVulnNode);
    assert.equal(result.entry.severity, "medium");
  });

  it("copies advisory metadata correctly", () => {
    const result = convertAdvisory(baseAdvisory, baseVulnNode);
    assert.equal(result.entry.title, "Prototype Pollution in lodash");
    assert.equal(result.entry.url, "https://github.com/advisories/GHSA-35jh-r3h4-6jhm");
    assert.equal(result.entry.publishedAt, "2020-07-15T19:15:00Z");
    assert.equal(result.entry.modifiedAt, "2023-09-13T19:54:00Z");
    assert.equal(result.entry.source, "github");
  });

  it("maps identifiers preserving type and value", () => {
    const result = convertAdvisory(baseAdvisory, baseVulnNode);
    assert.deepEqual(result.entry.identifiers, [
      { type: "GHSA", value: "GHSA-35jh-r3h4-6jhm" },
      { type: "CVE", value: "CVE-2020-8203" },
    ]);
  });

  it("creates affectedVersions with range and fixed version", () => {
    const result = convertAdvisory(baseAdvisory, baseVulnNode);
    assert.deepEqual(result.entry.affectedVersions, [
      { range: "<4.17.19", fixed: "4.17.19" },
    ]);
  });

  it("handles missing firstPatchedVersion (no fix available)", () => {
    const unpatched = {
      ...baseVulnNode,
      firstPatchedVersion: null,
    };
    const result = convertAdvisory(baseAdvisory, unpatched);
    assert.equal(result.entry.affectedVersions[0].fixed, undefined);
    assert.equal(result.entry.affectedVersions[0].range, "<4.17.19");
  });

  it("truncates descriptions longer than 500 chars", () => {
    const longDesc = "x".repeat(600);
    const verbose = { ...baseAdvisory, description: longDesc };
    const result = convertAdvisory(verbose, baseVulnNode);
    assert.ok(result.entry.description!.length <= 500);
    assert.equal(result.entry.description!.length, 500);
  });

  it("preserves short descriptions unchanged", () => {
    const result = convertAdvisory(baseAdvisory, baseVulnNode);
    assert.equal(
      result.entry.description,
      "A long description that is definitely under 500 chars.",
    );
  });
});

// ---------------------------------------------------------------------------
// normalizePackageData
// ---------------------------------------------------------------------------

describe("normalizePackageData", () => {
  it("returns null for null/undefined input", () => {
    assert.equal(normalizePackageData(null, "fallback"), null);
    assert.equal(normalizePackageData(undefined, "fallback"), null);
  });

  it("returns null for non-object input", () => {
    assert.equal(normalizePackageData("string", "fallback"), null);
    assert.equal(normalizePackageData(42, "fallback"), null);
  });

  it("uses obj.packageName when available", () => {
    const raw = { packageName: "from-obj", vulnerabilities: [] };
    const result = normalizePackageData(raw, "fallback");
    assert.equal(result!.packageName, "from-obj");
  });

  it("falls back to obj.name when packageName is missing", () => {
    const raw = { name: "from-name", vulnerabilities: [] };
    const result = normalizePackageData(raw, "fallback");
    assert.equal(result!.packageName, "from-name");
  });

  it("falls back to the packageName argument when neither field exists", () => {
    const raw = { vulnerabilities: [] };
    const result = normalizePackageData(raw, "fallback-name");
    assert.equal(result!.packageName, "fallback-name");
  });

  it("returns null when no name is available at all", () => {
    const raw = { vulnerabilities: [] };
    const result = normalizePackageData(raw, "");
    assert.equal(result, null);
  });

  it("uses obj.lastUpdated when present", () => {
    const raw = { packageName: "pkg", lastUpdated: "2024-01-01T00:00:00Z", vulnerabilities: [] };
    const result = normalizePackageData(raw, "pkg");
    assert.equal(result!.lastUpdated, "2024-01-01T00:00:00Z");
  });

  it("generates lastUpdated as ISO string when missing", () => {
    const raw = { packageName: "pkg", vulnerabilities: [] };
    const result = normalizePackageData(raw, "pkg");
    // Should be a valid ISO date string
    assert.ok(!isNaN(Date.parse(result!.lastUpdated)));
  });

  it("normalizes vulnerabilities with the current affectedVersions schema", () => {
    const raw = {
      packageName: "lodash",
      vulnerabilities: [
        {
          id: "GHSA-35jh-r3h4-6jhm",
          packageName: "lodash",
          title: "Prototype Pollution",
          severity: "high",
          url: "https://example.com",
          publishedAt: "2020-07-15T19:15:00Z",
          modifiedAt: "2023-09-13T19:54:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-35jh-r3h4-6jhm" },
            { type: "CVE", value: "CVE-2020-8203" },
          ],
          affectedVersions: [
            { range: "<4.17.19", fixed: "4.17.19" },
          ],
        },
      ],
    };
    const result = normalizePackageData(raw, "lodash")!;
    assert.equal(result.vulnerabilities.length, 1);
    const vuln = result.vulnerabilities[0];
    assert.equal(vuln.id, "GHSA-35jh-r3h4-6jhm");
    assert.equal(vuln.severity, "high");
    assert.equal(vuln.source, "github");
    assert.deepEqual(vuln.affectedVersions, [{ range: "<4.17.19", fixed: "4.17.19" }]);
    assert.deepEqual(vuln.identifiers, [
      { type: "GHSA", value: "GHSA-35jh-r3h4-6jhm" },
      { type: "CVE", value: "CVE-2020-8203" },
    ]);
  });

  it("normalizes legacy affectedRange/fixedVersion to affectedVersions", () => {
    const raw = {
      packageName: "express",
      vulnerabilities: [
        {
          id: "GHSA-rv95-896h-c2vc",
          severity: "medium",
          affectedRange: "<4.19.2",
          fixedVersion: "4.19.2",
        },
      ],
    };
    const result = normalizePackageData(raw, "express")!;
    assert.equal(result.vulnerabilities.length, 1);
    assert.deepEqual(result.vulnerabilities[0].affectedVersions, [
      { range: "<4.19.2", fixed: "4.19.2" },
    ]);
  });

  it("handles legacy affectedRange without fixedVersion", () => {
    const raw = {
      packageName: "ip",
      vulnerabilities: [
        {
          id: "GHSA-78xj-cgh5-2h22",
          severity: "high",
          affectedRange: "<=2.0.1",
        },
      ],
    };
    const result = normalizePackageData(raw, "ip")!;
    assert.equal(result.vulnerabilities.length, 1);
    assert.deepEqual(result.vulnerabilities[0].affectedVersions, [
      { range: "<=2.0.1" },
    ]);
  });

  it("skips vulnerabilities without an id", () => {
    const raw = {
      packageName: "pkg",
      vulnerabilities: [
        { severity: "high" }, // no id
        { id: "", severity: "low" }, // empty id
        { id: "GHSA-valid", severity: "medium" },
      ],
    };
    const result = normalizePackageData(raw, "pkg")!;
    assert.equal(result.vulnerabilities.length, 1);
    assert.equal(result.vulnerabilities[0].id, "GHSA-valid");
  });

  it("skips non-object entries in vulnerabilities array", () => {
    const raw = {
      packageName: "pkg",
      vulnerabilities: [null, "not-an-object", 42, { id: "GHSA-ok", severity: "low" }],
    };
    const result = normalizePackageData(raw, "pkg")!;
    assert.equal(result.vulnerabilities.length, 1);
    assert.equal(result.vulnerabilities[0].id, "GHSA-ok");
  });

  it("skips affectedVersions entries with empty/missing range", () => {
    const raw = {
      packageName: "pkg",
      vulnerabilities: [
        {
          id: "GHSA-test",
          severity: "high",
          affectedVersions: [
            { range: "", fixed: "1.0.0" },  // empty range → skip
            { fixed: "2.0.0" },              // missing range → skip
            { range: "<1.0.0", fixed: "1.0.0" }, // valid
          ],
        },
      ],
    };
    const result = normalizePackageData(raw, "pkg")!;
    assert.equal(result.vulnerabilities[0].affectedVersions.length, 1);
    assert.deepEqual(result.vulnerabilities[0].affectedVersions[0], {
      range: "<1.0.0",
      fixed: "1.0.0",
    });
  });

  it("filters out invalid identifiers (missing type or value)", () => {
    const raw = {
      packageName: "pkg",
      vulnerabilities: [
        {
          id: "GHSA-test",
          severity: "high",
          identifiers: [
            { type: "GHSA", value: "GHSA-abc" },  // valid
            { type: "", value: "CVE-123" },        // empty type → skip
            { type: "CVE", value: "" },            // empty value → skip
            { type: "OSV", value: "OSV-456" },    // valid
            null,                                   // null → skip
            "not-an-object",                        // not object → skip
          ],
        },
      ],
    };
    const result = normalizePackageData(raw, "pkg")!;
    assert.deepEqual(result.vulnerabilities[0].identifiers, [
      { type: "GHSA", value: "GHSA-abc" },
      { type: "OSV", value: "OSV-456" },
    ]);
  });

  it("returns undefined identifiers when the field is missing", () => {
    const raw = {
      packageName: "pkg",
      vulnerabilities: [{ id: "GHSA-test", severity: "low" }],
    };
    const result = normalizePackageData(raw, "pkg")!;
    assert.equal(result.vulnerabilities[0].identifiers, undefined);
  });

  it("defaults to empty affectedVersions when neither schema is present", () => {
    const raw = {
      packageName: "pkg",
      vulnerabilities: [{ id: "GHSA-test", severity: "low" }],
    };
    const result = normalizePackageData(raw, "pkg")!;
    assert.deepEqual(result.vulnerabilities[0].affectedVersions, []);
  });

  it("defaults severity to 'unknown' when missing or non-string", () => {
    const raw = {
      packageName: "pkg",
      vulnerabilities: [
        { id: "GHSA-no-sev" },             // missing severity
        { id: "GHSA-bad-sev", severity: 42 }, // non-string severity
      ],
    };
    const result = normalizePackageData(raw, "pkg")!;
    assert.equal(result.vulnerabilities[0].severity, "unknown");
    assert.equal(result.vulnerabilities[1].severity, "unknown");
  });

  it("falls back to parent packageName when vuln.packageName is missing", () => {
    const raw = {
      packageName: "parent-pkg",
      vulnerabilities: [{ id: "GHSA-test", severity: "low" }],
    };
    const result = normalizePackageData(raw, "parent-pkg")!;
    assert.equal(result.vulnerabilities[0].packageName, "parent-pkg");
  });

  it("normalizes sample-vulns.json fixture data (integration check)", async () => {
    // Load the real fixture file to verify normalization works end-to-end
    const { default: sampleVulns } = await import(
      "../../scripts/fixtures/sample-vulns.json",
      { with: { type: "json" } }
    ) as { default: Array<{ pkg: string; vulns: Array<Record<string, unknown>> }> };

    for (const item of sampleVulns) {
      // Simulate the shape that generateSampleData would have written to disk
      const raw = {
        packageName: item.pkg,
        lastUpdated: "2025-01-01T00:00:00Z",
        vulnerabilities: item.vulns.map((v) => ({
          ...v,
          // The fixture uses legacy `affectedRange`/`fixedVersion` schema
          affectedRange: (v as Record<string, unknown>).affectedRange,
          fixedVersion: (v as Record<string, unknown>).fixedVersion,
        })),
      };
      const result = normalizePackageData(raw, item.pkg)!;
      assert.ok(result, `normalizePackageData should return data for ${item.pkg}`);
      assert.equal(result.packageName, item.pkg);
      assert.ok(
        result.vulnerabilities.length > 0,
        `${item.pkg} should have at least one vulnerability`,
      );
      // Every vulnerability should have at least one affected version range
      for (const vuln of result.vulnerabilities) {
        assert.ok(
          vuln.affectedVersions.length > 0,
          `${item.pkg}/${vuln.id} should have affectedVersions`,
        );
        assert.equal(vuln.source, "github");
        assert.ok(vuln.id, "vulnerability id should be non-empty");
      }
    }
  });
});

