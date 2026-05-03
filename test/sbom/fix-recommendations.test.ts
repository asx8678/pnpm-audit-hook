/**
 * Fix Recommendations in SBOM Output Tests.
 *
 * Tests for CycloneDX vulnerability fix recommendations including:
 * - Fix version recommendations
 * - Fix availability status
 * - Upgrade path information
 * - Handling of missing fix information
 */

import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { generateCycloneDX } from "../../src/sbom/cyclonedx-generator";
import { serializeCycloneDXToXml } from "../../src/sbom/cyclonedx-generator";
import type { PackageRef, VulnerabilityFinding } from "../../src/types";
import type { SbomComponent, ComponentVulnerabilityMap } from "../../src/sbom/types";

// ============================================================================
// Test Fixtures
// ============================================================================

const mockComponents: SbomComponent[] = [
  {
    name: "vulnerable-package",
    version: "1.0.0",
    purl: "pkg:npm/vulnerable-package@1.0.0",
    vulnerabilities: [],
  },
  {
    name: "another-package",
    version: "2.0.0",
    purl: "pkg:npm/another-package@2.0.0",
    vulnerabilities: [],
  },
];

const findingsWithFix: VulnerabilityFinding[] = [
  {
    id: "CVE-2021-44906",
    source: "github",
    packageName: "vulnerable-package",
    packageVersion: "1.0.0",
    severity: "medium",
    title: "Prototype Pollution in vulnerable-package",
    fixedVersion: "1.2.6",
    cvssScore: 5.6,
    publishedAt: "2021-03-22T00:00:00Z",
    url: "https://github.com/advisories/GHSA-rvff-897h-2f5p",
  },
];

const findingsWithMultipleFixes: VulnerabilityFinding[] = [
  {
    id: "CVE-2021-12345",
    source: "github",
    packageName: "vulnerable-package",
    packageVersion: "1.0.0",
    severity: "high",
    title: "Security vulnerability with multiple fixes",
    fixedVersion: "1.3.0, 2.0.0, 2.1.0",
    cvssScore: 7.5,
    publishedAt: "2021-06-15T00:00:00Z",
    url: "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx",
  },
];

const findingsWithoutFix: VulnerabilityFinding[] = [
  {
    id: "CVE-2021-99999",
    source: "nvd",
    packageName: "vulnerable-package",
    packageVersion: "1.0.0",
    severity: "critical",
    title: "Critical vulnerability with no fix",
    cvssScore: 9.8,
    publishedAt: "2021-08-10T00:00:00Z",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2021-99999",
  },
];

const findingsWithCommaSpacedFixes: VulnerabilityFinding[] = [
  {
    id: "CVE-2021-54321",
    source: "github",
    packageName: "vulnerable-package",
    packageVersion: "1.0.0",
    severity: "low",
    title: "Low severity with comma spaced fixes",
    fixedVersion: "1.5.0,  2.0.0  , 3.0.0",
    cvssScore: 3.2,
    publishedAt: "2021-09-20T00:00:00Z",
  },
];

// ============================================================================
// Helper Functions
// ============================================================================

function createVulnMap(
  components: SbomComponent[],
  findings: VulnerabilityFinding[],
): ComponentVulnerabilityMap {
  const vulnMap: ComponentVulnerabilityMap = new Map();
  for (const component of components) {
    const pkgKey = `${component.name}@${component.version}`;
    const componentFindings = findings.filter(
      (f) => f.packageName === component.name,
    );
    if (componentFindings.length > 0) {
      vulnMap.set(pkgKey, componentFindings);
    }
  }
  return vulnMap;
}

// ============================================================================
// Tests
// ============================================================================

describe("Fix Recommendations in SBOM Output", () => {
  describe("JSON Output (CycloneDX)", () => {
    it("should include fix recommendation for vulnerability with fixedVersion", () => {
      const vulnMap = createVulnMap(mockComponents, findingsWithFix);
      const bom = generateCycloneDX(mockComponents, vulnMap, {
        format: "cyclonedx",
        includeVulnerabilities: true,
      });

      assert.equal(bom.vulnerabilities?.length, 1);
      const vuln = bom.vulnerabilities![0];

      assert.equal(vuln.fixAvailable, true);
      assert.deepEqual(vuln.fixVersions, ["1.2.6"]);
      assert.ok(vuln.recommendation?.includes("1.2.6"));
      assert.ok(vuln.recommendation?.includes("vulnerable-package"));
      assert.equal(vuln.upgradePath, "vulnerable-package@1.0.0 → vulnerable-package@1.2.6");
    });

    it("should include multiple fix versions when available", () => {
      const vulnMap = createVulnMap(mockComponents, findingsWithMultipleFixes);
      const bom = generateCycloneDX(mockComponents, vulnMap, {
        format: "cyclonedx",
        includeVulnerabilities: true,
      });

      assert.equal(bom.vulnerabilities?.length, 1);
      const vuln = bom.vulnerabilities![0];

      assert.equal(vuln.fixAvailable, true);
      assert.deepEqual(vuln.fixVersions, ["1.3.0", "2.0.0", "2.1.0"]);
      assert.ok(vuln.recommendation?.includes("1.3.0"));
      assert.ok(vuln.recommendation?.includes("2.0.0"));
      assert.ok(vuln.recommendation?.includes("2.1.0"));
      assert.equal(vuln.upgradePath, "vulnerable-package@1.0.0 → vulnerable-package@1.3.0 (or later)");
    });

    it("should indicate no fix available when fixedVersion is missing", () => {
      const vulnMap = createVulnMap(mockComponents, findingsWithoutFix);
      const bom = generateCycloneDX(mockComponents, vulnMap, {
        format: "cyclonedx",
        includeVulnerabilities: true,
      });

      assert.equal(bom.vulnerabilities?.length, 1);
      const vuln = bom.vulnerabilities![0];

      assert.equal(vuln.fixAvailable, false);
      assert.equal(vuln.fixVersions, undefined);
      assert.ok(vuln.recommendation?.includes("No fix is currently available"));
      assert.equal(vuln.upgradePath, undefined);
    });

    it("should handle comma-spaced fix versions correctly", () => {
      const vulnMap = createVulnMap(mockComponents, findingsWithCommaSpacedFixes);
      const bom = generateCycloneDX(mockComponents, vulnMap, {
        format: "cyclonedx",
        includeVulnerabilities: true,
      });

      assert.equal(bom.vulnerabilities?.length, 1);
      const vuln = bom.vulnerabilities![0];

      assert.equal(vuln.fixAvailable, true);
      assert.deepEqual(vuln.fixVersions, ["1.5.0", "2.0.0", "3.0.0"]);
    });

    it("should not include fix recommendation fields when vulnerabilities are excluded", () => {
      const vulnMap = createVulnMap(mockComponents, findingsWithFix);
      const bom = generateCycloneDX(mockComponents, vulnMap, {
        format: "cyclonedx",
        includeVulnerabilities: false,
      });

      assert.equal(bom.vulnerabilities, undefined);
    });

    it("should include fix recommendation for all vulnerabilities in multi-vulnerability scenario", () => {
      const allFindings = [
        ...findingsWithFix,
        ...findingsWithoutFix,
      ];
      const vulnMap = createVulnMap(mockComponents, allFindings);
      const bom = generateCycloneDX(mockComponents, vulnMap, {
        format: "cyclonedx",
        includeVulnerabilities: true,
      });

      assert.equal(bom.vulnerabilities?.length, 2);

      // First vulnerability should have fix
      const vuln1 = bom.vulnerabilities![0];
      assert.equal(vuln1.fixAvailable, true);
      assert.ok(vuln1.recommendation?.includes("1.2.6"));

      // Second vulnerability should indicate no fix
      const vuln2 = bom.vulnerabilities![1];
      assert.equal(vuln2.fixAvailable, false);
      assert.ok(vuln2.recommendation?.includes("No fix is currently available"));
    });
  });

  describe("XML Output (CycloneDX-XML)", () => {
    it("should include fix recommendation in XML output", () => {
      const vulnMap = createVulnMap(mockComponents, findingsWithFix);
      const bom = generateCycloneDX(mockComponents, vulnMap, {
        format: "cyclonedx-xml",
        includeVulnerabilities: true,
      });

      const xml = serializeCycloneDXToXml(bom);

      assert.ok(xml.includes("<recommendation>"));
      assert.ok(xml.includes("<fixAvailable>true</fixAvailable>"));
      assert.ok(xml.includes("<fixVersions>"));
      assert.ok(xml.includes("<fixVersion>1.2.6</fixVersion>"));
      assert.ok(xml.includes("<upgradePath>"));
      assert.ok(xml.includes("vulnerable-package@1.0.0 → vulnerable-package@1.2.6"));
    });

    it("should include multiple fix versions in XML output", () => {
      const vulnMap = createVulnMap(mockComponents, findingsWithMultipleFixes);
      const bom = generateCycloneDX(mockComponents, vulnMap, {
        format: "cyclonedx-xml",
        includeVulnerabilities: true,
      });

      const xml = serializeCycloneDXToXml(bom);

      assert.ok(xml.includes("<fixVersions>"));
      assert.ok(xml.includes("<fixVersion>1.3.0</fixVersion>"));
      assert.ok(xml.includes("<fixVersion>2.0.0</fixVersion>"));
      assert.ok(xml.includes("<fixVersion>2.1.0</fixVersion>"));
    });

    it("should indicate no fix available in XML output", () => {
      const vulnMap = createVulnMap(mockComponents, findingsWithoutFix);
      const bom = generateCycloneDX(mockComponents, vulnMap, {
        format: "cyclonedx-xml",
        includeVulnerabilities: true,
      });

      const xml = serializeCycloneDXToXml(bom);

      assert.ok(xml.includes("<fixAvailable>false</fixAvailable>"));
      assert.ok(xml.includes("No fix is currently available"));
      assert.ok(!xml.includes("<fixVersions>"));
      assert.ok(!xml.includes("<upgradePath>"));
    });

    it("should not include fix recommendation fields when vulnerabilities are excluded", () => {
      const vulnMap = createVulnMap(mockComponents, findingsWithFix);
      const bom = generateCycloneDX(mockComponents, vulnMap, {
        format: "cyclonedx-xml",
        includeVulnerabilities: false,
      });

      const xml = serializeCycloneDXToXml(bom);

      assert.ok(!xml.includes("<recommendation>"));
      assert.ok(!xml.includes("<fixAvailable>"));
      assert.ok(!xml.includes("<fixVersions>"));
    });
  });

  describe("Edge Cases", () => {
    it("should handle empty fixedVersion string", () => {
      const finding: VulnerabilityFinding = {
        id: "CVE-2021-00001",
        source: "github",
        packageName: "vulnerable-package",
        packageVersion: "1.0.0",
        severity: "medium",
        title: "Empty fix version",
        fixedVersion: "",
        cvssScore: 5.0,
      };

      const vulnMap = createVulnMap(mockComponents, [finding]);
      const bom = generateCycloneDX(mockComponents, vulnMap, {
        format: "cyclonedx",
        includeVulnerabilities: true,
      });

      const vuln = bom.vulnerabilities![0];
      assert.equal(vuln.fixAvailable, false);
      assert.ok(vuln.recommendation?.includes("No fix is currently available"));
    });

    it("should handle fixedVersion with only whitespace", () => {
      const finding: VulnerabilityFinding = {
        id: "CVE-2021-00002",
        source: "github",
        packageName: "vulnerable-package",
        packageVersion: "1.0.0",
        severity: "medium",
        title: "Whitespace fix version",
        fixedVersion: "   ",
        cvssScore: 5.0,
      };

      const vulnMap = createVulnMap(mockComponents, [finding]);
      const bom = generateCycloneDX(mockComponents, vulnMap, {
        format: "cyclonedx",
        includeVulnerabilities: true,
      });

      const vuln = bom.vulnerabilities![0];
      assert.equal(vuln.fixAvailable, false);
      assert.ok(vuln.recommendation?.includes("No fix is currently available"));
    });

    it("should handle single version in fixedVersion", () => {
      const finding: VulnerabilityFinding = {
        id: "CVE-2021-00003",
        source: "github",
        packageName: "vulnerable-package",
        packageVersion: "1.0.0",
        severity: "medium",
        title: "Single fix version",
        fixedVersion: "1.5.0",
        cvssScore: 5.0,
      };

      const vulnMap = createVulnMap(mockComponents, [finding]);
      const bom = generateCycloneDX(mockComponents, vulnMap, {
        format: "cyclonedx",
        includeVulnerabilities: true,
      });

      const vuln = bom.vulnerabilities![0];
      assert.equal(vuln.fixAvailable, true);
      assert.deepEqual(vuln.fixVersions, ["1.5.0"]);
      assert.equal(vuln.upgradePath, "vulnerable-package@1.0.0 → vulnerable-package@1.5.0");
    });

    it("should handle version ranges in fixedVersion", () => {
      const finding: VulnerabilityFinding = {
        id: "CVE-2021-00004",
        source: "github",
        packageName: "vulnerable-package",
        packageVersion: "1.0.0",
        severity: "medium",
        title: "Version range fix",
        fixedVersion: ">=1.2.0 <2.0.0",
        cvssScore: 5.0,
      };

      const vulnMap = createVulnMap(mockComponents, [finding]);
      const bom = generateCycloneDX(mockComponents, vulnMap, {
        format: "cyclonedx",
        includeVulnerabilities: true,
      });

      const vuln = bom.vulnerabilities![0];
      assert.equal(vuln.fixAvailable, true);
      assert.deepEqual(vuln.fixVersions, [">=1.2.0 <2.0.0"]);
      assert.ok(vuln.recommendation?.includes(">=1.2.0 <2.0.0"));
    });

    it("should properly escape XML characters in recommendations", () => {
      const finding: VulnerabilityFinding = {
        id: "CVE-2021-00005",
        source: "github",
        packageName: "vulnerable-package",
        packageVersion: "1.0.0",
        severity: "medium",
        title: "XML escaping test",
        fixedVersion: "1.0.0",
        cvssScore: 5.0,
        description: "Vulnerability with <special> & \"characters\"",
      };

      const vulnMap = createVulnMap(mockComponents, [finding]);
      const bom = generateCycloneDX(mockComponents, vulnMap, {
        format: "cyclonedx-xml",
        includeVulnerabilities: true,
      });

      const xml = serializeCycloneDXToXml(bom);

      // Should not contain raw XML special characters in recommendations
      assert.ok(!xml.includes("vulnerable-package\""));
      assert.ok(xml.includes("&lt;special&gt;"));
      assert.ok(xml.includes("&amp;"));
    });
  });

  describe("Integration with Existing Vulnerability Data", () => {
    it("should preserve existing vulnerability fields while adding fix recommendations", () => {
      const vulnMap = createVulnMap(mockComponents, findingsWithFix);
      const bom = generateCycloneDX(mockComponents, vulnMap, {
        format: "cyclonedx",
        includeVulnerabilities: true,
      });

      const vuln = bom.vulnerabilities![0];

      // Existing fields should be preserved
      assert.equal(vuln.id, "CVE-2021-44906");
      assert.equal(vuln.source?.name, "github");
      assert.equal(vuln.source?.url, "https://github.com/advisories/GHSA-rvff-897h-2f5p");
      assert.equal(vuln.ratings.length, 1);
      assert.equal(vuln.ratings[0].score, 5.6);
      assert.equal(vuln.ratings[0].severity, "medium");
      assert.equal(vuln.published, "2021-03-22T00:00:00Z");
      assert.equal(vuln.affects.length, 1);
      assert.equal(vuln.problemTypes?.length, 1);
      assert.equal(vuln.references?.length, 1);

      // New fix recommendation fields should be added
      assert.equal(vuln.fixAvailable, true);
      assert.deepEqual(vuln.fixVersions, ["1.2.6"]);
      assert.ok(vuln.recommendation?.includes("1.2.6"));
      assert.equal(vuln.upgradePath, "vulnerable-package@1.0.0 → vulnerable-package@1.2.6");
    });

    it("should work correctly with component vulnerability map", () => {
      const vulnMap: ComponentVulnerabilityMap = new Map();
      vulnMap.set("vulnerable-package@1.0.0", findingsWithFix);
      vulnMap.set("another-package@2.0.0", findingsWithoutFix);

      const bom = generateCycloneDX(mockComponents, vulnMap, {
        format: "cyclonedx",
        includeVulnerabilities: true,
      });

      assert.equal(bom.vulnerabilities?.length, 2);

      // Check first component's vulnerability
      const vuln1 = bom.vulnerabilities?.find((v) => v.id === "CVE-2021-44906");
      assert.ok(vuln1);
      assert.equal(vuln1.fixAvailable, true);

      // Check second component's vulnerability
      const vuln2 = bom.vulnerabilities?.find((v) => v.id === "CVE-2021-99999");
      assert.ok(vuln2);
      assert.equal(vuln2.fixAvailable, false);
    });
  });
});
