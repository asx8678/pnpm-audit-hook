/**
 * SBOM (Software Bill of Materials) generation tests.
 *
 * Tests for CycloneDX and SPDX output formats, vulnerability integration,
 * and CLI integration.
 */

import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import {
  generateSbom,
  packagesToSbomComponents,
  buildVulnerabilityMap,
} from "../../src/sbom/generator";
import { generateCycloneDX } from "../../src/sbom/cyclonedx-generator";
import { generateSPDX } from "../../src/sbom/spdx-generator";
import type { PackageRef, VulnerabilityFinding } from "../../src/types";
import type { SbomComponent, ComponentVulnerabilityMap } from "../../src/sbom/types";

// ============================================================================
// Test Fixtures
// ============================================================================

const mockPackages: PackageRef[] = [
  { name: "express", version: "4.18.2", integrity: "sha512-abc123def456" },
  { name: "lodash", version: "4.17.21", dependencies: ["express"] },
  { name: "@scope/package", version: "1.0.0" },
  { name: "minimist", version: "1.2.5", integrity: "sha256-xyz789" },
];

const mockFindings: VulnerabilityFinding[] = [
  {
    id: "GHSA-4xc9-xhrj-v574",
    source: "github",
    packageName: "node-fetch",
    packageVersion: "2.6.1",
    severity: "medium",
    title: "Exposure of Sensitive Information",
    cvssScore: 6.5,
    publishedAt: "2022-01-21T00:00:00Z",
    url: "https://github.com/advisories/GHSA-4xc9-xhrj-v574",
  },
  {
    id: "CVE-2021-44906",
    source: "github",
    packageName: "minimist",
    packageVersion: "1.2.5",
    severity: "medium",
    title: "Prototype Pollution in minimist",
    fixedVersion: "1.2.6",
    cvssScore: 5.6,
    publishedAt: "2021-03-22T00:00:00Z",
    url: "https://github.com/advisories/GHSA-rvff-897h-2f5p",
  },
  {
    id: "CVE-2020-28500",
    source: "github",
    packageName: "lodash",
    packageVersion: "4.17.21",
    severity: "high",
    title: "ReDoS in lodash",
    cvssScore: 7.5,
    publishedAt: "2021-04-01T00:00:00Z",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2020-28500",
  },
];

// ============================================================================
// Helper Functions
// ============================================================================

function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sbom-test-"));
}

function cleanupTempDir(dir: string): void {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    // Ignore cleanup errors
  }
}

// ============================================================================
// Tests
// ============================================================================

describe("SBOM Generation", () => {
  // -------------------------------------------------------------------------
  // packagesToSbomComponents
  // -------------------------------------------------------------------------
  describe("packagesToSbomComponents", () => {
    it("should convert PackageRef to SbomComponent", () => {
      const components = packagesToSbomComponents(mockPackages);

      assert.equal(components.length, 4);
      assert.equal(components[0].name, "express");
      assert.equal(components[0].version, "4.18.2");
      assert.equal(components[0].purl, "pkg:npm/express@4.18.2");
    });

    it("should handle scoped packages", () => {
      const components = packagesToSbomComponents(mockPackages);
      const scoped = components.find((c) => c.name === "@scope/package");

      assert.ok(scoped);
      assert.equal(scoped.purl, "pkg:npm/%40scope%2Fpackage@1.0.0");
    });

    it("should handle empty packages", () => {
      const components = packagesToSbomComponents([]);
      assert.equal(components.length, 0);
    });
  });

  // -------------------------------------------------------------------------
  // buildVulnerabilityMap
  // -------------------------------------------------------------------------
  describe("buildVulnerabilityMap", () => {
    it("should build map from findings", () => {
      const map = buildVulnerabilityMap(mockFindings);

      assert.ok(map.has("minimist@1.2.5"));
      assert.equal(map.get("minimist@1.2.5")!.length, 1);
      assert.equal(map.get("minimist@1.2.5")![0].id, "CVE-2021-44906");
    });

    it("should group findings by package", () => {
      const findings = [
        { ...mockFindings[0], packageName: "test", packageVersion: "1.0.0", id: "ID-1" },
        { ...mockFindings[0], packageName: "test", packageVersion: "1.0.0", id: "ID-2" },
      ];
      const map = buildVulnerabilityMap(findings);

      assert.ok(map.has("test@1.0.0"));
      assert.equal(map.get("test@1.0.0")!.length, 2);
    });

    it("should handle empty findings", () => {
      const map = buildVulnerabilityMap([]);
      assert.equal(map.size, 0);
    });
  });

  // -------------------------------------------------------------------------
  // CycloneDX Generation
  // -------------------------------------------------------------------------
  describe("CycloneDX Generation", () => {
    it("should generate valid CycloneDX BOM", () => {
      const vulnMap = buildVulnerabilityMap(mockFindings);
      const components = packagesToSbomComponents(mockPackages);

      const bom = generateCycloneDX(components, vulnMap, {
        format: "cyclonedx",
        includeVulnerabilities: true,
      });

      assert.equal(bom.bomFormat, "CycloneDX");
      assert.equal(bom.specVersion, "1.5");
      assert.equal(bom.version, 1);
      assert.ok(bom.serialNumber.startsWith("urn:uuid:"));
      assert.equal(bom.components.length, 4);
    });

    it("should include metadata with timestamp", () => {
      const components = packagesToSbomComponents(mockPackages);
      const bom = generateCycloneDX(components, new Map(), {
        format: "cyclonedx",
      });

      assert.ok(bom.metadata.timestamp);
      assert.ok(bom.metadata.tools.length > 0);
      assert.equal(bom.metadata.tools[0].name, "pnpm-audit-hook");
    });

    it("should include components with purl", () => {
      const components = packagesToSbomComponents(mockPackages);
      const bom = generateCycloneDX(components, new Map(), {
        format: "cyclonedx",
      });

      const express = bom.components.find((c) => c.name === "express");
      assert.ok(express);
      assert.equal(express.purl, "pkg:npm/express@4.18.2");
      assert.equal(express.type, "library");
    });

    it("should include hashes when available", () => {
      const components = packagesToSbomComponents(mockPackages);
      const bom = generateCycloneDX(components, new Map(), {
        format: "cyclonedx",
      });

      const express = bom.components.find((c) => c.name === "express");
      assert.ok(express);
      assert.ok(express.hashes);
      assert.equal(express.hashes!.length, 1);
      assert.equal(express.hashes![0].alg, "sha512");
    });

    it("should include dependencies when provided", () => {
      const components = packagesToSbomComponents(mockPackages);
      const bom = generateCycloneDX(components, new Map(), {
        format: "cyclonedx",
        includeDependencies: true,
      });

      assert.ok(bom.dependencies);
      const lodashDep = bom.dependencies.find((d) => d.ref.includes("lodash"));
      assert.ok(lodashDep);
      assert.ok(lodashDep.dependsOn);
      assert.ok(lodashDep.dependsOn.some((dep) => dep.includes("express")));
    });

    it("should include vulnerabilities when enabled", () => {
      const vulnMap = buildVulnerabilityMap(mockFindings);
      const components = packagesToSbomComponents(mockPackages);

      const bom = generateCycloneDX(components, vulnMap, {
        format: "cyclonedx",
        includeVulnerabilities: true,
      });

      assert.ok(bom.vulnerabilities);
      assert.ok(bom.vulnerabilities!.length > 0);

      const vuln = bom.vulnerabilities!.find((v) => v.id === "CVE-2021-44906");
      assert.ok(vuln);
      assert.equal(vuln.ratings.length, 1);
      assert.equal(vuln.ratings[0].severity, "medium");
    });

    it("should exclude vulnerabilities when disabled", () => {
      const vulnMap = buildVulnerabilityMap(mockFindings);
      const components = packagesToSbomComponents(mockPackages);

      const bom = generateCycloneDX(components, vulnMap, {
        format: "cyclonedx",
        includeVulnerabilities: false,
      });

      assert.equal(bom.vulnerabilities, undefined);
    });

    it("should include project metadata when provided", () => {
      const components = packagesToSbomComponents(mockPackages);
      const bom = generateCycloneDX(components, new Map(), {
        format: "cyclonedx",
        projectName: "test-project",
        projectVersion: "1.2.3",
      });

      assert.ok(bom.metadata.component);
      assert.equal(bom.metadata.component.name, "test-project");
      assert.equal(bom.metadata.component.version, "1.2.3");
    });
  });

  // -------------------------------------------------------------------------
  // CycloneDX XML Generation
  // -------------------------------------------------------------------------
  describe("CycloneDX XML Generation", () => {
    it("should generate valid CycloneDX XML SBOM", () => {
      const vulnMap = buildVulnerabilityMap(mockFindings);
      const components = packagesToSbomComponents(mockPackages);

      const bom = generateCycloneDX(components, vulnMap, {
        format: "cyclonedx-xml",
        includeVulnerabilities: true,
      });

      const { serializeCycloneDXToXml } = require("../../src/sbom/cyclonedx-generator");
      const xmlContent = serializeCycloneDXToXml(bom);

      // Verify it's valid XML
      assert.ok(xmlContent.includes('<?xml version="1.0" encoding="UTF-8"?>'));
      assert.ok(xmlContent.includes('<bom '));
      assert.ok(xmlContent.includes('</bom>'));
      assert.ok(xmlContent.includes('xmlns="http://cyclonedx.org/schema/bom/1.5"'));

      // Verify format is correct
      assert.equal(bom.bomFormat, "CycloneDX");
      assert.equal(bom.specVersion, "1.5");
      assert.equal(bom.version, 1);
      assert.ok(bom.serialNumber.startsWith("urn:uuid:"));
    });

    it("should include metadata in XML output", () => {
      const components = packagesToSbomComponents(mockPackages);
      const bom = generateCycloneDX(components, new Map(), {
        format: "cyclonedx-xml",
      });

      const { serializeCycloneDXToXml } = require("../../src/sbom/cyclonedx-generator");
      const xmlContent = serializeCycloneDXToXml(bom);

      assert.ok(xmlContent.includes('<metadata>'));
      assert.ok(xmlContent.includes('<timestamp>'));
      assert.ok(xmlContent.includes('<tools>'));
      assert.ok(xmlContent.includes('<tool>'));
      assert.ok(xmlContent.includes('<vendor>pnpm-audit-hook</vendor>'));
      assert.ok(xmlContent.includes('<name>pnpm-audit-hook</name>'));
    });

    it("should include components in XML output", () => {
      const components = packagesToSbomComponents(mockPackages);
      const bom = generateCycloneDX(components, new Map(), {
        format: "cyclonedx-xml",
      });

      const { serializeCycloneDXToXml } = require("../../src/sbom/cyclonedx-generator");
      const xmlContent = serializeCycloneDXToXml(bom);

      assert.ok(xmlContent.includes('<components>'));
      assert.ok(xmlContent.includes('</components>'));
      assert.ok(xmlContent.includes('<component type="library"'));
      assert.ok(xmlContent.includes('<name>express</name>'));
      assert.ok(xmlContent.includes('<version>4.18.2</version>'));
      assert.ok(xmlContent.includes('<purl>pkg:npm/express@4.18.2</purl>'));
    });

    it("should include vulnerabilities in XML output when enabled", () => {
      const vulnMap = buildVulnerabilityMap(mockFindings);
      const components = packagesToSbomComponents(mockPackages);

      const bom = generateCycloneDX(components, vulnMap, {
        format: "cyclonedx-xml",
        includeVulnerabilities: true,
      });

      const { serializeCycloneDXToXml } = require("../../src/sbom/cyclonedx-generator");
      const xmlContent = serializeCycloneDXToXml(bom);

      assert.ok(xmlContent.includes('<vulnerabilities>'));
      assert.ok(xmlContent.includes('</vulnerabilities>'));
      assert.ok(xmlContent.includes('<vulnerability>'));
      assert.ok(xmlContent.includes('<id>CVE-2021-44906</id>'));
      assert.ok(xmlContent.includes('<severity>medium</severity>'));
    });

    it("should generate CycloneDX XML SBOM via generateSbom", () => {
      const result = generateSbom(mockPackages, mockFindings, {
        format: "cyclonedx-xml",
        includeVulnerabilities: true,
        includeDependencies: true,
      });

      assert.equal(result.format, "cyclonedx-xml");
      assert.equal(result.componentCount, 4);
      assert.ok(result.content);
      assert.ok(result.durationMs >= 0);

      // Verify it's valid XML
      assert.ok(result.content.includes('<?xml version="1.0" encoding="UTF-8"?>'));
      assert.ok(result.content.includes('<bom '));
      assert.ok(result.content.includes('</bom>'));
      assert.ok(result.content.includes('xmlns="http://cyclonedx.org/schema/bom/1.5"'));

      // Verify format is correct
      assert.ok(result.content.includes('<specVersion>1.5</specVersion>') || result.content.includes('specVersion="1.5"'));
    });

    it("should include dependencies in XML output when enabled", () => {
      const components = packagesToSbomComponents(mockPackages);
      const bom = generateCycloneDX(components, new Map(), {
        format: "cyclonedx-xml",
        includeDependencies: true,
      });

      const { serializeCycloneDXToXml } = require("../../src/sbom/cyclonedx-generator");
      const xmlContent = serializeCycloneDXToXml(bom);

      assert.ok(xmlContent.includes('<dependencies>'));
      assert.ok(xmlContent.includes('</dependencies>'));
      assert.ok(xmlContent.includes('<dependency ref='));
      assert.ok(xmlContent.includes('<depends-on ref='));
    });

    it("should escape XML special characters in component names", () => {
      const specialPackages: PackageRef[] = [
        { name: "@scope/pkg&name", version: "1.0.0" },
        { name: "pkg<test>", version: "2.0.0" },
        { name: "pkg\"quoted\"", version: "3.0.0" },
      ];

      const components = packagesToSbomComponents(specialPackages);
      const bom = generateCycloneDX(components, new Map(), {
        format: "cyclonedx-xml",
      });

      const { serializeCycloneDXToXml } = require("../../src/sbom/cyclonedx-generator");
      const xmlContent = serializeCycloneDXToXml(bom);

      // Verify XML escaping
      assert.ok(xmlContent.includes('&amp;'));
      assert.ok(xmlContent.includes('&lt;'));
      assert.ok(xmlContent.includes('&gt;'));
      assert.ok(xmlContent.includes('&quot;'));

      // Verify the XML is still well-formed by checking closing tags
      assert.ok(xmlContent.includes('</components>'));
      assert.ok(xmlContent.includes('</bom>'));
    });
  });

  // -------------------------------------------------------------------------
  // SPDX Generation
  // -------------------------------------------------------------------------
  describe("SPDX Generation", () => {
    it("should generate valid SPDX document", () => {
      const vulnMap = buildVulnerabilityMap(mockFindings);
      const components = packagesToSbomComponents(mockPackages);

      const doc = generateSPDX(components, vulnMap, {
        format: "spdx",
        includeVulnerabilities: true,
      });

      assert.equal(doc.spdxVersion, "SPDX-2.3");
      assert.equal(doc.dataLicense, "CC0-1.0");
      assert.equal(doc.SPDXID, "SPDXRef-DOCUMENT");
      assert.ok(doc.documentNamespace.startsWith("https://spdx.org/spdxdocs/"));
    });

    it("should include packages with purl", () => {
      const components = packagesToSbomComponents(mockPackages);
      const doc = generateSPDX(components, new Map(), {
        format: "spdx",
      });

      // Root document + 4 packages
      assert.equal(doc.packages.length, 5);

      const express = doc.packages.find((p) => p.name === "express");
      assert.ok(express);
      assert.equal(express.versionInfo, "4.18.2");
      assert.ok(express.externalRefs);
      const purlRef = express.externalRefs!.find((r) => r.referenceType === "purl");
      assert.ok(purlRef);
      assert.equal(purlRef.referenceLocator, "pkg:npm/express@4.18.2");
    });

    it("should include checksums when available", () => {
      const components = packagesToSbomComponents(mockPackages);
      const doc = generateSPDX(components, new Map(), {
        format: "spdx",
      });

      const express = doc.packages.find((p) => p.name === "express");
      assert.ok(express);
      assert.ok(express.checksums);
      assert.equal(express.checksums!.length, 1);
      assert.equal(express.checksums![0].algorithm, "SHA512");
    });

    it("should include DEPENDS_ON relationships when provided", () => {
      const components = packagesToSbomComponents(mockPackages);
      const doc = generateSPDX(components, new Map(), {
        format: "spdx",
        includeDependencies: true,
      });

      const dependsOnRels = doc.relationships.filter(
        (r) => r.RelationshipType === "DEPENDS_ON",
      );
      assert.ok(dependsOnRels.length > 0);
      const lodashDep = dependsOnRels.find((r) => r.SPDXElementID.includes("lodash"));
      assert.ok(lodashDep);
      assert.ok(lodashDep.RelatedSPDXElement.includes("express"));
    });

    it("should include CONTAINS relationships", () => {
      const components = packagesToSbomComponents(mockPackages);
      const doc = generateSPDX(components, new Map(), {
        format: "spdx",
      });

      assert.ok(doc.relationships.length > 0);
      const containsRels = doc.relationships.filter(
        (r) => r.RelationshipType === "CONTAINS" && r.SPDXElementID === "SPDXRef-DOCUMENT",
      );
      assert.equal(containsRels.length, 4);
    });

    it("should include vulnerability annotations when enabled", () => {
      const vulnMap = buildVulnerabilityMap(mockFindings);
      const components = packagesToSbomComponents(mockPackages);

      const doc = generateSPDX(components, vulnMap, {
        format: "spdx",
        includeVulnerabilities: true,
      });

      assert.ok(doc.annotations);
      assert.ok(doc.annotations!.length > 0);

      const vulnAnnotation = doc.annotations!.find((a) =>
        a.Comment.includes("CVE-2021-44906"),
      );
      assert.ok(vulnAnnotation);
      assert.equal(vulnAnnotation.AnnotationType, "OTHER");
    });

    it("should include creation info", () => {
      const components = packagesToSbomComponents(mockPackages);
      const doc = generateSPDX(components, new Map(), {
        format: "spdx",
      });

      assert.ok(doc.creationInfo.created);
      assert.ok(doc.creationInfo.creators.length > 0);
      assert.ok(doc.creationInfo.creators.some((c) => c.includes("pnpm-audit-hook")));
    });
  });

  // -------------------------------------------------------------------------
  // Main generateSbom function
  // -------------------------------------------------------------------------
  describe("generateSbom", () => {
    it("should generate CycloneDX SBOM", () => {
      const result = generateSbom(mockPackages, mockFindings, {
        format: "cyclonedx",
        includeVulnerabilities: true,
        includeDependencies: true,
      });

      assert.equal(result.format, "cyclonedx");
      assert.equal(result.componentCount, 4);
      assert.ok(result.content);
      assert.ok(result.durationMs >= 0);

      const parsed = JSON.parse(result.content);
      assert.equal(parsed.bomFormat, "CycloneDX");
      assert.ok(parsed.dependencies);
    });

    it("should generate SPDX SBOM", () => {
      const result = generateSbom(mockPackages, mockFindings, {
        format: "spdx",
        includeVulnerabilities: true,
      });

      assert.equal(result.format, "spdx");
      assert.equal(result.componentCount, 4);
      assert.ok(result.content);

      const parsed = JSON.parse(result.content);
      assert.equal(parsed.spdxVersion, "SPDX-2.3");
    });

    it("should write to file when outputPath is provided", () => {
      const tempDir = createTempDir();
      try {
        const outputPath = path.join(tempDir, "sbom.json");
        const result = generateSbom(mockPackages, mockFindings, {
          format: "cyclonedx",
          outputPath,
        });

        assert.ok(fs.existsSync(outputPath));
        const content = fs.readFileSync(outputPath, "utf-8");
        const parsed = JSON.parse(content);
        assert.equal(parsed.bomFormat, "CycloneDX");
      } finally {
        cleanupTempDir(tempDir);
      }
    });

    it("should handle empty packages", () => {
      const result = generateSbom([], [], {
        format: "cyclonedx",
      });

      assert.equal(result.componentCount, 0);
      assert.equal(result.vulnerabilityCount, 0);
    });

    it("should throw on invalid format", () => {
      assert.throws(
        () => generateSbom(mockPackages, [], { format: "invalid" as any }),
        /Unsupported SBOM format/,
      );
    });
  });

  // -------------------------------------------------------------------------
  // Edge Cases
  // -------------------------------------------------------------------------
  describe("Edge Cases", () => {
    it("should handle packages with special characters", () => {
      const packages: PackageRef[] = [
        { name: "@scope/pkg-name", version: "1.0.0" },
        { name: "pkg.with.dots", version: "2.0.0" },
        { name: "pkg_with_underscores", version: "3.0.0" },
      ];

      const result = generateSbom(packages, [], {
        format: "cyclonedx",
      });

      assert.equal(result.componentCount, 3);
      const parsed = JSON.parse(result.content);
      assert.ok(parsed.components);
    });

    it("should handle findings without optional fields", () => {
      const minimalFinding: VulnerabilityFinding = {
        id: "TEST-001",
        source: "github",
        packageName: "express",
        packageVersion: "4.18.2",
        severity: "low",
      };

      const result = generateSbom(mockPackages, [minimalFinding], {
        format: "cyclonedx",
        includeVulnerabilities: true,
      });

      assert.ok(result.content);
      const parsed = JSON.parse(result.content);
      assert.ok(parsed.vulnerabilities);
      assert.equal(parsed.vulnerabilities.length, 1);
      assert.equal(parsed.vulnerabilities[0].id, "TEST-001");
    });

    it("should generate SWID Tags SBOM", () => {
      const result = generateSbom(mockPackages, mockFindings, {
        format: "swid",
        includeVulnerabilities: true,
        projectName: "test-project",
      });

      assert.equal(result.format, "swid");
      assert.equal(result.componentCount, 4);
      assert.ok(result.content);
      assert.ok(result.durationMs >= 0);

      // Verify it's valid XML
      assert.ok(result.content.includes('<?xml version="1.0" encoding="UTF-8"?>'));
      assert.ok(result.content.includes('<swidTagSet>'));
      assert.ok(result.content.includes('</swidTagSet>'));

      // Verify SWID tags are present
      assert.ok(result.content.includes('<swid>'));
      assert.ok(result.content.includes('<tagId>'));
      assert.ok(result.content.includes('<regid>'));
      assert.ok(result.content.includes('<name>express</name>'));
    });
  });

  // -------------------------------------------------------------------------
  // SWID Tags Generation
  // -------------------------------------------------------------------------
  describe("SWID Tags Generation", () => {
    it("should generate valid SWID tag set", () => {
      const { generateSwidTags } = require("../../src/sbom/swid-generator");
      const components = packagesToSbomComponents(mockPackages);

      const tagSet = generateSwidTags(components, {
        regid: "com.example.project",
      });

      assert.ok(tagSet.tags);
      assert.equal(tagSet.tags.length, 4);

      const expressTag = tagSet.tags.find((t) => t.name === "express");
      assert.ok(expressTag);
      assert.ok(expressTag.tagId);
      assert.ok(expressTag.regid);
      assert.equal(expressTag.name, "express");
      assert.equal(expressTag.tagVersion, "1.0");
      assert.equal(expressTag.softwareIdentificationScheme, "swid");
    });

    it("should include required entities per ISO/IEC 19770-2", () => {
      const { generateSwidTags } = require("../../src/sbom/swid-generator");
      const components = packagesToSbomComponents(mockPackages);

      const tagSet = generateSwidTags(components);
      const tag = tagSet.tags[0];

      // Must have software entity
      const softwareEntity = tag.entities.find((e) => e.role === "software");
      assert.ok(softwareEntity);
      assert.ok(softwareEntity.name);

      // Must have tagCreator entity
      const tagCreatorEntity = tag.entities.find((e) => e.role === "tagCreator");
      assert.ok(tagCreatorEntity);
      assert.ok(tagCreatorEntity.name);
      assert.ok(tagCreatorEntity.regid);
    });

    it("should serialize tag to XML", () => {
      const { generateSwidTags, serializeSwidTagToXml } = require("../../src/sbom/swid-generator");
      const components = packagesToSbomComponents(mockPackages);

      const tagSet = generateSwidTags(components);
      const xml = serializeSwidTagToXml(tagSet.tags[0]);

      assert.ok(xml.includes('<?xml version="1.0" encoding="UTF-8"?>'));
      assert.ok(xml.includes('<swid>'));
      assert.ok(xml.includes('</swid>'));
      assert.ok(xml.includes('<tagId>'));
      assert.ok(xml.includes('<regid>'));
      assert.ok(xml.includes('<name>'));
      assert.ok(xml.includes('<meta>'));
      assert.ok(xml.includes('<entity>'));
    });

    it("should serialize tag set to XML", () => {
      const { generateSwidTags, serializeSwidTagSetToXml } = require("../../src/sbom/swid-generator");
      const components = packagesToSbomComponents(mockPackages);

      const tagSet = generateSwidTags(components);
      const xml = serializeSwidTagSetToXml(tagSet);

      assert.ok(xml.includes('<?xml version="1.0" encoding="UTF-8"?>'));
      assert.ok(xml.includes('<swidTagSet>'));
      assert.ok(xml.includes('</swidTagSet>'));

      // Should contain all 4 tags
      const swidCount = (xml.match(/<swid>/g) || []).length;
      assert.equal(swidCount, 4);
    });

    it("should handle custom SWID options", () => {
      const { generateSwidTags } = require("../../src/sbom/swid-generator");
      const components = packagesToSbomComponents(mockPackages);

      const tagSet = generateSwidTags(components, {
        regid: "com.custom.regid",
        tagVersion: "2.0",
        structure: "multivolume",
        addOn: true,
        softwareCreator: { name: "Custom Creator", regid: "com.custom.creator" },
        softwareLicensor: { name: "Custom Licensor", regid: "com.custom.licensor" },
      });

      const tag = tagSet.tags[0];
      assert.equal(tag.tagVersion, "2.0");
      assert.equal(tag.structure, "multivolume");
      assert.equal(tag.addOn, true);
      assert.equal(tag.regid, "com.custom.regid.express");

      // Verify custom entities
      const tagCreator = tag.entities.find((e) => e.role === "tagCreator");
      assert.equal(tagCreator?.name, "Custom Creator");
      assert.equal(tagCreator?.regid, "com.custom.creator");

      const licensor = tag.entities.find((e) => e.role === "softwareLicensor");
      assert.equal(licensor?.name, "Custom Licensor");
      assert.equal(licensor?.regid, "com.custom.licensor");
    });

    it("should handle empty components", () => {
      const { generateSwidTags } = require("../../src/sbom/swid-generator");

      const tagSet = generateSwidTags([]);
      assert.equal(tagSet.tags.length, 0);
    });

    it("should generate SWID SBOM via main generator", () => {
      const result = generateSbom(mockPackages, mockFindings, {
        format: "swid",
        projectName: "my-project",
      });

      assert.equal(result.format, "swid");
      assert.equal(result.componentCount, 4);
      assert.ok(result.content.includes("express"));
      assert.ok(result.content.includes("lodash"));
    });
  });
});
