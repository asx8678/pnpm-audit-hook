/**
 * SBOM Schema Validation tests.
 *
 * Tests for CycloneDX and SPDX schema validation.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateCycloneDX } from '../../src/sbom/cyclonedx-generator';
import { generateSPDX } from '../../src/sbom/spdx-generator';
import { packagesToSbomComponents, buildVulnerabilityMap } from '../../src/sbom/generator';
import { validateSbom, isValidSbom } from '../../src/sbom/schema-validator';
import type { PackageRef, VulnerabilityFinding } from '../../src/types';

// ============================================================================
// Test Fixtures
// ============================================================================

const mockPackages: PackageRef[] = [
  { name: 'express', version: '4.18.2' },
  { name: 'lodash', version: '4.17.21' },
];

const mockFindings: VulnerabilityFinding[] = [
  {
    id: 'CVE-2021-44906',
    source: 'github',
    packageName: 'minimist',
    packageVersion: '1.2.5',
    severity: 'medium',
    title: 'Prototype Pollution',
    cvssScore: 5.6,
  },
];

// ============================================================================
// Tests
// ============================================================================

describe('SBOM Schema Validation', () => {
  describe('validateSbom', () => {
    it('should validate a valid CycloneDX document', () => {
      const components = packagesToSbomComponents(mockPackages);
      const vulnMap = buildVulnerabilityMap(mockFindings);
      const bom = generateCycloneDX(components, vulnMap, {
        format: 'cyclonedx',
        projectName: 'test-project',
        projectVersion: '1.0.0',
      });

      const result = validateSbom(bom, 'cyclonedx');
      assert.equal(result.valid, true);
      assert.equal(result.errors.length, 0);
      assert.equal(result.format, 'cyclonedx');
    });

    it('should validate a valid SPDX document', () => {
      const components = packagesToSbomComponents(mockPackages);
      const vulnMap = buildVulnerabilityMap(mockFindings);
      const doc = generateSPDX(components, vulnMap, {
        format: 'spdx',
        projectName: 'test-project',
        projectVersion: '1.0.0',
      });

      const result = validateSbom(doc, 'spdx');
      assert.equal(result.valid, true);
      assert.equal(result.errors.length, 0);
      assert.equal(result.format, 'spdx');
    });

    it('should detect missing required fields in CycloneDX', () => {
      const invalidBom = {
        // Missing bomFormat
        specVersion: '1.5',
        version: 1,
        metadata: { timestamp: new Date().toISOString(), tools: [] },
        components: [],
      };

      const result = validateSbom(invalidBom, 'cyclonedx');
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.message.includes('Missing required field')));
    });

    it('should detect invalid bomFormat', () => {
      const invalidBom = {
        bomFormat: 'InvalidFormat',
        specVersion: '1.5',
        serialNumber: 'urn:uuid:test',
        version: 1,
        metadata: { timestamp: new Date().toISOString(), tools: [] },
        components: [],
      };

      const result = validateSbom(invalidBom, 'cyclonedx');
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.message.includes('not in allowed values')));
    });

    it('should detect invalid JSON string', () => {
      const result = validateSbom('not valid json', 'cyclonedx');
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.message.includes('Invalid JSON')));
    });

    it('should detect missing SPDX required fields', () => {
      const invalidDoc = {
        // Missing spdxVersion
        dataLicense: 'CC0-1.0',
        SPDXID: 'SPDXRef-DOCUMENT',
        name: 'test',
        documentNamespace: 'https://example.com',
        creationInfo: { created: new Date().toISOString(), creators: ['Tool: test'] },
        packages: [],
        relationships: [],
      };

      const result = validateSbom(invalidDoc, 'spdx');
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.message.includes('Missing required field')));
    });

    it('should validate component properties', () => {
      const components = packagesToSbomComponents(mockPackages);
      const bom = generateCycloneDX(components, new Map(), {
        format: 'cyclonedx',
      });

      // Remove a component name to trigger validation error
      const invalidBom = { ...bom };
      if (invalidBom.components[0]) {
        invalidBom.components[0] = { ...invalidBom.components[0], name: '' };
      }

      const result = validateSbom(invalidBom, 'cyclonedx');
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.message.includes('missing name')));
    });

    it('should warn about missing purl in CycloneDX', () => {
      const components = packagesToSbomComponents(mockPackages);
      const bom = generateCycloneDX(components, new Map(), {
        format: 'cyclonedx',
      });

      // Remove purl to trigger warning
      const invalidBom = { ...bom };
      if (invalidBom.components[0]) {
        const { purl, ...rest } = invalidBom.components[0];
        invalidBom.components[0] = rest as typeof invalidBom.components[0];
      }

      const result = validateSbom(invalidBom, 'cyclonedx');
      assert.equal(result.valid, true); // Warnings don't make it invalid
      assert.ok(result.warnings.some(w => w.message.includes('missing purl')));
    });
  });

  describe('isValidSbom', () => {
    it('should return true for valid CycloneDX', () => {
      const components = packagesToSbomComponents(mockPackages);
      const bom = generateCycloneDX(components, new Map(), {
        format: 'cyclonedx',
      });

      assert.equal(isValidSbom(bom, 'cyclonedx'), true);
    });

    it('should return true for valid SPDX', () => {
      const components = packagesToSbomComponents(mockPackages);
      const doc = generateSPDX(components, new Map(), {
        format: 'spdx',
      });

      assert.equal(isValidSbom(doc, 'spdx'), true);
    });

    it('should return false for invalid document', () => {
      const invalidDoc = { invalid: true };
      assert.equal(isValidSbom(invalidDoc, 'cyclonedx'), false);
    });

    it('should return false for invalid JSON string', () => {
      assert.equal(isValidSbom('invalid json', 'cyclonedx'), false);
    });
  });

  describe('validateSbom with JSON string', () => {
    it('should validate JSON string content', () => {
      const components = packagesToSbomComponents(mockPackages);
      const bom = generateCycloneDX(components, new Map(), {
        format: 'cyclonedx',
      });
      const jsonString = JSON.stringify(bom);

      const result = validateSbom(jsonString, 'cyclonedx');
      assert.equal(result.valid, true);
      assert.equal(result.errors.length, 0);
    });

    it('should handle malformed JSON string', () => {
      const result = validateSbom('{ invalid json }', 'cyclonedx');
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.message.includes('Invalid JSON')));
    });
  });

  describe('SWID Validation', () => {
    it('should validate a valid SWID XML string', () => {
      const validSwidXml = `<?xml version="1.0" encoding="UTF-8"?>
<swidTagSet>
  <swid>
    <tagId>12345678-1234-4123-8123-123456789012</tagId>
    <regid>com.example.test</regid>
    <name>TestPackage</name>
    <tagVersion>1.0</tagVersion>
    <softwareIdentificationScheme>swid</softwareIdentificationScheme>
    <entity>
      <name>TestPackage</name>
      <role>software</role>
    </entity>
  </swid>
</swidTagSet>`;

      const result = validateSbom(validSwidXml, 'swid');
      assert.equal(result.valid, true);
      assert.equal(result.errors.length, 0);
    });

    it('should detect missing XML declaration', () => {
      const swidWithoutDecl = `<swidTagSet>
  <swid>
    <tagId>12345678-1234-4123-8123-123456789012</tagId>
    <regid>com.example.test</regid>
    <name>TestPackage</name>
    <tagVersion>1.0</tagVersion>
    <softwareIdentificationScheme>swid</softwareIdentificationScheme>
    <entity>
      <name>TestPackage</name>
      <role>software</role>
    </entity>
  </swid>
</swidTagSet>`;

      const result = validateSbom(swidWithoutDecl, 'swid');
      // Should be valid but have a warning
      assert.equal(result.valid, true);
      assert.ok(result.warnings.some(w => w.message.includes('Missing XML declaration')));
    });

    it('should detect missing root element', () => {
      const swidWithoutRoot = `<?xml version="1.0" encoding="UTF-8"?>
<swid>
  <tagId>12345678-1234-4123-8123-123456789012</tagId>
</swid>`;

      const result = validateSbom(swidWithoutRoot, 'swid');
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.message.includes('Missing <swidTagSet> root element')));
    });

    it('should detect missing SWID tags', () => {
      const emptySwid = `<?xml version="1.0" encoding="UTF-8"?>
<swidTagSet>
</swidTagSet>`;

      const result = validateSbom(emptySwid, 'swid');
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.message.includes('No SWID tags found')));
    });

    it('should detect missing required elements', () => {
      const swidMissingElements = `<?xml version="1.0" encoding="UTF-8"?>
<swidTagSet>
  <swid>
    <tagId>12345678-1234-4123-8123-123456789012</tagId>
    <regid>com.example.test</regid>
    <name>TestPackage</name>
    <!-- Missing tagVersion and softwareIdentificationScheme -->
    <entity>
      <name>TestPackage</name>
      <role>software</role>
    </entity>
  </swid>
</swidTagSet>`;

      const result = validateSbom(swidMissingElements, 'swid');
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.message.includes('Missing required element <tagVersion>')));
      assert.ok(result.errors.some(e => e.message.includes('Missing required element <softwareIdentificationScheme>')));
    });

    it('should detect missing entity elements', () => {
      const swidWithoutEntities = `<?xml version="1.0" encoding="UTF-8"?>
<swidTagSet>
  <swid>
    <tagId>12345678-1234-4123-8123-123456789012</tagId>
    <regid>com.example.test</regid>
    <name>TestPackage</name>
    <tagVersion>1.0</tagVersion>
    <softwareIdentificationScheme>swid</softwareIdentificationScheme>
  </swid>
</swidTagSet>`;

      const result = validateSbom(swidWithoutEntities, 'swid');
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.message.includes('SWID tag must have at least one entity element')));
    });

    it('should require string content for SWID format', () => {
      const invalidContent = { notAString: true };
      const result = validateSbom(invalidContent as any, 'swid');
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.message.includes('SWID format requires string content')));
    });

    it('should validate generated SWID content', () => {
      // Import the SWID generator to get actual generated content
      const { generateSwidSbom } = require('../../src/sbom/swid-generator');
      const { generateSwidTags, serializeSwidTagSetToXml } = require('../../src/sbom/swid-generator');
      const components = packagesToSbomComponents(mockPackages);

      const tagSet = generateSwidTags(components);
      const xmlContent = serializeSwidTagSetToXml(tagSet);

      const result = validateSbom(xmlContent, 'swid');
      assert.equal(result.valid, true);
      assert.equal(result.errors.length, 0);
    });
  });
});
