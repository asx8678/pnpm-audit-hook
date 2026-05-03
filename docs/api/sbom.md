# SBOM (Software Bill of Materials) API

> Generate SBOMs from pnpm audit results in CycloneDX and SPDX formats.

## Overview

The SBOM module provides functionality to generate Software Bill of Materials documents from vulnerability audit results. It supports two industry-standard formats:

- **CycloneDX 1.5** - OWASP standard for security tooling
- **SPDX 2.3** - Linux Foundation standard (ISO/IEC 5962:2021)

## Quick Start

```typescript
import { generateSbom, SbomFormat } from 'pnpm-audit-hook';

// After running an audit...
const packages = [{ name: 'express', version: '4.18.2' }];
const findings = [{ /* vulnerability findings */ }];

// Generate CycloneDX SBOM
const result = generateSbom(packages, findings, {
  format: 'cyclonedx',
  includeVulnerabilities: true,
  includeDependencies: true,
  projectName: 'my-project',
  projectVersion: '1.0.0',
});

// Write to file
fs.writeFileSync('sbom.json', result.content);

console.log(`Generated ${result.componentCount} components`);
console.log(`Found ${result.vulnerabilityCount} vulnerabilities`);
```

## CLI Usage

Generate SBOMs directly from the command line:

```bash
# Generate CycloneDX SBOM (default)
pnpm-audit-scan --sbom

# Generate SPDX SBOM
pnpm-audit-scan --sbom --sbom-format spdx

# Write to file
pnpm-audit-scan --sbom --sbom-output sbom.json

# Full example with all options
pnpm-audit-scan --sbom --sbom-format cyclonedx --sbom-output sbom.json
```

### CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--sbom` | Enable SBOM generation | `false` |
| `--sbom-format <fmt>` | SBOM format: `cyclonedx`, `spdx` | `cyclonedx` |
| `--sbom-output <path>` | Write SBOM to file | stdout |

## API Reference

### `generateSbom(packages, findings, options)`

Main entry point for SBOM generation.

```typescript
function generateSbom(
  packages: PackageRef[],
  findings: VulnerabilityFinding[],
  options: SbomOptions
): SbomResult;
```

**Parameters:**

- `packages` - Array of package references from lockfile extraction
- `findings` - Vulnerability findings from audit
- `options` - SBOM generation options

**Returns:** `SbomResult` with generated SBOM content and metadata

### `packagesToSbomComponents(packages)`

Convert PackageRef array to SBOM component format.

```typescript
function packagesToSbomComponents(packages: PackageRef[]): SbomComponent[];
```

### `buildVulnerabilityMap(findings)`

Build a vulnerability map for quick component lookup.

```typescript
function buildVulnerabilityMap(findings: VulnerabilityFinding[]): ComponentVulnerabilityMap;
```

### `validateSbom(sbomContent, format)`

Validate an SBOM document against the appropriate schema.

```typescript
function validateSbom(
  sbomContent: string | Record<string, unknown>,
  format: SbomFormat
): ValidationResult;
```

**Parameters:**

- `sbomContent` - SBOM content as JSON string or parsed object
- `format` - Expected SBOM format (`cyclonedx` or `spdx`)

**Returns:** `ValidationResult` with errors and warnings

### `isValidSbom(sbomContent, format)`

Quick check if SBOM content is valid.

```typescript
function isValidSbom(
  sbomContent: string | Record<string, unknown>,
  format: SbomFormat
): boolean;
```

## Types

### `SbomOptions`

```typescript
interface SbomOptions {
  format: SbomFormat;
  outputPath?: string;
  includeVulnerabilities?: boolean;
  includeDependencies?: boolean;
  projectName?: string;
  projectVersion?: string;
  projectDescription?: string;
}
```

### `SbomResult`

```typescript
interface SbomResult {
  content: string;
  format: SbomFormat;
  componentCount: number;
  vulnerabilityCount: number;
  outputPath?: string;
  durationMs: number;
}
```

### `SbomComponent`

```typescript
interface SbomComponent {
  name: string;
  version: string;
  purl: string;
  license?: string;
  description?: string;
  homepage?: string;
  repository?: string;
  hashes?: PackageHash[];
  dependencies?: string[];
  vulnerabilities?: VulnerabilityFinding[];
}
```

### `PackageHash`

```typescript
interface PackageHash {
  algorithm: HashAlgorithm;
  value: string;
}

type HashAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-512' | 'MD5';
```

## Features

### Integrity Hashes

SBOM generation includes package integrity hashes when available from the lockfile:

- **CycloneDX**: Hashes in the `hashes` array with algorithm and hex-encoded values
- **SPDX**: Checksums in the `checksums` array with algorithm and hex-encoded values

Hashes are parsed from npm integrity strings (e.g., `sha512-abc123...`).

### Dependency Relationships

When `includeDependencies: true`:

- **CycloneDX**: Dependencies array with `ref` and `dependsOn` fields
- **SPDX**: `DEPENDS_ON` relationships between packages

### Vulnerability Enrichment

When `includeVulnerabilities: true`:

- **CycloneDX**: Vulnerabilities array with ratings, descriptions, and affected components
- **SPDX**: Annotations with vulnerability details and external references

## Output Formats

### CycloneDX Example

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-15T10:30:00Z",
    "tools": [
      {
        "vendor": "pnpm-audit-hook",
        "name": "pnpm-audit-hook",
        "version": "1.4.3"
      }
    ],
    "component": {
      "type": "application",
      "name": "my-project",
      "version": "1.0.0",
      "purl": "pkg:npm/my-project@1.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:npm/express@4.18.2",
      "name": "express",
      "version": "4.18.2",
      "purl": "pkg:npm/express@4.18.2",
      "hashes": [
        {
          "alg": "sha512",
          "content": "abc123..."
        }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:npm/express@4.18.2",
      "dependsOn": [
        "pkg:npm/body-parser@1.20.2"
      ]
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2021-44906",
      "ratings": [
        {
          "severity": "medium",
          "score": 5.6
        }
      ],
      "affects": [
        {
          "ref": "pkg:npm/minimist@1.2.5"
        }
      ]
    }
  ]
}
```

### SPDX Example

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "SPDX-my-project-SBOM",
  "documentNamespace": "https://spdx.org/spdxdocs/...",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": [
      "Tool: pnpm-audit-hook-1.4.3"
    ]
  },
  "documentDescribes": ["SPDXRef-DOCUMENT"],
  "packages": [
    {
      "SPDXID": "SPDXRef-DOCUMENT",
      "name": "my-project",
      "versionInfo": "1.0.0"
    },
    {
      "SPDXID": "SPDXRef-Package-express-4.18.2",
      "name": "express",
      "versionInfo": "4.18.2",
      "checksums": [
        {
          "algorithm": "SHA512",
          "checksumValue": "abc123..."
        }
      ],
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/express@4.18.2"
        }
      ]
    }
  ],
  "relationships": [
    {
      "SPDXElementID": "SPDXRef-DOCUMENT",
      "RelationshipType": "CONTAINS",
      "RelatedSPDXElement": "SPDXRef-Package-express-4.18.2"
    },
    {
      "SPDXElementID": "SPDXRef-Package-lodash-4.17.21",
      "RelationshipType": "DEPENDS_ON",
      "RelatedSPDXElement": "SPDXRef-Package-express-4.18.2"
    }
  ]
}
```

## Integration Examples

### With Audit Results

```typescript
import { runAudit, generateSbom } from 'pnpm-audit-hook';

const auditResult = await runAudit(lockfile, runtime);

// Generate SBOM from audit results
const sbom = generateSbom(
  auditResult.packages,
  auditResult.findings,
  {
    format: 'cyclonedx',
    includeVulnerabilities: true,
    includeDependencies: true,
  }
);
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Generate SBOM
  run: |
    pnpm-audit-scan --sbom --sbom-format cyclonedx --sbom-output sbom.json
    
- name: Upload SBOM
  uses: actions/upload-artifact@v3
  with:
    name: sbom
    path: sbom.json
```

## Best Practices

1. **Include dependencies**: Enable `includeDependencies: true` for complete dependency graphs
2. **Include vulnerabilities**: Enable `includeVulnerabilities: true` for security context
3. **Store SBOMs**: Archive SBOMs for supply chain security audits
4. **Version your SBOMs**: Use `projectVersion` to track SBOM versions
5. **Validate SBOMs**: Use built-in schema validation to verify SBOM format compliance

## Schema Validation

Validate generated SBOMs against their respective schemas:

```typescript
import { generateSbom, validateSbom } from 'pnpm-audit-hook';

const result = generateSbom(packages, findings, {
  format: 'cyclonedx',
});

const validation = validateSbom(result.content, 'cyclonedx');
if (!validation.valid) {
  console.error('SBOM validation failed:');
  validation.errors.forEach(err => {
    console.error(`  ${err.path}: ${err.message}`);
  });
}

if (validation.warnings.length > 0) {
  console.warn('SBOM validation warnings:');
  validation.warnings.forEach(warn => {
    console.warn(`  ${warn.path}: ${warn.message}`);
  });
}
```

### Validation Features

- **CycloneDX**: Validates against CycloneDX 1.5 schema
- **SPDX**: Validates against SPDX 2.3 schema
- **Error detection**: Catches missing required fields, invalid formats
- **Warning generation**: Alerts about optional but recommended fields
- **JSON string support**: Accepts both string and parsed objects

## Further Reading

- [CycloneDX Specification](https://cyclonedx.org/)
- [SPDX Specification](https://spdx.org/)
- [NIST SBOM Guidance](https://www.nist.gov/itl/ssd/software-quality-group/sbom)
