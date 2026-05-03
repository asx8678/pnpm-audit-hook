/**
 * SBOM (Software Bill of Materials) type definitions.
 *
 * Defines the structures for CycloneDX and SPDX output formats,
 * as well as internal types used for SBOM generation.
 *
 * @module sbom/types
 */

import type { Severity, VulnerabilityFinding, PackageRef } from "../types";

/** Supported SBOM output formats */
export type SbomFormat = "cyclonedx" | "spdx";

/** Hash algorithm for integrity verification */
export type HashAlgorithm = "SHA-1" | "SHA-256" | "SHA-512" | "MD5";

/** Hash information for package integrity */
export interface PackageHash {
  /** Hash algorithm */
  algorithm: HashAlgorithm;
  /** Hash value (hex-encoded) */
  value: string;
}

/** SBOM generation options */
export interface SbomOptions {
  /** SBOM output format */
  format: SbomFormat;
  /** Output file path (undefined = stdout) */
  outputPath?: string;
  /** Include vulnerability information in SBOM */
  includeVulnerabilities?: boolean;
  /** Include dependency relationships in SBOM */
  includeDependencies?: boolean;
  /** Project name for SBOM metadata */
  projectName?: string;
  /** Project version for SBOM metadata */
  projectVersion?: string;
  /** Project description for SBOM metadata */
  projectDescription?: string;
}

/** Internal component representation before format conversion */
export interface SbomComponent {
  /** Package name (purl-compatible) */
  name: string;
  /** Package version */
  version: string;
  /** Package manager type (always "npm" for pnpm ecosystem) */
  purl: string;
  /** License identifier (SPDX format) or object (CycloneDX) */
  license?: string;
  /** Package description from registry (if available) */
  description?: string;
  /** Package homepage URL */
  homepage?: string;
  /** Package repository URL */
  repository?: string;
  /** Package integrity hashes */
  hashes?: PackageHash[];
  /** Package dependencies (other package names this depends on) */
  dependencies?: string[];
  /** Vulnerability findings for this component */
  vulnerabilities?: VulnerabilityFinding[];
}

/** CycloneDX BOM metadata */
export interface CycloneDXMetadata {
  timestamp: string;
  tools: Array<{
    vendor: string;
    name: string;
    version: string;
  }>;
  component?: CycloneDXComponent;
}

/** CycloneDX component */
export interface CycloneDXComponent {
  type: string;
  "bom-ref": string;
  name: string;
  version: string;
  purl: string;
  description?: string;
  licenses?: Array<{
    license: {
      id?: string;
      name?: string;
      url?: string;
    };
  }>;
  externalReferences?: Array<{
    type: string;
    url: string;
  }>;
  hashes?: Array<{
    alg: string;
    content: string;
  }>;
  properties?: Array<{
    name: string;
    value: string;
  }>;
}

/** CycloneDX vulnerability */
export interface CycloneDXVulnerability {
  id: string;
  source?: {
    name: string;
    url?: string;
  };
  ratings: Array<{
    source?: { name: string; url?: string };
    score?: number;
    severity?: string;
    vector?: string;
  }>;
  description?: string;
  published?: string;
  updated?: string;
  affects: Array<{
    ref: string;
  }>;
  problemTypes?: Array<{
    descriptions: Array<{
      lang: string;
      value: string;
    }>;
  }>;
  references?: Array<{
    source?: { name: string };
    url: string;
  }>;
}

/** CycloneDX BOM document */
export interface CycloneDXBom {
  bomFormat: "CycloneDX";
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: CycloneDXMetadata;
  components: CycloneDXComponent[];
  dependencies?: CycloneDXDependency[];
  vulnerabilities?: CycloneDXVulnerability[];
}

/** CycloneDX dependency relationship */
export interface CycloneDXDependency {
  ref: string;
  dependsOn?: string[];
}

/** SPDX document creation info */
export interface SPDXCreationInfo {
  created: string;
  creators: string[];
  documentNamespace: string;
}

/** SPDX package */
export interface SPDXPackage {
  SPDXID: string;
  name: string;
  versionInfo: string;
  downloadLocation: string;
  filesAnalyzed: false;
  licenseConcluded: string;
  licenseDeclared: string;
  copyrightText: string;
  externalRefs?: Array<{
    referenceCategory: string;
    referenceType: string;
    referenceLocator: string;
  }>;
  checksums?: Array<{
    algorithm: string;
    checksumValue: string;
  }>;
  comment?: string;
}

/** SPDX relationship */
export interface SPDXRelationship {
  SPDXElementID: string;
  RelationshipType: string;
  RelatedSPDXElement: string;
}

/** SPDX annotation */
export interface SPDXAnnotation {
  SPDXDataCreated: string;
  SPDXID: string;
  Annotator: string;
  AnnotationType: "REVIEW" | "OTHER";
  Comment: string;
}

/** SPDX document */
export interface SPDXDocument {
  spdxVersion: string;
  dataLicense: string;
  SPDXID: string;
  name: string;
  documentNamespace: string;
  creationInfo: SPDXCreationInfo;
  documentDescribes: string[];
  packages: SPDXPackage[];
  relationships: SPDXRelationship[];
  annotations?: SPDXAnnotation[];
}

/** SBOM generation result */
export interface SbomResult {
  /** Generated SBOM content (JSON string) */
  content: string;
  /** SBOM format used */
  format: SbomFormat;
  /** Total components in SBOM */
  componentCount: number;
  /** Total vulnerabilities included */
  vulnerabilityCount: number;
  /** Output path (if file output) */
  outputPath?: string;
  /** Generation duration in milliseconds */
  durationMs: number;
}

/** Component vulnerability map for quick lookup */
export type ComponentVulnerabilityMap = Map<string, VulnerabilityFinding[]>;

/** Validation error */
export interface ValidationError {
  /** Path to the error location */
  path: string;
  /** Error message */
  message: string;
  /** Error severity */
  severity: 'error' | 'warning';
}

/** Validation result */
export interface ValidationResult {
  /** Whether the SBOM is valid */
  valid: boolean;
  /** List of validation errors */
  errors: ValidationError[];
  /** List of validation warnings */
  warnings: ValidationError[];
  /** SBOM format validated */
  format: SbomFormat;
}
