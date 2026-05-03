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
export type SbomFormat = "cyclonedx" | "cyclonedx-xml" | "spdx" | "swid";

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
  /** Deprecated: use format: 'cyclonedx-xml' instead */
  xml?: boolean;
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
  /** SWID-specific options */
  swidOptions?: SwidOptions;
  /** Component cache options (undefined = no caching) */
  cacheOptions?: ComponentCacheOptions;
}

/**
 * Options for the SBOM component cache.
 */
export interface ComponentCacheOptions {
  /** Maximum cache entries (default: 1000) */
  maxEntries?: number;
  /** Cache file path for persistence */
  cacheFilePath?: string;
  /** Cache TTL in milliseconds (default: 24 hours = 86400000ms) */
  ttlMs?: number;
  /** Enable debug logging (default: false) */
  debug?: boolean;
}

/** SWID Tags generation options */
export interface SwidOptions {
  /** Registration ID (regid) - domain-based identifier for the tag creator */
  regid?: string;
  /** Software identification scheme (default: "swid") */
  softwareIdentificationScheme?: string;
  /** Tag version (default: 1.0) */
  tagVersion?: string;
  /** Product structure (default: "single") */
  structure?: "single" | "multivolume";
  /** Add-on flag (default: false) */
  addOn?: boolean;
  /** Software creator entity */
  softwareCreator?: {
    name: string;
    regid?: string;
  };
  /** Software licensor entity */
  softwareLicensor?: {
    name: string;
    regid?: string;
  };
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

/** CycloneDX vulnerability rating method */
export type CycloneDXRatingMethod =
  | "cvssv3"
  | "cvssv31"
  | "cvssv4"
  | "epss"
  | "other";

/** CycloneDX vulnerability rating */
export interface CycloneDXVulnerabilityRating {
  source?: { name: string; url?: string };
  score?: number;
  severity?: string;
  vector?: string;
  /** Rating method (e.g., "cvssv3", "epss") */
  method?: CycloneDXRatingMethod;
  /** For EPSS ratings: the percentile value */
  percentile?: number;
}

/** CycloneDX vulnerability */
export interface CycloneDXVulnerability {
  id: string;
  source?: {
    name: string;
    url?: string;
  };
  ratings: CycloneDXVulnerabilityRating[];
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
  /** Human-readable recommendation for fixing the vulnerability */
  recommendation?: string;
  /** Whether a fix is available for this vulnerability */
  fixAvailable?: boolean;
  /** List of versions that fix the vulnerability */
  fixVersions?: string[];
  /** Upgrade path information when available */
  upgradePath?: string;
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

/** SWID Tag entity */
export interface SwidEntity {
  name: string;
  regid?: string;
  role: "software" | "tagCreator" | "softwareCreator" | "softwareLicensor";
}

/** SWID Tag link */
export interface SwidLink {
  href: string;
  rel: "component" | "requires" | "supersedes" | "history" | "installation" | "package" | "parent" | "patch" | "supplement" | "supplementalMedia" | "predecessor" | "seeAlso";
}

/** SWID Tag */
export interface SwidTag {
  tagId: string;
  regid: string;
  name: string;
  tagVersion: string;
  softwareIdentificationScheme: string;
  csi?: string;
  summary?: string;
  addOn?: boolean;
  structure?: string;
  entities: SwidEntity[];
  meta?: {
    product: string;
    vendor?: string;
    version?: string;
    versionScheme?: string;
    date?: string;
  };
  links?: SwidLink[];
}

/** SWID Tag Set containing multiple tags */
export interface SwidTagSet {
  tags: SwidTag[];
}

/** SBOM generation result */
export interface SbomResult {
  /** Generated SBOM content (JSON string for CycloneDX/SPDX, XML string for SWID) */
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

// ===========================================================================
// SBOM Diff Types
// ===========================================================================

/** Entry in an SBOM diff (added, removed, updated, or unchanged) */
export interface SbomDiffEntry {
  /** Package name */
  name: string;
  /** Current version (from new SBOM) */
  version: string;
  /** Previous version (only for updated entries) */
  previousVersion?: string;
  /** Package URL */
  purl?: string;
  /** Package group/namespace (e.g., @scope) */
  group?: string;
}

/** Summary counts of the diff */
export interface SbomDiffSummary {
  totalAdded: number;
  totalRemoved: number;
  totalUpdated: number;
  totalUnchanged: number;
}

/** Metadata about the comparison */
export interface SbomDiffMetadata {
  oldFormat: string;
  newFormat: string;
  comparedAt: string;
}

/** Complete diff result comparing two SBOM documents */
export interface SbomDiffResult {
  added: SbomDiffEntry[];
  removed: SbomDiffEntry[];
  updated: SbomDiffEntry[];
  unchanged: SbomDiffEntry[];
  summary: SbomDiffSummary;
  metadata: SbomDiffMetadata;
}

/** Normalized package representation for format-agnostic comparison */
export interface NormalizedPackage {
  name: string;
  version: string;
  purl?: string;
  group?: string;
}

/** Options for SBOM diffing */
export interface SbomDiffOptions {
  /** Custom key function for package identity (default: purl or name) */
  keyFn?: (pkg: NormalizedPackage) => string;
  /** Ignore version differences (only report added/removed) */
  ignoreVersions?: boolean;
}

// ===========================================================================
// SBOM Dependency Tree Types
// ===========================================================================

/** Options for dependency tree visualization */
export interface TreeOptions {
  /** Maximum depth to traverse (default: Infinity) */
  maxDepth?: number;
  /** Show package versions in output (default: true) */
  showVersions?: boolean;
  /** Show vulnerability markers in ASCII output (default: true) */
  showVulnerabilities?: boolean;
  /** Highlight vulnerable packages (default: true) */
  highlightVulnerable?: boolean;
  /** Output format (default: 'ascii') */
  format?: "ascii" | "json";
}

/** Vulnerability info attached to a tree node */
export interface TreeVulnerability {
  /** Vulnerability identifier (e.g., CVE-2023-26159) */
  id: string;
  /** Severity level (e.g., low, medium, high, critical) */
  severity: string;
}

/** A node in the dependency tree */
export interface TreeNode {
  /** Package name */
  name: string;
  /** Package version */
  version: string;
  /** Package group/scope (e.g., @scope) */
  group?: string;
  /** Package URL identifier */
  purl?: string;
  /** Child dependency nodes */
  children: TreeNode[];
  /** Known vulnerabilities */
  vulnerabilities?: TreeVulnerability[];
  /** Depth in the tree (root = 0) */
  depth: number;
}

/** JSON tree output format */
export interface TreeJsonOutput {
  /** Package name */
  name: string;
  /** Package version (if showVersions is true) */
  version?: string;
  /** Package group */
  group?: string;
  /** Package URL */
  purl?: string;
  /** Known vulnerabilities */
  vulnerabilities?: TreeVulnerability[];
  /** Child nodes */
  children?: TreeJsonOutput[];
}

// ===========================================================================
// SBOM Mermaid Diagram Types
// ===========================================================================

/** Options for Mermaid dependency graph generation */
export interface MermaidOptions {
  /** Graph direction (default: 'TB' = top-bottom) */
  direction?: 'TB' | 'BT' | 'LR' | 'RL';
  /** Show package versions in node labels (default: true) */
  showVersions?: boolean;
  /** Highlight vulnerable nodes with color coding (default: true) */
  highlightVulnerable?: boolean;
  /** Optional diagram title */
  title?: string;
  /** Maximum tree depth to render (default: Infinity) */
  maxDepth?: number;
}

/** Severity → color mapping for Mermaid style directives */
export interface MermaidVulnerabilityStyle {
  /** CSS color for the node fill */
  fill: string;
  /** CSS color for the text */
  color: string;
}

// ===========================================================================
// SBOM Graphviz DOT Diagram Types
// ===========================================================================

/** Options for Graphviz DOT dependency graph generation */
export interface DotOptions {
  /** Graph direction/layout (default: 'TB' = top-bottom) */
  rankdir?: 'TB' | 'BT' | 'LR' | 'RL';
  /** Show package versions in node labels (default: true) */
  showVersions?: boolean;
  /** Highlight vulnerable nodes with color coding (default: true) */
  highlightVulnerable?: boolean;
  /** Optional diagram title */
  title?: string;
  /** Maximum tree depth to render (default: Infinity) */
  maxDepth?: number;
}

// ===========================================================================
// Monorepo SBOM Types
// ===========================================================================

/**
 * Options for monorepo SBOM generation.
 *
 * Extends the base {@link SbomOptions} with concurrency and workspace
 * control knobs.
 */
export interface MonorepoSbomOptions extends SbomOptions {
  /**
   * Maximum number of workspace SBOMs to generate concurrently.
   * @default 4
   */
  concurrency: number;

  /**
   * When `true`, the aggregated root SBOM will include packages from
   * all workspaces (deduplicated by name+version).
   * @default true
   */
  includeWorkspacesInRoot: boolean;

  /**
   * When `true`, individual SBOM files are generated for each workspace.
   * @default true
   */
  generateWorkspaceSboms: boolean;

  /**
   * Optional callback invoked after each workspace is processed.
   * Useful for progress reporting in large monorepos.
   */
  onWorkspaceComplete?: (completed: number, total: number, workspacePath: string) => void;
}

/**
 * Result of SBOM generation for a single workspace.
 */
export interface WorkspaceSbomResult {
  /** Workspace path as it appears in the lockfile (e.g. `"./packages/pkg1"`) */
  workspacePath: string;
  /** Workspace name derived from its `package.json` name field, or the path itself */
  workspaceName: string;
  /** The generated SBOM result */
  result: SbomResult;
  /** Packages found in this workspace */
  packageCount: number;
}

/**
 * Error information for a failed workspace SBOM generation.
 */
export interface WorkspaceSbomError {
  /** Workspace path that failed */
  workspacePath: string;
  /** The error that occurred */
  error: Error;
}

/**
 * Complete result of monorepo SBOM generation.
 */
export interface MonorepoSbomResult {
  /** Root SBOM (aggregating all workspaces or just root workspace) */
  root: SbomResult;
  /** Individual workspace SBOM results (empty if `generateWorkspaceSboms` is false) */
  workspaces: WorkspaceSbomResult[];
  /** Workspace errors that occurred during generation (non-fatal) */
  errors: WorkspaceSbomError[];
  /** Aggregated SBOM combining all workspace results (same as root unless overridden) */
  aggregated: SbomResult;
  /** Summary statistics */
  stats: {
    /** Total number of workspaces detected */
    totalWorkspaces: number;
    /** Number of workspaces that were successfully processed */
    processedWorkspaces: number;
    /** Total unique components across all workspaces */
    totalComponents: number;
    /** Total vulnerabilities found across all workspaces */
    totalVulnerabilities: number;
    /** Total generation time in milliseconds */
    generationTimeMs: number;
    /** Per-workspace breakdown of component counts */
    workspaceComponentCounts: Record<string, number>;
  };
}
