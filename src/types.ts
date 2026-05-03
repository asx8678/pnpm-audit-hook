/**
 * @module types
 * TypeScript type definitions for pnpm-audit-hook.
 *
 * This module contains all interfaces and types used throughout the package,
 * including lockfile structures, vulnerability findings, policy decisions,
 * and configuration options.
 *
 * @example
 * ```typescript
 * import type {
 *   AuditResult,
 *   VulnerabilityFinding,
 *   PolicyDecision,
 *   Severity,
 * } from 'pnpm-audit-hook';
 * ```
 */

/**
 * Vulnerability severity level.
 *
 * - `critical`: Exploitable with severe impact
 * - `high`: Exploitable with significant impact
 * - `medium`: Moderate impact or limited exploitability
 * - `low`: Minimal impact
 * - `unknown`: Severity could not be determined
 */
export type Severity = "critical" | "high" | "medium" | "low" | "unknown";

/** Source of vulnerability information */
export type FindingSource = "github" | "nvd" | "osv";

/** Action taken for a vulnerability finding */
export type PolicyAction = "allow" | "warn" | "block";

/** Source of the policy decision */
export type DecisionSource = "severity" | "source" | "allowlist";

/** Type of vulnerability identifier */
export type VulnerabilityIdType = "CVE" | "GHSA" | "OSV" | "OTHER";

/** Resolution info for a lockfile package entry */
export interface LockfileResolution {
  type?: string;
  directory?: string;
  path?: string;
  tarball?: string;
  integrity?: string;
}

/** A package entry in pnpm lockfile packages section */
export interface LockfilePackageEntry {
  resolution?: LockfileResolution;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

/** Version value from pnpm lockfile: can be a plain string or an object with specifier/version (v9 format) */
export type LockfileDepVersion = string | { specifier?: string; version: string };

/** An importer entry (workspace root or workspace package) */
export interface LockfileImporter {
  dependencies?: Record<string, LockfileDepVersion>;
  devDependencies?: Record<string, LockfileDepVersion>;
  optionalDependencies?: Record<string, LockfileDepVersion>;
  specifiers?: Record<string, string>;
}

/** Pnpm lockfile structure passed to hooks */
export interface PnpmLockfile {
  lockfileVersion?: string | number;
  packages?: Record<string, LockfilePackageEntry>;
  importers?: Record<string, LockfileImporter>;
}

/** Context provided by pnpm to hook functions */
export interface PnpmHookContext {
  lockfileDir?: string;
  storeDir?: string;
  registries?: Record<string, string>;
}

interface AllowlistEntryBase {
  version?: string; // Semver range to match (e.g., "<1.0.0", ">=2.0.0 <3.0.0")
  reason?: string; // Why it's allowed
  expires?: string; // ISO date string, optional expiration
  /** When true, this allowlist entry only applies to direct dependencies */
  directOnly?: boolean;
}

interface AllowlistEntryById extends AllowlistEntryBase {
  id: string; // CVE-XXXX-XXXX, GHSA-XXXX, etc.
  package?: string; // Package name to ignore
}

interface AllowlistEntryByPackage extends AllowlistEntryBase {
  id?: string; // CVE-XXXX-XXXX, GHSA-XXXX, etc.
  package: string; // Package name to ignore
}

export type AllowlistEntry = AllowlistEntryById | AllowlistEntryByPackage;

export interface PackageRef {
  name: string;
  version: string;
  /** Registry URL this package was fetched from (e.g., "https://registry.npmjs.org") */
  registry?: string;
  /** Package integrity hash (e.g., "sha512-...") */
  integrity?: string;
  /** Package dependencies (other package names this depends on) */
  dependencies?: string[];
}

/** A node in the dependency graph */
export interface DependencyNode {
  name: string;
  version: string;
  /** Whether this is a direct dependency (listed in importers) */
  isDirect: boolean;
  /** Whether this is a dev-only dependency */
  isDev: boolean;
  /** Packages this node depends on (forward edges, as "name@version" keys) */
  dependencies: string[];
}

/** Full dependency graph built from lockfile */
export interface DependencyGraph {
  /** Map from "name@version" key to node */
  nodes: Map<string, DependencyNode>;
  /** Map from package name to all "name@version" keys (a package can have multiple versions) */
  byName: Map<string, string[]>;
  /** Reverse edges: map from "name@version" to set of "name@version" keys that depend on it */
  dependents: Map<string, Set<string>>;
  /** Set of "name@version" keys that are direct dependencies */
  directKeys: Set<string>;
}

/** Impact analysis for a vulnerable package */
export interface ImpactAnalysis {
  /** Package key being analyzed */
  targetKey: string;
  /** Number of direct dependents (packages that directly depend on this) */
  directDependents: number;
  /** Total number of dependents (including transitive) */
  totalDependents: number;
  /** Maximum depth of dependency chain from this package */
  depth: number;
  /** Maximum breadth (number of dependents at any level) */
  breadth: number;
  /** Calculated risk score (0-10) based on impact factors */
  riskScore: number;
}

/** Comprehensive dependency chain analysis */
export interface DependencyChainAnalysis {
  /** Package key being analyzed */
  targetKey: string;
  /** Shortest chain from direct dependency to this package */
  shortestChain: string[] | null;
  /** All chains from direct dependencies to this package */
  allChains: string[][];
  /** Impact analysis results */
  impact: ImpactAnalysis;
  /** Complete dependency tree (all transitive dependencies) */
  dependencyTree: string[];
  /** Whether this is a direct dependency */
  isDirect: boolean;
}

/** Risk assessment with CVSS integration */
export interface RiskAssessment {
  /** Base CVSS score */
  cvssScore: number;
  /** Environmental risk score (adjusted for context) */
  environmentalScore: number;
  /** Temporal score (adjusted for exploitability and fix availability) */
  temporalScore: number;
  /** Final composite risk score */
  compositeScore: number;
  /** Risk level based on composite score */
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'none';
  /** Factors contributing to the risk score */
  factors: RiskFactor[];
}

/** Individual risk factor */
export interface RiskFactor {
  /** Name of the factor */
  name: string;
  /** Description of the factor */
  description: string;
  /** Weight of this factor (0-1) */
  weight: number;
  /** Score contribution (0-10) */
  score: number;
}

export interface VulnerabilityIdentifier {
  type: VulnerabilityIdType;
  value: string;
}

export interface VulnerabilityFinding {
  id: string;
  source: FindingSource;
  packageName: string;
  packageVersion: string;
  title?: string;
  url?: string;
  description?: string;
  severity: Severity;
  cvssScore?: number;
  cvssVector?: string;
  publishedAt?: string;
  modifiedAt?: string;
  identifiers?: VulnerabilityIdentifier[];
  affectedRange?: string;
  fixedVersion?: string;
  /** Dependency chain from direct dependency to this vulnerable package */
  dependencyChain?: string[];
  /** Enriched context from dependency chain analysis */
  chainContext?: VulnerabilityChainContext;
  /** CVSS parsed details when vector is available */
  cvssDetails?: CvssFindingDetails;
  /** EPSS (Exploit Prediction Scoring System) data for this vulnerability */
  epss?: EpssData;
}

/** Enriched context attached to a vulnerability finding after chain analysis */
export interface VulnerabilityChainContext {
  /** Whether this is a direct or transitive dependency */
  isDirect: boolean;
  /** Chain depth from the nearest direct dependency (0 = direct) */
  chainDepth: number;
  /** Number of distinct paths from direct deps to this package */
  numberOfPaths: number;
  /** Total number of packages transitively affected by this vulnerability */
  totalAffected: number;
  /** Propagated severity after chain-aware adjustment */
  propagatedSeverity: Severity;
  /** Whether a fix is available for this vulnerability */
  fixAvailable: boolean;
  /** Whether the vulnerable package is a dev-only dependency */
  isDevOnly: boolean;
  /** List of direct dependencies that chain to this package ("name@version" keys) */
  directAncestors: string[];
  /** Risk factors contributing to the assessment */
  riskFactors: RiskFactor[];
  /** Composite risk score (0-10) incorporating CVSS + chain factors */
  compositeRiskScore: number;
}

/** CVSS details parsed from the finding's vector for rich context display */
export interface CvssFindingDetails {
  score: number;
  severity: Severity;
  attackVector: string;
  attackComplexity: string;
  privilegesRequired: string;
  userInteraction: string;
  scope: string;
  confidentiality: string;
  integrity: string;
  availability: string;
  /** Human-readable exploitability summary */
  exploitabilityLabel: string;
}

/**
 * EPSS (Exploit Prediction Scoring System) data for a vulnerability.
 *
 * EPSS provides a probability score (0.0 - 1.0) representing the likelihood
 * that a vulnerability will be exploited in the wild within the next 30 days.
 * The percentile indicates how the score compares to all other CVEs.
 *
 * @see {@link https://www.first.org/epss/} - FIRST.org EPSS documentation
 * @see {@link https://api.first.org/data/v1/epss} - EPSS API endpoint
 */
export interface EpssData {
  /** CVE identifier (e.g., "CVE-2023-26159") */
  cveId: string;
  /** EPSS probability score (0.0 - 1.0) */
  epssScore: number;
  /** EPSS percentile ranking (0.0 - 1.0) */
  epssPercentile: number;
  /** Date the EPSS data was generated (ISO date string) */
  date: string;
  /** Model version used to generate the score */
  modelVersion: string;
}

export interface PolicyDecision {
  action: PolicyAction;
  reason: string;
  source: DecisionSource;
  at: string;
  findingId?: string;
  findingSeverity?: Severity;
  packageName?: string;
  packageVersion?: string;
}

export interface PackageAuditResult {
  pkg: PackageRef;
  findings: VulnerabilityFinding[];
}

export interface SourceStatus {
  ok: boolean;
  error?: string;
  durationMs: number;
}

/** User-provided config (all fields optional, merged with defaults) */
/** SBOM configuration options */
export type SbomFormat = "cyclonedx" | "cyclonedx-xml" | "spdx" | "swid";

export interface SbomConfig {
  /** Enable/disable SBOM generation (default: false) */
  enabled?: boolean;
  /** SBOM output format: cyclonedx, cyclonedx-xml, spdx, or swid (default: cyclonedx) */
  format?: SbomFormat;
  /** Output file path (undefined = stdout) */
  outputPath?: string;
  /** Include vulnerability information in SBOM (default: true) */
  includeVulnerabilities?: boolean;
  /** Project name for SBOM metadata */
  projectName?: string;
  /** Project version for SBOM metadata */
  projectVersion?: string;
  /** SWID-specific options (only used when format is "swid") */
  swidOptions?: {
    regid?: string;
    softwareIdentificationScheme?: string;
    tagVersion?: string;
    structure?: "single" | "multivolume";
    addOn?: boolean;
    softwareCreator?: { name: string; regid?: string };
    softwareLicensor?: { name: string; regid?: string };
  };
}

export interface AuditConfigInput {
  policy?: {
    block?: Severity[];
    warn?: Severity[];
    allowlist?: AllowlistEntry[];
    /** When set, transitive dependency findings have severity downgraded for policy evaluation */
    transitiveSeverityOverride?: 'downgrade-by-one';
  };
  sources?: {
    github?: boolean | { enabled?: boolean };
    nvd?: boolean | { enabled?: boolean };
    osv?: boolean | { enabled?: boolean };
    epss?: boolean | { enabled?: boolean };
  };
  performance?: {
    timeoutMs?: number;
  };
  cache?: {
    ttlSeconds?: number;
  };
  /** Block installation when all sources are disabled (default: true for security) */
  failOnNoSources?: boolean;
  /** Block installation when a source fails (default: true for security) */
  failOnSourceError?: boolean;
  /** Skip all API calls, use only static DB + cache (default: false) */
  offline?: boolean;
  /** Static baseline configuration for historical vulnerabilities */
  staticBaseline?: StaticBaselineConfigInput;
  /** SBOM generation configuration */
  sbom?: SbomConfig;
}

/** Fully-resolved config returned by loadConfig() */
export interface AuditConfig {
  policy: {
    block: Severity[];
    warn: Severity[];
    allowlist: AllowlistEntry[];
    /** When set, transitive dependency findings have severity downgraded for policy evaluation */
    transitiveSeverityOverride?: 'downgrade-by-one';
  };
  sources: {
    github: { enabled: boolean };
    nvd: { enabled: boolean };
    osv: { enabled: boolean };
    epss: { enabled: boolean };
  };
  performance: {
    timeoutMs: number;
  };
  cache: {
    ttlSeconds: number;
  };
  /** Block installation when all sources are disabled (default: true for security) */
  failOnNoSources: boolean;
  /** Block installation when a source fails (default: true for security) */
  failOnSourceError: boolean;
  /** Skip all API calls, use only static DB + cache (default: false) */
  offline: boolean;
  /** Static baseline configuration for historical vulnerabilities */
  staticBaseline: StaticBaselineConfig;
  /** SBOM generation configuration */
  sbom?: SbomConfig;
}

export interface RuntimeOptions {
  cwd: string;
  registryUrl: string;
  env: Record<string, string | undefined>;
}

/** Configuration for static vulnerability baseline */
export interface StaticBaselineConfig {
  /** Enable/disable static baseline (default: true) */
  enabled: boolean;
  /** Vulnerabilities before this date use static DB (ISO date string) */
  cutoffDate: string;
  /** Optional custom path to static data directory */
  dataPath?: string;
}

/** User-provided static baseline config (all fields optional) */
export interface StaticBaselineConfigInput {
  enabled?: boolean;
  cutoffDate?: string;
  dataPath?: string;
}
