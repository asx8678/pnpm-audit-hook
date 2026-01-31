export type Severity = "critical" | "high" | "medium" | "low" | "unknown";
export type FindingSource = "github" | "nvd";
export type PolicyAction = "allow" | "warn" | "block";
export type DecisionSource = "severity" | "source" | "allowlist";
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

/** An importer entry (workspace root or workspace package) */
export interface LockfileImporter {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
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
  direct?: boolean;
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
  publishedAt?: string;
  modifiedAt?: string;
  identifiers?: VulnerabilityIdentifier[];
  affectedRange?: string;
  fixedVersion?: string;
}

export interface PolicyDecision {
  action: PolicyAction;
  reason: string;
  source: DecisionSource;
  at: string;
  findingId?: string;
  packageName?: string;
  packageVersion?: string;
}

export interface PackageAuditResult {
  pkg: PackageRef;
  findings: VulnerabilityFinding[];
  decisions: PolicyDecision[];
}

export interface SourceStatus {
  ok: boolean;
  error?: string;
  durationMs?: number;
}

/** User-provided config (all fields optional, merged with defaults) */
export interface AuditConfigInput {
  policy?: {
    block?: Severity[];
    warn?: Severity[];
    allowlist?: AllowlistEntry[];
  };
  sources?: {
    github?: boolean | { enabled?: boolean };
    nvd?: boolean | { enabled?: boolean };
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
  /** Static baseline configuration for historical vulnerabilities */
  staticBaseline?: StaticBaselineConfigInput;
}

/** Fully-resolved config returned by loadConfig() */
export interface AuditConfig {
  policy: {
    block: Severity[];
    warn: Severity[];
    allowlist: AllowlistEntry[];
  };
  sources: {
    github: { enabled: boolean };
    nvd: { enabled: boolean };
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
  /** Static baseline configuration for historical vulnerabilities */
  staticBaseline: StaticBaselineConfig;
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
