export type Severity = "critical" | "high" | "medium" | "low" | "unknown";
export type FindingSource = "github" | "nvd" | "osv";
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
