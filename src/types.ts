export type Severity = "critical" | "high" | "medium" | "low" | "unknown";
export type FindingSource = "github" | "nvd";
export type PolicyAction = "allow" | "warn" | "block";
export type DecisionSource = "severity" | "source" | "allowlist";
export type VulnerabilityIdType = "CVE" | "GHSA" | "OTHER";

export interface AllowlistEntry {
  id?: string; // CVE-XXXX-XXXX, GHSA-XXXX, etc.
  package?: string; // Package name to ignore
  version?: string; // Semver range to match (e.g., "<1.0.0", ">=2.0.0 <3.0.0")
  reason?: string; // Why it's allowed
  expires?: string; // ISO date string, optional expiration
}

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
}

export interface RuntimeOptions {
  cwd: string;
  registryUrl: string;
  env: Record<string, string | undefined>;
}
