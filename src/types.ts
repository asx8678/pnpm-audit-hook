export type Severity = "critical" | "high" | "medium" | "low" | "unknown";
export type NetworkPolicy = "fail-open" | "fail-closed";
export type UnknownDataPolicy = "allow" | "warn" | "block";
export type FindingSource = "osv" | "github" | "npm" | "nvd" | "ossindex" | "integrity" | "policy";
export type PolicyAction = "allow" | "warn" | "block";
export type DecisionSource = "blocklist" | "allowlist" | "severity" | "integrity" | "network" | "unknown" | "policy";
export type VulnerabilityIdType = "CVE" | "GHSA" | "OSV" | "SONATYPE" | "OTHER";

export interface PackageRef {
  name: string;
  version: string;
  integrity?: string;
  tarball?: string;
  direct?: boolean;
  importers?: string[];
  registry?: string;
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
  references?: string[];
  affectedRange?: string;
  fixedVersion?: string;
  raw?: Record<string, unknown>;
}

export interface AllowlistApproval {
  approvedBy: string;
  reason: string;
  expires: string;
}

export interface PolicyDecision {
  action: PolicyAction;
  reason: string;
  source: DecisionSource;
  at: string;
  findingId?: string;
  packageName?: string;
  packageVersion?: string;
  allowlist?: AllowlistApproval;
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

export interface AuditSummary {
  totalPackages: number;
  directPackages: number;
  vulnerablePackages: number;
  countsBySeverity: Record<Severity, number>;
  blockedFindings: number;
  warnedFindings: number;
  blocked: boolean;
  warnings: boolean;
  startedAt: string;
  finishedAt: string;
  sources: Record<string, SourceStatus>;
}

export interface AuditReport {
  summary: AuditSummary;
  packages: PackageAuditResult[];
  decisions: PolicyDecision[];
}

export interface AllowlistEntry {
  cve?: string;
  id?: string;
  package: string;
  expires: string;
  reason: string;
  approvedBy: string;
}

interface SourceToggle {
  enabled: boolean;
}

export interface AuditConfig {
  version: number;
  policies: {
    block: Severity[];
    warn: Severity[];
    gracePeriod: number;
    unknownVulnData: UnknownDataPolicy;
    networkPolicy: NetworkPolicy;
    allowlist: AllowlistEntry[];
    blocklist: string[];
  };
  sources?: {
    osv?: SourceToggle;
    github?: SourceToggle;
    npm?: SourceToggle;
    nvd?: SourceToggle;
    ossIndex?: SourceToggle;
  };
  integrity?: { requireSha512Integrity?: boolean };
  performance?: { concurrency?: number; timeoutMs?: number; earlyExitOnBlock?: boolean };
  cache?: { ttlSeconds?: number; dir?: string; allowStale?: boolean };
  reporting?: { formats?: string[]; outputDir?: string; basename?: string };
  azureDevOps?: { prComment?: SourceToggle; logAnalytics?: SourceToggle };
  notifications?: { email?: { enabled: boolean; to: string[] } };
}

export interface RuntimeOptions {
  cwd: string;
  registryUrl: string;
  env: Record<string, string | undefined>;
}

// Type aliases for backward compatibility
export type Finding = VulnerabilityFinding;
export type PackageResult = PackageAuditResult;
