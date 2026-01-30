export type Severity = "critical" | "high" | "medium" | "low" | "unknown";
export type FindingSource = "osv" | "npm" | "github" | "nvd" | "depsdev";
export type PolicyAction = "allow" | "warn" | "block";
export type DecisionSource = "severity" | "source";
export type VulnerabilityIdType = "CVE" | "GHSA" | "OSV" | "OTHER";

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

export interface AuditConfig {
  policy: {
    block: Severity[];
    warn: Severity[];
  };
  sources?: {
    osv?: { enabled?: boolean };
    npm?: { enabled?: boolean };
    github?: { enabled?: boolean };
    nvd?: { enabled?: boolean };
    depsdev?: { enabled?: boolean };
  };
  performance?: {
    timeoutMs?: number;
  };
  cache?: {
    ttlSeconds?: number;
  };
}

export interface RuntimeOptions {
  cwd: string;
  registryUrl: string;
  env: Record<string, string | undefined>;
}
