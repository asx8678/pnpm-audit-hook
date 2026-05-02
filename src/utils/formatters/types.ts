import type {
  PolicyDecision,
  Severity,
  SourceStatus,
  VulnerabilityFinding,
} from "../../types";

export interface AuditSummary {
  totalPackages: number;
  safePackages: number;
  packagesWithVulnerabilities: number;
  vulnerabilitiesBySeverity: Record<Severity, number>;
  blockedCount: number;
  warnCount: number;
  allowedCount: number;
  allowlistedCount: number;
  sourceStatus: Record<string, SourceStatus>;
  totalDurationMs: number;
}

export interface AuditOutputData {
  summary: AuditSummary;
  findings: VulnerabilityFinding[];
  decisions: PolicyDecision[];
  blocked: boolean;
  warnings: boolean;
  exitCode: number;
}

export type OutputFormat = "human" | "azure" | "github" | "aws" | "json";
