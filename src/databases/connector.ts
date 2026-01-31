import type { PackageRef, VulnerabilityFinding, FindingSource } from "../types";
import type { Cache } from "../cache/types";
import type { HttpClient } from "../utils/http";
import type { AuditConfig } from "../types";

export interface SourceContext {
  cfg: AuditConfig;
  env: Record<string, string | undefined>;
  http: HttpClient;
  cache: Cache;
  registryUrl: string;
}

/**
 * Options for filtering vulnerability queries.
 */
export interface VulnerabilitySourceOptions {
  /**
   * Only return vulnerabilities published after this date.
   * Format: ISO 8601 date string (YYYY-MM-DD), e.g., "2025-01-01"
   *
   * For GitHub Advisory API, this translates to: published=>YYYY-MM-DD
   */
  publishedAfter?: string;
}

export interface SourceResult {
  source: FindingSource;
  ok: boolean;
  error?: string;
  durationMs: number;
  findings: VulnerabilityFinding[];
}

export interface VulnerabilitySource {
  id: FindingSource;
  isEnabled(cfg: AuditConfig, env: Record<string, string | undefined>): boolean;
  query(pkgs: PackageRef[], ctx: SourceContext, options?: VulnerabilitySourceOptions): Promise<SourceResult>;
}
