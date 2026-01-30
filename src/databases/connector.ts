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
  query(pkgs: PackageRef[], ctx: SourceContext): Promise<SourceResult>;
}
