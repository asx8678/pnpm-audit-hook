import type { PackageRef, VulnerabilityFinding, FindingSource } from "../types";
import type { Cache } from "../cache/memory-cache";
import type { Logger } from "../utils/logger";
import type { HttpClient } from "../utils/http";
import type { AuditConfig, NetworkPolicy } from "../types";

export interface SourceContext {
  cfg: AuditConfig;
  env: Record<string, string | undefined>;
  http: HttpClient;
  cache: Cache;
  logger: Logger;
  registryUrl: string;
  offline: boolean;
  networkPolicy: NetworkPolicy;
}

export interface SourceResult {
  source: FindingSource;
  ok: boolean;
  error?: string;
  durationMs: number;
  findings: VulnerabilityFinding[];
  unknownDataForPackages?: Set<string>; // package@version keys with unknown data (due to failure/offline)
}

export interface VulnerabilitySource {
  id: FindingSource;
  isEnabled(cfg: AuditConfig, env: Record<string, string | undefined>): boolean;
  query(pkgs: PackageRef[], ctx: SourceContext): Promise<SourceResult>;
}
