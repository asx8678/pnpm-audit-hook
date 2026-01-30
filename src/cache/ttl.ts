import type { Severity, VulnerabilityFinding } from "../types";
import { severityRank } from "../utils/severity";

/**
 * Choose an effective TTL based on the most severe finding.
 *
 * Rationale: critical/high vulns can change quickly during incident response; keep cache fresher.
 * This is a best-effort heuristic and can be overridden by setting a smaller base TTL in config.
 */
const SEVERITY_TTL: Partial<Record<Severity, number>> = {
  critical: 15 * 60,
  high: 30 * 60,
  medium: 60 * 60,
};

export function ttlForFindings(
  baseTtlSeconds: number,
  findings: VulnerabilityFinding[],
): number {
  const maxSeverity = findings.reduce<Severity>(
    (max, f) => (severityRank(f.severity) > severityRank(max) ? f.severity : max),
    "unknown",
  );
  const ttl = SEVERITY_TTL[maxSeverity];
  return ttl ? Math.max(60, Math.min(baseTtlSeconds, ttl)) : baseTtlSeconds;
}
