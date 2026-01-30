import type { Severity, VulnerabilityFinding } from "../types";
import { severityRank } from "../utils/severity";

/**
 * Choose an effective TTL based on the most severe finding.
 *
 * Rationale: critical/high vulns can change quickly during incident response; keep cache fresher.
 * This is a best-effort heuristic and can be overridden by setting a smaller base TTL in config.
 */
export function ttlForFindings(
  baseTtlSeconds: number,
  findings: VulnerabilityFinding[],
): number {
  let max: Severity = "unknown";
  for (const f of findings) {
    if (severityRank(f.severity) > severityRank(max)) max = f.severity;
  }

  const cap = (s: number) => Math.max(60, Math.min(baseTtlSeconds, s));

  if (max === "critical") return cap(15 * 60); // 15 minutes
  if (max === "high") return cap(30 * 60); // 30 minutes
  if (max === "medium") return cap(60 * 60); // 1 hour
  return baseTtlSeconds;
}
