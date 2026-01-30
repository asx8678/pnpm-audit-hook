import type { Severity } from "../types.js";

/**
 * Map a string severity value to the canonical Severity type.
 * Handles variations like 'moderate' -> 'medium'.
 */
export function mapSeverity(sev: string | undefined): Severity {
  switch ((sev ?? "").toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
    case "moderate":
      return "medium";
    case "low":
      return "low";
    default:
      return "unknown";
  }
}

/**
 * Severity ranking for comparison and sorting.
 * Higher number = more severe.
 */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  unknown: 0,
};

/**
 * Get numeric rank for a severity level.
 */
export function severityRank(s: Severity): number {
  return SEVERITY_RANK[s] ?? 0;
}

/**
 * Compare two severities. Returns negative if a < b, positive if a > b, 0 if equal.
 */
export function compareSeverity(a: Severity, b: Severity): number {
  return severityRank(a) - severityRank(b);
}
