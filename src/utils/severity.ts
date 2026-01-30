import type { Severity } from "../types.js";

const SEV_MAP: Record<string, Severity> = {
  critical: "critical", high: "high", medium: "medium", moderate: "medium", low: "low",
};

/** Map a string severity to canonical Severity type (handles 'moderate' -> 'medium'). */
export const mapSeverity = (sev: string | undefined): Severity =>
  SEV_MAP[(sev ?? "").toLowerCase()] ?? "unknown";

/** Severity ranking for comparison (higher = more severe). */
export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };

export const severityRank = (s: Severity) => SEVERITY_RANK[s] ?? 0;
