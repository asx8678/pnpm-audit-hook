import type { Severity } from "../types";

// ─────────────────────────────────────────────────────
// §1  CVSS v3.x Vector Parsing
// ─────────────────────────────────────────────────────

/** Parsed CVSS 3.x metrics */
interface CvssMetrics {
  AV: "N" | "A" | "L" | "P";  // Attack Vector
  AC: "L" | "H";              // Attack Complexity
  PR: "N" | "L" | "H";        // Privileges Required
  UI: "N" | "R";              // User Interaction
  S: "U" | "C";               // Scope
  C: "H" | "L" | "N";        // Confidentiality
  I: "H" | "L" | "N";        // Integrity
  A: "H" | "L" | "N";        // Availability
}

/** CVSS 3.x metric weight tables (per NVD spec) */
const AV_WEIGHTS: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC_WEIGHTS: Record<string, number> = { L: 0.77, H: 0.44 };
const UI_WEIGHTS: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA_WEIGHTS: Record<string, number> = { H: 0.56, L: 0.22, N: 0.0 };
const PR_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };

/** Parse a CVSS 3.x vector string into structured metrics. Returns null on failure. */
function parseCvssV3Vector(vector: string): CvssMetrics | null {
  const v = vector.trim();
  if (!v.startsWith("CVSS:3.")) return null;

  const map: Record<string, string> = {};
  for (const p of v.split("/").slice(1)) {
    const [k, val] = p.split(":");
    if (k && val) map[k] = val;
  }

  const AV = map.AV as CvssMetrics["AV"] | undefined;
  const AC = map.AC as CvssMetrics["AC"] | undefined;
  const PR = map.PR as CvssMetrics["PR"] | undefined;
  const UI = map.UI as CvssMetrics["UI"] | undefined;
  const S  = map.S  as CvssMetrics["S"]  | undefined;
  const C  = map.C  as CvssMetrics["C"]  | undefined;
  const I  = map.I  as CvssMetrics["I"]  | undefined;
  const A  = map.A  as CvssMetrics["A"]  | undefined;

  if (!AV || !AC || !PR || !UI || !S || !C || !I || !A) return null;
  if (AV_WEIGHTS[AV] == null || AC_WEIGHTS[AC] == null || UI_WEIGHTS[UI] == null ||
      CIA_WEIGHTS[C] == null || CIA_WEIGHTS[I] == null || CIA_WEIGHTS[A] == null) return null;
  const prTable = S === "U" ? PR_UNCHANGED : PR_CHANGED;
  if (prTable[PR] == null) return null;

  return { AV, AC, PR, UI, S, C, I, A };
}

// ─────────────────────────────────────────────────────
// §2  CVSS Score Calculation (NVD spec)
// ─────────────────────────────────────────────────────

/**
 * Calculate the CVSS v3.x base score from a vector string.
 * Returns the numeric score (0.0–10.0) or null if parsing fails.
 */
export function cvssV3ToScore(vector: string): number | null {
  const m = parseCvssV3Vector(vector);
  if (!m) return null;

  const prTable = m.S === "U" ? PR_UNCHANGED : PR_CHANGED;
  const exploitability = 8.22 * AV_WEIGHTS[m.AV]! * AC_WEIGHTS[m.AC]! * prTable[m.PR]! * UI_WEIGHTS[m.UI]!;
  const iscBase = 1 - (1 - CIA_WEIGHTS[m.C]!) * (1 - CIA_WEIGHTS[m.I]!) * (1 - CIA_WEIGHTS[m.A]!);

  const impact = m.S === "U"
    ? 6.42 * iscBase
    : 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);

  if (impact <= 0) return 0;

  const raw = m.S === "U"
    ? impact + exploitability
    : 1.08 * (impact + exploitability);

  // Round up to nearest 0.1 per NVD spec (epsilon prevents floating-point rounding issues)
  return Math.ceil((Math.min(raw, 10) + 1e-10) * 10) / 10;
}

/**
 * Parse all metrics from a CVSS v3.x vector for detailed context.
 */
export interface CvssParsedResult {
  vector: string;
  score: number;
  severity: Severity;
  metrics: {
    attackVector: string;
    attackComplexity: string;
    privilegesRequired: string;
    userInteraction: string;
    scope: string;
    confidentiality: string;
    integrity: string;
    availability: string;
  };
  attackVectorLabel: string;
  exploitabilityLabel: string;
}

const AV_LABELS: Record<string, string> = { N: "Network", A: "Adjacent Network", L: "Local", P: "Physical" };
const AC_LABELS: Record<string, string> = { L: "Low", H: "High" };
const PR_LABELS: Record<string, string> = { N: "None", L: "Low", H: "High" };
const UI_LABELS: Record<string, string> = { N: "None", R: "Required" };
const S_LABELS: Record<string, string> = { U: "Unchanged", C: "Changed" };
const CIA_LABELS: Record<string, string> = { H: "High", L: "Low", N: "None" };

/**
 * Full CVSS 3.x parse: returns score, severity, and human-readable metric labels.
 */
export function parseCvssV3(vector: string): CvssParsedResult | null {
  const m = parseCvssV3Vector(vector);
  if (!m) return null;

  const score = cvssV3ToScore(vector)!;
  const severity = scoreToSeverity(score);

  return {
    vector,
    score,
    severity,
    metrics: {
      attackVector: m.AV,
      attackComplexity: m.AC,
      privilegesRequired: m.PR,
      userInteraction: m.UI,
      scope: m.S,
      confidentiality: m.C,
      integrity: m.I,
      availability: m.A,
    },
    attackVectorLabel: AV_LABELS[m.AV] ?? m.AV,
    exploitabilityLabel: buildExploitabilityLabel(m),
  };
}

function buildExploitabilityLabel(m: CvssMetrics): string {
  const parts: string[] = [];
  if (m.AV === "N") parts.push("remotely exploitable");
  else if (m.AV === "A") parts.push("exploitable from adjacent network");
  else if (m.AV === "L") parts.push("requires local access");
  else parts.push("requires physical access");

  if (m.UI === "N") parts.push("no user interaction");
  if (m.PR === "N") parts.push("no privileges required");
  else if (m.PR === "L") parts.push("low privileges required");

  return parts.join(", ");
}

// ─────────────────────────────────────────────────────
// §3  Severity Helpers
// ─────────────────────────────────────────────────────

/** Convert a numeric CVSS score to a severity level. */
export function scoreToSeverity(score: number): Severity {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0) return "low";
  return "unknown";
}

// ─────────────────────────────────────────────────────
// §4  Legacy API (backward compat)
// ─────────────────────────────────────────────────────

/** Convert CVSS v3.x vector string to severity. Returns "unknown" if parsing fails. */
export function cvssV3VectorToSeverity(vector: string): Severity {
  const score = cvssV3ToScore(vector);
  if (score == null || score <= 0) return "unknown";
  return scoreToSeverity(score);
}
