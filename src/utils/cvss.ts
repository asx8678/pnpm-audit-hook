import type { Severity } from "../types";

export function severityFromCvssScore(score: number | undefined): Severity {
  if (score === undefined || Number.isNaN(score) || !Number.isFinite(score))
    return "unknown";
  if (score < 0 || score > 10) return "unknown"; // CVSS scores must be 0-10
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0.0) return "low";
  return "unknown";
}

/**
 * Compute CVSS v3.x base score from a vector string.
 * Returns undefined if the vector is missing required metrics or unsupported.
 *
 * Supported: CVSS:3.0 and CVSS:3.1
 *
 * Reference: CVSS v3.1 specification (FIRST).
 */
export function cvssV3VectorToBaseScore(vector: string): number | undefined {
  const v = vector.trim();
  if (!v.startsWith("CVSS:3.")) return undefined;

  const parts = v.split("/");
  if (parts.length < 2) return undefined;

  const metrics: Record<string, string> = {};
  for (const p of parts.slice(1)) {
    const [k, val] = p.split(":");
    if (!k || !val) continue;
    metrics[k] = val;
  }

  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[
    metrics.AV as "N" | "A" | "L" | "P"
  ];
  const AC = { L: 0.77, H: 0.44 }[metrics.AC as "L" | "H"];
  const UI = { N: 0.85, R: 0.62 }[metrics.UI as "N" | "R"];
  const S = metrics.S as "U" | "C" | undefined;

  const C = { H: 0.56, L: 0.22, N: 0.0 }[metrics.C as "H" | "L" | "N"];
  const I = { H: 0.56, L: 0.22, N: 0.0 }[metrics.I as "H" | "L" | "N"];
  const A = { H: 0.56, L: 0.22, N: 0.0 }[metrics.A as "H" | "L" | "N"];

  if (
    AV === undefined ||
    AC === undefined ||
    UI === undefined ||
    S === undefined ||
    C === undefined ||
    I === undefined ||
    A === undefined
  ) {
    return undefined;
  }

  const PR_U = { N: 0.85, L: 0.62, H: 0.27 }[metrics.PR as "N" | "L" | "H"];
  const PR_C = { N: 0.85, L: 0.68, H: 0.5 }[metrics.PR as "N" | "L" | "H"];
  const PR = S === "U" ? PR_U : PR_C;
  if (PR === undefined) return undefined;

  const exploitability = 8.22 * AV * AC * PR * UI;

  const iscBase = 1 - (1 - C) * (1 - I) * (1 - A);

  let impact: number;
  if (S === "U") {
    impact = 6.42 * iscBase;
  } else {
    impact = 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
  }

  let baseScore: number;
  if (impact <= 0) baseScore = 0;
  else {
    if (S === "U") baseScore = roundUp1(Math.min(impact + exploitability, 10));
    else baseScore = roundUp1(Math.min(1.08 * (impact + exploitability), 10));
  }

  return baseScore;
}

function roundUp1(x: number): number {
  // Avoid floating point errors by using an epsilon
  return Math.ceil((x + 1e-10) * 10) / 10;
}
