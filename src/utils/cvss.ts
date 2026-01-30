import type { Severity } from "../types";

/** Convert CVSS v3.x vector string to severity. Returns "unknown" if parsing fails. */
export function cvssV3VectorToSeverity(vector: string): Severity {
  const v = vector.trim();
  if (!v.startsWith("CVSS:3.")) return "unknown";

  const metrics: Record<string, string> = {};
  for (const p of v.split("/").slice(1)) {
    const [k, val] = p.split(":");
    if (k && val) metrics[k] = val;
  }

  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[metrics.AV as "N" | "A" | "L" | "P"];
  const AC = { L: 0.77, H: 0.44 }[metrics.AC as "L" | "H"];
  const UI = { N: 0.85, R: 0.62 }[metrics.UI as "N" | "R"];
  const S = metrics.S as "U" | "C" | undefined;
  const C = { H: 0.56, L: 0.22, N: 0.0 }[metrics.C as "H" | "L" | "N"];
  const I = { H: 0.56, L: 0.22, N: 0.0 }[metrics.I as "H" | "L" | "N"];
  const A = { H: 0.56, L: 0.22, N: 0.0 }[metrics.A as "H" | "L" | "N"];

  if (AV == null || AC == null || UI == null || S == null || C == null || I == null || A == null) return "unknown";

  const PR = (S === "U" ? { N: 0.85, L: 0.62, H: 0.27 } : { N: 0.85, L: 0.68, H: 0.5 })[metrics.PR as "N" | "L" | "H"];
  if (PR == null) return "unknown";

  const exploitability = 8.22 * AV * AC * PR * UI;
  const iscBase = 1 - (1 - C) * (1 - I) * (1 - A);
  const impact = S === "U" ? 6.42 * iscBase : 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);

  if (impact <= 0) return "unknown";
  const score = Math.ceil((Math.min(S === "U" ? impact + exploitability : 1.08 * (impact + exploitability), 10) + 1e-10) * 10) / 10;

  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return score > 0 ? "low" : "unknown";
}
