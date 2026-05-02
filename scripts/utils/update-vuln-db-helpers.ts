/**
 * Pure helper functions extracted from update-vuln-db.ts for testability.
 *
 * These functions have no side effects and no dependencies on filesystem
 * or network — perfect for unit testing.
 */

import type {
  StaticVulnerability,
  StaticPackageData,
  AffectedVersionRange,
} from "../../src/static-db/types";
import type { Severity, VulnerabilityIdentifier } from "../../src/types";

// ---------------------------------------------------------------------------
// GitHub Advisory GraphQL types (mirrors the shape returned by the API)
// ---------------------------------------------------------------------------

export interface GitHubAdvisory {
  ghsaId: string;
  summary: string;
  description: string;
  severity: string;
  publishedAt: string;
  updatedAt: string;
  permalink: string;
  identifiers: { type: string; value: string }[];
  vulnerabilities: {
    nodes: {
      package: { name: string; ecosystem: string };
      vulnerableVersionRange: string;
      firstPatchedVersion: { identifier: string } | null;
    }[];
  };
}

// ---------------------------------------------------------------------------
// Severity mapping
// ---------------------------------------------------------------------------

/**
 * Map GitHub Advisory severity string to our canonical Severity type.
 * GitHub uses "moderate" where we use "medium".
 */
export function mapSeverity(
  ghSeverity: string,
): "critical" | "high" | "medium" | "low" | "unknown" {
  const severity = ghSeverity.toLowerCase();
  if (severity === "critical") return "critical";
  if (severity === "high") return "high";
  if (severity === "moderate" || severity === "medium") return "medium";
  if (severity === "low") return "low";
  return "unknown";
}

export const SEVERITY_RANK: Record<StaticVulnerability["severity"], number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  unknown: 0,
};

// ---------------------------------------------------------------------------
// Advisory conversion
// ---------------------------------------------------------------------------

/**
 * Convert a GitHub Advisory + one of its NPM vulnerability nodes into
 * our internal StaticVulnerability format.
 */
export function convertAdvisory(
  advisory: GitHubAdvisory,
  vuln: GitHubAdvisory["vulnerabilities"]["nodes"][0],
): { packageName: string; entry: StaticVulnerability } {
  return {
    packageName: vuln.package.name,
    entry: {
      id: advisory.ghsaId,
      packageName: vuln.package.name,
      title: advisory.summary,
      description: advisory.description?.slice(0, 500),
      severity: mapSeverity(advisory.severity),
      url: advisory.permalink,
      publishedAt: advisory.publishedAt,
      modifiedAt: advisory.updatedAt,
      identifiers: advisory.identifiers.map((id) => ({
        type: id.type as VulnerabilityIdentifier["type"],
        value: id.value,
      })),
      affectedVersions: [
        {
          range: vuln.vulnerableVersionRange,
          fixed: vuln.firstPatchedVersion?.identifier,
        } as AffectedVersionRange,
      ],
      source: "github",
    },
  };
}

// ---------------------------------------------------------------------------
// Package data normalization
// ---------------------------------------------------------------------------

/**
 * Normalize raw (possibly legacy) JSON into a StaticPackageData object.
 * Handles both the current schema and the legacy `affectedRange`/`fixedVersion`
 * fields so that old shard files can be loaded correctly.
 */
export function normalizePackageData(
  raw: unknown,
  packageName: string,
): StaticPackageData | null {
  if (!raw || typeof raw !== "object") return null;
  const obj = raw as Record<string, unknown>;
  const name =
    typeof obj.packageName === "string"
      ? obj.packageName
      : typeof obj.name === "string"
        ? obj.name
        : packageName;

  if (!name) return null;

  const vulnerabilitiesRaw = Array.isArray(obj.vulnerabilities) ? obj.vulnerabilities : [];
  const vulnerabilities: StaticVulnerability[] = [];

  for (const vuln of vulnerabilitiesRaw) {
    if (!vuln || typeof vuln !== "object") continue;
    const v = vuln as Record<string, unknown>;
    const id = typeof v.id === "string" ? v.id : "";
    if (!id) continue;
    const affectedVersions = Array.isArray(v.affectedVersions)
      ? (v.affectedVersions as Array<{ range?: unknown; fixed?: unknown }>)
          .map((av) => {
            const range = typeof av?.range === "string" ? av.range : "";
            if (!range) return null;
            const fixed = typeof av.fixed === "string" ? av.fixed : undefined;
            return { range, fixed } as AffectedVersionRange;
          })
          .filter((av): av is AffectedVersionRange => av !== null)
      : typeof v.affectedRange === "string"
        ? [
            {
              range: v.affectedRange,
              ...(typeof v.fixedVersion === "string" ? { fixed: v.fixedVersion } : {}),
            } as AffectedVersionRange,
          ]
        : [] as AffectedVersionRange[];

    vulnerabilities.push({
      id,
      packageName: typeof v.packageName === "string" ? v.packageName : name,
      title: typeof v.title === "string" ? v.title : undefined,
      description: typeof v.description === "string" ? v.description : undefined,
      severity: mapSeverity(typeof v.severity === "string" ? v.severity : "unknown"),
      url: typeof v.url === "string" ? v.url : undefined,
      publishedAt: typeof v.publishedAt === "string" ? v.publishedAt : undefined,
      modifiedAt: typeof v.modifiedAt === "string" ? v.modifiedAt : undefined,
      identifiers: Array.isArray(v.identifiers)
        ? v.identifiers
            .map((idEntry) => {
              if (!idEntry || typeof idEntry !== "object") return null;
              const idObj = idEntry as Record<string, unknown>;
              const type = typeof idObj.type === "string" ? idObj.type : "";
              const value = typeof idObj.value === "string" ? idObj.value : "";
              if (!type || !value) return null;
              return { type, value } as VulnerabilityIdentifier;
            })
            .filter((i): i is VulnerabilityIdentifier => i !== null)
        : undefined,
      affectedVersions,
      source: "github",
    });
  }

  return {
    packageName: name,
    lastUpdated:
      typeof obj.lastUpdated === "string"
        ? obj.lastUpdated
        : new Date().toISOString(),
    vulnerabilities,
  };
}
