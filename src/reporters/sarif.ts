import type {
  AuditReport,
  PackageAuditResult,
  Severity,
  VulnerabilityFinding,
} from "../types";

function sarifLevelForSeverity(sev: Severity): "error" | "warning" | "note" {
  switch (sev) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
    case "unknown":
    default:
      return "note";
  }
}

function ruleIdForFinding(f: VulnerabilityFinding): string {
  return `pnpm-audit/${f.id}`;
}

export function toSarif(
  report: AuditReport,
  opts?: { lockfilePath?: string },
): any {
  const lockfilePath = opts?.lockfilePath ?? "pnpm-lock.yaml";

  const results: any[] = [];
  const rulesMap = new Map<string, any>();

  for (const p of report.packages) {
    for (const f of p.findings) {
      const rid = ruleIdForFinding(f);
      if (!rulesMap.has(rid)) {
        rulesMap.set(rid, {
          id: rid,
          name: f.id,
          shortDescription: { text: f.title ?? f.id },
          fullDescription: { text: f.description ?? f.title ?? f.id },
          helpUri: f.url,
          properties: {
            tags: ["security", "dependency"],
            severity: f.severity,
            source: f.source,
          },
        });
      }

      results.push({
        ruleId: rid,
        level: sarifLevelForSeverity(f.severity),
        message: {
          text: `${f.packageName}@${f.packageVersion}: ${f.title ?? f.id} (${f.severity})`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: lockfilePath },
              region: { startLine: 1, startColumn: 1 },
            },
          },
        ],
        properties: {
          packageName: f.packageName,
          packageVersion: f.packageVersion,
          vulnerabilityId: f.id,
          source: f.source,
          cvssScore: f.cvssScore,
          url: f.url,
        },
      });
    }
  }

  const rules = Array.from(rulesMap.values());

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "pnpm-audit-hook",
            informationUri: "https://example.org/pnpm-audit-hook",
            rules,
          },
        },
        results,
      },
    ],
  };

  return sarif;
}
