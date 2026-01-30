import type { AuditReport, PackageAuditResult, Severity } from "../types";
import { severityRank } from "./severity";

function sevEmoji(sev: Severity): string {
  switch (sev) {
    case "critical":
      return "🛑";
    case "high":
      return "❌";
    case "medium":
      return "⚠️";
    case "low":
      return "ℹ️";
    default:
      return "❔";
  }
}

export function reportToMarkdown(
  report: AuditReport,
  opts?: { maxItems?: number },
): string {
  const maxItems = opts?.maxItems ?? 50;
  const { summary } = report;

  const lines: string[] = [];

  lines.push(`# pnpm security audit report`);
  lines.push("");
  lines.push(`- Started: ${summary.startedAt}`);
  lines.push(`- Finished: ${summary.finishedAt}`);
  lines.push(
    `- Total packages: **${summary.totalPackages}** (direct: **${summary.directPackages}**)`,
  );
  lines.push(`- Vulnerable packages: **${summary.vulnerablePackages}**`);
  lines.push(
    `- Findings by severity: critical ${summary.countsBySeverity.critical}, high ${summary.countsBySeverity.high}, medium ${summary.countsBySeverity.medium}, low ${summary.countsBySeverity.low}, unknown ${summary.countsBySeverity.unknown}`,
  );
  lines.push(
    `- Status: ${summary.blocked ? "**BLOCKED**" : summary.warnings ? "**WARNINGS**" : "**OK**"}`,
  );
  lines.push("");

  const allFindings: Array<{ pkg: string; f: any }> = [];
  for (const p of report.packages) {
    for (const f of p.findings)
      allFindings.push({ pkg: `${p.pkg.name}@${p.pkg.version}`, f });
  }

  allFindings.sort(
    (a, b) => severityRank(b.f.severity) - severityRank(a.f.severity),
  );

  if (allFindings.length === 0) {
    lines.push("No vulnerabilities found.");
    return lines.join("\n");
  }

  lines.push("## Top findings");
  lines.push("");
  for (const item of allFindings.slice(0, maxItems)) {
    const f = item.f;
    const link = f.url ? `[${f.id}](${f.url})` : f.id;
    lines.push(
      `- ${sevEmoji(f.severity)} **${f.severity.toUpperCase()}** ${item.pkg} — ${link}${f.title ? `: ${escapeInline(f.title)}` : ""}`,
    );
  }

  if (allFindings.length > maxItems) {
    lines.push("");
    lines.push(
      `...and ${allFindings.length - maxItems} more findings. See the full report artifact.`,
    );
  }

  lines.push("");
  lines.push("## Sources");
  lines.push("");
  for (const [k, v] of Object.entries(summary.sources)) {
    lines.push(
      `- ${k}: ${v.ok ? "ok" : `error (${escapeInline(v.error ?? "unknown")})`}`,
    );
  }

  return lines.join("\n");
}

function escapeInline(s: string): string {
  return s.replace(/\r?\n/g, " ").slice(0, 300);
}
