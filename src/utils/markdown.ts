import type { AuditReport, Severity } from "../types";
import { severityRank } from "./severity";

const SEV_EMOJI: Record<Severity, string> = { critical: "🛑", high: "❌", medium: "⚠️", low: "ℹ️", unknown: "❔" };
const sevEmoji = (sev: Severity) => SEV_EMOJI[sev] ?? "❔";

export function reportToMarkdown(report: AuditReport, opts?: { maxItems?: number }): string {
  const maxItems = opts?.maxItems ?? 50;
  const { summary } = report;
  const c = summary.countsBySeverity;

  const lines = [
    `# pnpm security audit report`,
    "",
    `- Started: ${summary.startedAt}`,
    `- Finished: ${summary.finishedAt}`,
    `- Total packages: **${summary.totalPackages}** (direct: **${summary.directPackages}**)`,
    `- Vulnerable packages: **${summary.vulnerablePackages}**`,
    `- Findings by severity: critical ${c.critical}, high ${c.high}, medium ${c.medium}, low ${c.low}, unknown ${c.unknown}`,
    `- Status: ${summary.blocked ? "**BLOCKED**" : summary.warnings ? "**WARNINGS**" : "**OK**"}`,
    "",
  ];

  const allFindings = report.packages
    .flatMap((p) => p.findings.map((f) => ({ pkg: `${p.pkg.name}@${p.pkg.version}`, f })))
    .sort((a, b) => severityRank(b.f.severity) - severityRank(a.f.severity));

  if (!allFindings.length) return [...lines, "No vulnerabilities found."].join("\n");

  lines.push("## Top findings");
  lines.push("");
  for (const item of allFindings.slice(0, maxItems)) {
    const f = item.f;
    const link = f.url ? `[${f.id}](${f.url})` : f.id;
    lines.push(
      `- ${sevEmoji(f.severity)} **${f.severity.toUpperCase()}** ${item.pkg} — ${link}${f.title ? `: ${escapeInline(f.title)}` : ""}`,
    );
  }

  if (allFindings.length > maxItems)
    lines.push("", `...and ${allFindings.length - maxItems} more findings. See the full report artifact.`);

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
