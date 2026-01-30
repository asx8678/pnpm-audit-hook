import type { AuditReport, AuditSummary, Finding, PackageResult } from "../types";
import { htmlEscape as esc } from "../utils/escape";

const badge = (type: "blocked" | "ok" | "warn", label: string) =>
  `<span class="badge ${type}">${label}</span>`;

const card = (label: string, value: number) =>
  `<div class="card"><div>${label}</div><div><strong>${value}</strong></div></div>`;

const link = (url: string | undefined, text: string) =>
  url ? `<a href="${esc(url)}" target="_blank" rel="noreferrer">${esc(text)}</a>` : esc(text);

const findingRow = (p: PackageResult, f: Finding) => `
  <tr class="sev-${f.severity}">
    <td>${esc(f.severity)}</td>
    <td>${esc(p.pkg.name)}</td>
    <td>${esc(p.pkg.version)}</td>
    <td>${link(f.url, f.id)}</td>
    <td>${esc(f.title ?? "")}</td>
    <td>${f.cvssScore !== undefined ? f.cvssScore : ""}</td>
    <td>${esc(f.source)}</td>
  </tr>`;

const statusBadge = (summary: AuditSummary) =>
  summary.blocked ? badge("blocked", "BLOCKED")
    : summary.warnings ? badge("warn", "WARNINGS")
    : badge("ok", "OK");

export function toHtml(report: AuditReport): string {
  const { summary } = report;

  const rows = report.packages.flatMap((p) => p.findings.map((f) => findingRow(p, f)));

  const decisions = report.decisions
    .filter((d) => d.action !== "allow")
    .slice(0, 500)
    .map((d) => `<li><strong>${esc(d.action.toUpperCase())}</strong> ${esc(d.packageName ?? "")}@${esc(d.packageVersion ?? "")}: ${esc(d.reason)}</li>`)
    .join("\n");

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>pnpm audit report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }
    .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 16px; }
    .card { border: 1px solid #ddd; border-radius: 8px; padding: 12px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; font-size: 12px; vertical-align: top; }
    th { background: #f7f7f7; text-align: left; }
    .sev-critical td { background: #ffe5e5; }
    .sev-high td { background: #fff1e5; }
    .sev-medium td { background: #fffbe5; }
    .sev-low td { background: #eaffea; }
    .sev-unknown td { background: #f1f1f1; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; color: #fff; }
    .badge.blocked { background: #c62828; }
    .badge.ok { background: #2e7d32; }
    .badge.warn { background: #ed6c02; }
    details { margin: 12px 0; }
  </style>
</head>
<body>
  <h1>pnpm security audit report</h1>
  <p>Status: ${statusBadge(summary)}</p>

  <div class="summary">
    ${card("Total packages", summary.totalPackages)}
    ${card("Direct packages", summary.directPackages)}
    ${card("Vulnerable packages", summary.vulnerablePackages)}
    ${card("Findings", summary.blockedFindings + summary.warnedFindings)}
  </div>

  <details open>
    <summary>Findings</summary>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Package</th>
          <th>Version</th>
          <th>ID</th>
          <th>Title</th>
          <th>CVSS</th>
          <th>Source</th>
        </tr>
      </thead>
      <tbody>
        ${rows.join("\n")}
      </tbody>
    </table>
  </details>

  <details>
    <summary>Policy decisions (top 500 non-allow)</summary>
    <ul>
      ${decisions}
    </ul>
  </details>

  <details>
    <summary>Sources</summary>
    <ul>
      ${Object.entries(summary.sources)
        .map(([k, v]) => `<li>${esc(k)}: ${v.ok ? "ok" : "error"}${v.error ? ` (${esc(v.error)})` : ""}</li>`)
        .join("\n")}
    </ul>
  </details>

  <p style="margin-top: 24px; font-size: 12px; color: #666;">
    Started: ${esc(summary.startedAt)}<br/>
    Finished: ${esc(summary.finishedAt)}
  </p>
</body>
</html>
`;
}
