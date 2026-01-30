import type { AuditReport, Severity } from "../types";

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function sevClass(sev: Severity): string {
  return `sev-${sev}`;
}

export function toHtml(report: AuditReport): string {
  const { summary } = report;

  const rows: string[] = [];

  for (const p of report.packages) {
    for (const f of p.findings) {
      rows.push(`
        <tr class="${sevClass(f.severity)}">
          <td>${esc(f.severity)}</td>
          <td>${esc(p.pkg.name)}</td>
          <td>${esc(p.pkg.version)}</td>
          <td>${f.url ? `<a href="${esc(f.url)}" target="_blank" rel="noreferrer">${esc(f.id)}</a>` : esc(f.id)}</td>
          <td>${esc(f.title ?? "")}</td>
          <td>${f.cvssScore !== undefined ? esc(String(f.cvssScore)) : ""}</td>
          <td>${esc(f.source)}</td>
        </tr>
      `);
    }
  }

  const decisions = report.decisions
    .filter((d) => d.action !== "allow")
    .slice(0, 500)
    .map(
      (d) =>
        `<li><strong>${esc(d.action.toUpperCase())}</strong> ${esc(d.packageName ?? "")}@${esc(d.packageVersion ?? "")}: ${esc(d.reason)}</li>`,
    )
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
    tr.sev-critical td { background: #ffe5e5; }
    tr.sev-high td { background: #fff1e5; }
    tr.sev-medium td { background: #fffbe5; }
    tr.sev-low td { background: #eaffea; }
    tr.sev-unknown td { background: #f1f1f1; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; }
    .badge.blocked { background: #c62828; color: white; }
    .badge.ok { background: #2e7d32; color: white; }
    .badge.warn { background: #ed6c02; color: white; }
    details { margin: 12px 0; }
  </style>
</head>
<body>
  <h1>pnpm security audit report</h1>
  <p>
    Status:
    ${
      summary.blocked
        ? '<span class="badge blocked">BLOCKED</span>'
        : summary.warnings
          ? '<span class="badge warn">WARNINGS</span>'
          : '<span class="badge ok">OK</span>'
    }
  </p>

  <div class="summary">
    <div class="card"><div>Total packages</div><div><strong>${summary.totalPackages}</strong></div></div>
    <div class="card"><div>Direct packages</div><div><strong>${summary.directPackages}</strong></div></div>
    <div class="card"><div>Vulnerable packages</div><div><strong>${summary.vulnerablePackages}</strong></div></div>
    <div class="card"><div>Findings</div><div><strong>${summary.blockedFindings + summary.warnedFindings}</strong></div></div>
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
        .map(
          ([k, v]) =>
            `<li>${esc(k)}: ${v.ok ? "ok" : "error"} ${v.error ? "(" + esc(v.error) + ")" : ""}</li>`,
        )
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
