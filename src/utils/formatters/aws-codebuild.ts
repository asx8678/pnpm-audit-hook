import type { AuditOutputData } from "./types";

export function formatCodeBuild(data: AuditOutputData): string {
  const { summary, findings, decisions, blocked, warnings } = data;
  const lines: string[] = [];

  // Source status group
  lines.push("##[group]Source Status");
  for (const [name, status] of Object.entries(summary.sourceStatus)) {
    const icon = status.ok ? "OK" : "FAILED";
    const duration = ` (${status.durationMs}ms)`;
    const error = status.error ? ` - ${status.error}` : "";
    if (!status.ok) {
      lines.push(`[WARNING] ${name}: ${icon}${duration}${error}`);
    } else {
      lines.push(`${name}: ${icon}${duration}${error}`);
    }
  }
  lines.push("##[endgroup]");

  // Package summary group
  lines.push("##[group]Package Summary");
  lines.push(`Total packages scanned: ${summary.totalPackages}`);
  lines.push(`Safe packages: ${summary.safePackages}`);
  lines.push(`Packages with vulnerabilities: ${summary.packagesWithVulnerabilities}`);
  lines.push("##[endgroup]");

  // Vulnerability breakdown group
  lines.push("##[group]Vulnerabilities by Severity");
  for (const severity of ["critical", "high", "medium", "low", "unknown"]) {
    const count = summary.vulnerabilitiesBySeverity[severity as keyof typeof summary.vulnerabilitiesBySeverity];
    lines.push(`${severity.toUpperCase()}: ${count}`);
  }
  lines.push("##[endgroup]");

  // Vulnerability details group
  if (findings.length > 0) {
    lines.push("##[group]Vulnerability Details");
    for (const finding of findings) {
      const msg = `[${finding.severity.toUpperCase()}] ${finding.id} in ${finding.packageName}@${finding.packageVersion}`;
      if (finding.severity === "critical" || finding.severity === "high") {
        lines.push(`[ERROR] ${msg}`);
      } else {
        lines.push(`[WARNING] ${msg}`);
      }
      if (finding.title) {
        lines.push(`  Title: ${finding.title}`);
      }
      if (finding.url) {
        lines.push(`  URL: ${finding.url}`);
      }
    }
    lines.push("##[endgroup]");
  }

  // Policy decisions group
  lines.push("##[group]Policy Decisions");
  lines.push(`Blocked: ${summary.blockedCount}`);
  lines.push(`Warnings: ${summary.warnCount}`);
  lines.push(`Allowed: ${summary.allowedCount}`);
  lines.push(`Allowlisted: ${summary.allowlistedCount}`);

  const blockedDecisions = decisions.filter((d) => d.action === "block");
  for (const d of blockedDecisions) {
    const pkg = d.packageName ? `${d.packageName}@${d.packageVersion}` : "";
    const finding = d.findingId ? ` (${d.findingId})` : "";
    lines.push(`[ERROR] BLOCKED: ${pkg}${finding} - ${d.reason}`);
  }
  lines.push("##[endgroup]");

  // Final status
  if (blocked) {
    lines.push("[ERROR] AUDIT FAILED - Installation blocked");
  } else if (warnings) {
    lines.push("[WARNING] AUDIT PASSED WITH WARNINGS");
  } else {
    lines.push("[INFO] AUDIT PASSED - No issues found");
  }

  return lines.join("\n");
}