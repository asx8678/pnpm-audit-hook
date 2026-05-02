import type { AuditOutputData } from "./types";

export function formatAzureDevOps(data: AuditOutputData): string {
  const { summary, findings, decisions, blocked, warnings } = data;
  const lines: string[] = [];

  // Source status group
  lines.push("##[group]Source Status");
  for (const [name, status] of Object.entries(summary.sourceStatus)) {
    const icon = status.ok ? "OK" : "FAILED";
    const duration = ` (${status.durationMs}ms)`;
    const error = status.error ? ` - ${status.error}` : "";
    if (!status.ok) {
      lines.push(`##[warning]${name}: ${icon}${duration}${error}`);
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
        lines.push(`##[error]${msg}`);
      } else {
        lines.push(`##[warning]${msg}`);
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
    lines.push(`##[error]BLOCKED: ${pkg}${finding} - ${d.reason}`);
  }
  lines.push("##[endgroup]");

  // Set pipeline variables
  lines.push(
    `##vso[task.setvariable variable=AUDIT_BLOCKED]${blocked ? "true" : "false"}`,
  );
  lines.push(
    `##vso[task.setvariable variable=AUDIT_VULNERABILITY_COUNT]${findings.length}`,
  );
  lines.push(
    `##vso[task.setvariable variable=AUDIT_CRITICAL_COUNT]${summary.vulnerabilitiesBySeverity.critical}`,
  );
  lines.push(
    `##vso[task.setvariable variable=AUDIT_HIGH_COUNT]${summary.vulnerabilitiesBySeverity.high}`,
  );

  // Final status
  if (blocked) {
    lines.push("##[error]AUDIT FAILED - Installation blocked");
  } else if (warnings) {
    lines.push("##[warning]AUDIT PASSED WITH WARNINGS");
  } else {
    lines.push("##[section]AUDIT PASSED - No issues found");
  }

  return lines.join("\n");
}