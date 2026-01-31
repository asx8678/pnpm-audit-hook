import type {
  PolicyDecision,
  Severity,
  SourceStatus,
  VulnerabilityFinding,
} from "../types";

export interface AuditSummary {
  totalPackages: number;
  scannedPackages: number;
  safePackages: number;
  packagesWithVulnerabilities: number;
  vulnerabilitiesBySeverity: Record<Severity, number>;
  blockedCount: number;
  warnCount: number;
  allowedCount: number;
  allowlistedCount: number;
  sourceStatus: Record<string, SourceStatus>;
  totalDurationMs: number;
}

export interface AuditOutputData {
  summary: AuditSummary;
  findings: VulnerabilityFinding[];
  decisions: PolicyDecision[];
  blocked: boolean;
  warnings: boolean;
  exitCode: number;
}

export function buildSummary(
  totalPackages: number,
  findings: VulnerabilityFinding[],
  decisions: PolicyDecision[],
  sourceStatus: Record<string, SourceStatus>,
): AuditSummary {
  const packagesWithFindings = new Set(
    findings.map((f) => `${f.packageName}@${f.packageVersion}`),
  );

  const vulnerabilitiesBySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
  };

  for (const finding of findings) {
    vulnerabilitiesBySeverity[finding.severity]++;
  }

  let blockedCount = 0;
  let warnCount = 0;
  let allowedCount = 0;
  let allowlistedCount = 0;

  for (const decision of decisions) {
    switch (decision.action) {
      case "block":
        blockedCount++;
        break;
      case "warn":
        warnCount++;
        break;
      case "allow":
        if (decision.source === "allowlist") {
          allowlistedCount++;
        } else {
          allowedCount++;
        }
        break;
    }
  }

  const totalDurationMs = Object.values(sourceStatus).reduce(
    (sum, s) => sum + (s.durationMs ?? 0),
    0,
  );

  return {
    totalPackages,
    scannedPackages: totalPackages,
    safePackages: totalPackages - packagesWithFindings.size,
    packagesWithVulnerabilities: packagesWithFindings.size,
    vulnerabilitiesBySeverity,
    blockedCount,
    warnCount,
    allowedCount,
    allowlistedCount,
    sourceStatus,
    totalDurationMs,
  };
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "unknown"];

function severityColor(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "\x1b[31m"; // red
    case "high":
      return "\x1b[91m"; // bright red
    case "medium":
      return "\x1b[33m"; // yellow
    case "low":
      return "\x1b[36m"; // cyan
    default:
      return "\x1b[90m"; // gray
  }
}

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";

export function formatHumanReadable(data: AuditOutputData): string {
  const { summary, findings, decisions, blocked } = data;
  const lines: string[] = [];

  // Header banner
  lines.push("");
  lines.push(`${BOLD}===============================================${RESET}`);
  lines.push(`${BOLD}           PNPM AUDIT SECURITY REPORT          ${RESET}`);
  lines.push(`${BOLD}===============================================${RESET}`);
  lines.push("");

  // Source status group
  lines.push(`${BOLD}Source Status:${RESET}`);
  for (const [name, status] of Object.entries(summary.sourceStatus)) {
    const icon = status.ok ? `${GREEN}OK${RESET}` : `${RED}FAILED${RESET}`;
    const duration = status.durationMs ? ` (${status.durationMs}ms)` : "";
    const error = status.error ? ` - ${status.error}` : "";
    lines.push(`  ${name}: ${icon}${duration}${error}`);
  }
  lines.push("");

  // Package summary
  lines.push(`${BOLD}Package Summary:${RESET}`);
  lines.push(`  Total packages scanned: ${summary.scannedPackages}`);
  lines.push(`  Safe packages: ${GREEN}${summary.safePackages}${RESET}`);
  lines.push(
    `  Packages with vulnerabilities: ${summary.packagesWithVulnerabilities > 0 ? RED : GREEN}${summary.packagesWithVulnerabilities}${RESET}`,
  );
  lines.push("");

  // Vulnerability breakdown by severity
  lines.push(`${BOLD}Vulnerabilities by Severity:${RESET}`);
  for (const severity of SEVERITY_ORDER) {
    const count = summary.vulnerabilitiesBySeverity[severity];
    if (count > 0) {
      lines.push(`  ${severityColor(severity)}${severity.toUpperCase()}${RESET}: ${count}`);
    }
  }
  const totalVulns = Object.values(summary.vulnerabilitiesBySeverity).reduce(
    (a, b) => a + b,
    0,
  );
  if (totalVulns === 0) {
    lines.push(`  ${GREEN}No vulnerabilities found${RESET}`);
  }
  lines.push("");

  // Detailed vulnerability list
  if (findings.length > 0) {
    lines.push(`${BOLD}Vulnerability Details:${RESET}`);
    for (const finding of findings) {
      const color = severityColor(finding.severity);
      lines.push(`  ${color}[${finding.severity.toUpperCase()}]${RESET} ${finding.id}`);
      lines.push(`    Package: ${finding.packageName}@${finding.packageVersion}`);
      if (finding.title) {
        lines.push(`    Title: ${finding.title}`);
      }
      if (finding.url) {
        lines.push(`    URL: ${finding.url}`);
      }
      if (finding.affectedRange) {
        lines.push(`    Affected: ${finding.affectedRange}`);
      }
      if (finding.fixedVersion) {
        lines.push(`    Fixed in: ${finding.fixedVersion}`);
      }
      lines.push("");
    }
  }

  // Policy decision summary
  lines.push(`${BOLD}Policy Decisions:${RESET}`);
  lines.push(`  ${RED}Blocked${RESET}: ${summary.blockedCount}`);
  lines.push(`  ${YELLOW}Warnings${RESET}: ${summary.warnCount}`);
  lines.push(`  ${GREEN}Allowed${RESET}: ${summary.allowedCount}`);
  lines.push(`  Allowlisted: ${summary.allowlistedCount}`);
  lines.push("");

  // Show blocked decisions
  const blockedDecisions = decisions.filter((d) => d.action === "block");
  if (blockedDecisions.length > 0) {
    lines.push(`${BOLD}${RED}Blocked Items:${RESET}`);
    for (const d of blockedDecisions) {
      const pkg = d.packageName ? `${d.packageName}@${d.packageVersion}` : "";
      const finding = d.findingId ? ` (${d.findingId})` : "";
      lines.push(`  - ${pkg}${finding}: ${d.reason}`);
    }
    lines.push("");
  }

  // Final status line
  lines.push(`${BOLD}===============================================${RESET}`);
  if (blocked) {
    lines.push(`${BOLD}${RED}AUDIT FAILED - Installation blocked${RESET}`);
  } else if (data.warnings) {
    lines.push(`${BOLD}${YELLOW}AUDIT PASSED WITH WARNINGS${RESET}`);
  } else {
    lines.push(`${BOLD}${GREEN}AUDIT PASSED - No issues found${RESET}`);
  }
  lines.push(`${BOLD}===============================================${RESET}`);
  lines.push(`Total time: ${summary.totalDurationMs}ms`);
  lines.push("");

  return lines.join("\n");
}

export function formatAzureDevOps(data: AuditOutputData): string {
  const { summary, findings, decisions, blocked } = data;
  const lines: string[] = [];

  // Source status group
  lines.push("##[group]Source Status");
  for (const [name, status] of Object.entries(summary.sourceStatus)) {
    const icon = status.ok ? "OK" : "FAILED";
    const duration = status.durationMs ? ` (${status.durationMs}ms)` : "";
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
  lines.push(`Total packages scanned: ${summary.scannedPackages}`);
  lines.push(`Safe packages: ${summary.safePackages}`);
  lines.push(`Packages with vulnerabilities: ${summary.packagesWithVulnerabilities}`);
  lines.push("##[endgroup]");

  // Vulnerability breakdown group
  lines.push("##[group]Vulnerabilities by Severity");
  for (const severity of SEVERITY_ORDER) {
    const count = summary.vulnerabilitiesBySeverity[severity];
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
  } else if (data.warnings) {
    lines.push("##[warning]AUDIT PASSED WITH WARNINGS");
  } else {
    lines.push("AUDIT PASSED - No issues found");
  }

  lines.push(`Total time: ${summary.totalDurationMs}ms`);

  return lines.join("\n");
}

export function formatJson(data: AuditOutputData): string {
  return JSON.stringify(
    {
      summary: data.summary,
      findings: data.findings,
      decisions: data.decisions,
      blocked: data.blocked,
      warnings: data.warnings,
      exitCode: data.exitCode,
    },
    null,
    2,
  );
}

export type OutputFormat = "human" | "azure" | "json";

export function getOutputFormat(env: Record<string, string | undefined>): OutputFormat {
  if (env.PNPM_AUDIT_JSON === "true") {
    return "json";
  }
  if (env.PNPM_AUDIT_FORMAT === "azure" || env.TF_BUILD === "True") {
    return "azure";
  }
  return "human";
}

export function outputResults(
  data: AuditOutputData,
  env: Record<string, string | undefined>,
): void {
  const format = getOutputFormat(env);

  let output: string;
  switch (format) {
    case "json":
      output = formatJson(data);
      break;
    case "azure":
      output = formatAzureDevOps(data);
      break;
    default:
      output = formatHumanReadable(data);
  }

  console.log(output);
}
