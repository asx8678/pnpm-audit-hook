import fs from "node:fs";
import type {
  PolicyDecision,
  Severity,
  SourceStatus,
  VulnerabilityFinding,
} from "../types";

export interface AuditSummary {
  totalPackages: number;
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
  wallClockMs?: number,
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

  const totalDurationMs = wallClockMs ??
    Object.values(sourceStatus).reduce((sum, s) => sum + s.durationMs, 0);

  return {
    totalPackages,
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

/**
 * Compact status banner — always shown during pnpm install.
 *
 * Clean:    🛡️  pnpm-audit ── 142 packages ── github ✓  osv ✓  static-db ✓ ── ✅ clean ── 312ms
 * Warnings: 🛡️  pnpm-audit ── 142 packages ── github ✓  osv ✓ ── ⚠️  3 warnings ── 428ms
 *             ⚠  CVE-2024-39338 [MEDIUM] axios@1.5.0 — Server-Side Request Forgery
 * Blocked:  🛡️  pnpm-audit ── 142 packages ── github ✓  osv ✓ ── 🚫 2 BLOCKED ── 428ms
 *             🚫 CVE-2021-23337 [CRITICAL] lodash@4.17.15 — Command Injection (fix: 4.17.21)
 */
export function formatCompactBanner(data: AuditOutputData): string {
  const { summary, findings, decisions, blocked, warnings } = data;
  const lines: string[] = [];

  // Source status chips
  const sourceChips: string[] = [];
  for (const [name, status] of Object.entries(summary.sourceStatus)) {
    if (status.error === "disabled by configuration") continue;
    const icon = status.ok ? `${GREEN}✓${RESET}` : `${RED}✗${RESET}`;
    sourceChips.push(`${name} ${icon}`);
  }
  const sourceLine = sourceChips.length > 0 ? sourceChips.join("  ") : `${YELLOW}no sources${RESET}`;

  // Status chip
  let statusChip: string;
  if (blocked) {
    const count = decisions.filter(d => d.action === "block").length;
    statusChip = `${BOLD}${RED}🚫 ${count} BLOCKED${RESET}`;
  } else if (warnings) {
    const count = decisions.filter(d => d.action === "warn").length;
    // Build severity breakdown for warnings
    const sevCounts: Partial<Record<Severity, number>> = {};
    for (const d of decisions) {
      if (d.action === "warn" && d.findingSeverity) {
        sevCounts[d.findingSeverity] = (sevCounts[d.findingSeverity] ?? 0) + 1;
      }
    }
    const sevParts = SEVERITY_ORDER
      .filter(s => (sevCounts[s] ?? 0) > 0)
      .map(s => `${sevCounts[s]} ${s}`);
    const sevDetail = sevParts.length > 0 ? ` (${sevParts.join(", ")})` : "";
    statusChip = `${BOLD}${YELLOW}⚠️  ${count} warning${count !== 1 ? "s" : ""}${sevDetail}${RESET}`;
  } else {
    statusChip = `${GREEN}✅ clean${RESET}`;
  }

  // Main banner line
  const durationStr = `${summary.totalDurationMs}ms`;
  lines.push(
    `${BOLD}🛡️  pnpm-audit${RESET} ── ${summary.totalPackages} packages ── ${sourceLine} ── ${statusChip} ── ${durationStr}`
  );

  // Detail lines for blocked items (show CVE, severity, package, title, fix)
  const blockedDecisions = decisions.filter(d => d.action === "block" && d.findingId);
  for (const d of blockedDecisions) {
    const sev = d.findingSeverity ? `${severityColor(d.findingSeverity)}[${d.findingSeverity.toUpperCase()}]${RESET}` : "";
    const pkg = d.packageName ? `${d.packageName}@${d.packageVersion}` : "";
    const finding = findings.find(f => f.id === d.findingId && f.packageName === d.packageName);
    const title = finding?.title ? ` — ${finding.title}` : "";
    const fix = finding?.fixedVersion ? ` ${GREEN}(fix: ${finding.fixedVersion})${RESET}` : "";
    lines.push(`  ${RED}🚫${RESET} ${d.findingId} ${sev} ${pkg}${title}${fix}`);
  }

  // Detail lines for warnings (show CVE, severity, package, title)
  if (!blocked) {
    const warnDecisions = decisions.filter(d => d.action === "warn" && d.findingId);
    // Show up to 5 warnings to keep it compact
    const shownWarnings = warnDecisions.slice(0, 5);
    for (const d of shownWarnings) {
      const sev = d.findingSeverity ? `${severityColor(d.findingSeverity)}[${d.findingSeverity.toUpperCase()}]${RESET}` : "";
      const pkg = d.packageName ? `${d.packageName}@${d.packageVersion}` : "";
      const finding = findings.find(f => f.id === d.findingId && f.packageName === d.packageName);
      const title = finding?.title ? ` — ${finding.title}` : "";
      lines.push(`  ${YELLOW}⚠${RESET}  ${d.findingId} ${sev} ${pkg}${title}`);
    }
    if (warnDecisions.length > 5) {
      lines.push(`  ${YELLOW}...and ${warnDecisions.length - 5} more warning${warnDecisions.length - 5 !== 1 ? "s" : ""}${RESET}`);
    }
  }

  return lines.join("\n");
}

export function formatHumanReadable(data: AuditOutputData): string {
  const { summary, findings, decisions, blocked, warnings } = data;
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
    const duration = ` (${status.durationMs}ms)`;
    const error = status.error ? ` - ${status.error}` : "";
    lines.push(`  ${name}: ${icon}${duration}${error}`);
  }
  lines.push("");

  // Package summary
  lines.push(`${BOLD}Package Summary:${RESET}`);
  lines.push(`  Total packages scanned: ${summary.totalPackages}`);
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
  if (findings.length === 0) {
    lines.push(`  ${GREEN}No vulnerabilities found${RESET}`);
  }
  lines.push("");

  // Detailed vulnerability list
  if (findings.length > 0) {
    lines.push(`${BOLD}Vulnerability Details:${RESET}`);
    for (const finding of findings) {
      const color = severityColor(finding.severity);
      const cvss = typeof finding.cvssScore === "number" ? ` (CVSS ${finding.cvssScore})` : "";
      lines.push(`  ${color}[${finding.severity.toUpperCase()}]${RESET} ${finding.id}${cvss}`);
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
  } else if (warnings) {
    lines.push(`${BOLD}${YELLOW}AUDIT PASSED WITH WARNINGS${RESET}`);
  } else {
    lines.push(`${BOLD}${GREEN}AUDIT PASSED - No issues found${RESET}`);
  }
  lines.push(`${BOLD}===============================================${RESET}`);
  lines.push(`Source query time: ${summary.totalDurationMs}ms`);
  lines.push("");

  return lines.join("\n");
}

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
  } else if (warnings) {
    lines.push("##[warning]AUDIT PASSED WITH WARNINGS");
  } else {
    lines.push("AUDIT PASSED - No issues found");
  }

  lines.push(`Source query time: ${summary.totalDurationMs}ms`);

  return lines.join("\n");
}

/**
 * GitHub Actions output format.
 * Emits ::error:: and ::warning:: workflow commands for PR annotations.
 */
export function formatGitHubActions(data: AuditOutputData): string {
  const { summary, findings, decisions, blocked, warnings } = data;
  const lines: string[] = [];

  // Group header
  lines.push("::group::pnpm-audit Security Report");

  // Source status
  for (const [name, status] of Object.entries(summary.sourceStatus)) {
    if (!status.ok) {
      lines.push(`::warning::Source ${name} failed: ${status.error ?? "unknown"}`);
    }
  }

  // Package summary
  lines.push(`Scanned ${summary.totalPackages} packages: ${summary.safePackages} safe, ${summary.packagesWithVulnerabilities} with vulnerabilities`);

  // Severity breakdown
  const sevParts: string[] = [];
  for (const severity of SEVERITY_ORDER) {
    const count = summary.vulnerabilitiesBySeverity[severity];
    if (count > 0) sevParts.push(`${count} ${severity}`);
  }
  if (sevParts.length > 0) lines.push(`Vulnerabilities: ${sevParts.join(", ")}`);

  lines.push("::endgroup::");

  // Emit annotations for findings
  for (const finding of findings) {
    const cvss = typeof finding.cvssScore === "number" ? ` (CVSS ${finding.cvssScore})` : "";
    const fix = finding.fixedVersion ? ` — fix: upgrade to ${finding.fixedVersion}` : "";
    const msg = `${finding.id} [${finding.severity.toUpperCase()}]${cvss} in ${finding.packageName}@${finding.packageVersion}${fix}`;

    if (finding.severity === "critical" || finding.severity === "high") {
      lines.push(`::error file=package.json,title=Vulnerability ${finding.id}::${msg}`);
    } else {
      lines.push(`::warning file=package.json,title=Vulnerability ${finding.id}::${msg}`);
    }
  }

  // Blocked items as errors
  const blockedDecisions = decisions.filter((d) => d.action === "block" && d.source === "source");
  for (const d of blockedDecisions) {
    lines.push(`::error::${d.reason}`);
  }

  // Final status
  if (blocked) {
    lines.push(`::error::AUDIT FAILED — ${summary.blockedCount} issue(s) blocked installation`);
  } else if (warnings) {
    lines.push(`::warning::AUDIT PASSED WITH WARNINGS — ${summary.warnCount} warning(s)`);
  }

  return lines.join("\n");
}

/**
 * Write GitHub Actions outputs directly to the GITHUB_OUTPUT environment file.
 * This is the proper way to set outputs in GitHub Actions — shell echo commands
 * in console.log text don't work.
 */
export function emitGitHubOutputs(
  blocked: boolean,
  total: number,
  critical: number,
  high: number,
): void {
  const githubOutput = process.env.GITHUB_OUTPUT;
  if (!githubOutput) return; // Not in GitHub Actions environment

  const lines = [
    `audit-blocked=${blocked}`,
    `vulnerability-count=${total}`,
    `critical-count=${critical}`,
    `high-count=${high}`,
  ];

  fs.appendFileSync(githubOutput, lines.join("\n") + "\n");
}

export function formatJson(data: AuditOutputData): string {
  return JSON.stringify(data, null, 2);
}

export type OutputFormat = "human" | "azure" | "github" | "json";

export function getOutputFormat(env: Record<string, string | undefined>): OutputFormat {
  if (env.PNPM_AUDIT_JSON === "true") {
    return "json";
  }
  const format = env.PNPM_AUDIT_FORMAT;
  if (format === "azure" || env.TF_BUILD === "True") {
    return "azure";
  }
  if (format === "github" || (env.GITHUB_ACTIONS === "true" && format !== "human")) {
    return "github";
  }
  return "human";
}

export function outputResults(
  data: AuditOutputData,
  format: OutputFormat,
): void {
  // JSON and CI formats: no compact banner, just the structured output
  if (format === "json") {
    console.log(formatJson(data));
    return;
  }
  if (format === "azure") {
    console.log(formatAzureDevOps(data));
    return;
  }
  if (format === "github") {
    console.log(formatGitHubActions(data));
    emitGitHubOutputs(
      data.blocked,
      data.findings.length,
      data.summary.vulnerabilitiesBySeverity.critical,
      data.summary.vulnerabilitiesBySeverity.high,
    );
    return;
  }

  // Human format: always show compact banner
  console.log(formatCompactBanner(data));

  // Show full detailed report ONLY when there are blocked items
  // (warnings get enough detail from the compact banner)
  if (data.blocked) {
    console.log(formatHumanReadable(data));
  }
}
