import fs from "node:fs";
import type {
  PolicyDecision,
  Severity,
  SourceStatus,
  VulnerabilityFinding,
} from "../types";
import type { AuditSummary, AuditOutputData, OutputFormat } from "./formatters";
import {
  SEVERITY_ORDER,
  severityColor,
  BOLD,
  GREEN,
  RED,
  YELLOW,
  CYAN,
  DIM,
  RESET,
  horizontalLine,
  sectionHeader,
  subsectionHeader,
  indent,
  listItem,
  statusText,
  severityLabel,
  truncate,
  pad,
} from "./formatters/base-formatter";
import { formatAzureDevOps } from "./formatters/azure-devops";
import { formatGitHubActions } from "./formatters/github-actions";
import { formatCodeBuild } from "./formatters/aws-codebuild";
import { getOutputFormatFromEnv } from "./env-manager";

// Re-export for backward compatibility
export type { AuditSummary, AuditOutputData, OutputFormat } from "./formatters";
export { formatGitHubActions } from "./formatters/github-actions";
export { formatAzureDevOps } from "./formatters/azure-devops";

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
      .map(s => `${severityColor(s)}${sevCounts[s]} ${s}${RESET}`);
    const sevDetail = sevParts.length > 0 ? ` (${sevParts.join(", ")})` : "";
    statusChip = `${BOLD}${YELLOW}⚠️  ${count} warning${count !== 1 ? "s" : ""}${sevDetail}${RESET}`;
  } else {
    statusChip = `${GREEN}✅ clean${RESET}`;
  }

  // Main banner line
  const durationStr = `${summary.totalDurationMs}ms`;
  lines.push(
    `${BOLD}🛡️  pnpm-audit${RESET} ── ${summary.totalPackages} packages ── ${sourceLine} ── ${statusChip} ── ${DIM}${durationStr}${RESET}`
  );

  // Detail lines for blocked items (show CVE, severity, package, title, fix)
  const blockedDecisions = decisions.filter(d => d.action === "block" && d.findingId);
  for (const d of blockedDecisions) {
    const sev = d.findingSeverity ? severityLabel(d.findingSeverity) : "";
    const pkg = d.packageName ? `${BOLD}${d.packageName}@${d.packageVersion}${RESET}` : "";
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
      const sev = d.findingSeverity ? severityLabel(d.findingSeverity) : "";
      const pkg = d.packageName ? `${BOLD}${d.packageName}@${d.packageVersion}${RESET}` : "";
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
  lines.push(sectionHeader("PNPM AUDIT SECURITY REPORT"));
  lines.push("");

  // Source status group
  lines.push(subsectionHeader("Source Status"));
  for (const [name, status] of Object.entries(summary.sourceStatus)) {
    const statusStr = statusText(status.ok, `${name}: ${status.ok ? 'OK' : 'FAILED'}`);
    const duration = `${DIM} (${status.durationMs}ms)${RESET}`;
    const error = status.error ? ` ${RED}- ${status.error}${RESET}` : "";
    lines.push(`  ${statusStr}${duration}${error}`);
  }
  lines.push("");

  // Package summary
  lines.push(subsectionHeader("Package Summary"));
  lines.push(`  Total packages scanned: ${BOLD}${summary.totalPackages}${RESET}`);
  lines.push(`  Safe packages: ${GREEN}${summary.safePackages}${RESET}`);
  lines.push(
    `  Packages with vulnerabilities: ${summary.packagesWithVulnerabilities > 0 ? RED : GREEN}${summary.packagesWithVulnerabilities}${RESET}`,
  );
  lines.push("");

  // Vulnerability breakdown by severity
  lines.push(subsectionHeader("Vulnerabilities by Severity"));
  for (const severity of SEVERITY_ORDER) {
    const count = summary.vulnerabilitiesBySeverity[severity];
    if (count > 0) {
      lines.push(`  ${severityLabel(severity)}: ${count}`);
    }
  }
  if (findings.length === 0) {
    lines.push(`  ${GREEN}✓ No vulnerabilities found${RESET}`);
  }
  lines.push("");

  // Detailed vulnerability list
  if (findings.length > 0) {
    lines.push(subsectionHeader("Vulnerability Details"));
    for (const finding of findings) {
      const cvssStr = typeof finding.cvssScore === "number" ? ` (CVSS ${finding.cvssScore})` : "";
      lines.push(`  ${severityLabel(finding.severity)} ${finding.id}${cvssStr}`);
      lines.push(`    Package: ${BOLD}${finding.packageName}@${finding.packageVersion}${RESET}`);
      if (finding.title) {
        lines.push(`    Title: ${finding.title}`);
      }
      if (finding.url) {
        lines.push(`    URL: ${CYAN}${finding.url}${RESET}`);
      }
      if (finding.affectedRange) {
        lines.push(`    Affected: ${finding.affectedRange}`);
      }
      if (finding.fixedVersion) {
        lines.push(`    Fixed in: ${GREEN}${finding.fixedVersion}${RESET}`);
      }

      // Enhanced chain context
      const ctx = finding.chainContext;
      if (ctx) {
        const depType = ctx.isDirect ? `${GREEN}direct dependency${RESET}` : `${YELLOW}transitive dependency${RESET}`;
        lines.push(`    Dependency type: ${depType}`);
        if (!ctx.isDirect && ctx.chainDepth > 0) {
          lines.push(`    Chain depth: ${ctx.chainDepth} level${ctx.chainDepth !== 1 ? "s" : ""} from nearest direct dependency`);
        }
        if (ctx.totalAffected > 0) {
          lines.push(`    Blast radius: ${ctx.totalAffected} package${ctx.totalAffected !== 1 ? "s" : ""} affected transitively`);
        }
        if (ctx.propagatedSeverity !== finding.severity) {
          lines.push(`    Propagated severity: ${severityLabel(ctx.propagatedSeverity)} (adjusted for chain context)`);
        }
        if (ctx.directAncestors.length > 0) {
          lines.push(`    Introduced by: ${ctx.directAncestors.join(", ")}`);
        }
        lines.push(`    Risk score: ${BOLD}${ctx.compositeRiskScore}/10${RESET}`);
      }

      // CVSS exploitability details
      if (finding.cvssDetails && finding.cvssDetails.attackVector !== "unknown") {
        lines.push(`    Exploitability: ${finding.cvssDetails.exploitabilityLabel}`);
      }

      lines.push("");
    }
  }

  // Policy decision summary
  lines.push(subsectionHeader("Policy Decisions"));
  lines.push(`  ${RED}Blocked${RESET}: ${summary.blockedCount}`);
  lines.push(`  ${YELLOW}Warnings${RESET}: ${summary.warnCount}`);
  lines.push(`  ${GREEN}Allowed${RESET}: ${summary.allowedCount}`);
  lines.push(`  Allowlisted: ${summary.allowlistedCount}`);
  lines.push("");

  // Show blocked decisions
  const blockedDecisions = decisions.filter((d) => d.action === "block");
  if (blockedDecisions.length > 0) {
    lines.push(subsectionHeader("Blocked Items"));
    for (const d of blockedDecisions) {
      const pkg = d.packageName ? `${BOLD}${d.packageName}@${d.packageVersion}${RESET}` : "";
      const finding = d.findingId ? ` (${d.findingId})` : "";
      lines.push(`  ${RED}🚫${RESET} ${pkg}${finding}: ${d.reason}`);
    }
    lines.push("");
  }

  // Final status line
  lines.push(sectionHeader("STATUS"));
  if (blocked) {
    lines.push(`${BOLD}${RED}AUDIT FAILED - Installation blocked${RESET}`);
  } else if (warnings) {
    lines.push(`${BOLD}${YELLOW}AUDIT PASSED WITH WARNINGS${RESET}`);
  } else {
    lines.push(`${BOLD}${GREEN}AUDIT PASSED - No issues found${RESET}`);
  }
  lines.push(`
${DIM}Source query time: ${summary.totalDurationMs}ms${RESET}`);
  lines.push("");

  return lines.join("\n");
}

export function formatJson(data: AuditOutputData): string {
  return JSON.stringify(data, null, 2);
}

/**
 * Format a progress indicator for long operations.
 */
export function formatProgress(
  current: number,
  total: number,
  label: string,
  startTime?: number
): string {
  const percent = total > 0 ? Math.round((current / total) * 100) : 0;
  const barLength = 20;
  const filled = Math.round((current / total) * barLength);
  const bar = '█'.repeat(filled) + '░'.repeat(barLength - filled);
  
  let etaStr = '';
  if (startTime && current > 0) {
    const elapsed = Date.now() - startTime;
    const estimatedTotal = (elapsed / current) * total;
    const remaining = Math.max(0, estimatedTotal - elapsed);
    
    if (remaining < 1000) {
      etaStr = ' <1s';
    } else if (remaining < 60000) {
      etaStr = ` ${Math.round(remaining / 1000)}s`;
    } else {
      const minutes = Math.floor(remaining / 60000);
      const seconds = Math.round((remaining % 60000) / 1000);
      etaStr = ` ${minutes}m ${seconds}s`;
    }
  }
  
  return `${BOLD}${label}${RESET} [${bar}] ${percent}%${etaStr}`;
}

/**
 * Format an error message with clear boundaries and actionable suggestions.
 */
export function formatError(
  title: string,
  details: string[],
  suggestions: string[] = []
): string {
  const lines: string[] = [];
  
  lines.push("");
  lines.push(`${BOLD}${RED}╔══════════════════════════════════════════════════════════╗${RESET}`);
  lines.push(`${BOLD}${RED}║  ERROR: ${title.padEnd(50)}║${RESET}`);
  lines.push(`${BOLD}${RED}╚══════════════════════════════════════════════════════════╝${RESET}`);
  
  for (const detail of details) {
    lines.push(`${RED}  • ${detail}${RESET}`);
  }
  
  if (suggestions.length > 0) {
    lines.push("");
    lines.push(`${BOLD}${YELLOW}Suggestions:${RESET}`);
    for (const suggestion of suggestions) {
      lines.push(`${YELLOW}  → ${suggestion}${RESET}`);
    }
  }
  
  lines.push("");
  return lines.join("\n");
}

/**
 * Format a warning message.
 */
export function formatWarning(title: string, details: string[]): string {
  const lines: string[] = [];
  
  lines.push("");
  lines.push(`${BOLD}${YELLOW}╔══════════════════════════════════════════════════════════╗${RESET}`);
  lines.push(`${BOLD}${YELLOW}║  WARNING: ${title.padEnd(49)}║${RESET}`);
  lines.push(`${BOLD}${YELLOW}╚══════════════════════════════════════════════════════════╝${RESET}`);
  
  for (const detail of details) {
    lines.push(`${YELLOW}  • ${detail}${RESET}`);
  }
  
  lines.push("");
  return lines.join("\n");
}

/**
 * Format a success message.
 */
export function formatSuccess(title: string, details: string[] = []): string {
  const lines: string[] = [];
  
  lines.push("");
  lines.push(`${BOLD}${GREEN}╔══════════════════════════════════════════════════════════╗${RESET}`);
  lines.push(`${BOLD}${GREEN}║  ✓ ${title.padEnd(53)}║${RESET}`);
  lines.push(`${BOLD}${GREEN}╚══════════════════════════════════════════════════════════╝${RESET}`);
  
  for (const detail of details) {
    lines.push(`${GREEN}  • ${detail}${RESET}`);
  }
  
  lines.push("");
  return lines.join("\n");
}

export function getOutputFormat(env: Record<string, string | undefined>): OutputFormat {
  // Delegate to env-manager for consistent environment variable handling
  const format = getOutputFormatFromEnv(env);
  
  // Ensure backward compatibility by validating the returned format
  const validFormats: OutputFormat[] = ["human", "json", "azure", "github", "aws"];
  if (validFormats.includes(format as OutputFormat)) {
    return format as OutputFormat;
  }
  
  return "human";
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
  if (format === "aws") {
    console.log(formatCodeBuild(data));
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
