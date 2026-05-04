/**
 * Report command handler for pnpm-audit-report.
 *
 * Displays the last audit report from .pnpm-audit-cache/last-audit-report.json.
 */

import fs from "node:fs";
import path from "node:path";

/**
 * Run the report command.
 *
 * Reads and displays the last audit report from the cache directory.
 *
 * @param options - Command options
 * @returns Process exit code
 */
export function runReportCommand(options?: { format?: string }): number {
  const cwd = process.cwd();
  const reportPath = path.resolve(cwd, ".pnpm-audit-cache", "last-audit-report.json");

  if (!fs.existsSync(reportPath)) {
    console.error("Error: No audit report found.");
    console.error(`Expected: ${reportPath}`);
    console.error("");
    console.error("Run 'pnpm-audit-scan --dry-run' to generate a report first.");
    return 1;
  }

  let report;
  try {
    report = JSON.parse(fs.readFileSync(reportPath, "utf-8"));
  } catch (e) {
    console.error(`Error reading report: ${(e as Error).message}`);
    return 1;
  }

  const format = options?.format ?? "human";

  if (format === "json") {
    console.log(JSON.stringify(report, null, 2));
    return 0;
  }

  // Human-readable format
  const { summary, decisions, blocked, warnings, exitCode } = report;

  console.log("");
  console.log("=== PNPM AUDIT REPORT ===");
  console.log(`Generated: ${new Date(report.timestamp || Date.now()).toISOString()}`);
  console.log("");

  // Summary
  console.log("--- Summary ---");
  console.log(`  Total packages: ${summary.totalPackages}`);
  console.log(`  Safe packages: ${summary.safePackages}`);
  console.log(`  With vulnerabilities: ${summary.packagesWithVulnerabilities}`);
  console.log("");

  // Severities
  console.log("--- Vulnerabilities by Severity ---");
  const sevOrder = ["critical", "high", "medium", "low", "unknown"] as const;
  for (const sev of sevOrder) {
    const count = summary.vulnerabilitiesBySeverity[sev];
    if (count > 0) {
      console.log(`  ${sev.toUpperCase()}: ${count}`);
    }
  }
  console.log("");

  // Policy decisions
  console.log("--- Policy Decisions ---");
  console.log(`  Blocked: ${summary.blockedCount}`);
  console.log(`  Warnings: ${summary.warnCount}`);
  console.log(`  Allowed: ${summary.allowedCount}`);
  console.log(`  Allowlisted: ${summary.allowlistedCount}`);
  console.log("");

  // Source status
  if (report.sourceStatus) {
    console.log("--- Source Status ---");
    for (const [name, status] of Object.entries(report.sourceStatus) as Array<[string, { ok: boolean; durationMs?: number; error?: string }]>) {
      const icon = status.ok ? "✅" : "❌";
      const duration = status.durationMs != null ? ` (${status.durationMs}ms)` : "";
      const error = !status.ok && status.error ? ` — ${status.error}` : "";
      console.log(`  ${icon} ${name}${duration}${error}`);
    }
    console.log("");
  }

  // Trend analysis
  if (report.trend) {
    console.log("--- Trend Analysis ---");
    if (report.trend.previousScanTime) {
      const prevDate = new Date(report.trend.previousScanTime);
      console.log(`  Previous scan: ${prevDate.toISOString()}`);
    } else {
      console.log("  Previous scan: (none — first scan)");
    }
    if (report.trend.newFindings > 0) {
      console.log(`  🆕 New findings: ${report.trend.newFindings}`);
      for (const id of report.trend.newFindingIds ?? []) {
        console.log(`     - ${id}`);
      }
    } else {
      console.log("  🆕 New findings: 0");
    }
    if (report.trend.resolvedFindings > 0) {
      console.log(`  ✅ Resolved: ${report.trend.resolvedFindings}`);
      for (const id of report.trend.resolvedFindingIds ?? []) {
        console.log(`     - ${id}`);
      }
    } else {
      console.log("  ✅ Resolved: 0");
    }
    console.log("");
  }

  // Blocked items
  const blockedDecisions = decisions.filter((d: { action: string }) => d.action === "block");
  if (blockedDecisions.length > 0) {
    console.log("--- Blocked Items ---");
    for (const d of blockedDecisions) {
      const pkg = d.packageName ? `${d.packageName}@${d.packageVersion}` : "unknown";
      const ws = d.workspace && d.workspace !== "." ? ` [workspace: ${d.workspace}]` : "";
      const finding = d.findingId ? ` (${d.findingId})` : "";
      console.log(`  🚫 ${pkg}${finding}${ws}: ${d.reason}`);
    }
    console.log("");
  }

  // Duration
  if (report.durationMs != null) {
    console.log(`Duration: ${report.durationMs}ms`);
    console.log("");
  }

  // Status
  console.log("--- Status ---");
  if (blocked) {
    console.log("  ❌ AUDIT FAILED - Installation would be blocked");
  } else if (warnings) {
    console.log("  ⚠️  AUDIT PASSED WITH WARNINGS");
  } else {
    console.log("  ✅ AUDIT PASSED - No issues found");
  }
  console.log("");

  return exitCode ?? 0;
}
