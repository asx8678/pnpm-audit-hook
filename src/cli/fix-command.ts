/**
 * Audit fix command handler for pnpm-audit-fix.
 *
 * Reads the last audit report, suggests version upgrades for vulnerable
 * packages, runs pnpm update for each fixable finding, and re-audits
 * to confirm the fixes.
 */

import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import type { VulnerabilityFinding } from "../types.js";

/** Interface for the persisted audit report */
interface AuditReport {
  timestamp?: string;
  findings?: VulnerabilityFinding[];
  blocked?: boolean;
  exitCode?: number;
  durationMs?: number;
  sourceStatus?: Record<string, { ok: boolean; durationMs?: number; error?: string }>;
  trend?: {
    previousScanTime: string | null;
    newFindings: number;
    resolvedFindings: number;
    newFindingIds: string[];
    resolvedFindingIds: string[];
  };
}

/** Result of a single package fix attempt */
interface FixAttempt {
  packageName: string;
  currentVersion: string;
  fixedVersion: string | null;
  success: boolean;
  error?: string;
}

/**
 * Run the audit fix command.
 *
 * Reads the last audit report and attempts to fix vulnerable packages
 * by running `pnpm update` for each package with a known fix.
 *
 * @param options - Command options
 * @returns Process exit code
 */
export async function runFixCommand(options?: {
  dryRun?: boolean;
  workspace?: string;
}): Promise<number> {
  const cwd = process.cwd();
  const reportPath = path.resolve(cwd, ".pnpm-audit-cache", "last-audit-report.json");

  // Check for lockfile
  const lockfilePath = path.resolve(cwd, "pnpm-lock.yaml");
  if (!fs.existsSync(lockfilePath)) {
    console.error("Error: No pnpm-lock.yaml found in current directory.");
    console.error("This tool fixes pnpm lockfile vulnerabilities. Run it from a pnpm project root.");
    return 1;
  }

  // Load the last audit report
  if (!fs.existsSync(reportPath)) {
    console.error("Error: No audit report found.");
    console.error(`Expected: ${reportPath}`);
    console.error("");
    console.error("Run 'pnpm-audit-scan' first to generate an audit report.");
    return 1;
  }

  let report: AuditReport;
  try {
    report = JSON.parse(fs.readFileSync(reportPath, "utf-8"));
  } catch (e) {
    console.error(`Error reading audit report: ${(e as Error).message}`);
    return 1;
  }

  console.log("");
  console.log("=== PNPM AUDIT FIX ===");
  console.log(`Report from: ${report.timestamp ? new Date(report.timestamp).toISOString() : "unknown"}`);
  console.log("");

  // Get findings with fix available
  const findings = report.findings ?? [];
  const fixableFindings = findings.filter(
    (f) => f.fixedVersion && !f.fixedVersion.includes("*"),
  );

  if (fixableFindings.length === 0) {
    console.log("No fixable vulnerabilities found.");

    const blockedCount = findings.length;
    if (blockedCount > 0) {
      console.log("");
      console.log(`${blockedCount} vulnerability(ies) found but none have known fixes.`);
      console.log("Consider:");
      console.log("  - Checking for manual workarounds");
      console.log("  - Filing an issue with the vulnerable package");
      console.log("  - Using an allowlist entry for known acceptable risks");
    } else {
      console.log("");
      console.log("✅ No vulnerabilities found!");
    }

    return 0;
  }

  // Deduplicate: group by package and pick the highest fixed version
  const packageFixMap = new Map<string, { fixedVersion: string; findings: VulnerabilityFinding[] }>();
  for (const f of fixableFindings) {
    const pkgKey = f.packageName;
    const existing = packageFixMap.get(pkgKey);
    if (!existing || (f.fixedVersion && compareVersions(f.fixedVersion, existing.fixedVersion) > 0)) {
      packageFixMap.set(pkgKey, {
        fixedVersion: f.fixedVersion!,
        findings: existing ? [...existing.findings, f] : [f],
      });
    } else if (f.fixedVersion) {
      existing.findings.push(f);
    }
  }

  const fixablePackages = Array.from(packageFixMap.entries());
  console.log(`Found ${fixablePackages.length} package(s) with available fixes:`);
  console.log("");

  for (const [pkgName, { fixedVersion, findings: pkgFindings }] of fixablePackages) {
    const uniqueSev = [...new Set(pkgFindings.map((f) => f.severity))];
    console.log(`  📦 ${pkgName}`);
    console.log(`     Fix: update to >=${fixedVersion}`);
    console.log(`     Severity: ${uniqueSev.map((s) => `${severityIcon(s)} ${s}`).join(", ")}`);
    console.log(`     Findings: ${pkgFindings.map((f) => f.id).join(", ")}`);
  }

  console.log("");

  if (options?.dryRun) {
    console.log("Dry-run mode: no changes will be made.");
    console.log("");
    console.log("To apply fixes, run without --dry-run:");
    console.log("  pnpm-audit-fix");
    return 0;
  }

  // Apply fixes
  console.log("Applying fixes...");
  console.log("");

  const attempts: FixAttempt[] = [];
  let successCount = 0;

  for (const [pkgName, { fixedVersion }] of fixablePackages) {
    process.stdout.write(`  Updating ${pkgName} to >=${fixedVersion}... `);

    try {
      const wsFlag = options?.workspace ? `--filter ${options.workspace}` : "";
      const cmd = `pnpm update ${wsFlag} ${pkgName}@>=${fixedVersion}`.trim();
      execSync(cmd, {
        cwd,
        stdio: "pipe",
        timeout: 60_000,
      });

      console.log("✅");
      attempts.push({
        packageName: pkgName,
        currentVersion: "unknown",
        fixedVersion,
        success: true,
      });
      successCount++;
    } catch (e) {
      const errMsg = (e as Error).message.split("\n")[0] ?? "unknown error";
      console.log(`❌ ${errMsg}`);
      attempts.push({
        packageName: pkgName,
        currentVersion: "unknown",
        fixedVersion,
        success: false,
        error: errMsg,
      });
    }
  }

  console.log("");
  console.log(`Fixed ${successCount}/${fixablePackages.length} package(s).`);
  console.log("");

  // Re-audit to confirm
  if (successCount > 0) {
    console.log("Re-auditing to confirm fixes...");
    console.log("");

    try {
      const distEntry = path.join(__dirname, "..", "..", "dist", "index.js");
      if (fs.existsSync(distEntry)) {
        const YAML = await import("yaml");
        const lockfile = YAML.parse(fs.readFileSync(lockfilePath, "utf-8"));

        const distModule = require(distEntry);
        const runAudit = distModule.runAudit;

        const registryUrl =
          process.env.PNPM_REGISTRY ??
          process.env.npm_config_registry ??
          process.env.NPM_CONFIG_REGISTRY ??
          "https://registry.npmjs.org/";

        const result = await runAudit(lockfile, {
          cwd,
          env: process.env,
          registryUrl,
        });

        if (result.blocked) {
          console.log("⚠️  Some vulnerabilities still remain after fixes.");
          console.log(`   Run 'pnpm-audit-scan' for details.`);
        } else if (result.warnings) {
          console.log("✅ All blocking vulnerabilities fixed. Some warnings remain.");
          console.log(`   Run 'pnpm-audit-scan' for details.`);
        } else {
          console.log("✅ All vulnerabilities fixed!");
        }

        return result.exitCode;
      }
    } catch (e) {
      console.log(`Re-audit failed: ${(e as Error).message}`);
      console.log("Run 'pnpm-audit-scan' manually to check status.");
    }
  }

  return successCount > 0 ? 0 : 1;
}

/** Simple severity-to-icon mapping */
function severityIcon(severity: string): string {
  switch (severity) {
    case "critical": return "🔴";
    case "high": return "🟠";
    case "medium": return "🟡";
    case "low": return "🔵";
    default: return "⚪";
  }
}

/** Simple semver comparison: returns >0 if a > b, <0 if a < b, 0 if equal */
function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] ?? 0;
    const nb = pb[i] ?? 0;
    if (na !== nb) return na - nb;
  }
  return 0;
}
