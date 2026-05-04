/**
 * Main CLI entry point for pnpm-audit-scan.
 *
 * Parses arguments and routes to the appropriate command handler.
 */

import fs from "node:fs";
import path from "node:path";
import { parseArgs, HELP } from "./cli/parse-args.js";
import { runAuditCommand } from "./cli/audit-command.js";
import { runSbomDiffCommand, runValidateSbomCommand, runDepTreeCommand } from "./cli/sbom-command.js";
import { runReportCommand } from "./cli/report-command.js";
import { runFixCommand } from "./cli/fix-command.js";
import type { StaticDbCoverage, StaticDbIndex } from "./static-db/types.js";

/** Read version from package.json */
function getVersion(): string {
  try {
    const pkg = JSON.parse(
      fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf-8"),
    );
    return pkg.version;
  } catch {
    return "unknown";
  }
}

function formatCoverageSummary(
  coverage: StaticDbCoverage | undefined,
): { summary: string; warning?: string } {
  if (!coverage) {
    return { summary: "Legacy/unknown coverage metadata" };
  }

  if (coverage.mode === "full") {
    return { summary: "Full history" };
  }

  if (coverage.mode === "sample") {
    return {
      summary: "Sample/demo data",
      warning: "Sample/demo DB is not production coverage.",
    };
  }

  const years = coverage.retentionYears != null ? `${coverage.retentionYears} years` : "filtered";
  const since = coverage.sinceDate ?? "unknown date";
  return {
    summary: `Recent only, ${years} since ${since}`,
    warning: `Older vulnerabilities before ${since} may not be detected by the static DB.`,
  };
}

/** Show troubleshooting information */
function showTroubleshoot(): void {
  console.log("pnpm-audit-hook Troubleshooting Information");
  console.log("==========================================");
  console.log("");

  // Version info
  console.log("1. Version Information:");
  console.log(`   pnpm-audit-hook: ${getVersion()}`);
  console.log(`   Node.js: ${process.version}`);
  console.log("");

  // System info
  console.log("2. System Information:");
  console.log(`   Platform: ${process.platform}`);
  console.log(`   Architecture: ${process.arch}`);
  console.log(`   Current directory: ${process.cwd()}`);
  console.log("");

  // Check for lockfile
  const lockfilePath = path.resolve(process.cwd(), "pnpm-lock.yaml");
  console.log("3. Project Checks:");
  console.log(`   pnpm-lock.yaml: ${fs.existsSync(lockfilePath) ? "✅ Found" : "❌ Not found"}`);

  const configPath = path.resolve(process.cwd(), ".pnpm-audit.yaml");
  console.log(`   .pnpm-audit.yaml: ${fs.existsSync(configPath) ? "✅ Found" : "❌ Not found"}`);

  const pnpmfilePath = path.resolve(process.cwd(), ".pnpmfile.cjs");
  console.log(`   .pnpmfile.cjs: ${fs.existsSync(pnpmfilePath) ? "✅ Found" : "❌ Not found"}`);
  console.log("");

  // Environment variables
  console.log("4. Environment Variables:");
  const envVars = [
    "PNPM_AUDIT_OFFLINE",
    "PNPM_AUDIT_QUIET",
    "PNPM_AUDIT_VERBOSE",
    "PNPM_AUDIT_DEBUG",
    "PNPM_AUDIT_BLOCK_SEVERITY",
    "PNPM_AUDIT_DISABLE_GITHUB",
    "PNPM_AUDIT_DISABLE_OSV",
    "PNPM_AUDIT_DISABLE_NVD",
    "PNPM_AUDIT_DISABLE_STATIC_DB",
    "GITHUB_TOKEN",
    "NVD_API_KEY",
  ];
  for (const envVar of envVars) {
    const value = process.env[envVar];
    if (value !== undefined) {
      console.log(`   ${envVar}: ${envVar.includes("TOKEN") || envVar.includes("KEY") ? "***" : value}`);
    }
  }
  console.log("");

  // Network checks
  console.log("5. Network Checks:");
  console.log("   To test network connectivity, run:");
  console.log("     curl -I https://api.osv.dev/v1/query");
  console.log("     curl -I https://api.github.com/rate_limit");
  console.log("");

  // Common solutions
  console.log("6. Common Solutions:");
  console.log("   - If 'AUDIT FAILED': Review findings with 'pnpm-audit-scan --format json'");
  console.log("   - If slow: Set GITHUB_TOKEN or use --offline");
  console.log("   - If not found: Run 'pnpm add -g pnpm-audit-hook'");
  console.log("   - For detailed help: See docs/troubleshooting.md");
  console.log("");
}

/** Show database status */
async function showDbStatus(): Promise<number> {
  const pkgRoot = path.join(__dirname, "..");
  const dataPath = path.join(pkgRoot, "dist", "static-db", "data");
  const defaultCutoffDate = "2025-12-31";

  try {
    const { createStaticDbReader } = require(path.join(pkgRoot, "dist", "static-db", "reader.js"));

    const reader = await createStaticDbReader({
      dataPath,
      cutoffDate: defaultCutoffDate,
    });

    if (!reader) {
      console.error("Database not loaded or not ready.");
      return 1;
    }

    const index = reader.getIndex() as StaticDbIndex | null;
    const coverage = formatCoverageSummary(index?.coverage);

    console.log("Database Status");
    console.log("───────────────");
    console.log(`  Loaded & ready:    ${reader.isReady() ? "\u2713 Yes" : "\u2717 No"}`);
    console.log(`  DB version:        ${index?.lastUpdated || "unknown"}`);
    console.log(`  Cutoff date:       ${reader.getCutoffDate()}`);
    console.log(`  Total vulns:       ${index?.totalVulnerabilities ?? "unknown"}`);
    console.log(`  Total packages:    ${index?.totalPackages ?? "unknown"}`);
    console.log(`  Schema version:    ${index?.schemaVersion ?? "unknown"}`);
    console.log(`  Coverage:          ${coverage.summary}`);
    if (coverage.warning) {
      console.warn(`  Warning:           ${coverage.warning}`);
    }

    if (index?.buildInfo) {
      const bi = index.buildInfo;
      if (bi.generator) {
        console.log(`  Generator:         ${bi.generator}`);
      }
      if (bi.sources) {
        console.log(`  Sources:           ${bi.sources.join(", ")}`);
      }
      if (bi.durationMs != null) {
        console.log(`  Build duration:    ${bi.durationMs}ms`);
      }
    }

    // Consistency check
    try {
      const { analyzeStaticDbConsistency } = require(path.join(
        pkgRoot,
        "dist",
        "static-db",
        "consistency.js",
      ));
      const report = await analyzeStaticDbConsistency(dataPath);

      console.log("");
      console.log("Consistency");
      console.log("───────────");
      console.log(`  Index loaded:               ${report.indexLoaded ? "\u2713 Yes" : "\u2717 No"}`);
      console.log(`  Indexed packages:           ${report.indexedPackageCount}`);
      console.log(`  Shard files on disk:        ${report.shardFileCount}`);
      console.log(`  Orphan shards:              ${report.orphanShards.length}`);
      console.log(`  Missing shards:             ${report.missingShards.length}`);
      console.log(`  Count mismatches:           ${report.countMismatches.length}`);
      console.log(`  Package name mismatches:    ${report.packageNameMismatches.length}`);
      console.log(`  Metadata mismatches:        ${report.metadataMismatches.length}`);
      console.log(`  Consistent:                 ${report.isConsistent ? "\u2713 Yes" : "\u2717 No"}`);
    } catch {
      // Consistency check is best-effort; don't fail the status command
    }

    return 0;
  } catch (e) {
    console.error(`Error reading database status: ${(e as Error).message}`);
    return 1;
  }
}

/** Run database update */
function runUpdateDb(mode: "incremental" | "full"): number {
  const { spawnSync } = require("node:child_process");
  const pkgRoot = path.join(__dirname, "..");
  const scriptPath = path.join(pkgRoot, "scripts", "update-vuln-db.ts");
  const tsxPath = path.join(pkgRoot, "node_modules", ".bin", "tsx");
  const updateArgs = mode === "full" ? [scriptPath] : [scriptPath, "--incremental"];

  console.log(`Updating vulnerability database (${mode})...\n`);

  const result = spawnSync(tsxPath, updateArgs, {
    stdio: "inherit",
    cwd: pkgRoot,
  });

  if (result.error) {
    console.error(`Error: Failed to run DB update: ${result.error.message}`);
    console.error("Make sure tsx is installed (pnpm install) and scripts/update-vuln-db.ts exists.");
    return 1;
  }

  return result.status ?? 1;
}

/**
 * Main entry point for the CLI.
 */
export async function main(argv: string[]): Promise<number> {
  const args = parseArgs(argv);

  // Reject unknown flags
  if (args.unknownFlags && args.unknownFlags.length > 0) {
    console.error(`Error: Unknown flag(s): ${args.unknownFlags.join(", ")}`);
    console.error("");
    console.error("Run with --help to see available options.");
    return 1;
  }

  if (args.help) {
    console.log(HELP);
    return 0;
  }

  if (args.version) {
    console.log(getVersion());
    return 0;
  }

  if (args.troubleshoot) {
    showTroubleshoot();
    return 0;
  }

  // Handle SBOM diff mode (no lockfile required)
  if (args.sbomDiff) {
    return runSbomDiffCommand(args);
  }

  // Handle SBOM validation mode (no lockfile required)
  if (args.validateSbom) {
    return runValidateSbomCommand(args);
  }

  // Handle dependency tree mode
  if (args.depTree) {
    return runDepTreeCommand(args);
  }

  // Handle report mode
  if (args.help === false && process.argv.includes("--report")) {
    return runReportCommand({ format: args.format });
  }

  // Handle fix mode
  if (args.fix) {
    return runFixCommand({
      dryRun: args.dryRun,
      workspace: args.workspace,
    });
  }

  if (args.updateDb) {
    return runUpdateDb(args.updateDb);
  }

  if (args.dbStatus) {
    return showDbStatus();
  }

  // Default: run audit
  return runAuditCommand(args);
}

// Run when executed directly (not imported as module)
// Check if this is the main module using CommonJS pattern
if (require.main === module) {
  main(process.argv.slice(2)).then((exitCode) => {
    process.exit(exitCode);
  });
}
