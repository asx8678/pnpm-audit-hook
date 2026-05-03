#!/usr/bin/env tsx
// =============================================================================
// basic-usage.ts — Core Audit API Demo
// =============================================================================
//
// Demonstrates the fundamental pnpm-audit-hook API:
//   - Setting up runtime options and lockfile parsing
//   - Running a complete vulnerability audit
//   - Reading configuration from .pnpm-audit.yaml
//   - Processing and grouping findings by severity
//   - Checking for fixable vulnerabilities
//   - Handling exit codes properly
//
// Prerequisites:
//   - Node.js >= 18
//   - Project dependencies installed (`pnpm install`)
//   - Run from project root: npx tsx examples/basic-usage.ts
// =============================================================================

import fs from "node:fs/promises";
import path from "node:path";

// ---------------------------------------------------------------------------
// Imports from pnpm-audit-hook source (relative to this file)
// ---------------------------------------------------------------------------
import {
  createPnpmHooks,
  runAudit,
  EXIT_CODES,
} from "../src/index";

import type {
  AuditResult,
  PnpmLockfile,
  RuntimeOptions,
  VulnerabilityFinding,
} from "../src/index";

// ---------------------------------------------------------------------------
// Example lockfile — a minimal pnpm lockfile structure for demonstration.
// In a real project, you'd parse your actual pnpm-lock.yaml.
// ---------------------------------------------------------------------------
const DEMO_LOCKFILE: PnpmLockfile = {
  lockfileVersion: "9.0",
  importers: {
    ".": {
      dependencies: {
        express: { version: "4.18.2" },
        lodash: { version: "4.17.21" },
      },
      devDependencies: {
        typescript: { version: "5.3.3" },
      },
    },
  },
  packages: {
    "express@4.18.2": {
      dependencies: {
        "accepts": "~1.3.8",
        "body-parser": "1.20.2",
      },
    },
    "accepts@1.3.8": {
      dependencies: {
        "negotiator": "0.6.3",
      },
    },
    "body-parser@1.20.2": {
      dependencies: {
        "bytes": "3.1.2",
        "debug": "4.3.4",
      },
    },
    "lodash@4.17.21": {},
    "typescript@5.3.3": {},
    "negotiator@0.6.3": {},
    "bytes@3.1.2": {},
    "debug@4.3.4": {
      dependencies: {
        "ms": "2.1.2",
      },
    },
    "ms@2.1.2": {},
  },
};

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║     pnpm-audit-hook — Basic Usage Example                  ║");
  console.log("╚══════════════════════════════════════════════════════════════╝\n");

  // -------------------------------------------------------------------------
  // Step 1: Create the runtime options
  // -------------------------------------------------------------------------
  console.log("▸ Step 1: Setting up runtime options…");

  const runtime: RuntimeOptions = {
    cwd: process.cwd(),
    registryUrl: process.env.NPM_CONFIG_REGISTRY ?? "https://registry.npmjs.org",
    env: process.env,
  };

  console.log(`  cwd:          ${runtime.cwd}`);
  console.log(`  registryUrl:  ${runtime.registryUrl}`);
  console.log(`  node version: ${process.version}\n`);

  // -------------------------------------------------------------------------
  // Step 2: Load configuration (optional, but useful to inspect)
  // -------------------------------------------------------------------------
  console.log("▸ Step 2: Loading configuration…");

  try {
    // The config is loaded automatically by runAudit(), but you can also
    // load it explicitly to inspect or pre-validate settings.
    const configPath = path.join(process.cwd(), ".pnpm-audit.yaml");
    const configFile = await fs.readFile(configPath, "utf-8");
    const config = JSON.parse(configFile);

    console.log(`  Config file: ${configPath}`);
    console.log(`  Block severities: ${config?.policy?.block?.join(", ") ?? "default"}`);
    console.log(`  Warn severities:  ${config?.policy?.warn?.join(", ") ?? "default"}`);
    console.log();
  } catch {
    console.log("  No .pnpm-audit.yaml found — using defaults.\n");
  }

  // -------------------------------------------------------------------------
  // Step 3: Run the audit
  // -------------------------------------------------------------------------
  console.log("▸ Step 3: Running audit…");

  let result: AuditResult;
  try {
    result = await runAudit(DEMO_LOCKFILE, runtime);
  } catch (err) {
    console.error("  ✖ Audit threw an error:");
    console.error(`    ${err instanceof Error ? err.message : String(err)}\n`);
    // In a real project you might want to process.exit(1) here,
    // but for the demo we'll just return.
    return;
  }

  // -------------------------------------------------------------------------
  // Step 4: Inspect the audit result
  // -------------------------------------------------------------------------
  console.log("▸ Step 4: Processing results…\n");

  printResultSummary(result);

  // -------------------------------------------------------------------------
  // Step 5: Group findings by severity
  // -------------------------------------------------------------------------
  console.log("▸ Step 5: Findings grouped by severity…\n");

  const grouped = groupBySeverity(result.findings);
  for (const [severity, findings] of Object.entries(grouped)) {
    console.log(`  ${severity.toUpperCase()} (${findings.length}):`);
    for (const f of findings) {
      console.log(`    • ${f.packageName}@${f.packageVersion} — ${f.id}`);
      if (f.fixedVersion) {
        console.log(`      └─ fix available: upgrade to ${f.fixedVersion}`);
      }
    }
  }
  if (result.findings.length === 0) {
    console.log("  (no vulnerabilities found — 🎉)");
  }
  console.log();

  // -------------------------------------------------------------------------
  // Step 6: Check for fixable vulnerabilities
  // -------------------------------------------------------------------------
  console.log("▸ Step 6: Fixable vulnerabilities…\n");

  const fixable = result.findings.filter((f) => f.fixedVersion);
  if (fixable.length > 0) {
    console.log(`  ${fixable.length} issue(s) can be fixed by upgrading:\n`);
    for (const f of fixable) {
      console.log(
        `    ${f.packageName}@${f.packageVersion} → ${f.fixedVersion}  (${f.id})`,
      );
    }
  } else {
    console.log("  No fixable vulnerabilities (or no vulnerabilities at all).");
  }
  console.log();

  // -------------------------------------------------------------------------
  // Step 7: Handle exit codes
  // -------------------------------------------------------------------------
  console.log("▸ Step 7: Exit code handling…\n");

  switch (result.exitCode) {
    case EXIT_CODES.SUCCESS:
      console.log("  ✅ SUCCESS — No blocking issues. Safe to install.");
      break;
    case EXIT_CODES.BLOCKED:
      console.log("  🛑 BLOCKED — Installation was prevented by policy.");
      console.log(`     ${result.decisions.filter((d) => d.action === "block").length} block decision(s) made.`);
      break;
    case EXIT_CODES.WARNINGS:
      console.log("  ⚠️  WARNINGS — Issues found but not blocking.");
      console.log(`     ${result.warnings} warning(s) issued.`);
      break;
    case EXIT_CODES.SOURCE_ERROR:
      console.log("  ❌ SOURCE ERROR — A vulnerability source failed.");
      for (const [name, status] of Object.entries(result.sourceStatus)) {
        if (!status.ok) {
          console.log(`     ${name}: ${status.error}`);
        }
      }
      break;
    default:
      console.log(`  Unknown exit code: ${result.exitCode}`);
  }
  console.log();

  // -------------------------------------------------------------------------
  // Step 8: Using the pnpm hooks API (demonstration only, not actually wiring)
  // -------------------------------------------------------------------------
  console.log("▸ Step 8: pnpm hooks API (createPnpmHooks)…\n");

  const hooks = createPnpmHooks();
  console.log("  Created pnpm hooks object:");
  console.log(`    hooks.afterAllResolved: ${typeof hooks.hooks.afterAllResolved}`);
  console.log("  (This is what you export from .pnpmfile.cjs)\n");

  // -------------------------------------------------------------------------
  // Done!
  // -------------------------------------------------------------------------
  console.log("─".repeat(62));
  console.log("Done! All basic usage steps completed. 🐶");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Print a formatted summary of the audit result.
 *
 * @param result - The complete audit result from runAudit()
 */
function printResultSummary(result: AuditResult) {
  console.log(`  Total packages audited:  ${result.totalPackages}`);
  console.log(`  Vulnerabilities found:   ${result.findings.length}`);
  console.log(`  Policy decisions made:   ${result.decisions.length}`);
  console.log(`  Audit duration:          ${result.durationMs}ms`);
  console.log(`  Blocked:                 ${result.blocked}`);
  console.log(`  Warnings:                ${result.warnings}`);
  console.log(`  Exit code:               ${result.exitCode}`);

  console.log("\n  Source status:");
  for (const [name, status] of Object.entries(result.sourceStatus)) {
    const icon = status.ok ? "✅" : "❌";
    const detail = status.ok
      ? `OK (${status.durationMs}ms)`
      : `ERROR: ${status.error}`;
    console.log(`    ${icon} ${name}: ${detail}`);
  }
  console.log();
}

/**
 * Group vulnerability findings by their severity level.
 *
 * @param findings - Array of vulnerability findings to group
 * @returns An object mapping severity names to arrays of findings
 */
function groupBySeverity(
  findings: VulnerabilityFinding[],
): Record<string, VulnerabilityFinding[]> {
  return findings.reduce(
    (acc, f) => {
      (acc[f.severity] ??= []).push(f);
      return acc;
    },
    {} as Record<string, VulnerabilityFinding[]>,
  );
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------
main().catch((err) => {
  console.error("Unhandled error:", err);
  process.exit(1);
});
