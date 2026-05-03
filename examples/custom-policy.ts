#!/usr/bin/env tsx
// =============================================================================
// custom-policy.ts — Policy Engine Demo
// =============================================================================
//
// Demonstrates the policy engine for evaluating vulnerability findings:
//   - Defining custom block/warn severity lists
//   - Creating allowlist exceptions by CVE ID or package name
//   - Using version constraints on allowlist entries
//   - Setting expiration dates for temporary exceptions
//   - Configuring transitive severity downgrade
//   - Evaluating vulnerability findings against policies
//   - Building and inspecting policy decisions
//
// Prerequisites:
//   - Node.js >= 18
//   - Project built (`pnpm run build` in the project root)
//   - Run from project root: npx tsx examples/custom-policy.ts
// =============================================================================

import fs from "node:fs/promises";
import path from "node:path";
import YAML from "yaml";

// ---------------------------------------------------------------------------
// Imports from the built package
// ---------------------------------------------------------------------------
import {
  runAudit,
  EXIT_CODES,
} from "../dist/index.js";

import type {
  AuditConfigInput,
  AuditResult,
  PnpmLockfile,
  RuntimeOptions,
  Severity,
  VulnerabilityFinding,
  PolicyDecision,
} from "../dist/index.js";

// ---------------------------------------------------------------------------
// Demo lockfile with a variety of packages
// ---------------------------------------------------------------------------
const POLICY_LOCKFILE: PnpmLockfile = {
  lockfileVersion: "9.0",
  importers: {
    ".": {
      dependencies: {
        express: { version: "4.18.2" },
        lodash: { version: "4.17.21" },
        axios: { version: "0.21.1" },
      },
      devDependencies: {
        typescript: { version: "5.3.3" },
        "ts-node": { version: "10.9.2" },
      },
    },
  },
  packages: {
    "express@4.18.2": { dependencies: { "body-parser": "1.20.2" } },
    "body-parser@1.20.2": { dependencies: { "debug": "4.3.4" } },
    "debug@4.3.4": { dependencies: { "ms": "2.1.2" } },
    "ms@2.1.2": {},
    "lodash@4.17.21": {},
    "axios@0.21.1": { dependencies: { "follow-redirects": "1.14.8" } },
    "follow-redirects@1.14.8": {},
    "typescript@5.3.3": {},
    "ts-node@10.9.2": {},
  },
};

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║     pnpm-audit-hook — Custom Policy Example                ║");
  console.log("╚══════════════════════════════════════════════════════════════╝\n");

  const runtime: RuntimeOptions = {
    cwd: process.cwd(),
    registryUrl: "https://registry.npmjs.org",
    env: process.env,
  };

  // -------------------------------------------------------------------------
  // Step 1: Understand severity levels
  // -------------------------------------------------------------------------
  console.log("▸ Step 1: Severity levels…\n");

  const severityLevels: Severity[] = ["critical", "high", "medium", "low", "unknown"];

  console.log("  Available severity levels (most to least severe):");
  console.log("  ┌────────────┬─────────────────────────────────────────────┐");
  console.log("  │ Severity   │ Description                                 │");
  console.log("  ├────────────┼─────────────────────────────────────────────┤");
  console.log("  │ critical   │ Exploitable with severe impact              │");
  console.log("  │ high       │ Exploitable with significant impact         │");
  console.log("  │ medium     │ Moderate impact or limited exploitability    │");
  console.log("  │ low        │ Minimal impact                               │");
  console.log("  │ unknown    │ Severity could not be determined             │");
  console.log("  └────────────┴─────────────────────────────────────────────┘");
  console.log();

  // -------------------------------------------------------------------------
  // Step 2: Default policy behavior
  // -------------------------------------------------------------------------
  console.log("▸ Step 2: Default policy (block critical + high)…\n");

  console.log("  Default .pnpm-audit.yaml:");
  const defaultConfig = {
    policy: {
      block: ["critical", "high"],
      warn: ["medium", "low", "unknown"],
      allowlist: [],
    },
  };
  printYamlConfig(defaultConfig);

  console.log("  With defaults:");
  console.log("    critical → BLOCK");
  console.log("    high     → BLOCK");
  console.log("    medium   → WARN");
  console.log("    low      → WARN");
  console.log("    unknown  → WARN");
  console.log();

  // -------------------------------------------------------------------------
  // Step 3: Custom severity thresholds
  // -------------------------------------------------------------------------
  console.log("▸ Step 3: Custom severity thresholds…\n");

  console.log("  Example: Only block critical, warn on everything else:");
  const strictConfig = {
    policy: {
      block: ["critical"],
      warn: ["high", "medium", "low", "unknown"],
    },
  };
  printYamlConfig(strictConfig);

  console.log("  Example: Block critical + high + medium (strict):");
  const strict2Config = {
    policy: {
      block: ["critical", "high", "medium"],
      warn: ["low", "unknown"],
    },
  };
  printYamlConfig(strict2Config);
  console.log();

  // -------------------------------------------------------------------------
  // Step 4: Allowlist exceptions
  // -------------------------------------------------------------------------
  console.log("▸ Step 4: Allowlist exceptions…\n");

  console.log("  Allow by vulnerability ID:");
  const allowById = {
    policy: {
      block: ["critical", "high"],
      allowlist: [
        {
          id: "CVE-2021-44228",
          reason: "Not applicable — we don't use JNDI lookup",
        },
      ],
    },
  };
  printYamlConfig(allowById);

  console.log("  Allow by package name:");
  const allowByPackage = {
    policy: {
      block: ["critical", "high"],
      allowlist: [
        {
          package: "lodash",
          version: ">=4.17.21",
          reason: "Patched version, risk accepted by security team",
        },
      ],
    },
  };
  printYamlConfig(allowByPackage);

  console.log("  Allow only direct dependencies:");
  const directOnlyConfig = {
    policy: {
      block: ["critical", "high"],
      allowlist: [
        {
          package: "moment",
          directOnly: true,
          reason: "Dev dependency, low exposure risk",
        },
      ],
    },
  };
  printYamlConfig(directOnlyConfig);

  console.log("  Time-limited exception:");
  const temporaryConfig = {
    policy: {
      block: ["critical", "high"],
      allowlist: [
        {
          package: "axios",
          expires: "2025-12-31",
          reason: "Migration to v1.x in progress — deadline Q4 2025",
        },
      ],
    },
  };
  printYamlConfig(temporaryConfig);

  console.log("  Combined ID + package match:");
  const combinedConfig = {
    policy: {
      block: ["critical", "high"],
      allowlist: [
        {
          id: "GHSA-xxxx-xxxx-xxxx",
          package: "axios",
          version: ">=0.21.0 <1.0.0",
          reason: "Mitigated by network controls",
        },
      ],
    },
  };
  printYamlConfig(combinedConfig);
  console.log();

  // -------------------------------------------------------------------------
  // Step 5: Transitive dependency severity override
  // -------------------------------------------------------------------------
  console.log("▸ Step 5: Transitive dependency handling…\n");

  console.log("  Downgrade severity for transitive dependencies:");
  const transitiveConfig = {
    policy: {
      block: ["critical", "high"],
      warn: ["medium", "low", "unknown"],
      transitiveSeverityOverride: "downgrade-by-one",
    },
  };
  printYamlConfig(transitiveConfig);

  console.log("  Effect of downgrade-by-one:");
  console.log("  ┌──────────────┬──────────────┐");
  console.log("  │ Original     │ Downgraded   │");
  console.log("  ├──────────────┼──────────────┤");
  console.log("  │ critical     │ high         │");
  console.log("  │ high         │ medium       │");
  console.log("  │ medium       │ low          │");
  console.log("  │ low          │ low          │");
  console.log("  │ unknown      │ unknown      │");
  console.log("  └──────────────┴──────────────┘");
  console.log();

  // -------------------------------------------------------------------------
  // Step 6: Running with custom policies
  // -------------------------------------------------------------------------
  console.log("▸ Step 6: Running audit with default policy…\n");

  let result: AuditResult;
  try {
    result = await runAudit(POLICY_LOCKFILE, runtime);
  } catch (err) {
    console.error(`  Audit error: ${err instanceof Error ? err.message : String(err)}`);
    console.log("  (This is expected if the lockfile is synthetic)\n");

    // Build a mock result for demonstration
    result = createMockResult();
  }

  console.log("  Audit result:");
  console.log(`    Exit code:    ${exitCodeName(result.exitCode)}`);
  console.log(`    Blocked:      ${result.blocked}`);
  console.log(`    Warnings:     ${result.warnings}`);
  console.log(`    Findings:     ${result.findings.length}`);
  console.log(`    Decisions:    ${result.decisions.length}`);
  console.log();

  // -------------------------------------------------------------------------
  // Step 7: Analyzing policy decisions
  // -------------------------------------------------------------------------
  console.log("▸ Step 7: Analyzing policy decisions…\n");

  const decisionsByAction = groupBy(result.decisions, (d) => d.action);

  for (const [action, decisions] of Object.entries(decisionsByAction)) {
    const icon = action === "block" ? "🛑" : action === "warn" ? "⚠️ " : "✅";
    console.log(`  ${icon} ${action.toUpperCase()} (${decisions.length}):`);
    for (const d of decisions) {
      const pkg = d.packageName && d.packageVersion
        ? `${d.packageName}@${d.packageVersion}`
        : "unknown";
      console.log(`    • ${pkg}`);
      console.log(`      reason: ${d.reason}`);
      console.log(`      source: ${d.source}`);
      if (d.findingSeverity) {
        console.log(`      severity: ${d.findingSeverity}`);
      }
    }
    console.log();
  }

  // -------------------------------------------------------------------------
  // Step 8: Decision source breakdown
  // -------------------------------------------------------------------------
  console.log("▸ Step 8: Decision source breakdown…\n");

  const decisionsBySource = groupBy(result.decisions, (d) => d.source);

  console.log("  Decisions by source:");
  for (const [source, decisions] of Object.entries(decisionsBySource)) {
    const actions = groupBy(decisions, (d) => d.action);
    const summary = Object.entries(actions)
      .map(([action, arr]) => `${arr.length} ${action}`)
      .join(", ");
    console.log(`    ${source}: ${summary}`);
  }
  console.log();

  // -------------------------------------------------------------------------
  // Step 9: Building a custom policy config programmatically
  // -------------------------------------------------------------------------
  console.log("▸ Step 9: Programmatic policy configuration…\n");

  // Create a policy config in code
  const customPolicy: AuditConfigInput = {
    policy: {
      // Only block critical vulnerabilities
      block: ["critical"],
      // Warn on high and medium
      warn: ["high", "medium"],
      // Silently allow low and unknown
      // (they won't appear in block or warn lists)

      // Custom allowlist
      allowlist: [
        // Allow lodash in any version (well-maintained, low risk)
        {
          package: "lodash",
          reason: "Well-maintained, acceptable risk profile",
        },
        // Allow a specific CVE with expiration
        {
          id: "CVE-2023-XXXXX",
          package: "express",
          version: ">=4.18.0",
          expires: "2026-01-01",
          reason: "Mitigated by WAF rules",
        },
      ],

      // Downgrade transitive vulnerabilities
      transitiveSeverityOverride: "downgrade-by-one",
    },
    sources: {
      github: true,
      nvd: false,   // Disable NVD for faster audits
      osv: true,
    },
    performance: {
      timeoutMs: 30000,
    },
    cache: {
      ttlSeconds: 7200,
    },
  };

  console.log("  Generated policy config:");
  printYamlConfig(customPolicy);

  // Write example config file
  const configPath = path.join(process.cwd(), "examples", "custom-policy.yaml");
  await fs.writeFile(configPath, YAML.stringify(customPolicy, { indent: 2 }), "utf-8");
  console.log(`  📁 Written to: ${configPath}\n`);

  // -------------------------------------------------------------------------
  // Step 10: Policy evaluation summary
  // -------------------------------------------------------------------------
  console.log("▸ Step 10: Policy evaluation summary…\n");

  console.log("  Key concepts:");
  console.log("  ┌───────────────────────────────────────────────────────────┐");
  console.log("  │ 1. Block list:  Severities that prevent installation     │");
  console.log("  │ 2. Warn list:   Severities that log warnings             │");
  console.log("  │ 3. Allowlist:   Exceptions that override block/warn      │");
  console.log("  │ 4. Transitive:  Optional downgrade for transitive deps   │");
  console.log("  │ 5. Expiration:  Allowlist entries can have deadlines     │");
  console.log("  │ 6. Direct-only: Allowlist can target direct deps only    │");
  console.log("  └───────────────────────────────────────────────────────────┘");
  console.log();

  console.log("  Policy evaluation order:");
  console.log("    1. Check allowlist (if matched → ALLOW, skip severity check)");
  console.log("    2. Apply transitive downgrade (if configured)");
  console.log("    3. Check block list (if severity matches → BLOCK)");
  console.log("    4. Check warn list (if severity matches → WARN)");
  console.log("    5. Otherwise → ALLOW (not in any list)");
  console.log();

  // -------------------------------------------------------------------------
  // Done!
  // -------------------------------------------------------------------------
  console.log("─".repeat(62));
  console.log("Done! Custom policy example completed. 🐶");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function groupBy<T>(items: T[], keyFn: (item: T) => string): Record<string, T[]> {
  return items.reduce(
    (acc, item) => {
      const key = keyFn(item);
      (acc[key] ??= []).push(item);
      return acc;
    },
    {} as Record<string, T[]>,
  );
}

function exitCodeName(code: number): string {
  switch (code) {
    case EXIT_CODES.SUCCESS: return "SUCCESS (0)";
    case EXIT_CODES.BLOCKED: return "BLOCKED (1)";
    case EXIT_CODES.WARNINGS: return "WARNINGS (2)";
    case EXIT_CODES.SOURCE_ERROR: return "SOURCE_ERROR (3)";
    default: return `UNKNOWN (${code})`;
  }
}

function printYamlConfig(config: Record<string, unknown>) {
  const yaml = YAML.stringify(config, { indent: 2 });
  for (const line of yaml.split("\n")) {
    console.log(`    ${line}`);
  }
  console.log();
}

/** Create a mock AuditResult for demonstration when the real audit can't run */
function createMockResult(): AuditResult {
  const now = new Date().toISOString();
  const findings: VulnerabilityFinding[] = [
    {
      id: "CVE-2023-26159",
      source: "github",
      packageName: "follow-redirects",
      packageVersion: "1.14.8",
      title: "Authorization header leak on redirect",
      severity: "high",
      cvssScore: 7.4,
      fixedVersion: "1.15.4",
    },
    {
      id: "CVE-2021-44228",
      source: "github",
      packageName: "lodash",
      packageVersion: "4.17.21",
      title: "Prototype Pollution",
      severity: "medium",
      cvssScore: 5.6,
      fixedVersion: "4.17.22",
    },
  ];

  const decisions: PolicyDecision[] = [
    {
      action: "block",
      reason: "Severity 'high' is in block list",
      source: "severity",
      at: now,
      packageName: "follow-redirects",
      packageVersion: "1.14.8",
      findingId: "CVE-2023-26159",
      findingSeverity: "high",
    },
    {
      action: "warn",
      reason: "Severity 'medium' is in warn list",
      source: "severity",
      at: now,
      packageName: "lodash",
      packageVersion: "4.17.21",
      findingId: "CVE-2021-44228",
      findingSeverity: "medium",
    },
  ];

  return {
    blocked: true,
    warnings: true,
    decisions,
    exitCode: EXIT_CODES.BLOCKED,
    findings,
    sourceStatus: {
      github: { ok: true, durationMs: 234 },
      nvd: { ok: true, durationMs: 156 },
      osv: { ok: true, durationMs: 89 },
    },
    totalPackages: 9,
    durationMs: 479,
  };
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------
main().catch((err) => {
  console.error("Unhandled error:", err);
  process.exit(1);
});
