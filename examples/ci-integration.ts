#!/usr/bin/env tsx
// =============================================================================
// ci-integration.ts — CI/CD Integration Demo
// =============================================================================
//
// Demonstrates CI/CD pipeline integration patterns:
//   - Configuring for GitHub Actions workflows
//   - Configuring for Azure DevOps pipelines
//   - Configuring for AWS CodeBuild
//   - Configuring for GitLab CI
//   - Setting output formats (JSON, SARIF-compatible)
//   - Handling exit codes (EXIT_CODES.BLOCKED, etc.)
//   - Setting up environment variable overrides
//
// Prerequisites:
//   - Node.js >= 18
//   - Project dependencies installed (`pnpm install`)
//   - Run from project root: npx tsx examples/ci-integration.ts
// =============================================================================

import fs from "node:fs/promises";
import path from "node:path";

// ---------------------------------------------------------------------------
// Imports from pnpm-audit-hook source (relative to this file)
// ---------------------------------------------------------------------------
import {
  runAudit,
  generateSbom,
  EXIT_CODES,
} from "../src/index";

import type {
  AuditResult,
  PnpmLockfile,
  RuntimeOptions,
} from "../src/index";

// ---------------------------------------------------------------------------
// Demo lockfile for CI simulation — minimal but realistic structure
// ---------------------------------------------------------------------------
const CI_LOCKFILE: PnpmLockfile = {
  lockfileVersion: "9.0",
  importers: {
    ".": {
      dependencies: {
        express: { version: "4.18.2" },
      },
      devDependencies: {
        typescript: { version: "5.3.3" },
      },
    },
  },
  packages: {
    "express@4.18.2": { dependencies: { "body-parser": "1.20.2" } },
    "body-parser@1.20.2": { dependencies: { "bytes": "3.1.2", "debug": "4.3.4" } },
    "bytes@3.1.2": {},
    "debug@4.3.4": { dependencies: { "ms": "2.1.2" } },
    "ms@2.1.2": {},
    "typescript@5.3.3": {},
  },
};

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║     pnpm-audit-hook — CI/CD Integration Example            ║");
  console.log("╚══════════════════════════════════════════════════════════════╝\n");

  // -------------------------------------------------------------------------
  // Step 1: GitHub Actions integration
  // -------------------------------------------------------------------------
  console.log("▸ Step 1: GitHub Actions configuration…\n");

  /**
   * GitHub Actions workflow for automated security auditing on every push
   * and pull request. Uses environment variables to override policy
   * thresholds and generates SBOM artifacts.
   */
  const githubActionsYaml = `
# .github/workflows/security-audit.yml
name: Security Audit

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write    # For SARIF upload

jobs:
  audit:
    name: pnpm-audit-hook
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: pnpm/action-setup@v4
        with:
          version: 9

      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: pnpm

      - name: Install dependencies
        run: pnpm install --frozen-lockfile

      - name: Security audit
        env:
          # Override block severities for this workflow
          PNPM_AUDIT_BLOCK_SEVERITY: "critical,high"
          # Don't fail on source errors in CI (be permissive)
          PNPM_AUDIT_FAIL_ON_SOURCE_ERROR: "false"
        run: |
          pnpm-audit-scan --format=json --output=audit-results.json || {
            EXIT_CODE=$?
            echo "::error::Security audit failed with exit code $EXIT_CODE"
            exit $EXIT_CODE
          }

      - name: Generate SBOM
        if: success()
        run: pnpm-audit-scan --sbom --sbom-format cyclonedx --sbom-output sbom.json

      - name: Upload audit results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-audit-results
          path: |
            audit-results.json
            sbom.json
`.trim();

  console.log("  Generated GitHub Actions workflow:");
  printCodeBlock(githubActionsYaml, "yaml");
  console.log();

  // -------------------------------------------------------------------------
  // Step 2: Azure DevOps integration
  // -------------------------------------------------------------------------
  console.log("▸ Step 2: Azure DevOps configuration…\n");

  /**
   * Azure DevOps pipeline with staged security scanning. The audit step
   * publishes results as build artifacts for downstream consumers.
   */
  const azureYaml = `
# azure-pipelines.yml
trigger:
  branches:
    include:
      - main
      - develop
  paths:
    include:
      - package.json
      - pnpm-lock.yaml

pool:
  vmImage: ubuntu-latest

variables:
  PNPM_AUDIT_BLOCK_SEVERITY: "critical,high"
  PNPM_AUDIT_FAIL_ON_SOURCE_ERROR: "false"

steps:
  - task: NodeTool@0
    inputs:
      versionSpec: '20'
    displayName: 'Install Node.js'

  - script: |
      corepack enable
      corepack prepare pnpm@latest --activate
      pnpm install --frozen-lockfile
    displayName: 'Install dependencies'

  - script: |
      pnpm-audit-scan --format=json --output=$(Build.ArtifactStagingDirectory)/audit-results.json
    displayName: 'Security audit'
    name: audit

  - script: |
      pnpm-audit-scan --sbom --sbom-format cyclonedx --sbom-output=$(Build.ArtifactStagingDirectory)/sbom.json
    displayName: 'Generate SBOM'

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: '$(Build.ArtifactStagingDirectory)'
      artifactName: 'security-reports'
    displayName: 'Publish artifacts'
`.trim();

  console.log("  Generated Azure DevOps pipeline:");
  printCodeBlock(azureYaml, "yaml");
  console.log();

  // -------------------------------------------------------------------------
  // Step 3: AWS CodeBuild integration
  // -------------------------------------------------------------------------
  console.log("▸ Step 3: AWS CodeBuild configuration…\n");

  /**
   * AWS CodeBuild buildspec with environment variables for policy overrides.
   * Artifacts are collected automatically from the working directory.
   */
  const codebuildYaml = `
# buildspec.yml (AWS CodeBuild)
version: 0.2

env:
  variables:
    PNPM_AUDIT_BLOCK_SEVERITY: "critical,high"
    PNPM_AUDIT_FAIL_ON_SOURCE_ERROR: "false"

phases:
  install:
    runtime-versions:
      nodejs: 20
    commands:
      - corepack enable
      - corepack prepare pnpm@latest --activate
      - pnpm install --frozen-lockfile

  pre_build:
    commands:
      - echo "Running security audit..."

  build:
    commands:
      - |
        pnpm-audit-scan \\
          --format=json \\
          --output=$CODEBUILD_SRC_DIR/audit-results.json \\
        || {
          EXIT_CODE=$?
          echo "Security audit failed with exit code $EXIT_CODE"
          exit $EXIT_CODE
        }
      - |
        pnpm-audit-scan \\
          --sbom \\
          --sbom-format cyclonedx \\
          --sbom-output=$CODEBUILD_SRC_DIR/sbom.json

  post_build:
    commands:
      - echo "Build completed on $(date)"

artifacts:
  files:
    - audit-results.json
    - sbom.json
  discard-paths: yes
`.trim();

  console.log("  Generated AWS CodeBuild buildspec:");
  printCodeBlock(codebuildYaml, "yaml");
  console.log();

  // -------------------------------------------------------------------------
  // Step 4: GitLab CI integration
  // -------------------------------------------------------------------------
  console.log("▸ Step 4: GitLab CI configuration…\n");

  /**
   * GitLab CI config with job dependencies, caching, and artifact rules.
   * The security-audit job runs only on merge requests and main/develop.
   */
  const gitlabYaml = `
# .gitlab-ci.yml
stages:
  - install
  - security
  - build

variables:
  PNPM_AUDIT_BLOCK_SEVERITY: "critical,high"
  PNPM_AUDIT_FAIL_ON_SOURCE_ERROR: "false"

install-deps:
  stage: install
  image: node:20
  cache:
    key:
      files:
        - pnpm-lock.yaml
    paths:
      - node_modules/
  script:
    - corepack enable
    - corepack prepare pnpm@latest --activate
    - pnpm install --frozen-lockfile
  artifacts:
    paths:
      - node_modules/
    expire_in: 1 hour

security-audit:
  stage: security
  image: node:20
  needs:
    - install-deps
  script:
    - pnpm-audit-scan --format=json --output=audit-results.json
    - pnpm-audit-scan --sbom --sbom-format cyclonedx --sbom-output=sbom.json
  artifacts:
    paths:
      - audit-results.json
      - sbom.json
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'
    - if: '$CI_COMMIT_BRANCH == "develop"'
`.trim();

  console.log("  Generated GitLab CI config:");
  printCodeBlock(gitlabYaml, "yaml");
  console.log();

  // -------------------------------------------------------------------------
  // Step 5: Exit code handling in CI
  // -------------------------------------------------------------------------
  console.log("▸ Step 5: Exit code handling patterns…\n");

  // Run a simulated audit to demonstrate exit code handling
  const runtime: RuntimeOptions = {
    cwd: process.cwd(),
    registryUrl: "https://registry.npmjs.org",
    env: process.env,
  };

  let result: AuditResult;
  try {
    result = await runAudit(CI_LOCKFILE, runtime);
  } catch (err) {
    console.error(`  Audit error: ${err instanceof Error ? err.message : String(err)}\n`);
    return;
  }

  /**
   * EXIT_CODES maps to shell exit codes used by the CLI and programmatic API.
   * CI systems use these to determine pass/fail status of the audit step.
   */
  console.log("  Exit code mapping:");
  console.log("  ┌──────────────────────┬────┬───────────────────────────────────┐");
  console.log("  │ Constant             │Code│ Meaning                           │");
  console.log("  ├──────────────────────┼────┼───────────────────────────────────┤");
  console.log("  │ EXIT_CODES.SUCCESS   │  0 │ No blocking issues                │");
  console.log("  │ EXIT_CODES.BLOCKED   │  1 │ Installation blocked              │");
  console.log("  │ EXIT_CODES.WARNINGS  │  2 │ Warnings only (non-blocking)      │");
  console.log("  │ EXIT_CODES.SOURCE_ERR│  3 │ Vulnerability source failed       │");
  console.log("  └──────────────────────┴────┴───────────────────────────────────┘\n");

  console.log(`  Current result: exitCode=${result.exitCode} (${exitCodeName(result.exitCode)})`);
  console.log(`  blocked=${result.blocked}, warnings=${result.warnings}\n`);

  const shellPattern = `
# Pattern: handle pnpm-audit-hook exit codes in shell scripts
pnpm-audit-scan --format=json --output=results.json
EXIT_CODE=$?

case $EXIT_CODE in
  0)
    echo "✅ Audit passed — no issues"
    ;;
  1)
    echo "🛑 Audit BLOCKED — vulnerable dependencies detected"
    # Optionally parse results.json for details
    cat results.json | jq '.findings[] | select(.action=="block")'
    exit 1
    ;;
  2)
    echo "⚠️  Audit had warnings — proceeding with caution"
    # Don't fail the build, but maybe add a comment
    ;;
  3)
    echo "❌ Vulnerability source error — partial results only"
    # Decide: fail open or fail closed?
    exit 1  # Fail closed for security
    ;;
  *)
    echo "❓ Unexpected exit code: $EXIT_CODE"
    exit $EXIT_CODE
    ;;
esac
`.trim();

  console.log("  Shell script pattern for CI:");
  printCodeBlock(shellPattern, "bash");
  console.log();

  // -------------------------------------------------------------------------
  // Step 6: Environment variable overrides for CI
  // -------------------------------------------------------------------------
  console.log("▸ Step 6: Environment variable overrides…\n");

  console.log("  Environment variables that override .pnpm-audit.yaml:\n");

  /**
   * These env vars allow CI pipelines to customize audit behavior without
   * modifying the checked-in config file.
   */
  const envVars: Array<[string, string, string]> = [
    ["PNPM_AUDIT_CONFIG_PATH", "Custom config file path", ".pnpm-audit.yaml"],
    ["PNPM_AUDIT_BLOCK_SEVERITY", "Override block severities", "critical,high"],
    ["PNPM_AUDIT_FAIL_ON_NO_SOURCES", "Fail when all sources disabled", "true"],
    ["PNPM_AUDIT_FAIL_ON_SOURCE_ERROR", "Fail when source errors occur", "true"],
    ["PNPM_AUDIT_OFFLINE", "Use only static DB + cache", "false"],
  ];

  console.log("  ┌─────────────────────────────────┬──────────────────────────────────┬─────────────┐");
  console.log("  │ Variable                        │ Description                      │ Default     │");
  console.log("  ├─────────────────────────────────┼──────────────────────────────────┼─────────────┤");
  for (const [name, desc, def] of envVars) {
    console.log(`  │ ${name.padEnd(31)} │ ${desc.padEnd(32)} │ ${def.padEnd(11)} │`);
  }
  console.log("  └─────────────────────────────────┴──────────────────────────────────┴─────────────┘");
  console.log();

  // Example of using env vars programmatically
  console.log("  Example: overriding via environment in Node.js:\n");
  console.log("    process.env.PNPM_AUDIT_BLOCK_SEVERITY = 'critical';");
  console.log("    process.env.PNPM_AUDIT_OFFLINE = 'true';");
  console.log("    const result = await runAudit(lockfile, runtime);");
  console.log();

  // -------------------------------------------------------------------------
  // Step 7: JSON output for CI parsing
  // -------------------------------------------------------------------------
  console.log("▸ Step 7: JSON output for CI tooling…\n");

  /**
   * Build a CI-friendly JSON report that aggregates audit results into
   * a machine-readable format. CI systems can parse this to populate
   * dashboards, create PR comments, or trigger alerts.
   */
  const ciReport = {
    timestamp: new Date().toISOString(),
    tool: "pnpm-audit-hook",
    version: "1.4.3",
    result: {
      exitCode: result.exitCode,
      blocked: result.blocked,
      warnings: result.warnings,
    },
    summary: {
      totalPackages: result.totalPackages,
      totalFindings: result.findings.length,
      blockedDecisions: result.decisions.filter((d) => d.action === "block").length,
      warnDecisions: result.decisions.filter((d) => d.action === "warn").length,
      allowDecisions: result.decisions.filter((d) => d.action === "allow").length,
    },
    findings: result.findings.map((f) => ({
      id: f.id,
      package: f.packageName,
      version: f.packageVersion,
      severity: f.severity,
      fixedVersion: f.fixedVersion ?? null,
    })),
    sourceStatus: result.sourceStatus,
    durationMs: result.durationMs,
  };

  console.log("  CI report JSON:");
  const reportStr = JSON.stringify(ciReport, null, 2);
  const reportLines = reportStr.split("\n");
  for (const line of reportLines.slice(0, 25)) {
    console.log(`    ${line}`);
  }
  if (reportLines.length > 25) {
    console.log(`    … (${reportLines.length - 25} more lines)`);
  }
  console.log();

  // Write the report to disk
  const reportPath = path.join(process.cwd(), "examples", "ci-output");
  await fs.mkdir(reportPath, { recursive: true });
  const reportFilePath = path.join(reportPath, "ci-report.json");
  await fs.writeFile(reportFilePath, JSON.stringify(ciReport, null, 2), "utf-8");
  console.log(`  📁 Report written to: ${reportFilePath}\n`);

  // Step 8: SARIF-compatible output
  console.log("▸ Step 8: SARIF-compatible output pattern…\n");
  console.log("  Convert audit results to SARIF for GitHub Code Scanning:\n");

  const sarifPattern = `
// Convert audit results to SARIF format for GitHub Code Scanning
function toSarif(result: AuditResult) {
  return {
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "pnpm-audit-hook",
          version: "1.4.3",
          rules: result.findings.map(f => ({
            id: f.id,
            name: f.title ?? f.id,
            shortDescription: { text: f.title ?? f.id },
            defaultConfiguration: {
              level: severityToSarifLevel(f.severity),
            },
          })),
        },
      },
      results: result.findings.map(f => ({
        ruleId: f.id,
        level: severityToSarifLevel(f.severity),
        message: {
          text: \`\${f.packageName}@\${f.packageVersion}: \${f.title ?? f.id}\`,
        },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: "package.json" },
            region: { startLine: 1 },
          },
        }],
        fixes: f.fixedVersion ? [{
          artifactChanges: [{
            replacement: {
              content: \`"upgrade to \${f.fixedVersion}"\`,
            },
          }],
        }] : undefined,
      })),
    }],
  };
}

function severityToSarifLevel(sev: string): string {
  switch (sev) {
    case "critical":
    case "high":   return "error";
    case "medium": return "warning";
    default:       return "note";
  }
}
`.trim();

  printCodeBlock(sarifPattern, "typescript");
  console.log();

  // -------------------------------------------------------------------------
  // Done!
  // -------------------------------------------------------------------------
  console.log("─".repeat(62));
  console.log("Done! CI/CD integration example completed. 🐶");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Map an exit code to its human-readable name.
 *
 * @param code - Numeric exit code from EXIT_CODES
 * @returns String name like "SUCCESS", "BLOCKED", etc.
 */
function exitCodeName(code: number): string {
  switch (code) {
    case EXIT_CODES.SUCCESS: return "SUCCESS";
    case EXIT_CODES.BLOCKED: return "BLOCKED";
    case EXIT_CODES.WARNINGS: return "WARNINGS";
    case EXIT_CODES.SOURCE_ERROR: return "SOURCE_ERROR";
    default: return "UNKNOWN";
  }
}

/**
 * Print a code block with language-specific formatting.
 *
 * @param code - Source code string to display
 * @param lang - Language identifier for syntax highlighting
 */
function printCodeBlock(code: string, lang: string) {
  console.log(`    \`\`\`${lang}`);
  for (const line of code.split("\n")) {
    console.log(`    ${line}`);
  }
  console.log(`    \`\`\``);
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------
main().catch((err) => {
  console.error("Unhandled error:", err);
  process.exit(1);
});
