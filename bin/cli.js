#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const YAML = require("yaml");

const { parseArgs, HELP } = require("./parse-args.js");

async function main() {
  const args = parseArgs(process.argv.slice(2));

  // Reject unknown flags
  if (args.unknownFlags && args.unknownFlags.length > 0) {
    console.error(`Error: Unknown flag(s): ${args.unknownFlags.join(", ")}`);
    console.error("");
    console.error("Run with --help to see available options.");
    process.exit(1);
  }

  if (args.help) {
    console.log(HELP);
    process.exit(0);
  }

  // Handle SBOM diff mode (no lockfile required)
  if (args.sbomDiff) {
    handleSbomDiff(args);
    return;
  }

  // Handle SBOM validation mode (no lockfile required)
  if (args.validateSbom) {
    handleValidateSbom(args);
    return;
  }

  // Handle dependency tree mode
  if (args.depTree) {
    handleDepTree(args);
    return;
  }

  if (args.version) {
    try {
      const pkg = JSON.parse(
        fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf-8")
      );
      console.log(pkg.version);
    } catch {
      console.log("unknown");
    }
    process.exit(0);
  }

  if (args.troubleshoot) {
    console.log("pnpm-audit-hook Troubleshooting Information");
    console.log("==========================================");
    console.log("");

    // Version info
    console.log("1. Version Information:");
    try {
      const pkg = JSON.parse(
        fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf-8")
      );
      console.log(`   pnpm-audit-hook: ${pkg.version}`);
    } catch {
      console.log("   pnpm-audit-hook: unknown");
    }
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

    process.exit(0);
  }

  if (args.updateDb) {
    const { spawnSync } = require("child_process");
    const pkgRoot = path.join(__dirname, "..");
    const scriptPath = path.join(pkgRoot, "scripts", "update-vuln-db.ts");
    const tsxPath = path.join(pkgRoot, "node_modules", ".bin", "tsx");
    const updateArgs =
      args.updateDb === "full" ? [scriptPath] : [scriptPath, "--incremental"];

    console.log(
      `Updating vulnerability database (${args.updateDb})...\n`
    );

    const result = spawnSync(tsxPath, updateArgs, {
      stdio: "inherit",
      cwd: pkgRoot,
    });

    if (result.error) {
      console.error(
        `Error: Failed to run DB update: ${result.error.message}`
      );
      console.error(
        "Make sure tsx is installed (pnpm install) and scripts/update-vuln-db.ts exists."
      );
      process.exit(1);
    }

    process.exit(result.status ?? 1);
  }

  if (args.dbStatus) {
    const { createStaticDbReader } = require("../dist/static-db/reader.js");
    const pkgRoot = path.join(__dirname, "..");
    const dataPath = path.join(pkgRoot, "dist", "static-db", "data");
    const defaultCutoffDate = "2025-12-31";

    try {
      const reader = await createStaticDbReader({
        dataPath,
        cutoffDate: defaultCutoffDate,
      });

      if (!reader) {
        console.error("Database not loaded or not ready.");
        process.exit(1);
      }

      const index = reader.getIndex();

      console.log("Database Status");
      console.log("───────────────");
      console.log(
        `  Loaded & ready:    ${reader.isReady() ? "\u2713 Yes" : "\u2717 No"}`
      );
      console.log(
        `  DB version:        ${index?.lastUpdated || "unknown"}`
      );
      console.log(`  Cutoff date:       ${reader.getCutoffDate()}`);
      console.log(`  Total vulns:       ${index?.totalVulnerabilities ?? "unknown"}`);
      console.log(
        `  Total packages:    ${index?.totalPackages ?? "unknown"}`
      );
      console.log(`  Schema version:    ${index?.schemaVersion ?? "unknown"}`);

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

      process.exit(0);
    } catch (e) {
      console.error(`Error reading database status: ${e.message}`);
      process.exit(1);
    }
  }

  // Set env vars from CLI flags (before importing the module so logger picks them up)
  if (args.quiet) process.env.PNPM_AUDIT_QUIET = "true";
  if (args.verbose) process.env.PNPM_AUDIT_VERBOSE = "true";
  if (args.debug) process.env.PNPM_AUDIT_DEBUG = "true";
  if (args.offline) process.env.PNPM_AUDIT_OFFLINE = "true";
  if (args.sbom) process.env.PNPM_AUDIT_SBOM = "true";
  if (args.sbomFormat) process.env.PNPM_AUDIT_SBOM_FORMAT = args.sbomFormat;
  if (args.sbomOutput) process.env.PNPM_AUDIT_SBOM_OUTPUT = args.sbomOutput;
  if (args.format) {
    const validFormats = ["human", "json", "azure", "github", "aws"];
    if (!validFormats.includes(args.format)) {
      console.error(`Error: Invalid format '${args.format}'.`);
      console.error(`Valid formats: ${validFormats.join(", ")}`);
      process.exit(1);
    }
    if (args.format === "json") {
      process.env.PNPM_AUDIT_JSON = "true";
    } else {
      process.env.PNPM_AUDIT_FORMAT = args.format;
    }
  }
  if (args.config) process.env.PNPM_AUDIT_CONFIG_PATH = args.config;
  if (args.severity) {
    const validSeverities = ["critical", "high", "medium", "low"];
    const requestedSeverities = args.severity.split(",").map(s => s.trim());
    for (const sev of requestedSeverities) {
      if (!validSeverities.includes(sev)) {
        console.error(`Error: Invalid severity '${sev}'.`);
        console.error(`Valid severities: ${validSeverities.join(", ")}`);
        process.exit(1);
      }
    }
    process.env.PNPM_AUDIT_BLOCK_SEVERITY = args.severity;
  }
  if (args.updateDb) process.env.PNPM_AUDIT_UPDATE_DB = args.updateDb;

  // Find pnpm-lock.yaml
  const cwd = process.cwd();
  const lockfilePath = path.resolve(cwd, "pnpm-lock.yaml");

  if (!fs.existsSync(lockfilePath)) {
    console.error("Error: No pnpm-lock.yaml found in current directory.");
    console.error("This tool scans pnpm lockfiles. Run it from a pnpm project root.");
    console.error("");
    console.error("If this is an npm/yarn project, use 'npm audit' or 'yarn audit' instead.");
    process.exit(1);
  }

  // Parse the lockfile
  let lockfile;
  try {
    const raw = fs.readFileSync(lockfilePath, "utf-8");
    lockfile = YAML.parse(raw);
  } catch (e) {
    console.error(`Error: Failed to parse pnpm-lock.yaml: ${e.message}`);
    process.exit(1);
  }

  if (!lockfile || typeof lockfile !== "object") {
    console.error("Error: pnpm-lock.yaml is empty or invalid.");
    process.exit(1);
  }

  // Import the audit module (after env vars are set)
  const distEntry = path.join(__dirname, "..", "dist", "index.js");

  if (!fs.existsSync(distEntry)) {
    console.error("");
    console.error("pnpm-audit-hook: not built.");
    console.error("");
    console.error("Fix:");
    console.error("  1) Run: pnpm build");
    console.error("  2) Ensure dist/ is present");
    console.error("");
    console.error("See README for installation instructions.");
    console.error("");
    process.exit(1);
  }

  let runAudit;
  let generateSbom;
  try {
    const distModule = require(distEntry);
    runAudit = distModule.runAudit;
    generateSbom = distModule.generateSbom;
  } catch (e) {
    console.error(`Error loading pnpm-audit-hook module: ${e.message}`);
    console.error(`Expected: ${distEntry}`);
    process.exit(1);
  }

  // Determine registry URL
  const registryUrl =
    process.env.PNPM_REGISTRY ??
    process.env.npm_config_registry ??
    process.env.NPM_CONFIG_REGISTRY ??
    "https://registry.npmjs.org/";

  try {
    const result = await runAudit(lockfile, {
      cwd,
      env: process.env,
      registryUrl,
    });

    // Generate SBOM if requested
    if (args.sbom || process.env.PNPM_AUDIT_SBOM === "true") {
      const sbomFormat = args.sbomFormat || process.env.PNPM_AUDIT_SBOM_FORMAT || "cyclonedx";
      const sbomOutput = args.sbomOutput || process.env.PNPM_AUDIT_SBOM_OUTPUT;

      try {
        // Import lockfile extraction utility
        const { extractPackagesFromLockfile } = require(path.join(__dirname, "..", "dist", "utils", "lockfile.js"));
        const { packages } = extractPackagesFromLockfile(lockfile);

        const sbomResult = generateSbom(packages, result.findings, {
          format: sbomFormat,
          outputPath: sbomOutput,
          includeVulnerabilities: true,
          projectName: path.basename(cwd),
          projectVersion: "1.0.0",
        });

        if (!sbomOutput) {
          // Output to stdout
          console.log(sbomResult.content);
        } else {
          console.error(`SBOM written to ${sbomOutput} (${sbomResult.componentCount} components, ${sbomResult.vulnerabilityCount} vulnerabilities)`);
        }
      } catch (sbomErr) {
        console.error(`SBOM generation error: ${sbomErr.message}`);
        // Don't exit with error - audit succeeded, SBOM is optional
      }
    }

    process.exit(result.exitCode);
  } catch (e) {
    console.error(`Audit error: ${e.message}`);
    process.exit(1);
  }
}

/**
 * Handle the --dep-tree command: generate a dependency tree visualization.
 */
function handleDepTree(args) {
  const distEntry = path.join(__dirname, "..", "dist", "index.js");
  if (!fs.existsSync(distEntry)) {
    console.error("pnpm-audit-hook: not built. Run 'pnpm build' first.");
    process.exit(1);
  }

  let buildTreeFromSbom, buildTreeFromLockfile, renderTree, renderTreeJson;
  try {
    const distModule = require(distEntry);
    buildTreeFromSbom = distModule.buildTreeFromSbom;
    buildTreeFromLockfile = distModule.buildTreeFromLockfile;
    renderTree = distModule.renderTree;
    renderTreeJson = distModule.renderTreeJson;
  } catch (e) {
    console.error(`Error loading pnpm-audit-hook module: ${e.message}`);
    process.exit(1);
  }

  const treeFormat = args.treeFormat || "ascii";
  const treeDepth = args.treeDepth;
  const treeOutput = args.treeOutput;
  const sbomInput = args.sbomInput;

  const treeOptions = {
    maxDepth: treeDepth !== undefined && !isNaN(treeDepth) ? treeDepth : undefined,
    showVersions: true,
    showVulnerabilities: true,
  };

  try {
    let tree;

    if (sbomInput) {
      // Build tree from existing SBOM file
      if (!fs.existsSync(sbomInput)) {
        console.error(`Error: SBOM file not found: ${sbomInput}`);
        process.exit(1);
      }

      let sbomDoc;
      try {
        const content = fs.readFileSync(sbomInput, "utf-8");
        sbomDoc = JSON.parse(content);
      } catch (e) {
        if (e instanceof SyntaxError) {
          console.error(`Error: Invalid JSON in SBOM file: ${sbomInput}`);
        } else {
          console.error(`Error reading SBOM file: ${e.message}`);
        }
        process.exit(1);
      }

      tree = buildTreeFromSbom(sbomDoc, treeOptions);
    } else {
      // Build tree from lockfile
      const cwd = process.cwd();
      const lockfilePath = path.resolve(cwd, "pnpm-lock.yaml");

      if (!fs.existsSync(lockfilePath)) {
        console.error("Error: No pnpm-lock.yaml found in current directory.");
        console.error("This tool scans pnpm lockfiles. Run it from a pnpm project root.");
        console.error("");
        console.error("Tip: Use --sbom-input to generate a tree from an existing SBOM file.");
        process.exit(1);
      }

      tree = buildTreeFromLockfile(lockfilePath, treeOptions);
    }

    let output;
    if (treeFormat === "json") {
      output = JSON.stringify(renderTreeJson(tree, treeOptions), null, 2);
    } else {
      output = renderTree(tree, treeOptions);
    }

    if (treeOutput) {
      const dir = path.dirname(treeOutput);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(treeOutput, output, "utf-8");
      console.error(`Dependency tree written to ${treeOutput}`);
    } else {
      console.log(output);
    }

    process.exit(0);
  } catch (e) {
    console.error(`Dependency tree error: ${e.message}`);
    process.exit(1);
  }
}

/**
 * Handle the --sbom-diff command: compare two SBOM files and output diff.
 */
function handleSbomDiff(args) {
  const oldPath = args.sbomDiffOld;
  const newPath = args.sbomDiffNew;
  const diffOutput = args.diffOutput;

  if (!oldPath || !newPath) {
    console.error("Error: --sbom-diff requires two file arguments.");
    console.error("Usage: pnpm-audit-scan --sbom-diff <old-sbom.json> <new-sbom.json>");
    process.exit(1);
  }

  // Load the dist module
  const distEntry = path.join(__dirname, "..", "dist", "index.js");
  if (!fs.existsSync(distEntry)) {
    console.error("pnpm-audit-hook: not built. Run 'pnpm build' first.");
    process.exit(1);
  }

  let diffSbom, formatDiffResult;
  try {
    const distModule = require(distEntry);
    diffSbom = distModule.diffSbom;
    formatDiffResult = distModule.formatDiffResult;
  } catch (e) {
    console.error(`Error loading pnpm-audit-hook module: ${e.message}`);
    process.exit(1);
  }

  // Read old SBOM
  let oldSbom;
  try {
    const oldContent = fs.readFileSync(oldPath, "utf-8");
    oldSbom = JSON.parse(oldContent);
  } catch (e) {
    if (e.code === "ENOENT") {
      console.error(`Error: Old SBOM file not found: ${oldPath}`);
    } else if (e instanceof SyntaxError) {
      console.error(`Error: Invalid JSON in old SBOM file: ${oldPath}`);
    } else {
      console.error(`Error reading old SBOM: ${e.message}`);
    }
    process.exit(1);
  }

  // Read new SBOM
  let newSbom;
  try {
    const newContent = fs.readFileSync(newPath, "utf-8");
    newSbom = JSON.parse(newContent);
  } catch (e) {
    if (e.code === "ENOENT") {
      console.error(`Error: New SBOM file not found: ${newPath}`);
    } else if (e instanceof SyntaxError) {
      console.error(`Error: Invalid JSON in new SBOM file: ${newPath}`);
    } else {
      console.error(`Error reading new SBOM: ${e.message}`);
    }
    process.exit(1);
  }

  // Perform diff
  try {
    const result = diffSbom(oldSbom, newSbom);

    if (diffOutput) {
      // Write JSON diff to file
      const dir = path.dirname(diffOutput);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(diffOutput, JSON.stringify(result, null, 2), "utf-8");
      console.error(`Diff report written to ${diffOutput}`);
      console.error(`  Added: ${result.summary.totalAdded}, Removed: ${result.summary.totalRemoved}, Updated: ${result.summary.totalUpdated}`);
    } else {
      // Output human-readable format to stdout
      console.log(formatDiffResult(result));
    }

    // Exit with non-zero if there are any changes
    const hasChanges = result.summary.totalAdded > 0 || result.summary.totalRemoved > 0 || result.summary.totalUpdated > 0;
    process.exit(hasChanges ? 1 : 0);
  } catch (e) {
    console.error(`Diff error: ${e.message}`);
    process.exit(1);
  }
}

/**
 * Handle the --validate-sbom command: validate an SBOM file against its schema.
 */
function handleValidateSbom(args) {
  const filePath = args.validateSbom;
  const formatHint = args.format || "auto"; // reuse --format for SBOM format hint
  const outputPath = args.validationOutput;

  // Load the dist module for validation
  const distEntry = path.join(__dirname, "..", "dist", "index.js");
  if (!fs.existsSync(distEntry)) {
    console.error("pnpm-audit-hook: not built. Run 'pnpm build' first.");
    process.exit(1);
  }

  let validateSbom;
  try {
    const distModule = require(distEntry);
    validateSbom = distModule.validateSbom;
  } catch (e) {
    console.error(`Error loading pnpm-audit-hook module: ${e.message}`);
    process.exit(1);
  }

  // Read the SBOM file
  let content;
  try {
    content = fs.readFileSync(filePath, "utf-8");
  } catch (e) {
    if (e.code === "ENOENT") {
      console.error(`Error: SBOM file not found: ${filePath}`);
    } else {
      console.error(`Error reading SBOM file: ${e.message}`);
    }
    process.exit(1);
  }

  // Auto-detect format from file content
  function detectFormat(raw) {
    const trimmed = raw.trimStart();
    // Check if XML
    if (trimmed.startsWith("<?xml") || trimmed.startsWith("<")) {
      if (trimmed.includes("cyclonedx") || trimmed.includes("<bom")) {
        return "cyclonedx";
      }
      if (trimmed.includes("swidTagSet") || trimmed.includes("<swid>")) {
        return "swid";
      }
      return null; // unknown XML format
    }
    // JSON-based detection
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed.bomFormat === "CycloneDX") return "cyclonedx";
      if (parsed.spdxVersion) return "spdx";
    } catch {
      // not valid JSON
    }
    return null;
  }

  let resolvedFormat;
  if (formatHint && formatHint !== "auto") {
    resolvedFormat = formatHint;
  } else {
    resolvedFormat = detectFormat(content);
    if (!resolvedFormat) {
      console.error("Error: Could not auto-detect SBOM format.");
      console.error("Please specify the format with --format <cyclonedx|spdx|swid>.");
      process.exit(1);
    }
  }

  // Validate
  let result;
  try {
    result = validateSbom(content, resolvedFormat);
  } catch (e) {
    console.error(`Validation error: ${e.message}`);
    process.exit(1);
  }

  // Build the report object
  const report = {
    file: filePath,
    format: result.format || resolvedFormat,
    valid: result.valid,
    errors: result.errors.map((err) => ({
      path: err.path,
      message: err.message,
      severity: err.severity,
    })),
    warnings: result.warnings.map((warn) => ({
      path: warn.path,
      message: warn.message,
      severity: warn.severity,
    })),
  };

  // Output to file if requested
  if (outputPath) {
    const dir = path.dirname(outputPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), "utf-8");
    console.error(`Validation report written to ${outputPath}`);
  }

  // Pretty-print results to stdout
  const icon = result.valid ? "\u2713" : "\u2717";
  const status = result.valid ? "PASS" : "FAIL";
  console.log("");
  console.log(`SBOM Validation: ${icon} ${status}`);
  console.log(`  File:   ${filePath}`);
  console.log(`  Format: ${report.format}`);

  if (result.errors.length > 0) {
    console.log("");
    console.log(`  Errors (${result.errors.length}):`);
    for (const err of result.errors) {
      console.log(`    - [${err.path || "root"}] ${err.message}`);
    }
  }

  if (result.warnings.length > 0) {
    console.log("");
    console.log(`  Warnings (${result.warnings.length}):`);
    for (const warn of result.warnings) {
      console.log(`    - [${warn.path || "root"}] ${warn.message}`);
    }
  }

  console.log("");
  process.exit(result.valid ? 0 : 1);
}

main();
