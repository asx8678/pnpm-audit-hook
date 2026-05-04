/**
 * SBOM command handlers for pnpm-audit-scan.
 *
 * Handles --sbom-diff, --validate-sbom, and --dep-tree commands.
 */

import fs from "node:fs";
import path from "node:path";
import type { CliArgs } from "./types.js";

/**
 * Run the SBOM diff command.
 *
 * @param args - Parsed CLI arguments
 * @returns Process exit code
 */
export function runSbomDiffCommand(args: CliArgs): number {
  const oldPath = args.sbomDiffOld;
  const newPath = args.sbomDiffNew;
  const diffOutput = args.diffOutput;

  if (!oldPath || !newPath) {
    console.error("Error: --sbom-diff requires two file arguments.");
    console.error("Usage: pnpm-audit-scan --sbom-diff <old-sbom.json> <new-sbom.json>");
    return 1;
  }

  const distEntry = path.join(__dirname, "..", "..", "dist", "index.js");
  if (!fs.existsSync(distEntry)) {
    console.error("pnpm-audit-hook: not built. Run 'pnpm build' first.");
    return 1;
  }

  let diffSbom: Function;
  let formatDiffResult: Function;
  try {
    const distModule = require(distEntry);
    diffSbom = distModule.diffSbom;
    formatDiffResult = distModule.formatDiffResult;
  } catch (e) {
    console.error(`Error loading pnpm-audit-hook module: ${(e as Error).message}`);
    return 1;
  }

  // Read old SBOM
  let oldSbom;
  try {
    oldSbom = JSON.parse(fs.readFileSync(oldPath, "utf-8"));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") {
      console.error(`Error: Old SBOM file not found: ${oldPath}`);
    } else if (e instanceof SyntaxError) {
      console.error(`Error: Invalid JSON in old SBOM file: ${oldPath}`);
    } else {
      console.error(`Error reading old SBOM: ${(e as Error).message}`);
    }
    return 1;
  }

  // Read new SBOM
  let newSbom;
  try {
    newSbom = JSON.parse(fs.readFileSync(newPath, "utf-8"));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") {
      console.error(`Error: New SBOM file not found: ${newPath}`);
    } else if (e instanceof SyntaxError) {
      console.error(`Error: Invalid JSON in new SBOM file: ${newPath}`);
    } else {
      console.error(`Error reading new SBOM: ${(e as Error).message}`);
    }
    return 1;
  }

  // Perform diff
  try {
    const result = diffSbom(oldSbom, newSbom);

    if (diffOutput) {
      const dir = path.dirname(diffOutput);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(diffOutput, JSON.stringify(result, null, 2), "utf-8");
      console.error(`Diff report written to ${diffOutput}`);
      console.error(`  Added: ${result.summary.totalAdded}, Removed: ${result.summary.totalRemoved}, Updated: ${result.summary.totalUpdated}`);
    } else {
      console.log(formatDiffResult(result));
    }

    const hasChanges = result.summary.totalAdded > 0 || result.summary.totalRemoved > 0 || result.summary.totalUpdated > 0;
    return hasChanges ? 1 : 0;
  } catch (e) {
    console.error(`Diff error: ${(e as Error).message}`);
    return 1;
  }
}

/**
 * Run the SBOM validation command.
 *
 * @param args - Parsed CLI arguments
 * @returns Process exit code
 */
export function runValidateSbomCommand(args: CliArgs): number {
  const filePath = args.validateSbom!;
  const formatHint = args.format || "auto";
  const outputPath = args.validationOutput;

  const distEntry = path.join(__dirname, "..", "..", "dist", "index.js");
  if (!fs.existsSync(distEntry)) {
    console.error("pnpm-audit-hook: not built. Run 'pnpm build' first.");
    return 1;
  }

  let validateSbom: Function;
  try {
    const distModule = require(distEntry);
    validateSbom = distModule.validateSbom;
  } catch (e) {
    console.error(`Error loading pnpm-audit-hook module: ${(e as Error).message}`);
    return 1;
  }

  let content: string;
  try {
    content = fs.readFileSync(filePath, "utf-8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") {
      console.error(`Error: SBOM file not found: ${filePath}`);
    } else {
      console.error(`Error reading SBOM file: ${(e as Error).message}`);
    }
    return 1;
  }

  // Auto-detect format from file content
  function detectFormat(raw: string): string | null {
    const trimmed = raw.trimStart();
    if (trimmed.startsWith("<?xml") || trimmed.startsWith("<")) {
      if (trimmed.includes("cyclonedx") || trimmed.includes("<bom")) {
        return "cyclonedx";
      }
      if (trimmed.includes("swidTagSet") || trimmed.includes("<swid>")) {
        return "swid";
      }
      return null;
    }
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed.bomFormat === "CycloneDX") return "cyclonedx";
      if (parsed.spdxVersion) return "spdx";
    } catch {
      // not valid JSON
    }
    return null;
  }

  let resolvedFormat: string;
  if (formatHint && formatHint !== "auto") {
    resolvedFormat = formatHint;
  } else {
    const detected = detectFormat(content);
    if (!detected) {
      console.error("Error: Could not auto-detect SBOM format.");
      console.error("Please specify the format with --format <cyclonedx|spdx|swid>.");
      return 1;
    }
    resolvedFormat = detected;
  }

  let result;
  try {
    result = validateSbom(content, resolvedFormat);
  } catch (e) {
    console.error(`Validation error: ${(e as Error).message}`);
    return 1;
  }

  const report = {
    file: filePath,
    format: result.format || resolvedFormat,
    valid: result.valid,
    errors: result.errors.map((err: { path?: string; message: string; severity?: string }) => ({
      path: err.path,
      message: err.message,
      severity: err.severity,
    })),
    warnings: result.warnings.map((warn: { path?: string; message: string; severity?: string }) => ({
      path: warn.path,
      message: warn.message,
      severity: warn.severity,
    })),
  };

  if (outputPath) {
    const dir = path.dirname(outputPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), "utf-8");
    console.error(`Validation report written to ${outputPath}`);
  }

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
  return result.valid ? 0 : 1;
}

/**
 * Run the dependency tree command.
 *
 * @param args - Parsed CLI arguments
 * @returns Process exit code
 */
export function runDepTreeCommand(args: CliArgs): number {
  const distEntry = path.join(__dirname, "..", "..", "dist", "index.js");
  if (!fs.existsSync(distEntry)) {
    console.error("pnpm-audit-hook: not built. Run 'pnpm build' first.");
    return 1;
  }

  let buildTreeFromSbom: Function;
  let buildTreeFromLockfile: Function;
  let renderTree: Function;
  let renderTreeJson: Function;
  try {
    const distModule = require(distEntry);
    buildTreeFromSbom = distModule.buildTreeFromSbom;
    buildTreeFromLockfile = distModule.buildTreeFromLockfile;
    renderTree = distModule.renderTree;
    renderTreeJson = distModule.renderTreeJson;
  } catch (e) {
    console.error(`Error loading pnpm-audit-hook module: ${(e as Error).message}`);
    return 1;
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
      if (!fs.existsSync(sbomInput)) {
        console.error(`Error: SBOM file not found: ${sbomInput}`);
        return 1;
      }

      let sbomDoc;
      try {
        sbomDoc = JSON.parse(fs.readFileSync(sbomInput, "utf-8"));
      } catch (e) {
        if (e instanceof SyntaxError) {
          console.error(`Error: Invalid JSON in SBOM file: ${sbomInput}`);
        } else {
          console.error(`Error reading SBOM file: ${(e as Error).message}`);
        }
        return 1;
      }

      tree = buildTreeFromSbom(sbomDoc, treeOptions);
    } else {
      const cwd = process.cwd();
      const lockfilePath = path.resolve(cwd, "pnpm-lock.yaml");

      if (!fs.existsSync(lockfilePath)) {
        console.error("Error: No pnpm-lock.yaml found in current directory.");
        console.error("This tool scans pnpm lockfiles. Run it from a pnpm project root.");
        console.error("");
        console.error("Tip: Use --sbom-input to generate a tree from an existing SBOM file.");
        return 1;
      }

      tree = buildTreeFromLockfile(lockfilePath, treeOptions);
    }

    let output: string;
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

    return 0;
  } catch (e) {
    console.error(`Dependency tree error: ${(e as Error).message}`);
    return 1;
  }
}
