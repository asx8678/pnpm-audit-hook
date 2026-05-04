/**
 * Audit command handler for pnpm-audit-scan.
 *
 * Runs a vulnerability audit on the project's pnpm-lock.yaml.
 */

import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";
import type { CliArgs } from "./types.js";
import { VALID_FORMATS, VALID_SEVERITIES } from "./types.js";

/**
 * Run the audit command.
 *
 * Parses the lockfile, runs the audit, and reports results.
 *
 * @param args - Parsed CLI arguments
 * @returns Process exit code
 */
export async function runAuditCommand(args: CliArgs): Promise<number> {
  const cwd = process.cwd();
  const lockfilePath = path.resolve(cwd, "pnpm-lock.yaml");

  if (!fs.existsSync(lockfilePath)) {
    console.error("Error: No pnpm-lock.yaml found in current directory.");
    console.error("This tool scans pnpm lockfiles. Run it from a pnpm project root.");
    console.error("");
    console.error("If this is an npm/yarn project, use 'npm audit' or 'yarn audit' instead.");
    return 1;
  }

  // Parse the lockfile
  let lockfile;
  try {
    const raw = fs.readFileSync(lockfilePath, "utf-8");
    lockfile = YAML.parse(raw);
  } catch (e) {
    console.error(`Error: Failed to parse pnpm-lock.yaml: ${(e as Error).message}`);
    return 1;
  }

  if (!lockfile || typeof lockfile !== "object") {
    console.error("Error: pnpm-lock.yaml is empty or invalid.");
    return 1;
  }

  // Load the dist module
  const distEntry = path.join(__dirname, "..", "..", "dist", "index.js");
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
    return 1;
  }

  let runAudit: Function;
  let generateSbom: Function;
  try {
    const distModule = require(distEntry);
    runAudit = distModule.runAudit;
    generateSbom = distModule.generateSbom;
  } catch (e) {
    console.error(`Error loading pnpm-audit-hook module: ${(e as Error).message}`);
    console.error(`Expected: ${distEntry}`);
    return 1;
  }

  // Set env vars from CLI flags
  if (args.quiet) process.env.PNPM_AUDIT_QUIET = "true";
  if (args.verbose) process.env.PNPM_AUDIT_VERBOSE = "true";
  if (args.debug) process.env.PNPM_AUDIT_DEBUG = "true";
  if (args.offline) process.env.PNPM_AUDIT_OFFLINE = "true";
  if (args.sbom) process.env.PNPM_AUDIT_SBOM = "true";
  if (args.sbomFormat) process.env.PNPM_AUDIT_SBOM_FORMAT = args.sbomFormat;
  if (args.sbomOutput) process.env.PNPM_AUDIT_SBOM_OUTPUT = args.sbomOutput;
  if (args.dryRun) process.env.PNPM_AUDIT_DRY_RUN = "true";
  if (args.config) process.env.PNPM_AUDIT_CONFIG_PATH = args.config;
  if (args.workspace) process.env.PNPM_AUDIT_WORKSPACE = args.workspace;

  if (args.format) {
    if (!VALID_FORMATS.includes(args.format as typeof VALID_FORMATS[number])) {
      console.error(`Error: Invalid format '${args.format}'.`);
      console.error(`Valid formats: ${VALID_FORMATS.join(", ")}`);
      return 1;
    }
    if (args.format === "json") {
      process.env.PNPM_AUDIT_JSON = "true";
    } else {
      process.env.PNPM_AUDIT_FORMAT = args.format;
    }
  }

  if (args.severity) {
    const requestedSeverities = args.severity.split(",").map(s => s.trim());
    for (const sev of requestedSeverities) {
      if (!VALID_SEVERITIES.includes(sev as typeof VALID_SEVERITIES[number])) {
        console.error(`Error: Invalid severity '${sev}'.`);
        console.error(`Valid severities: ${VALID_SEVERITIES.join(", ")}`);
        return 1;
      }
    }
    process.env.PNPM_AUDIT_BLOCK_SEVERITY = args.severity;
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
        const { extractPackagesFromLockfile } = require(path.join(__dirname, "..", "..", "dist", "utils", "lockfile.js"));
        const { packages } = extractPackagesFromLockfile(lockfile);

        const sbomResult = generateSbom(packages, result.findings, {
          format: sbomFormat,
          outputPath: sbomOutput,
          includeVulnerabilities: true,
          projectName: path.basename(cwd),
          projectVersion: "1.0.0",
        });

        if (!sbomOutput) {
          console.log(sbomResult.content);
        } else {
          console.error(`SBOM written to ${sbomOutput} (${sbomResult.componentCount} components, ${sbomResult.vulnerabilityCount} vulnerabilities)`);
        }
      } catch (sbomErr) {
        console.error(`SBOM generation error: ${(sbomErr as Error).message}`);
      }
    }

    // Dry-run mode: always report, never block
    if (args.dryRun) {
      console.error(`\nDry-run mode: audit report written. Installation would ${result.blocked ? "be BLOCKED" : "pass"}.`);
      return 0;
    }

    return result.exitCode;
  } catch (e) {
    console.error(`Audit error: ${(e as Error).message}`);
    return 1;
  }
}
