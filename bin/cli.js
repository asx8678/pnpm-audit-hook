#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const YAML = require("yaml");

const { parseArgs, HELP } = require("./parse-args.js");

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    console.log(HELP);
    process.exit(0);
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

  // Set env vars from CLI flags (before importing the module so logger picks them up)
  if (args.quiet) process.env.PNPM_AUDIT_QUIET = "true";
  if (args.verbose) process.env.PNPM_AUDIT_VERBOSE = "true";
  if (args.debug) process.env.PNPM_AUDIT_DEBUG = "true";
  if (args.offline) process.env.PNPM_AUDIT_OFFLINE = "true";
  if (args.format) {
    if (args.format === "json") {
      process.env.PNPM_AUDIT_JSON = "true";
    } else {
      process.env.PNPM_AUDIT_FORMAT = args.format;
    }
  }
  if (args.config) process.env.PNPM_AUDIT_CONFIG_PATH = args.config;
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
  try {
    runAudit = require(distEntry).runAudit;
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

    process.exit(result.exitCode);
  } catch (e) {
    console.error(`Audit error: ${e.message}`);
    process.exit(1);
  }
}

main();
