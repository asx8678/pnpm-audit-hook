#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const YAML = require("yaml");

const HELP = `
pnpm-audit-hook — scan your pnpm lockfile for known vulnerabilities

Usage:
  pnpm-audit-scan [options]

Options:
  --format <format>   Output format: human, json, azure, github (default: human)
  --severity <list>   Comma-separated severity levels to block (default: critical,high)
  --offline           Skip live API calls, use only static DB + cache
  --update-db         Update the vulnerability database (incremental)
  --update-db=full    Update the vulnerability database (full rebuild)
  --quiet             Suppress non-error output
  --verbose           Enable verbose output
  --debug             Enable debug output
  --config <path>     Path to .pnpm-audit.yaml config file
  --help              Show this help
  --version           Show version

Examples:
  pnpm-audit-scan
  pnpm-audit-scan --format json
  pnpm-audit-scan --severity critical
  pnpm-audit-scan --offline
  pnpm-audit-scan --update-db
  pnpm-audit-scan --update-db=full
`;

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
    } else if (arg === "--version" || arg === "-v") {
      args.version = true;
    } else if (arg === "--offline") {
      args.offline = true;
    } else if (arg === "--quiet" || arg === "-q") {
      args.quiet = true;
    } else if (arg === "--verbose") {
      args.verbose = true;
    } else if (arg === "--debug") {
      args.debug = true;
    } else if ((arg === "--format" || arg === "-f") && argv[i + 1]) {
      args.format = argv[++i];
    } else if ((arg === "--severity" || arg === "-s") && argv[i + 1]) {
      args.severity = argv[++i];
    } else if (arg === "--update-db") {
      args.updateDb = "incremental";
    } else if (arg.startsWith("--update-db=")) {
      const value = arg.slice("--update-db=".length);
      args.updateDb = value === "full" ? "full" : "incremental";
    } else if ((arg === "--config" || arg === "-c") && argv[i + 1]) {
      args.config = argv[++i];
    } else {
      args._.push(arg);
    }
  }
  return args;
}

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
  const { runAudit } = require("../dist/index.js");

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
