#!/usr/bin/env node
"use strict";

const HELP = `
pnpm-audit-hook — scan your pnpm lockfile for known vulnerabilities

Usage:
  pnpm-audit-scan [options]

Options:
  --format <format>   Output format: human, json, azure, github, aws (default: human)
  --severity <list>   Comma-severity severity levels to block (default: critical,high)
  --offline           Skip live API calls, use only static DB + cache
  --db-status         Show database status
  --update-db         Update the vulnerability database (incremental)
  --update-db=full    Update the vulnerability database (full rebuild)
  --quiet             Suppress non-error output
  --verbose           Enable verbose output
  --debug             Enable debug output
  --config <path>     Path to .pnpm-audit.yaml config file
  --troubleshoot      Show troubleshooting information
  --help              Show this help
  --version           Show version

Examples:
  pnpm-audit-scan
  pnpm-audit-scan --format json
  pnpm-audit-scan --format azure
  pnpm-audit-scan --format github
  pnpm-audit-scan --format aws
  pnpm-audit-scan --severity critical
  pnpm-audit-scan --offline
  pnpm-audit-scan --update-db
  pnpm-audit-scan --update-db=full
  pnpm-audit-scan --troubleshoot

Troubleshooting:
  Run 'pnpm-audit-scan --troubleshoot' for diagnostic information
  or see docs/troubleshooting.md for comprehensive help.
`;

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
    } else if (arg === "--version" || arg === "-v") {
      args.version = true;
    } else if (arg === "--troubleshoot") {
      args.troubleshoot = true;
    } else if (arg === "--offline") {
      args.offline = true;
    } else if (arg === "--db-status") {
      args.dbStatus = true;
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

module.exports = { parseArgs, HELP };
