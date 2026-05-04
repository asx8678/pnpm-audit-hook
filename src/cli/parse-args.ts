/**
 * CLI argument parser for pnpm-audit-scan.
 *
 * Parses process.argv into a typed CliArgs object.
 * No external dependencies — pure manual parsing for minimal footprint.
 */

import type { CliArgs } from "./types.js";

export const HELP = `
pnpm-audit-hook — scan your pnpm lockfile for known vulnerabilities

Usage:
  pnpm-audit-scan [options]

Options:
  --format <format>     Output format: human, json, azure, github, aws (default: human)
  --severity <list>     Comma-separated severity levels to block (default: critical,high)
  --offline             Skip live API calls, use only static DB + cache
  --db-status           Show database status
  --update-db           Update the vulnerability database (incremental)
  --update-db=full      Update the vulnerability database (full rebuild)
  --sbom                Generate SBOM (Software Bill of Materials)
  --sbom-format <fmt>   SBOM format: cyclonedx, cyclonedx-xml, spdx, swid (default: cyclonedx)
  --sbom-output <path>  Write SBOM to file (default: stdout)
  --sbom-diff <old> <new>  Compare two SBOM documents
  --diff-output <path>     Write diff report to file (default: stdout)
  --dep-tree            Generate dependency tree visualization
  --tree-depth <n>      Max depth for dependency tree (default: unlimited)
  --tree-format <fmt>   Tree format: ascii, json (default: ascii)
  --tree-output <path>  Write tree output to file (default: stdout)
  --sbom-input <path>   Use existing SBOM file for tree generation
  --validate-sbom <file>  Validate an SBOM file against its schema
  --validation-output <path> Write validation report to file
  --workspace <name>    Filter results to a specific workspace (monorepo)
  --fix                 Attempt to fix vulnerable packages automatically
  --dry-run             Report-only mode — write report but don't block installation
  --quiet               Suppress non-error output
  --verbose             Enable verbose output
  --debug               Enable debug output
  --config <path>       Path to .pnpm-audit.yaml config file
  --troubleshoot        Show troubleshooting information
  --help                Show this help
  --version             Show version

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
  pnpm-audit-scan --sbom
  pnpm-audit-scan --sbom --sbom-format cyclonedx --sbom-output sbom.json
  pnpm-audit-scan --sbom --sbom-format cyclonedx-xml --sbom-output sbom.xml
  pnpm-audit-scan --sbom --sbom-format spdx
  pnpm-audit-scan --sbom --sbom-format swid
  pnpm-audit-scan --sbom-diff old-sbom.json new-sbom.json
  pnpm-audit-scan --sbom-diff old-sbom.json new-sbom.json --diff-output report.json
  pnpm-audit-scan --dep-tree
  pnpm-audit-scan --dep-tree --tree-depth 3
  pnpm-audit-scan --dep-tree --tree-format json
  pnpm-audit-scan --dep-tree --tree-output tree.txt
  pnpm-audit-scan --dep-tree --sbom-input existing-sbom.json
  pnpm-audit-scan --validate-sbom sbom.json
  pnpm-audit-scan --validate-sbom sbom.json --format cyclonedx
  pnpm-audit-scan --validate-sbom sbom.json --format spdx
  pnpm-audit-scan --validate-sbom sbom.json --validation-output report.json
  pnpm-audit-scan --workspace packages/app
  pnpm-audit-scan --dry-run
  pnpm-audit-scan --fix
  pnpm-audit-scan --fix --dry-run
  pnpm-audit-scan --troubleshoot

Troubleshooting:
  Run 'pnpm-audit-scan --troubleshoot' for diagnostic information
  or see docs/troubleshooting.md for comprehensive help.
`;

/**
 * Parse CLI arguments from an argv array (typically process.argv.slice(2)).
 *
 * @param argv - Argument array to parse
 * @returns Parsed CliArgs object
 */
export function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = { _: [] };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;

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
    } else if (arg === "--sbom") {
      args.sbom = true;
    } else if (arg === "--dry-run" || arg === "--report-only") {
      args.dryRun = true;
    } else if (arg === "--sbom-format" && argv[i + 1] !== undefined) {
      args.sbomFormat = argv[++i]!;
    } else if (arg === "--sbom-output" && argv[i + 1]) {
      args.sbomOutput = argv[++i];
    } else if (arg === "--sbom-diff") {
      const nextArg = argv[i + 1];
      const nextArg2 = argv[i + 2];
      if (nextArg && !nextArg.startsWith("--")) {
        args.sbomDiffOld = nextArg;
        i++;
        if (nextArg2 && !nextArg2.startsWith("--")) {
          args.sbomDiffNew = nextArg2;
          i++;
        }
      }
      args.sbomDiff = true;
    } else if (arg === "--diff-output" && argv[i + 1] !== undefined) {
      args.diffOutput = argv[++i]!;
    } else if (arg === "--dep-tree") {
      args.depTree = true;
    } else if (arg === "--tree-depth" && argv[i + 1] !== undefined) {
      args.treeDepth = parseInt(argv[++i]!, 10);
    } else if (arg === "--tree-format" && argv[i + 1] !== undefined) {
      args.treeFormat = argv[++i]!;
    } else if (arg === "--tree-output" && argv[i + 1] !== undefined) {
      args.treeOutput = argv[++i]!;
    } else if (arg === "--sbom-input" && argv[i + 1] !== undefined) {
      args.sbomInput = argv[++i]!;
    } else if (arg === "--validate-sbom" && argv[i + 1] !== undefined) {
      args.validateSbom = argv[++i]!;
    } else if (arg === "--validation-output" && argv[i + 1] !== undefined) {
      args.validationOutput = argv[++i]!;
    } else if (arg === "--workspace" && argv[i + 1] !== undefined) {
      args.workspace = argv[++i]!;
    } else if (arg === "--fix") {
      args.fix = true;
    } else if ((arg === "--format" || arg === "-f") && argv[i + 1] !== undefined) {
      args.format = argv[++i]!;
    } else if ((arg === "--severity" || arg === "-s") && argv[i + 1] !== undefined) {
      args.severity = argv[++i]!;
    } else if (arg === "--update-db") {
      args.updateDb = "incremental";
    } else if (arg.startsWith("--update-db=")) {
      const value = arg.slice("--update-db=".length);
      args.updateDb = value === "full" ? "full" : "incremental";
    } else if ((arg === "--config" || arg === "-c") && argv[i + 1]) {
      args.config = argv[++i];
    } else if (arg.startsWith("--")) {
      args.unknownFlags = args.unknownFlags || [];
      args.unknownFlags.push(arg);
    } else {
      args._.push(arg);
    }
  }

  return args;
}
