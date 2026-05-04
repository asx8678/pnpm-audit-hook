/**
 * CLI argument types and interfaces.
 *
 * Typed representation of all CLI flags for pnpm-audit-scan.
 */

/** All CLI arguments parsed from process.argv */
export interface CliArgs {
  /** Positional arguments */
  _: string[];
  /** Show help text */
  help?: boolean;
  /** Show version */
  version?: boolean;
  /** Show troubleshooting info */
  troubleshoot?: boolean;
  /** Output format */
  format?: string;
  /** Severity levels to block */
  severity?: string;
  /** Offline mode */
  offline?: boolean;
  /** Suppress non-error output */
  quiet?: boolean;
  /** Verbose output */
  verbose?: boolean;
  /** Debug output */
  debug?: boolean;
  /** Config file path */
  config?: string;
  /** Show DB status */
  dbStatus?: boolean;
  /** Update DB mode */
  updateDb?: "incremental" | "full";
  /** Generate SBOM */
  sbom?: boolean;
  /** SBOM format */
  sbomFormat?: string;
  /** SBOM output path */
  sbomOutput?: string;
  /** SBOM diff mode */
  sbomDiff?: boolean;
  /** Old SBOM file for diff */
  sbomDiffOld?: string;
  /** New SBOM file for diff */
  sbomDiffNew?: string;
  /** Diff output path */
  diffOutput?: string;
  /** Generate dependency tree */
  depTree?: boolean;
  /** Tree max depth */
  treeDepth?: number;
  /** Tree format */
  treeFormat?: string;
  /** Tree output path */
  treeOutput?: string;
  /** SBOM input for tree */
  sbomInput?: string;
  /** Validate SBOM file */
  validateSbom?: string;
  /** Validation output path */
  validationOutput?: string;
  /** Dry-run mode (report only, don't block) */
  dryRun?: boolean;
  /** Workspace filter */
  workspace?: string;
  /** Run audit fix mode */
  fix?: boolean;
  /** Unknown flags for error reporting */
  unknownFlags?: string[];
}

/** Output format options */
export type OutputFormat = "human" | "json" | "azure" | "github" | "aws";

/** Valid severity levels */
export const VALID_SEVERITIES = ["critical", "high", "medium", "low"] as const;

/** Valid output formats */
export const VALID_FORMATS: OutputFormat[] = ["human", "json", "azure", "github", "aws"];

/** Valid SBOM formats */
export const VALID_SBOM_FORMATS = ["cyclonedx", "cyclonedx-xml", "spdx", "swid"] as const;
