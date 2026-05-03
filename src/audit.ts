/**
 * @module audit
 * Core audit functionality for running vulnerability scans.
 *
 * This module provides the main entry point for auditing pnpm lockfiles
 * against multiple vulnerability sources (GitHub Advisory, NVD, OSV) and
 * the bundled static database.
 *
 * @example
 * ```typescript
 * import { runAudit } from 'pnpm-audit-hook/audit';
 *
 * const result = await runAudit(lockfile, {
 *   cwd: process.cwd(),
 *   registryUrl: 'https://registry.npmjs.org',
 *   env: process.env,
 * });
 *
 * console.log(`Found ${result.findings.length} vulnerabilities`);
 * ```
 */

import path from "node:path";
import type { PnpmLockfile, PolicyDecision, RuntimeOptions, SourceStatus, VulnerabilityFinding } from "./types";
import { loadConfig } from "./config";
import { logger } from "./utils/logger";
import { FileCache } from "./cache/file-cache";
import { aggregateVulnerabilities } from "./databases/aggregator";
import { extractPackagesFromLockfile, buildDependencyGraph, traceDependencyChain } from "./utils/lockfile";
import { analyzeAllVulnerabilities, sortByRisk } from "./utils/lockfile/dependency-chain-analyzer";
import { evaluatePackagePolicies } from "./policies/policy-engine";
import { buildSummary, getOutputFormat, outputResults } from "./utils/output-formatter";
import { validateLockfileStructure } from "./utils/security";

/** Directory name for the audit cache */
const CACHE_DIR = ".pnpm-audit-cache";

/** Minimum interval between auto-prune runs (1 hour) */
const PRUNE_INTERVAL_MS = 3600_000;
let lastPruneTime = 0;

/**
 * Process exit codes for audit results.
 *
 * @example
 * ```typescript
 * import { EXIT_CODES } from 'pnpm-audit-hook';
 *
 * if (result.exitCode === EXIT_CODES.BLOCKED) {
 *   console.error('Installation blocked');
 * }
 * ```
 */
export const EXIT_CODES = {
  /** Audit passed with no blocking issues */
  SUCCESS: 0,
  /** Installation blocked due to vulnerabilities */
  BLOCKED: 1,
  /** Warnings present but not blocking */
  WARNINGS: 2,
  /** Vulnerability source failed */
  SOURCE_ERROR: 3,
} as const;

/**
 * Complete result of an audit run.
 *
 * Contains all findings, policy decisions, and metadata about the audit execution.
 */
export interface AuditResult {
  /** Whether installation should be blocked */
  blocked: boolean;
  /** Whether warnings were generated */
  warnings: boolean;
  /** Policy decisions for each finding */
  decisions: PolicyDecision[];
  /** Process exit code (see {@link EXIT_CODES}) */
  exitCode: number;
  /** All vulnerability findings across all packages */
  findings: VulnerabilityFinding[];
  /** Status of each vulnerability source */
  sourceStatus: Record<string, SourceStatus>;
  /** Total number of packages audited */
  totalPackages: number;
  /** Audit duration in milliseconds */
  durationMs: number;
  /** Cache performance statistics */
  cacheStats?: {
    /** Cache hit rate (0-1) */
    hitRate: number;
    /** Total cached entries */
    totalEntries: number;
    /** Total cache size in bytes */
    totalSizeBytes: number;
    /** Average read time in milliseconds */
    averageReadTimeMs: number;
    /** Average write time in milliseconds */
    averageWriteTimeMs: number;
  };
  /** SBOM generation result (if enabled in config) */
  sbom?: {
    /** SBOM content as JSON string */
    content: string;
    /** SBOM format used */
    format: string;
    /** Number of components in SBOM */
    componentCount: number;
    /** Number of vulnerabilities included */
    vulnerabilityCount: number;
    /** Output file path (if written to file) */
    outputPath?: string;
    /** Generation duration in milliseconds */
    durationMs: number;
  };
}

/**
 * Runs a complete audit on the provided lockfile.
 *
 * Orchestrates multiple vulnerability sources, applies policy rules,
 * and returns structured results with findings and decisions.
 *
 * @param lockfile - The resolved pnpm lockfile structure
 * @param runtime - Runtime configuration (cwd, env, registry)
 * @returns Complete audit result with findings, decisions, and metadata
 *
 * @example
 * ```typescript
 * import { runAudit } from 'pnpm-audit-hook';
 * import fs from 'node:fs/promises';
 * import YAML from 'yaml';
 *
 * const content = await fs.readFile('pnpm-lock.yaml', 'utf-8');
 * const lockfile = YAML.parse(content);
 *
 * const result = await runAudit(lockfile, {
 *   cwd: process.cwd(),
 *   registryUrl: 'https://registry.npmjs.org',
 *   env: process.env,
 * });
 *
 * if (result.blocked) {
 *   console.error(`Blocked: ${result.findings.length} vulnerabilities`);
 *   process.exit(1);
 * }
 * ```
 *
 * @throws {Error} If config file has YAML syntax errors
 * @throws {Error} If config contains security violations
 */
export async function runAudit(lockfile: PnpmLockfile, runtime: RuntimeOptions): Promise<AuditResult> {
  const startTime = Date.now();
  const { cwd, env, registryUrl } = runtime;
  const cfg = await loadConfig({ cwd, env });
  const cache = new FileCache({ dir: path.resolve(cwd, CACHE_DIR) });

  // Validate lockfile structure for security
  const lockfileValidation = validateLockfileStructure(lockfile);
  if (lockfileValidation.warnings.length > 0) {
    for (const warning of lockfileValidation.warnings) {
      logger.warn(`Lockfile integrity: ${warning}`);
    }
  }
  if (!lockfileValidation.valid) {
    logger.warn(`Lockfile validation failed — proceeding with caution (may produce incomplete results)`);
  }

  // Auto-prune expired cache entries (at most once per hour, non-blocking)
  const now = Date.now();
  if (now - lastPruneTime > PRUNE_INTERVAL_MS) {
    lastPruneTime = now;
    cache.prune().then(({ pruned }) => {
      if (pruned > 0) logger.debug(`Cache auto-prune: removed ${pruned} expired entries`);
    }).catch(() => { /* ignore prune errors */ });
  }

  const { packages } = extractPackagesFromLockfile(lockfile);

  logger.verbose(`Starting audit of ${packages.length} packages`);

  const agg = await aggregateVulnerabilities(packages, { cfg, env, cache, registryUrl });

  // Build dependency graph and perform enhanced chain analysis
  const graph = buildDependencyGraph(lockfile);

  // Trace basic dependency chains for each finding
  for (const finding of agg.findings) {
    const findingKey = `${finding.packageName}@${finding.packageVersion}`;
    const chain = traceDependencyChain(graph, findingKey);
    if (chain) {
      finding.dependencyChain = chain;
    }
  }

  // Enhanced analysis: CVSS integration, severity propagation, risk scoring
  const enrichedFindings = analyzeAllVulnerabilities(agg.findings, graph);

  // Sort findings by composite risk score for prioritized reporting
  const sortedFindings = sortByRisk(enrichedFindings);

  // Replace findings with enriched and sorted version
  agg.findings = sortedFindings;

  // Group findings by package
  const findingsByPkg = new Map<string, VulnerabilityFinding[]>();
  for (const finding of agg.findings) {
    const key = `${finding.packageName}@${finding.packageVersion}`;
    if (!findingsByPkg.has(key)) {
      findingsByPkg.set(key, []);
    }
    findingsByPkg.get(key)!.push(finding);
  }

  // Evaluate policies per package
  const decisions: PolicyDecision[] = [];
  for (const p of packages) {
    const findings = findingsByPkg.get(`${p.name}@${p.version}`) ?? [];
    decisions.push(...evaluatePackagePolicies({ pkg: p, findings }, cfg, graph));
  }

  // Add decision for source failures (block when failOnSourceError, warn otherwise)
  const failedSources = Object.entries(agg.sources).filter(([, v]) => !v.ok);
  const hasSourceError = failedSources.length > 0;
  if (hasSourceError) {
    const srcList = failedSources.map(([k, v]) => `${k}: ${v.error ?? "unknown"}`).join("; ");
    const action = cfg.failOnSourceError !== false ? "block" : "warn";
    decisions.push({
      action,
      reason: `Source failure: ${srcList}`,
      source: "source",
      at: new Date().toISOString(),
    });
  }

  const blocked = decisions.some((d) => d.action === "block");
  const warnings = decisions.some((d) => d.action === "warn");
  const durationMs = Date.now() - startTime;

  // Determine exit code
  // Note: SOURCE_ERROR is only reachable when failOnSourceError is false (source failure
  // becomes a warn decision, not block). When failOnSourceError is true (default),
  // source failures push a block decision, so exitCode will be BLOCKED instead.
  let exitCode: number;
  if (blocked) {
    exitCode = EXIT_CODES.BLOCKED;
  } else if (hasSourceError) {
    exitCode = EXIT_CODES.SOURCE_ERROR;
  } else if (warnings) {
    exitCode = EXIT_CODES.WARNINGS;
  } else {
    exitCode = EXIT_CODES.SUCCESS;
  }

  // Build summary and output results
  const summary = buildSummary(packages.length, agg.findings, decisions, agg.sources, agg.wallClockMs);
  outputResults(
    {
      summary,
      findings: agg.findings,
      decisions,
      blocked,
      warnings,
      exitCode,
    },
    getOutputFormat(env),
  );

  // Generate SBOM if enabled in config
  let sbomResult: AuditResult['sbom'];
  if (cfg.sbom?.enabled) {
    try {
      const { generateSbom } = await import('./sbom/generator');
      const result = generateSbom(packages, agg.findings, {
        format: cfg.sbom.format ?? 'cyclonedx',
        outputPath: cfg.sbom.outputPath,
        includeVulnerabilities: cfg.sbom.includeVulnerabilities ?? true,
        projectName: cfg.sbom.projectName ?? path.basename(cwd),
        projectVersion: cfg.sbom.projectVersion ?? '1.0.0',
      });
      sbomResult = {
        content: result.content,
        format: result.format,
        componentCount: result.componentCount,
        vulnerabilityCount: result.vulnerabilityCount,
        outputPath: result.outputPath,
        durationMs: result.durationMs,
      };
    } catch (e) {
      logger.error(`SBOM generation failed: ${e instanceof Error ? e.message : e}`);
    }
  }

  // Get cache statistics
  const cacheStats = cache.getStatistics();
  const hitRate = cacheStats.hits + cacheStats.misses > 0
    ? cacheStats.hits / (cacheStats.hits + cacheStats.misses)
    : 0;

  return {
    blocked,
    warnings,
    decisions,
    exitCode,
    findings: agg.findings,
    sourceStatus: agg.sources,
    totalPackages: packages.length,
    durationMs,
    cacheStats: {
      hitRate,
      totalEntries: cacheStats.totalEntries,
      totalSizeBytes: cacheStats.totalSizeBytes,
      averageReadTimeMs: cacheStats.averageReadTimeMs,
      averageWriteTimeMs: cacheStats.averageWriteTimeMs,
    },
    sbom: sbomResult,
  };
}
