import path from "node:path";
import type { PnpmLockfile, PolicyDecision, RuntimeOptions, SourceStatus, VulnerabilityFinding } from "./types";
import { loadConfig } from "./config";
import { logger } from "./utils/logger";
import { FileCache } from "./cache/file-cache";
import { aggregateVulnerabilities } from "./databases/aggregator";
import { extractPackagesFromLockfile, buildDependencyGraph, traceDependencyChain } from "./utils/lockfile";
import { evaluatePackagePolicies } from "./policies/policy-engine";
import { buildSummary, getOutputFormat, outputResults } from "./utils/output-formatter";

const CACHE_DIR = ".pnpm-audit-cache";

/** Minimum interval between auto-prune runs (1 hour) */
const PRUNE_INTERVAL_MS = 3600_000;
let lastPruneTime = 0;

/** Exit codes for audit results */
export const EXIT_CODES = {
  SUCCESS: 0,
  BLOCKED: 1,
  WARNINGS: 2,
  SOURCE_ERROR: 3,
} as const;

export interface AuditResult {
  blocked: boolean;
  warnings: boolean;
  decisions: PolicyDecision[];
  exitCode: number;
  findings: VulnerabilityFinding[];
  sourceStatus: Record<string, SourceStatus>;
  totalPackages: number;
  durationMs: number;
  cacheStats?: {
    hitRate: number;
    totalEntries: number;
    totalSizeBytes: number;
    averageReadTimeMs: number;
    averageWriteTimeMs: number;
  };
}

export async function runAudit(lockfile: PnpmLockfile, runtime: RuntimeOptions): Promise<AuditResult> {
  const startTime = Date.now();
  const { cwd, env, registryUrl } = runtime;
  const cfg = await loadConfig({ cwd, env });
  const cache = new FileCache({ dir: path.resolve(cwd, CACHE_DIR) });

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

  // Trace dependency chains for each finding
  const graph = buildDependencyGraph(lockfile);
  for (const finding of agg.findings) {
    const findingKey = `${finding.packageName}@${finding.packageVersion}`;
    const chain = traceDependencyChain(graph, findingKey);
    if (chain) {
      finding.dependencyChain = chain;
    }
  }

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
  };
}
