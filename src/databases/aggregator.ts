import path from "node:path";
import type { AuditConfig, PackageRef, VulnerabilityFinding } from "../types";
import type { Cache } from "../cache/types";
import type { SourceContext, VulnerabilitySource } from "./connector";
import type { StaticDbReader } from "../static-db/reader";
import { HttpClient } from "../utils/http";
import { GitHubAdvisorySource } from "./github-advisory";
import { OsvSource } from "./osv";
import { enrichFindingsWithNvd } from "./nvd";
import { EpssFetcher, enrichFindingsWithEpss } from "../utils/epss-fetcher";
import { logger } from "../utils/logger";
import { errorMessage } from "../utils/error";
import { LazyStaticDbReader } from "../static-db/lazy-reader";
import { captureMemorySnapshot } from "../utils/performance";

export interface AggregateContext {
  cfg: AuditConfig;
  env: Record<string, string | undefined>;
  cache: Cache;
  registryUrl: string;
  /** Pre-initialized static DB reader (optional, will be created if not provided) */
  staticDb?: StaticDbReader | null;
}

export interface AggregateResult {
  findings: VulnerabilityFinding[];
  sources: Record<string, { ok: boolean; error?: string; durationMs: number }>;
  /** Wall-clock time for parallel source queries (ms). Undefined when no sources ran. */
  wallClockMs?: number;
  /** Memory snapshot at the end of aggregation (for monitoring). */
  memorySnapshot?: ReturnType<typeof captureMemorySnapshot>;
}

/**
 * Deduplicate findings by (packageName, packageVersion, id).
 * Keeps the first occurrence from each source for richer data.
 */
function dedupeFindings(findings: VulnerabilityFinding[]): VulnerabilityFinding[] {
  const seen = new Map<string, VulnerabilityFinding>();
  for (const f of findings) {
    const key = `${f.packageName}@${f.packageVersion}:${f.id}`;
    if (!seen.has(key)) {
      seen.set(key, f);
    }
  }
  return [...seen.values()];
}

/**
 * Query multiple vulnerability sources and aggregate findings.
 */
export async function aggregateVulnerabilities(
  pkgs: PackageRef[],
  ctx: AggregateContext,
): Promise<AggregateResult> {
  const http = new HttpClient({
    timeoutMs: ctx.cfg.performance?.timeoutMs ?? 15000,
    userAgent: "pnpm-audit-hook",
    retries: 2,
    rateLimit: {
      maxRequests: ctx.env.GITHUB_TOKEN || ctx.env.GH_TOKEN ? 100 : 10,
      intervalMs: 60000, // 1 minute window
    },
  });

  const queryCtx: SourceContext = {
    cfg: ctx.cfg,
    env: ctx.env,
    http,
    cache: ctx.cache,
    registryUrl: ctx.registryUrl,
  };

  const sourceStatus: Record<string, { ok: boolean; error?: string; durationMs: number }> = {};

  // Initialize static DB with lazy loading if enabled and not provided
  let staticDb: StaticDbReader | null = ctx.staticDb ?? null;
  const staticBaselineCfg = ctx.cfg.staticBaseline;

  if (staticBaselineCfg?.enabled && !staticDb) {
    try {
      // Path is relative to dist/ directory where index.js lives
      // Static DB data is at dist/static-db/data/
      const defaultDataPath = path.resolve(__dirname, "static-db", "data");
      logger.debug(`Static DB data path: ${staticBaselineCfg.dataPath ?? defaultDataPath}`);
      
      // Use lazy loading — database initializes only when first accessed
      staticDb = new LazyStaticDbReader({
        dataPath: staticBaselineCfg.dataPath ?? defaultDataPath,
        cutoffDate: staticBaselineCfg.cutoffDate,
      });
      logger.debug("Static DB configured with lazy loading");
    } catch (e) {
      logger.warn(`Failed to configure static DB: ${errorMessage(e)}`);
    }
  }

  // Use the static DB's actual cutoff date (from index.json) rather than config default.
  // This ensures API queries align with the DB's actual coverage.
  // For lazy-loaded reader, getCutoffDate() returns the config value until initialized.
  const effectiveCutoffDate = staticDb?.getCutoffDate() ?? staticBaselineCfg?.cutoffDate;

  // Read DB version once at startup and share across all cache key construction.
  // This ensures cache keys change when the static database is updated, causing
  // automatic cache invalidation.
  // For lazy-loaded reader, getDbVersion() returns empty string until initialized.
  const dbVersion = staticDb?.getDbVersion() ?? "";

  // Register vulnerability sources
  // The staticDb may be a LazyStaticDbReader — it will initialize on first query
  const githubSource = new GitHubAdvisorySource({
    staticDb,
    cutoffDate: effectiveCutoffDate,
    dbVersion,
  });
  const osvSource = new OsvSource();

  const sources: VulnerabilitySource[] = [githubSource, osvSource];
  const enabledSources = sources.filter((s) => s.isEnabled(ctx.cfg, ctx.env));

  // Offline mode: skip API calls entirely, rely on static DB + cache
  const isOffline = ctx.cfg.offline;
  if (isOffline) {
    logger.info("Offline mode: skipping live API queries, using static DB and cache only");
  }

  // Track disabled sources in status
  for (const s of sources) {
    if (!s.isEnabled(ctx.cfg, ctx.env)) {
      sourceStatus[s.id] = { ok: true, error: "disabled by configuration", durationMs: 0 };
    }
  }

  if (enabledSources.length === 0) {
    logger.warn("All vulnerability sources are disabled - no vulnerability checks will be performed");

    // Fail-closed: block when no sources are enabled (default behavior for security)
    if (ctx.cfg.failOnNoSources !== false) {
      throw new Error("All vulnerability sources are disabled. Set failOnNoSources: false to allow this.");
    }

    return { findings: [], sources: sourceStatus };
  }

  // Query all enabled sources in parallel and merge findings
  let findings: VulnerabilityFinding[] = [];
  const sourceErrors: string[] = [];

  const wallClockStart = Date.now();

  const settled = await Promise.allSettled(
    enabledSources.map((source) => source.query(pkgs, queryCtx, { offline: isOffline })),
  );

  for (let i = 0; i < settled.length; i++) {
    const source = enabledSources[i]!;
    const outcome = settled[i]!;

    if (outcome.status === "fulfilled") {
      const result = outcome.value;
      findings.push(...result.findings);
      sourceStatus[source.id] = { ok: result.ok, error: result.error, durationMs: result.durationMs };

      if (!result.ok) {
        sourceErrors.push(`${source.id}: ${result.error}`);
        // Fail-closed on source failure (default: true for security)
        if (ctx.cfg.failOnSourceError !== false) {
          throw new Error(`${source.id} source failed: ${result.error}`);
        }
      }
    } else {
      // Promise rejected (unexpected exception)
      const errMsg = errorMessage(outcome.reason);
      logger.error(`${source.id} source failed: ${errMsg}`);
      sourceStatus[source.id] = { ok: false, error: errMsg, durationMs: 0 };
      sourceErrors.push(`${source.id}: ${errMsg}`);

      // Fail-closed on exception (default: true for security)
      if (ctx.cfg.failOnSourceError !== false) {
        throw outcome.reason;
      }
    }
  }

  const wallClockMs = Date.now() - wallClockStart;

  if (sourceErrors.length > 0) {
    logger.warn(`Vulnerability source errors: ${sourceErrors.join(", ")}`);
  }

  // Deduplicate findings (in case of duplicates within GitHub response)
  const dedupedFindings = dedupeFindings(findings);

  // NVD enrichment - adds CVSS data and fills in missing severity for CVE IDs
  // Skip if disabled, offline, no findings, or no findings with unknown severity needing enrichment
  const needsNvdEnrichment =
    !isOffline &&
    ctx.cfg.sources?.nvd?.enabled !== false &&
    dedupedFindings.some((f) => f.severity === "unknown");

  if (needsNvdEnrichment) {
    const nvdResult = await enrichFindingsWithNvd(dedupedFindings, queryCtx);
    sourceStatus["nvd"] = { ok: nvdResult.ok, error: nvdResult.error, durationMs: nvdResult.durationMs };
  }

  // EPSS enrichment - adds exploit prediction scores to findings
  // Skip if disabled, offline, or no findings
  const needsEpssEnrichment =
    !isOffline &&
    dedupedFindings.length > 0 &&
    ctx.cfg.sources?.epss?.enabled !== false;

  if (needsEpssEnrichment) {
    const epssStartTime = Date.now();
    try {
      const epssFetcher = new EpssFetcher({
        disabled: ctx.cfg.sources?.epss?.enabled === false,
      });
      const enrichedFindings = await enrichFindingsWithEpss(dedupedFindings, epssFetcher);
      
      // Update findings with EPSS enrichment
      for (let i = 0; i < enrichedFindings.length; i++) {
        if (enrichedFindings[i]!.epss) {
          dedupedFindings[i] = enrichedFindings[i]!;
        }
      }
      
      sourceStatus["epss"] = {
        ok: true,
        durationMs: Date.now() - epssStartTime,
      };
      
      const epssCount = dedupedFindings.filter((f) => f.epss).length;
      if (epssCount > 0) {
        logger.debug(`EPSS: Enriched ${epssCount}/${dedupedFindings.length} findings with exploit prediction scores`);
      }
    } catch (error) {
      // EPSS enrichment is non-critical - log and continue
      sourceStatus["epss"] = {
        ok: false,
        error: errorMessage(error),
        durationMs: Date.now() - epssStartTime,
      };
      logger.debug(`EPSS enrichment failed: ${errorMessage(error)}`);
    }
  }

  // Capture memory snapshot for performance monitoring
  const memorySnapshot = captureMemorySnapshot();

  return {
    findings: dedupedFindings,
    sources: sourceStatus,
    wallClockMs,
    memorySnapshot,
  };
}
