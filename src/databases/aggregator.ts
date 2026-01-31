import type { AuditConfig, PackageRef, VulnerabilityFinding } from "../types";
import type { Cache } from "../cache/types";
import type { SourceContext } from "./connector";
import { HttpClient } from "../utils/http";
import { GitHubAdvisorySource } from "./github-advisory";
import { enrichFindingsWithNvd } from "./nvd";
import { logger } from "../utils/logger";

export interface AggregateContext {
  cfg: AuditConfig;
  env: Record<string, string | undefined>;
  cache: Cache;
  registryUrl: string;
}

export interface AggregateResult {
  findings: VulnerabilityFinding[];
  sources: Record<string, { ok: boolean; error?: string; durationMs: number }>;
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
  });

  const queryCtx: SourceContext = {
    cfg: ctx.cfg,
    env: ctx.env,
    http,
    cache: ctx.cache,
    registryUrl: ctx.registryUrl,
  };

  const sourceStatus: Record<string, { ok: boolean; error?: string; durationMs: number }> = {};

  // GitHub Advisory is the primary (and only) vulnerability source
  const githubSource = new GitHubAdvisorySource();
  const githubEnabled = githubSource.isEnabled(ctx.cfg, ctx.env);

  if (!githubEnabled) {
    logger.warn("GitHub Advisory source is disabled - no vulnerability checks will be performed");
    sourceStatus[githubSource.id] = { ok: true, error: "disabled by configuration", durationMs: 0 };

    // Fail-closed: block when no sources are enabled (default behavior for security)
    if (ctx.cfg.failOnNoSources !== false) {
      throw new Error("All vulnerability sources are disabled. Set failOnNoSources: false to allow this.");
    }

    return { findings: [], sources: sourceStatus };
  }

  let findings: VulnerabilityFinding[] = [];
  try {
    const result = await githubSource.query(pkgs, queryCtx);
    findings = result.findings;
    sourceStatus[githubSource.id] = { ok: result.ok, error: result.error, durationMs: result.durationMs };

    // Fail-closed on partial failure (default: true for security)
    if (!result.ok && ctx.cfg.failOnSourceError !== false) {
      throw new Error(`GitHub Advisory source failed: ${result.error}`);
    }
  } catch (e) {
    const errorMessage = e instanceof Error ? e.message : String(e);
    logger.error(`GitHub Advisory source failed: ${errorMessage}`);
    sourceStatus[githubSource.id] = { ok: false, error: errorMessage, durationMs: 0 };

    // Fail-closed on exception (default: true for security)
    if (ctx.cfg.failOnSourceError !== false) {
      throw e;
    }
  }

  // Deduplicate findings (in case of duplicates within GitHub response)
  const dedupedFindings = dedupeFindings(findings);

  // NVD enrichment - adds CVSS data and fills in missing severity for CVE IDs
  // Skip if disabled, no findings, or no findings with unknown severity needing enrichment
  const needsNvdEnrichment =
    ctx.cfg.sources?.nvd?.enabled !== false &&
    dedupedFindings.some((f) => f.severity === "unknown");

  if (needsNvdEnrichment) {
    const nvdResult = await enrichFindingsWithNvd(dedupedFindings, queryCtx);
    sourceStatus["nvd"] = { ok: nvdResult.ok, error: nvdResult.error, durationMs: nvdResult.durationMs };
  }

  return {
    findings: dedupedFindings,
    sources: sourceStatus,
  };
}
