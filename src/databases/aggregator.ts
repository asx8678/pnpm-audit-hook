import type { AuditConfig, PackageRef, VulnerabilityFinding } from "../types";
import type { Cache } from "../cache/types";
import type { VulnerabilitySource, SourceContext, SourceResult } from "./connector";
import { HttpClient } from "../utils/http";
import { OsvSource } from "./osv";
import { NpmAuditSource } from "./npm-audit";
import { GitHubAdvisorySource } from "./github-advisory";
import { DepsDevSource } from "./depsdev";
import { enrichFindingsWithNvd } from "./nvd";

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

  // All available sources
  const allSources: VulnerabilitySource[] = [
    new OsvSource(),
    new NpmAuditSource(),
    new GitHubAdvisorySource(),
    new DepsDevSource(),
  ];

  // Filter to enabled sources
  const enabledSources = allSources.filter((s) => s.isEnabled(ctx.cfg, ctx.env));

  if (enabledSources.length === 0) {
    return { findings: [], sources: {} };
  }

  // Query all enabled sources in parallel
  const results = await Promise.allSettled(
    enabledSources.map((source) =>
      source.query(pkgs, queryCtx).catch((e) => ({
        source: source.id,
        ok: false,
        error: String(e?.message ?? e),
        durationMs: 0,
        findings: [] as VulnerabilityFinding[],
      }))
    )
  );

  const allFindings: VulnerabilityFinding[] = [];
  const sourceStatus: Record<string, { ok: boolean; error?: string; durationMs: number }> = {};

  for (const result of results) {
    if (result.status === "fulfilled") {
      const r = result.value as SourceResult;
      allFindings.push(...r.findings);
      sourceStatus[r.source] = { ok: r.ok, error: r.error, durationMs: r.durationMs };
    }
  }

  // Deduplicate findings across sources
  const dedupedFindings = dedupeFindings(allFindings);

  // NVD enrichment - adds CVSS data and fills in missing severity for CVE IDs
  if (ctx.cfg.sources?.nvd?.enabled !== false) {
    const nvdResult = await enrichFindingsWithNvd(dedupedFindings, queryCtx);
    sourceStatus["nvd"] = { ok: nvdResult.ok, error: nvdResult.error, durationMs: nvdResult.durationMs };
  }

  return {
    findings: dedupedFindings,
    sources: sourceStatus,
  };
}
