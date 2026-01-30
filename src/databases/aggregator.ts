import type { AuditConfig, PackageRef, VulnerabilityFinding } from "../types";
import type { Cache } from "../cache/memory-cache";
import type { Logger } from "../utils/logger";
import { createAuditHttpClient } from "../utils/http-factory";
import type { NetworkPolicy } from "../types";
import type { SourceResult, VulnerabilitySource } from "./connector";
import { OsvSource } from "./osv";
import { NpmAuditSource } from "./npm-audit";
import { GitHubAdvisorySource } from "./github-advisory";
import { OssIndexSource } from "./ossindex";
import { enrichFindingsWithNvd } from "./nvd";

export interface AggregateContext {
  cfg: AuditConfig;
  env: Record<string, string | undefined>;
  cache: Cache;
  logger: Logger;
  registryUrl: string;
  offline: boolean;
  networkPolicy: NetworkPolicy;
}

export interface AggregateResult {
  findings: VulnerabilityFinding[];
  sources: Record<string, { ok: boolean; error?: string; durationMs: number }>;
  unknownPackages: Set<string>;
  nvdEnrichment?: {
    ok: boolean;
    error?: string;
    durationMs: number;
    unknownCves?: string[];
  };
}

function dedupeFindings(
  findings: VulnerabilityFinding[],
): VulnerabilityFinding[] {
  const seen = new Set<string>();
  const out: VulnerabilityFinding[] = [];
  for (const f of findings) {
    const key = `${f.packageName}@${f.packageVersion}:${f.id.toUpperCase()}:${f.source}`;
    // Dedupe across identical id across sources as well:
    const key2 = `${f.packageName}@${f.packageVersion}:${f.id.toUpperCase()}`;
    if (seen.has(key2)) continue;
    seen.add(key2);
    seen.add(key);
    out.push(f);
  }
  return out;
}

export async function aggregateVulnerabilities(
  pkgs: PackageRef[],
  ctx: AggregateContext,
): Promise<AggregateResult> {
  const http = createAuditHttpClient(ctx.cfg, ctx.logger);

  const sources: VulnerabilitySource[] = [
    new OsvSource(),
    new NpmAuditSource(),
    new GitHubAdvisorySource(),
    new OssIndexSource(),
  ].filter((s) => s.isEnabled(ctx.cfg, ctx.env));

  const results: SourceResult[] = [];

  const settled = await Promise.allSettled(
    sources.map((s) =>
      s.query(pkgs, {
        cfg: ctx.cfg,
        env: ctx.env,
        http,
        cache: ctx.cache,
        logger: ctx.logger,
        registryUrl: ctx.registryUrl,
        offline: ctx.offline,
        networkPolicy: ctx.networkPolicy,
      }),
    ),
  );

  for (let i = 0; i < settled.length; i++) {
    const s = sources[i]!;
    const r = settled[i]!;
    if (r.status === "fulfilled") results.push(r.value);
    else {
      results.push({
        source: s.id,
        ok: false,
        error: r.reason ? String(r.reason) : "unknown error",
        durationMs: 0,
        findings: [],
      });
    }
  }

  const findings = dedupeFindings(results.flatMap((r) => r.findings ?? []));

  const unknownPackages = new Set<string>();
  for (const r of results) {
    for (const k of r.unknownDataForPackages ?? []) unknownPackages.add(k);
  }

  const sourceStatus: Record<
    string,
    { ok: boolean; error?: string; durationMs: number }
  > = {};
  for (const r of results)
    sourceStatus[r.source] = {
      ok: r.ok,
      error: r.error,
      durationMs: r.durationMs,
    };

  // NVD enrichment (optional)
  let nvdEnrichment: AggregateResult["nvdEnrichment"] = undefined;
  if (ctx.cfg.sources?.nvd?.enabled !== false) {
    const res = await enrichFindingsWithNvd(findings, {
      cfg: ctx.cfg,
      env: ctx.env,
      http,
      cache: ctx.cache,
      logger: ctx.logger,
      registryUrl: ctx.registryUrl,
      offline: ctx.offline,
      networkPolicy: ctx.networkPolicy,
    });
    nvdEnrichment = res;
    sourceStatus["nvd"] = {
      ok: res.ok,
      error: res.error,
      durationMs: res.durationMs,
    };
  }

  return {
    findings,
    sources: sourceStatus,
    unknownPackages,
    nvdEnrichment,
  };
}
