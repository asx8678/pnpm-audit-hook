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

function dedupeFindings(findings: VulnerabilityFinding[]): VulnerabilityFinding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.packageName}@${f.packageVersion}:${f.id.toUpperCase()}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
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

  const queryCtx = {
    cfg: ctx.cfg,
    env: ctx.env,
    http,
    cache: ctx.cache,
    logger: ctx.logger,
    registryUrl: ctx.registryUrl,
    offline: ctx.offline,
    networkPolicy: ctx.networkPolicy,
  };

  const settled = await Promise.allSettled(sources.map((s) => s.query(pkgs, queryCtx)));

  const results: SourceResult[] = settled.map((r, i) =>
    r.status === "fulfilled"
      ? r.value
      : { source: sources[i]!.id, ok: false, error: String(r.reason ?? "unknown error"), durationMs: 0, findings: [] },
  );

  const findings = dedupeFindings(results.flatMap((r) => r.findings ?? []));

  const unknownPackages = new Set(results.flatMap((r) => [...(r.unknownDataForPackages ?? [])]));

  const sourceStatus = Object.fromEntries(
    results.map((r) => [r.source, { ok: r.ok, error: r.error, durationMs: r.durationMs }]),
  ) as Record<string, { ok: boolean; error?: string; durationMs: number }>;

  let nvdEnrichment: AggregateResult["nvdEnrichment"];
  if (ctx.cfg.sources?.nvd?.enabled !== false) {
    nvdEnrichment = await enrichFindingsWithNvd(findings, queryCtx);
    sourceStatus["nvd"] = { ok: nvdEnrichment.ok, error: nvdEnrichment.error, durationMs: nvdEnrichment.durationMs };
  }

  return {
    findings,
    sources: sourceStatus,
    unknownPackages,
    nvdEnrichment,
  };
}
