import type { FindingSource, Severity, VulnerabilityFinding } from "../types";
import type {
  SourceContext,
  SourceResult,
  VulnerabilitySource,
} from "./connector";
import { mapSeverity } from "../utils/severity";

function normalizeCve(id: string): string {
  return id.trim().toUpperCase();
}

function extractCveIds(findings: VulnerabilityFinding[]): string[] {
  const ids = new Set<string>();
  for (const f of findings) {
    if (f.id.toUpperCase().startsWith("CVE-")) ids.add(normalizeCve(f.id));
    for (const i of f.identifiers ?? []) {
      if (i.type === "CVE") ids.add(normalizeCve(i.value));
    }
  }
  return Array.from(ids);
}

export interface NvdCveDetail {
  id: string;
  baseScore?: number;
  baseSeverity?: Severity;
  vector?: string;
  published?: string;
  lastModified?: string;
  url?: string;
}

async function fetchNvdCve(
  cveId: string,
  ctx: SourceContext,
): Promise<NvdCveDetail | null> {
  const key = `nvd:cve:${cveId}`;
  const cached = await ctx.cache.get(key);
  if (cached?.value) return cached.value as NvdCveDetail;

  if (ctx.offline) return null;

  const apiKey = ctx.env.NVD_API_KEY || ctx.env.NIST_NVD_API_KEY;
  const base = "https://services.nvd.nist.gov/rest/json/cves/2.0";
  const url = new URL(base);
  url.searchParams.set("cveId", cveId);
  if (apiKey) url.searchParams.set("apiKey", apiKey);

  const json = await ctx.http.getJson<any>(url.toString());

  const v = Array.isArray(json?.vulnerabilities)
    ? json.vulnerabilities[0]
    : undefined;
  const cve = v?.cve;

  const metrics = cve?.metrics;
  const metricV31 = Array.isArray(metrics?.cvssMetricV31)
    ? metrics.cvssMetricV31[0]
    : undefined;
  const metricV30 = Array.isArray(metrics?.cvssMetricV30)
    ? metrics.cvssMetricV30[0]
    : undefined;
  const metricV2 = Array.isArray(metrics?.cvssMetricV2)
    ? metrics.cvssMetricV2[0]
    : undefined;

  const chosen = metricV31 ?? metricV30 ?? metricV2;

  const cvssData = chosen?.cvssData;
  const baseScore =
    typeof cvssData?.baseScore === "number" ? cvssData.baseScore : undefined;
  const baseSeverityStr =
    typeof cvssData?.baseSeverity === "string"
      ? cvssData.baseSeverity
      : undefined;
  const vector =
    typeof cvssData?.vectorString === "string"
      ? cvssData.vectorString
      : undefined;

  const published =
    typeof cve?.published === "string" ? cve.published : undefined;
  const lastModified =
    typeof cve?.lastModified === "string" ? cve.lastModified : undefined;

  const detail: NvdCveDetail = {
    id: cveId,
    baseScore,
    baseSeverity: mapSeverity(baseSeverityStr),
    vector,
    published,
    lastModified,
    url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`,
  };

  const ttl = ctx.cfg.cache?.ttlSeconds ?? 3600;
  await ctx.cache.set(key, detail, ttl);
  return detail;
}

/**
 * NVD integration as an *enrichment* step:
 * - OSV/npm/GitHub often supply identifiers but not always consistent scoring.
 * - NVD provides a canonical CVSS score + severity mapping for CVE IDs.
 */
export async function enrichFindingsWithNvd(
  findings: VulnerabilityFinding[],
  ctx: SourceContext,
): Promise<{
  ok: boolean;
  error?: string;
  durationMs: number;
  unknownCves?: string[];
}> {
  const start = Date.now();

  const cveIds = extractCveIds(findings);

  const needs = cveIds.filter((id) => {
    const related = findings.filter(
      (f) =>
        f.id.toUpperCase() === id ||
        (f.identifiers ?? []).some(
          (i) => i.type === "CVE" && i.value.toUpperCase() === id,
        ),
    );
    return related.some(
      (f) => f.cvssScore === undefined || f.severity === "unknown",
    );
  });

  const unknown: string[] = [];

  try {
    const concurrency = Math.max(1, ctx.cfg.performance?.concurrency ?? 8);
    const queue = needs.slice();
    let idx = 0;
    const getNextIndex = () => idx++;

    const details: Record<string, NvdCveDetail> = {};
    const workers = new Array(Math.min(concurrency, queue.length))
      .fill(0)
      .map(async () => {
        let myIdx: number;
        while ((myIdx = getNextIndex()) < queue.length) {
          const id = queue[myIdx]!;
          const d = await fetchNvdCve(id, ctx);
          if (d) details[id] = d;
          else unknown.push(id);
        }
      });

    await Promise.all(workers);

    for (const f of findings) {
      const ids: string[] = [];
      if (f.id.toUpperCase().startsWith("CVE-")) ids.push(normalizeCve(f.id));
      for (const i of f.identifiers ?? [])
        if (i.type === "CVE") ids.push(normalizeCve(i.value));

      for (const id of ids) {
        const d = details[id];
        if (!d) continue;
        if (f.cvssScore === undefined && d.baseScore !== undefined)
          f.cvssScore = d.baseScore;
        if ((f.severity === "unknown" || !f.severity) && d.baseSeverity)
          f.severity = d.baseSeverity;
        if (!f.cvssVector && d.vector) f.cvssVector = d.vector;
        if (!f.publishedAt && d.published) f.publishedAt = d.published;
        if (!f.modifiedAt && d.lastModified) f.modifiedAt = d.lastModified;
        if (!f.url && d.url) f.url = d.url;
      }
    }

    return {
      ok: true,
      durationMs: Date.now() - start,
      unknownCves: unknown.length ? unknown : undefined,
    };
  } catch (e: any) {
    const error = e?.message ? String(e.message) : String(e);
    return {
      ok: false,
      error,
      durationMs: Date.now() - start,
      unknownCves: unknown.length ? unknown : undefined,
    };
  }
}

// For completeness, expose NVD as a source object (no direct per-package lookup by default)
export class NvdSource implements VulnerabilitySource {
  id: FindingSource = "nvd";
  isEnabled(cfg: any, _env: Record<string, string | undefined>): boolean {
    return cfg.sources?.nvd?.enabled !== false;
  }
  async query(_pkgs: any[], _ctx: SourceContext): Promise<SourceResult> {
    return { source: this.id, ok: true, durationMs: 0, findings: [] };
  }
}
