import type { FindingSource, Severity, VulnerabilityFinding } from "../types";
import type { SourceContext, SourceResult, VulnerabilitySource } from "./connector";
import { mapSeverity } from "../utils/severity";

const normalizeCve = (id: string) => id.trim().toUpperCase();

function extractCveIds(findings: VulnerabilityFinding[]): string[] {
  const ids = new Set<string>();
  for (const f of findings) {
    if (f.id.toUpperCase().startsWith("CVE-")) ids.add(normalizeCve(f.id));
    (f.identifiers ?? []).filter((i) => i.type === "CVE").forEach((i) => ids.add(normalizeCve(i.value)));
  }
  return [...ids];
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

async function fetchNvdCve(cveId: string, ctx: SourceContext): Promise<NvdCveDetail | null> {
  const key = `nvd:cve:${cveId}`;
  const cached = await ctx.cache.get(key);
  if (cached?.value) return cached.value as NvdCveDetail;
  if (ctx.offline) return null;

  const apiKey = ctx.env.NVD_API_KEY || ctx.env.NIST_NVD_API_KEY;
  const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
  url.searchParams.set("cveId", cveId);
  if (apiKey) url.searchParams.set("apiKey", apiKey);

  const json = await ctx.http.getJson<any>(url.toString());
  const cve = json?.vulnerabilities?.[0]?.cve;
  const metrics = cve?.metrics;
  const cvssData = (metrics?.cvssMetricV31?.[0] ?? metrics?.cvssMetricV30?.[0] ?? metrics?.cvssMetricV2?.[0])?.cvssData;

  const detail: NvdCveDetail = {
    id: cveId,
    baseScore: typeof cvssData?.baseScore === "number" ? cvssData.baseScore : undefined,
    baseSeverity: mapSeverity(cvssData?.baseSeverity),
    vector: typeof cvssData?.vectorString === "string" ? cvssData.vectorString : undefined,
    published: cve?.published,
    lastModified: cve?.lastModified,
    url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`,
  };

  await ctx.cache.set(key, detail, ctx.cfg.cache?.ttlSeconds ?? 3600);
  return detail;
}

/** NVD enrichment: OSV/npm/GitHub often lack consistent scoring. NVD provides canonical CVSS for CVE IDs. */
export async function enrichFindingsWithNvd(findings: VulnerabilityFinding[], ctx: SourceContext): Promise<{ ok: boolean; error?: string; durationMs: number; unknownCves?: string[] }> {
  const start = Date.now();

  const cveIds = extractCveIds(findings);

  const needs = cveIds.filter((id) =>
    findings.some((f) =>
      (f.id.toUpperCase() === id || (f.identifiers ?? []).some((i) => i.type === "CVE" && i.value.toUpperCase() === id)) &&
      (f.cvssScore === undefined || f.severity === "unknown"),
    ),
  );

  const unknown: string[] = [];

  try {
    const details: Record<string, NvdCveDetail> = {};
    const concurrency = Math.max(1, ctx.cfg.performance?.concurrency ?? 8);
    let idx = 0;
    await Promise.all(Array.from({ length: Math.min(concurrency, needs.length) }, async () => {
      let i: number;
      while ((i = idx++) < needs.length) {
        const d = await fetchNvdCve(needs[i]!, ctx);
        if (d) details[needs[i]!] = d;
        else unknown.push(needs[i]!);
      }
    }));

    for (const f of findings) {
      const ids = [
        ...(f.id.toUpperCase().startsWith("CVE-") ? [normalizeCve(f.id)] : []),
        ...(f.identifiers ?? []).filter((i) => i.type === "CVE").map((i) => normalizeCve(i.value)),
      ];
      for (const id of ids) {
        const d = details[id];
        if (!d) continue;
        f.cvssScore ??= d.baseScore;
        if (!f.severity || f.severity === "unknown") f.severity = d.baseSeverity ?? f.severity;
        f.cvssVector ??= d.vector;
        f.publishedAt ??= d.published;
        f.modifiedAt ??= d.lastModified;
        f.url ??= d.url;
      }
    }
    return { ok: true, durationMs: Date.now() - start, unknownCves: unknown.length ? unknown : undefined };
  } catch (e: any) {
    return { ok: false, error: String(e?.message ?? e), durationMs: Date.now() - start, unknownCves: unknown.length ? unknown : undefined };
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
