import type { Severity, VulnerabilityFinding } from "../types";
import type { SourceContext } from "./connector";
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
  published?: string;
  lastModified?: string;
  url?: string;
}

async function fetchNvdCve(cveId: string, ctx: SourceContext): Promise<NvdCveDetail | null> {
  const key = `nvd:cve:${cveId}`;
  const cached = await ctx.cache.get(key);
  if (cached?.value) return cached.value as NvdCveDetail;

  const apiKey = ctx.env.NVD_API_KEY || ctx.env.NIST_NVD_API_KEY;
  const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
  url.searchParams.set("cveId", cveId);
  if (apiKey) url.searchParams.set("apiKey", apiKey);

  try {
    const json = await ctx.http.getJson<any>(url.toString());
    const cve = json?.vulnerabilities?.[0]?.cve;
    const metrics = cve?.metrics;
    const cvssData = (metrics?.cvssMetricV31?.[0] ?? metrics?.cvssMetricV30?.[0] ?? metrics?.cvssMetricV2?.[0])?.cvssData;

    const detail: NvdCveDetail = {
      id: cveId,
      baseScore: typeof cvssData?.baseScore === "number" ? cvssData.baseScore : undefined,
      baseSeverity: mapSeverity(cvssData?.baseSeverity),
      published: cve?.published,
      lastModified: cve?.lastModified,
      url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`,
    };

    await ctx.cache.set(key, detail, ctx.cfg.cache?.ttlSeconds ?? 3600);
    return detail;
  } catch {
    return null;
  }
}

/**
 * NVD enrichment: OSV/npm/GitHub often lack consistent scoring.
 * NVD provides canonical CVSS data for CVE IDs.
 * This enriches findings that have severity "unknown" with NVD data.
 */
export async function enrichFindingsWithNvd(
  findings: VulnerabilityFinding[],
  ctx: SourceContext
): Promise<{ ok: boolean; error?: string; durationMs: number }> {
  const start = Date.now();

  const cveIds = extractCveIds(findings);

  // Only fetch NVD data for findings with unknown severity
  const needs = cveIds.filter((id) =>
    findings.some((f) =>
      (f.id.toUpperCase() === id || (f.identifiers ?? []).some((i) => i.type === "CVE" && i.value.toUpperCase() === id)) &&
      f.severity === "unknown"
    )
  );

  if (needs.length === 0) {
    return { ok: true, durationMs: Date.now() - start };
  }

  try {
    const details: Record<string, NvdCveDetail> = {};
    const concurrency = 4;
    let idx = 0;

    await Promise.all(
      Array.from({ length: Math.min(concurrency, needs.length) }, async () => {
        let i: number;
        while ((i = idx++) < needs.length) {
          const d = await fetchNvdCve(needs[i]!, ctx);
          if (d) details[needs[i]!] = d;
        }
      })
    );

    // Enrich findings with NVD data
    for (const f of findings) {
      if (f.severity !== "unknown") continue;

      const ids = [
        ...(f.id.toUpperCase().startsWith("CVE-") ? [normalizeCve(f.id)] : []),
        ...(f.identifiers ?? []).filter((i) => i.type === "CVE").map((i) => normalizeCve(i.value)),
      ];

      for (const id of ids) {
        const d = details[id];
        if (!d) continue;
        if (d.baseSeverity && d.baseSeverity !== "unknown") {
          f.severity = d.baseSeverity;
        }
        f.publishedAt ??= d.published;
        f.modifiedAt ??= d.lastModified;
        f.url ??= d.url;
        break;
      }
    }

    return { ok: true, durationMs: Date.now() - start };
  } catch (e: any) {
    return { ok: false, error: String(e?.message ?? e), durationMs: Date.now() - start };
  }
}
