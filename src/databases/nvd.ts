import type { Severity, VulnerabilityFinding } from "../types";
import type { SourceContext } from "./connector";
import { ttlForFindings } from "../cache/ttl";
import { logger } from "../utils/logger";
import { mapSeverity } from "../utils/severity";
import { sleep } from "../utils/http";
import { errorMessage } from "../utils/error";

/** NVD rate limit delay with API key (ms) - 50 req/30s */
const NVD_DELAY_WITH_KEY_MS = 700;
/** NVD rate limit delay without API key (ms) - 5 req/30s */
const NVD_DELAY_NO_KEY_MS = 6500;

interface NvdCvssData {
  baseScore?: number;
  baseSeverity?: string;
}

interface NvdCvssMetric {
  type?: "Primary" | "Secondary";
  cvssData?: NvdCvssData;
}

interface NvdCve {
  published?: string;
  lastModified?: string;
  metrics?: {
    cvssMetricV31?: NvdCvssMetric[];
    cvssMetricV30?: NvdCvssMetric[];
    cvssMetricV2?: NvdCvssMetric[];
  };
}

interface NvdVulnerability {
  cve?: NvdCve;
}

interface NvdApiResponse {
  vulnerabilities?: NvdVulnerability[];
}

const normalizeCve = (id: string) => id.trim().toUpperCase();

/** Prefer "Primary" type metrics over "Secondary" when available */
function findPrimaryMetric(metrics: NvdCvssMetric[] | undefined): NvdCvssMetric | undefined {
  if (!metrics?.length) return undefined;
  return metrics.find((m) => m.type === "Primary") ?? metrics[0];
}

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

  // Pass API key in header (not query string) to avoid logging sensitive data
  const headers: Record<string, string> = {};
  if (apiKey) headers.apiKey = apiKey;

  try {
    const json = await ctx.http.getJson<NvdApiResponse>(url.toString(), headers);
    const cve = json?.vulnerabilities?.[0]?.cve;
    const metrics = cve?.metrics;
    // Prefer "Primary" type metrics over "Secondary"
    const cvssData = (
      findPrimaryMetric(metrics?.cvssMetricV31) ??
      findPrimaryMetric(metrics?.cvssMetricV30) ??
      findPrimaryMetric(metrics?.cvssMetricV2)
    )?.cvssData;

    const detail: NvdCveDetail = {
      id: cveId,
      baseScore: typeof cvssData?.baseScore === "number" ? cvssData.baseScore : undefined,
      baseSeverity: mapSeverity(cvssData?.baseSeverity),
      published: cve?.published,
      lastModified: cve?.lastModified,
      url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`,
    };

    const baseTtl = ctx.cfg.cache?.ttlSeconds ?? 3600;
    const dynamicTtl = ttlForFindings(baseTtl, [{ severity: detail.baseSeverity } as VulnerabilityFinding]);
    await ctx.cache.set(key, detail, dynamicTtl);
    return detail;
  } catch (e) {
    logger.error(`Failed to fetch NVD data for ${cveId}: ${errorMessage(e)}`);
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
    const failedCveIds: string[] = [];

    // NVD rate limits: 5 req/30s (no key), 50 req/30s (with key)
    const hasApiKey = !!(ctx.env.NVD_API_KEY || ctx.env.NIST_NVD_API_KEY);
    const delayMs = hasApiKey ? NVD_DELAY_WITH_KEY_MS : NVD_DELAY_NO_KEY_MS;
    const concurrency = hasApiKey ? 2 : 1;

    // Use queue.shift() pattern to avoid race conditions with shared index
    const queue = [...needs];

    await Promise.all(
      Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
        while (queue.length > 0) {
          const cveId = queue.shift();
          if (!cveId) break;

          const d = await fetchNvdCve(cveId, ctx);
          if (d) {
            details[cveId] = d;
          } else {
            failedCveIds.push(cveId);
          }

          // Only sleep if there are more items in the queue
          if (queue.length > 0) {
            await sleep(delayMs);
          }
        }
      })
    );

    // Log summary error if any CVE enrichments failed
    if (failedCveIds.length > 0) {
      const hint = hasApiKey ? "" : " (hint: set NVD_API_KEY to increase rate limits)";
      logger.error(`NVD enrichment failed for ${failedCveIds.length} CVE(s): ${failedCveIds.join(", ")}${hint}`);
    }

    // Enrich findings with NVD data (mutates findings array in-place intentionally)
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
  } catch (e: unknown) {
    return { ok: false, error: errorMessage(e), durationMs: Date.now() - start };
  }
}
