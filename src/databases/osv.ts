import type {
  VulnerabilitySource,
  SourceContext,
  SourceResult,
} from "./connector";
import type {
  FindingSource,
  PackageRef,
  Severity,
  VulnerabilityFinding,
  VulnerabilityIdentifier,
} from "../types";
import { cvssV3VectorToBaseScore, severityFromCvssScore } from "../utils/cvss";
import { isVersionAffectedByOsvSemverRange, npmPurl } from "../utils/semver";
import { mapSeverity } from "../utils/severity";

function pickCanonicalId(
  aliases: string[] | undefined,
  fallback: string,
): string {
  const cve = aliases?.find((a) => a.toUpperCase().startsWith("CVE-"));
  if (cve) return cve.toUpperCase();
  const ghsa = aliases?.find((a) => a.toUpperCase().startsWith("GHSA-"));
  if (ghsa) return ghsa.toUpperCase();
  return fallback;
}

function identifiersFromAliases(
  aliases: string[] | undefined,
): VulnerabilityIdentifier[] {
  const ids: VulnerabilityIdentifier[] = [];
  for (const a of aliases ?? []) {
    const u = a.toUpperCase();
    if (u.startsWith("CVE-")) ids.push({ type: "CVE", value: u });
    else if (u.startsWith("GHSA-")) ids.push({ type: "GHSA", value: u });
    else ids.push({ type: "OTHER", value: a });
  }
  return ids;
}

export class OsvSource implements VulnerabilitySource {
  id: FindingSource = "osv";

  isEnabled(cfg: any, _env: Record<string, string | undefined>): boolean {
    return cfg.sources?.osv?.enabled !== false;
  }

  async query(pkgs: PackageRef[], ctx: SourceContext): Promise<SourceResult> {
    const start = Date.now();
    const findings: VulnerabilityFinding[] = [];
    const unknown = new Set<string>();

    // 1) Determine which package@version need live query
    type P = { pkg: PackageRef; key: string };
    const needsQuery: P[] = [];
    const pkgToVulnIds: Record<
      string,
      Array<{ id: string; modified?: string }>
    > = {};

    for (const p of pkgs) {
      const key = `${p.name}@${p.version}`;
      const cacheKey = `osv:ids:${key}`;
      const cached = await ctx.cache.get(cacheKey);
      if (cached?.value) {
        pkgToVulnIds[key] = cached.value as Array<{
          id: string;
          modified?: string;
        }>;
        continue;
      }
      if (ctx.offline) {
        unknown.add(key);
        pkgToVulnIds[key] = [];
        continue;
      }
      needsQuery.push({ pkg: p, key });
    }

    // 2) Query OSV in batches
    const batchSize = 200;

    const queryBatch = async (
      batch: P[],
      pageTokens?: Record<string, string>,
    ): Promise<void> => {
      const queries = batch.map((item) => {
        const q: any = {
          package: { ecosystem: "npm", name: item.pkg.name },
          version: item.pkg.version,
        };
        if (pageTokens?.[item.key]) q.page_token = pageTokens[item.key];
        return q;
      });

      const res = await ctx.http.postJson<any>(
        "https://api.osv.dev/v1/querybatch",
        { queries },
      );

      const results: any[] = Array.isArray(res?.results) ? res.results : [];
      for (let i = 0; i < batch.length; i++) {
        const item = batch[i]!;
        const r = results[i] ?? {};
        const vulns: Array<{ id: string; modified?: string }> = Array.isArray(
          r.vulns,
        )
          ? r.vulns.map((v: any) => ({
              id: String(v.id),
              modified: v.modified ? String(v.modified) : undefined,
            }))
          : [];
        const existing = pkgToVulnIds[item.key] ?? [];
        pkgToVulnIds[item.key] = existing.concat(vulns);

        const token =
          typeof r.next_page_token === "string" ? r.next_page_token : undefined;
        if (token) {
          // Pagination: re-query only this item with page_token
          const tokens = { [item.key]: token };
          await queryBatch([item], tokens);
        }
      }
    };

    try {
      for (let i = 0; i < needsQuery.length; i += batchSize) {
        const batch = needsQuery.slice(i, i + batchSize);
        await queryBatch(batch);
      }

      // Cache vuln id lists per package@version
      const ttl = ctx.cfg.cache?.ttlSeconds ?? 3600;
      for (const [key, ids] of Object.entries(pkgToVulnIds)) {
        await ctx.cache.set(`osv:ids:${key}`, ids, ttl);
      }
    } catch (e: any) {
      const error = e?.message ? String(e.message) : String(e);

      if (ctx.networkPolicy === "fail-closed") {
        return {
          source: this.id,
          ok: false,
          error,
          durationMs: Date.now() - start,
          findings: [],
        };
      }

      // fail-open: mark all still-unknown packages
      for (const item of needsQuery) unknown.add(item.key);

      return {
        source: this.id,
        ok: false,
        error,
        durationMs: Date.now() - start,
        findings,
        unknownDataForPackages: unknown,
      };
    }

    // 3) Fetch vuln details for unique ids
    const allIds = new Set<string>();
    for (const ids of Object.values(pkgToVulnIds))
      for (const v of ids) allIds.add(v.id);

    const vulnDetails: Record<string, any> = {};
    const ttl = ctx.cfg.cache?.ttlSeconds ?? 3600;

    const fetchVuln = async (id: string): Promise<any | null> => {
      const cacheKey = `osv:vuln:${id}`;
      const cached = await ctx.cache.get(cacheKey);
      if (cached?.value) return cached.value;

      if (ctx.offline) return null;

      const detail = await ctx.http.getJson<any>(
        `https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`,
      );
      await ctx.cache.set(cacheKey, detail, ttl);
      return detail;
    };

    // Concurrency-limited fetch
    const concurrency = Math.max(1, ctx.cfg.performance?.concurrency ?? 8);
    const queue = Array.from(allIds);
    let idx = 0;
    const getNextIndex = () => idx++;
    const workers = new Array(Math.min(concurrency, queue.length))
      .fill(0)
      .map(async () => {
        let myIdx: number;
        while ((myIdx = getNextIndex()) < queue.length) {
          const id = queue[myIdx]!;
          const d = await fetchVuln(id);
          if (d) vulnDetails[id] = d;
        }
      });
    await Promise.all(workers);

    // 4) Build findings per package by checking affected ranges
    for (const p of pkgs) {
      const key = `${p.name}@${p.version}`;
      const ids = pkgToVulnIds[key] ?? [];
      for (const { id } of ids) {
        const d = vulnDetails[id];
        if (!d) continue;

        // Determine if this OSV record actually affects this npm package+version
        const aliases: string[] | undefined = Array.isArray(d.aliases)
          ? d.aliases.map(String)
          : undefined;
        const canonicalId = pickCanonicalId(aliases, String(d.id ?? id));

        let affectedRange: string | undefined;
        let fixedVersion: string | undefined;
        let severity: Severity = "unknown";
        let cvssScore: number | undefined;
        let cvssVector: string | undefined;

        // Try OSV severity array (CVSS vectors)
        if (Array.isArray(d.severity) && d.severity.length > 0) {
          const entry =
            d.severity.find((s: any) => s.type === "CVSS_V3") ?? d.severity[0];
          if (entry?.score && typeof entry.score === "string") {
            cvssVector = entry.score;
            const s = cvssV3VectorToBaseScore(entry.score);
            if (s !== undefined) {
              cvssScore = s;
              severity = severityFromCvssScore(s);
            }
          }
        }

        // Try affected[].ecosystem_specific/database_specific severity fields
        if (Array.isArray(d.affected)) {
          for (const a of d.affected) {
            const pkg = a?.package;
            if (!pkg) continue;
            const eco = String(pkg.ecosystem ?? "");
            const nm = String(pkg.name ?? "");
            if (eco !== "npm" || nm !== p.name) continue;

            // Determine if affected
            let affected = false;

            // Exact versions list
            if (Array.isArray(a.versions) && a.versions.includes(p.version))
              affected = true;

            // SEMVER ranges
            if (Array.isArray(a.ranges)) {
              for (const r of a.ranges) {
                if (String(r.type).toUpperCase() !== "SEMVER") continue;
                const events = Array.isArray(r.events) ? r.events : [];
                if (isVersionAffectedByOsvSemverRange(p.version, events)) {
                  affected = true;
                  // Best-effort: build human readable affected range
                  const intro = events.find(
                    (e: any) => e.introduced,
                  )?.introduced;
                  const fixed = events.find((e: any) => e.fixed)?.fixed;
                  if (intro && fixed) affectedRange = `>=${intro} <${fixed}`;
                  if (fixed) fixedVersion = fixed;
                  break;
                }
              }
            }

            if (!affected) continue;

            const ecoSev =
              a.ecosystem_specific?.severity ?? a.database_specific?.severity;
            if (typeof ecoSev === "string" && severity === "unknown")
              severity = mapSeverity(ecoSev);
          }
        }

        const identifiers = identifiersFromAliases(aliases);

        const references: string[] = Array.isArray(d.references)
          ? d.references.map((r: any) => String(r.url ?? r))
          : [];

        const finding: VulnerabilityFinding = {
          id: canonicalId,
          source: "osv",
          packageName: p.name,
          packageVersion: p.version,
          title:
            typeof d.summary === "string"
              ? d.summary
              : typeof d.details === "string"
                ? d.details.split("\n")[0]
                : undefined,
          url:
            typeof d.database_specific?.url === "string"
              ? d.database_specific.url
              : references[0],
          description: typeof d.details === "string" ? d.details : undefined,
          severity,
          cvssScore,
          cvssVector,
          publishedAt:
            typeof d.published === "string" ? d.published : undefined,
          modifiedAt: typeof d.modified === "string" ? d.modified : undefined,
          identifiers: identifiers.length ? identifiers : undefined,
          references: references.length ? references : undefined,
          affectedRange,
          fixedVersion,
          raw: { osvId: d.id, purl: npmPurl(p.name, p.version) },
        };

        findings.push(finding);
      }
    }

    return {
      source: this.id,
      ok: true,
      durationMs: Date.now() - start,
      findings,
      unknownDataForPackages: unknown.size ? unknown : undefined,
    };
  }
}
