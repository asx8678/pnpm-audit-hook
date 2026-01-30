import type { VulnerabilitySource, SourceContext, SourceResult } from "./connector";
import type { FindingSource, PackageRef, Severity, VulnerabilityFinding, VulnerabilityIdentifier } from "../types";
import { cvssV3VectorToBaseScore, severityFromCvssScore } from "../utils/cvss";
import { isVersionAffectedByOsvSemverRange, npmPurl } from "../utils/semver";
import { mapSeverity } from "../utils/severity";

function pickCanonicalId(aliases: string[] | undefined, fallback: string): string {
  return aliases?.find((a) => a.toUpperCase().startsWith("CVE-"))?.toUpperCase()
    ?? aliases?.find((a) => a.toUpperCase().startsWith("GHSA-"))?.toUpperCase()
    ?? fallback;
}

function identifiersFromAliases(aliases: string[] | undefined): VulnerabilityIdentifier[] {
  return (aliases ?? []).map((a) => {
    const u = a.toUpperCase();
    return u.startsWith("CVE-") ? { type: "CVE" as const, value: u }
      : u.startsWith("GHSA-") ? { type: "GHSA" as const, value: u }
      : { type: "OTHER" as const, value: a };
  });
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

    type P = { pkg: PackageRef; key: string };
    const needsQuery: P[] = [];
    const pkgToVulnIds: Record<string, Array<{ id: string; modified?: string }>> = {};

    for (const p of pkgs) {
      const key = `${p.name}@${p.version}`;
      const cached = await ctx.cache.get(`osv:ids:${key}`);
      if (cached?.value) { pkgToVulnIds[key] = cached.value as Array<{ id: string; modified?: string }>; continue; }
      if (ctx.offline) { unknown.add(key); pkgToVulnIds[key] = []; continue; }
      needsQuery.push({ pkg: p, key });
    }

    const queryBatch = async (batch: P[], pageTokens?: Record<string, string>): Promise<void> => {
      const queries = batch.map((item) => ({
        package: { ecosystem: "npm", name: item.pkg.name },
        version: item.pkg.version,
        ...(pageTokens?.[item.key] && { page_token: pageTokens[item.key] }),
      }));
      const res = await ctx.http.postJson<any>("https://api.osv.dev/v1/querybatch", { queries });
      for (let i = 0; i < batch.length; i++) {
        const { key } = batch[i]!;
        const r = res?.results?.[i] ?? {};
        const vulns = (r.vulns ?? []).map((v: any) => ({ id: String(v.id), modified: v.modified ? String(v.modified) : undefined }));
        pkgToVulnIds[key] = (pkgToVulnIds[key] ?? []).concat(vulns);
        if (typeof r.next_page_token === "string") await queryBatch([batch[i]!], { [key]: r.next_page_token });
      }
    };

    try {
      for (let i = 0; i < needsQuery.length; i += 200) await queryBatch(needsQuery.slice(i, i + 200));
      const ttl = ctx.cfg.cache?.ttlSeconds ?? 3600;
      for (const [key, ids] of Object.entries(pkgToVulnIds)) await ctx.cache.set(`osv:ids:${key}`, ids, ttl);
    } catch (e: any) {
      const error = String(e?.message ?? e);
      if (ctx.networkPolicy === "fail-closed") {
        return { source: this.id, ok: false, error, durationMs: Date.now() - start, findings: [] };
      }
      needsQuery.forEach((item) => unknown.add(item.key));
      return { source: this.id, ok: false, error, durationMs: Date.now() - start, findings, unknownDataForPackages: unknown };
    }

    const allIds = [...new Set(Object.values(pkgToVulnIds).flatMap((ids) => ids.map((v) => v.id)))];
    const vulnDetails: Record<string, any> = {};
    const ttl = ctx.cfg.cache?.ttlSeconds ?? 3600;

    const fetchVuln = async (id: string) => {
      const cached = await ctx.cache.get(`osv:vuln:${id}`);
      if (cached?.value) return cached.value;
      if (ctx.offline) return null;
      const detail = await ctx.http.getJson<any>(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`);
      await ctx.cache.set(`osv:vuln:${id}`, detail, ttl);
      return detail;
    };

    const concurrency = Math.max(1, ctx.cfg.performance?.concurrency ?? 8);
    let idx = 0;
    await Promise.all(Array.from({ length: Math.min(concurrency, allIds.length) }, async () => {
      let i: number;
      while ((i = idx++) < allIds.length) {
        const d = await fetchVuln(allIds[i]!);
        if (d) vulnDetails[allIds[i]!] = d;
      }
    }));

    for (const p of pkgs) {
      const key = `${p.name}@${p.version}`;
      for (const { id } of pkgToVulnIds[key] ?? []) {
        const d = vulnDetails[id];
        if (!d) continue;

        const aliases: string[] | undefined = Array.isArray(d.aliases) ? d.aliases.map(String) : undefined;
        const canonicalId = pickCanonicalId(aliases, String(d.id ?? id));
        let affectedRange: string | undefined, fixedVersion: string | undefined;
        let severity: Severity = "unknown", cvssScore: number | undefined, cvssVector: string | undefined;

        const sevEntry = d.severity?.find((s: any) => s.type === "CVSS_V3") ?? d.severity?.[0];
        if (sevEntry?.score) {
          cvssVector = sevEntry.score;
          const s = cvssV3VectorToBaseScore(sevEntry.score);
          if (s !== undefined) { cvssScore = s; severity = severityFromCvssScore(s); }
        }

        for (const a of d.affected ?? []) {
          const { ecosystem, name: nm } = a?.package ?? {};
          if (ecosystem !== "npm" || nm !== p.name) continue;
          let affected = a.versions?.includes(p.version) ?? false;
          for (const r of a.ranges ?? []) {
            if (String(r.type).toUpperCase() !== "SEMVER") continue;
            const events = r.events ?? [];
            if (isVersionAffectedByOsvSemverRange(p.version, events)) {
              affected = true;
              const intro = events.find((e: any) => e.introduced)?.introduced;
              const fixed = events.find((e: any) => e.fixed)?.fixed;
              if (intro && fixed) affectedRange = `>=${intro} <${fixed}`;
              if (fixed) fixedVersion = fixed;
              break;
            }
          }
          if (!affected) continue;
          const ecoSev = a.ecosystem_specific?.severity ?? a.database_specific?.severity;
          if (typeof ecoSev === "string" && severity === "unknown") severity = mapSeverity(ecoSev);
        }

        const identifiers = identifiersFromAliases(aliases);
        const references = (d.references ?? []).map((r: any) => String(r.url ?? r));
        findings.push({
          id: canonicalId, source: "osv", packageName: p.name, packageVersion: p.version,
          title: d.summary ?? d.details?.split("\n")[0],
          url: d.database_specific?.url ?? references[0],
          description: d.details,
          severity, cvssScore, cvssVector,
          publishedAt: d.published, modifiedAt: d.modified,
          identifiers: identifiers.length ? identifiers : undefined,
          references: references.length ? references : undefined,
          affectedRange, fixedVersion,
          raw: { osvId: d.id, purl: npmPurl(p.name, p.version) },
        });
      }
    }
    return { source: this.id, ok: true, durationMs: Date.now() - start, findings, unknownDataForPackages: unknown.size ? unknown : undefined };
  }
}
