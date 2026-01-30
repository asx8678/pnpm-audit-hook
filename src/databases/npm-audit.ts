import type { VulnerabilitySource, SourceContext, SourceResult } from "./connector";
import type { FindingSource, PackageRef, Severity, VulnerabilityFinding, VulnerabilityIdentifier } from "../types";
import { satisfies } from "../utils/semver";
import { ttlForFindings } from "../cache/ttl";
import { mapSeverity } from "../utils/severity";

const normalizeRegistryUrl = (url: string) => url.endsWith("/") ? url.slice(0, -1) : url;

export class NpmAuditSource implements VulnerabilitySource {
  id: FindingSource = "npm";

  isEnabled(cfg: any, _env: Record<string, string | undefined>): boolean {
    return cfg.sources?.npm?.enabled !== false;
  }

  async query(pkgs: PackageRef[], ctx: SourceContext): Promise<SourceResult> {
    const start = Date.now();
    const findings: VulnerabilityFinding[] = [];
    const unknown = new Set<string>();

    const registry = normalizeRegistryUrl(ctx.registryUrl);
    const url = `${registry}/-/npm/v1/security/advisories/bulk`;

    const queryBody: Record<string, string[]> = {};

    for (const p of pkgs) {
      const pkgKey = `${p.name}@${p.version}`;
      const cached = await ctx.cache.get(`npm:${pkgKey}`);
      if (cached?.value) { findings.push(...(cached.value as VulnerabilityFinding[])); continue; }
      if (ctx.offline) { unknown.add(pkgKey); continue; }
      (queryBody[p.name] ??= []).push(p.version);
    }

    if (Object.keys(queryBody).length === 0) {
      return { source: this.id, ok: true, durationMs: Date.now() - start, findings, unknownDataForPackages: unknown };
    }
    // De-dup versions per name
    for (const name of Object.keys(queryBody)) queryBody[name] = [...new Set(queryBody[name])];

    try {
      const res = await ctx.http.postJson<Record<string, any[]>>(url, queryBody);
      for (const p of pkgs) {
        // For each package@version we queried, filter advisories applicable.
        if (!queryBody[p.name]?.includes(p.version)) continue;

        const advisories = res[p.name] ?? [];
        const perPkgFindings: VulnerabilityFinding[] = [];

        for (const adv of advisories) {
          const vulnerableRange = adv.vulnerable_versions ?? adv.vulnerable_versions_range ?? adv.vulnerableVersionRange;
          if (vulnerableRange && !satisfies(p.version, vulnerableRange)) continue;

          const sev: Severity = mapSeverity(adv.severity);
          const cves = (adv.cves ?? []) as string[];
          const ghsa = typeof adv.github_advisory_id === "string" ? adv.github_advisory_id : undefined;
          const identifiers: VulnerabilityIdentifier[] = [
            ...cves.map((cve) => ({ type: "CVE" as const, value: cve })),
            ...(ghsa ? [{ type: "GHSA" as const, value: ghsa }] : []),
          ];
          const canonicalId = cves[0] ?? ghsa ?? `npm-advisory:${adv.id ?? adv._id ?? "unknown"}`;
          const url = adv.url ?? adv.advisory ?? adv.reference ?? adv.link;

          perPkgFindings.push({
            id: canonicalId,
            source: "npm",
            packageName: p.name,
            packageVersion: p.version,
            title: adv.title ?? adv.summary,
            url,
            description: adv.overview ?? adv.description,
            severity: sev,
            publishedAt: adv.created ?? adv.created_at ?? adv.published ?? adv.published_at,
            modifiedAt: adv.updated ?? adv.updated_at ?? adv.modified ?? adv.modified_at,
            affectedRange: vulnerableRange,
            fixedVersion: adv.patched_versions ?? adv.fixed_versions ?? adv.first_patched_version,
            identifiers: identifiers.length ? identifiers : undefined,
            raw: { id: adv.id ?? adv._id, severity: adv.severity, vulnerable_versions: adv.vulnerable_versions, patched_versions: adv.patched_versions },
          });
        }

        const ttl = ttlForFindings(ctx.cfg.cache?.ttlSeconds ?? 3600, perPkgFindings);
        await ctx.cache.set(`npm:${p.name}@${p.version}`, perPkgFindings, ttl);
        findings.push(...perPkgFindings);
      }
      return { source: this.id, ok: true, durationMs: Date.now() - start, findings, unknownDataForPackages: unknown };
    } catch (e: any) {
      const error = String(e?.message ?? e);
      if (ctx.networkPolicy === "fail-closed") {
        return { source: this.id, ok: false, error, durationMs: Date.now() - start, findings: [] };
      }
      for (const [name, vers] of Object.entries(queryBody)) vers.forEach((v) => unknown.add(`${name}@${v}`));
      return { source: this.id, ok: false, error, durationMs: Date.now() - start, findings, unknownDataForPackages: unknown };
    }
  }
}
