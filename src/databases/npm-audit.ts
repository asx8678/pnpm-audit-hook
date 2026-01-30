import type { VulnerabilitySource, SourceContext, SourceResult } from "./connector";
import type { FindingSource, PackageRef, VulnerabilityFinding, VulnerabilityIdentifier } from "../types";
import { satisfies } from "../utils/semver";
import { mapSeverity } from "../utils/severity";

export class NpmAuditSource implements VulnerabilitySource {
  id: FindingSource = "npm";

  isEnabled(cfg: any, _env: Record<string, string | undefined>): boolean {
    return cfg.sources?.npm?.enabled !== false;
  }

  async query(pkgs: PackageRef[], ctx: SourceContext): Promise<SourceResult> {
    const start = Date.now();

    // Build bulk query: { packageName: [versions...] }
    const queryBody: Record<string, string[]> = {};
    for (const p of pkgs) {
      (queryBody[p.name] ??= []).push(p.version);
    }
    for (const name of Object.keys(queryBody)) {
      queryBody[name] = Array.from(new Set(queryBody[name]));
    }

    const registry = ctx.registryUrl.endsWith("/") ? ctx.registryUrl.slice(0, -1) : ctx.registryUrl;
    const url = `${registry}/-/npm/v1/security/advisories/bulk`;

    try {
      const res = await ctx.http.postJson<Record<string, any[]>>(url, queryBody);
      const findings: VulnerabilityFinding[] = [];

      for (const p of pkgs) {
        const advisories = res[p.name] ?? [];
        for (const adv of advisories) {
          const vulnerableRange = adv.vulnerable_versions;
          if (vulnerableRange && !satisfies(p.version, vulnerableRange)) continue;

          const cves = (adv.cves ?? []) as string[];
          const ghsa = adv.github_advisory_id as string | undefined;
          const identifiers: VulnerabilityIdentifier[] = [
            ...cves.map(cve => ({ type: "CVE" as const, value: cve })),
            ...(ghsa ? [{ type: "GHSA" as const, value: ghsa }] : []),
          ];

          findings.push({
            id: cves[0] ?? ghsa ?? `npm-advisory:${adv.id}`,
            source: "npm",
            packageName: p.name,
            packageVersion: p.version,
            title: adv.title,
            url: adv.url,
            description: adv.overview,
            severity: mapSeverity(adv.severity),
            affectedRange: vulnerableRange,
            fixedVersion: adv.patched_versions,
            identifiers: identifiers.length ? identifiers : undefined,
          });
        }
      }

      return { source: this.id, ok: true, durationMs: Date.now() - start, findings };
    } catch (e: any) {
      const error = String(e?.message ?? e);
      return { source: this.id, ok: false, error, durationMs: Date.now() - start, findings: [] };
    }
  }
}
