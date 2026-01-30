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
import { satisfies } from "../utils/semver";
import { ttlForFindings } from "../cache/ttl";
import { mapSeverity } from "../utils/severity";

function normalizeRegistryUrl(registryUrl: string): string {
  return registryUrl.endsWith("/") ? registryUrl.slice(0, -1) : registryUrl;
}

function unique<T>(arr: T[]): T[] {
  return Array.from(new Set(arr));
}

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

    // Group missing cache by package name -> versions[]
    const queryBody: Record<string, string[]> = {};
    const cacheHits: Record<string, VulnerabilityFinding[]> = {};

    for (const p of pkgs) {
      const key = `npm:${p.name}@${p.version}`;
      const cached = await ctx.cache.get(key);
      if (cached && cached.value) {
        cacheHits[`${p.name}@${p.version}`] =
          cached.value as VulnerabilityFinding[];
        continue;
      }

      if (ctx.offline) {
        unknown.add(`${p.name}@${p.version}`);
        continue;
      }

      queryBody[p.name] = queryBody[p.name] ?? [];
      queryBody[p.name]!.push(p.version);
    }

    // Emit cached findings
    for (const [k, fs] of Object.entries(cacheHits)) {
      for (const f of fs) findings.push(f);
    }

    if (Object.keys(queryBody).length === 0) {
      return {
        source: this.id,
        ok: true,
        durationMs: Date.now() - start,
        findings,
        unknownDataForPackages: unknown,
      };
    }

    // De-dup versions per name
    for (const [name, vers] of Object.entries(queryBody))
      queryBody[name] = unique(vers);

    try {
      const res = await ctx.http.postJson<Record<string, any[]>>(
        url,
        queryBody,
        {
          // Some registries require a trailing slash? default is fine
        },
      );

      // Response format: { "pkg": [ advisoryObj, ...], ... }
      for (const p of pkgs) {
        // For each package@version we queried, filter advisories applicable.
        if (!queryBody[p.name]?.includes(p.version)) continue;

        const advisories = res[p.name] ?? [];
        const perPkgFindings: VulnerabilityFinding[] = [];

        for (const adv of advisories) {
          const vulnerableRange: string | undefined =
            adv.vulnerable_versions ??
            adv.vulnerable_versions_range ??
            adv.vulnerableVersionRange ??
            adv.vulnerable_versions_range;

          if (vulnerableRange && !satisfies(p.version, vulnerableRange))
            continue;

          const sev: Severity = mapSeverity(adv.severity);
          const identifiers: VulnerabilityIdentifier[] = [];

          const cves = Array.isArray(adv.cves) ? (adv.cves as string[]) : [];
          for (const cve of cves) identifiers.push({ type: "CVE", value: cve });

          const ghsa =
            typeof adv.github_advisory_id === "string"
              ? adv.github_advisory_id
              : undefined;
          if (ghsa) identifiers.push({ type: "GHSA", value: ghsa });

          const canonicalId = (
            cves[0] ??
            ghsa ??
            `npm-advisory:${String(adv.id ?? adv._id ?? "") || "unknown"}`
          ).toString();

          const url = (adv.url ?? adv.advisory ?? adv.reference ?? adv.link) as
            | string
            | undefined;

          const finding: VulnerabilityFinding = {
            id: canonicalId,
            source: "npm",
            packageName: p.name,
            packageVersion: p.version,
            title: (adv.title ?? adv.summary) as string | undefined,
            url,
            description: (adv.overview ?? adv.description) as
              | string
              | undefined,
            severity: sev,
            publishedAt: (adv.created ??
              adv.created_at ??
              adv.published ??
              adv.published_at) as string | undefined,
            modifiedAt: (adv.updated ??
              adv.updated_at ??
              adv.modified ??
              adv.modified_at) as string | undefined,
            affectedRange: vulnerableRange,
            fixedVersion: (adv.patched_versions ??
              adv.fixed_versions ??
              adv.first_patched_version) as string | undefined,
            identifiers: identifiers.length ? identifiers : undefined,
            raw: {
              id: adv.id ?? adv._id,
              severity: adv.severity,
              vulnerable_versions: adv.vulnerable_versions,
              patched_versions: adv.patched_versions,
            },
          };

          perPkgFindings.push(finding);
        }

        // Cache per package@version
        const ttlBase = ctx.cfg.cache?.ttlSeconds ?? 3600;
        const ttl = ttlForFindings(ttlBase, perPkgFindings);
        await ctx.cache.set(`npm:${p.name}@${p.version}`, perPkgFindings, ttl);

        for (const f of perPkgFindings) findings.push(f);
      }

      return {
        source: this.id,
        ok: true,
        durationMs: Date.now() - start,
        findings,
        unknownDataForPackages: unknown,
      };
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

      // fail-open: mark all queried packages as unknown
      for (const [name, vers] of Object.entries(queryBody)) {
        for (const v of vers) unknown.add(`${name}@${v}`);
      }

      return {
        source: this.id,
        ok: false,
        error,
        durationMs: Date.now() - start,
        findings,
        unknownDataForPackages: unknown,
      };
    }
  }
}
