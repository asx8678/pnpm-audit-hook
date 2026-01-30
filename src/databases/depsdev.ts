import type { VulnerabilitySource, SourceContext, SourceResult } from "./connector";
import type { FindingSource, PackageRef, Severity, VulnerabilityFinding, VulnerabilityIdentifier } from "../types";
import { mapSeverity } from "../utils/severity";

/**
 * deps.dev (Google's Open Source Insights) - free, no auth required.
 * Provides vulnerability data aggregated from multiple sources.
 * https://deps.dev/
 */
export class DepsDevSource implements VulnerabilitySource {
  id: FindingSource = "depsdev";

  isEnabled(cfg: any, env: Record<string, string | undefined>): boolean {
    return cfg.sources?.depsdev?.enabled !== false && env.PNPM_AUDIT_DISABLE_DEPSDEV !== "true";
  }

  async query(pkgs: PackageRef[], ctx: SourceContext): Promise<SourceResult> {
    const start = Date.now();
    const findings: VulnerabilityFinding[] = [];

    // Check cache first
    const toQuery: PackageRef[] = [];
    for (const p of pkgs) {
      const key = `depsdev:${p.name}@${p.version}`;
      const cached = await ctx.cache.get(key);
      if (cached?.value) {
        findings.push(...(cached.value as VulnerabilityFinding[]));
      } else {
        toQuery.push(p);
      }
    }

    if (toQuery.length === 0) {
      return { source: this.id, ok: true, durationMs: Date.now() - start, findings };
    }

    const ttl = ctx.cfg.cache?.ttlSeconds ?? 3600;

    try {
      // Query each package (deps.dev doesn't have batch API)
      // Use concurrency pool to avoid overwhelming the API
      const concurrency = 4;
      let idx = 0;

      await Promise.all(
        Array.from({ length: Math.min(concurrency, toQuery.length) }, async () => {
          let i: number;
          while ((i = idx++) < toQuery.length) {
            const p = toQuery[i]!;
            const pkgFindings = await this.queryPackage(p, ctx);
            const key = `depsdev:${p.name}@${p.version}`;
            await ctx.cache.set(key, pkgFindings, ttl);
            findings.push(...pkgFindings);
          }
        })
      );

      return { source: this.id, ok: true, durationMs: Date.now() - start, findings };
    } catch (e: any) {
      return {
        source: this.id,
        ok: false,
        error: String(e?.message ?? e),
        durationMs: Date.now() - start,
        findings,
      };
    }
  }

  private async queryPackage(pkg: PackageRef, ctx: SourceContext): Promise<VulnerabilityFinding[]> {
    const findings: VulnerabilityFinding[] = [];

    // deps.dev API endpoint for version info
    const encodedName = encodeURIComponent(pkg.name);
    const encodedVersion = encodeURIComponent(pkg.version);
    const url = `https://api.deps.dev/v3/systems/npm/packages/${encodedName}/versions/${encodedVersion}`;

    try {
      const data = await ctx.http.getJson<any>(url);
      const advisories = data?.advisoryKeys ?? [];

      for (const advKey of advisories) {
        // Fetch advisory details
        const advUrl = `https://api.deps.dev/v3/advisories/${encodeURIComponent(advKey.id)}`;
        try {
          const adv = await ctx.http.getJson<any>(advUrl);

          const severity: Severity = mapSeverity(adv?.severity);
          const identifiers: VulnerabilityIdentifier[] = [];

          // Extract aliases (CVE, GHSA, etc.)
          for (const alias of adv?.aliases ?? []) {
            if (alias.startsWith("CVE-")) {
              identifiers.push({ type: "CVE", value: alias });
            } else if (alias.startsWith("GHSA-")) {
              identifiers.push({ type: "GHSA", value: alias });
            } else {
              identifiers.push({ type: "OTHER", value: alias });
            }
          }

          // Use CVE or GHSA as canonical ID if available
          const canonicalId = identifiers.find(i => i.type === "CVE")?.value
            ?? identifiers.find(i => i.type === "GHSA")?.value
            ?? advKey.id;

          findings.push({
            id: canonicalId,
            source: "depsdev",
            packageName: pkg.name,
            packageVersion: pkg.version,
            title: adv?.summary ?? adv?.title,
            url: adv?.url ?? `https://deps.dev/advisory/${encodeURIComponent(advKey.id)}`,
            severity,
            identifiers: identifiers.length ? identifiers : undefined,
          });
        } catch {
          // Skip individual advisory fetch failures
        }
      }
    } catch {
      // Package not found or API error - return empty
    }

    return findings;
  }
}
