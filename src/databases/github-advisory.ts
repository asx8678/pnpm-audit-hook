import type { VulnerabilitySource, SourceContext, SourceResult } from "./connector";
import type { AuditConfig, FindingSource, PackageRef, VulnerabilityFinding, VulnerabilityIdentifier } from "../types";
import { ttlForFindings } from "../cache/ttl";
import { satisfies } from "../utils/semver";
import { mapSeverity } from "../utils/severity";

interface GitHubAdvisory {
  id?: string;
  ghsa_id?: string;
  cve_id?: string;
  html_url?: string;
  summary?: string;
  description?: string;
  severity?: string;
  identifiers?: Array<{ type: string; value: string }>;
  vulnerabilities?: Array<{
    package?: { name?: string; ecosystem?: string };
    vulnerable_version_range?: string;
    first_patched_version?: { identifier?: string } | string;
  }>;
  published_at?: string;
  updated_at?: string;
}

export class GitHubAdvisorySource implements VulnerabilitySource {
  id: FindingSource = "github";

  isEnabled(cfg: AuditConfig, env: Record<string, string | undefined>): boolean {
    return cfg.sources?.github?.enabled !== false && env.PNPM_AUDIT_DISABLE_GITHUB !== "true";
  }

  async query(pkgs: PackageRef[], ctx: SourceContext): Promise<SourceResult> {
    const start = Date.now();
    const findings: VulnerabilityFinding[] = [];

    // Check cache first (parallel reads)
    const targets: PackageRef[] = [];
    const cacheResults = await Promise.all(
      pkgs.map(p => ctx.cache.get(`github:${p.name}@${p.version}`))
    );
    pkgs.forEach((p, i) => {
      const cached = cacheResults[i];
      if (cached?.value) {
        findings.push(...(cached.value as VulnerabilityFinding[]));
      } else {
        targets.push(p);
      }
    });

    if (targets.length === 0) {
      return { source: this.id, ok: true, durationMs: Date.now() - start, findings };
    }

    const token = ctx.env.GITHUB_TOKEN || ctx.env.GH_TOKEN;
    const headers: Record<string, string> = {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      ...(token && { Authorization: `Bearer ${token}` }),
    };

    const perPkg: Record<string, VulnerabilityFinding[]> = {};
    for (const p of targets) perPkg[`${p.name}@${p.version}`] = [];

    const errors: string[] = [];
    const seen = new Set<string>();

    // Query each package individually - GitHub API returns incomplete results
    // when multiple `affects` parameters are used in a single request
    const MAX_CONCURRENT = 10;
    const queryPackage = async (p: PackageRef) => {
      try {
        let page = 1;
        let hasNextPage = true;

        while (hasNextPage) {
          const params = new URLSearchParams({
            ecosystem: "npm",
            per_page: "100",
            page: String(page),
            affects: `${p.name}@${p.version}`,
          });

          const url = `https://api.github.com/advisories?${params}`;
          const response = await ctx.http.getRaw(url, headers);
          let data: GitHubAdvisory[];
          try {
            data = (await response.json()) as GitHubAdvisory[];
          } catch {
            throw new Error("GitHub API returned invalid JSON response");
          }

          if (!Array.isArray(data)) {
            const errorMsg = (data as Record<string, unknown>)?.message;
            throw new Error(errorMsg ? String(errorMsg) : "GitHub API returned invalid response format");
          }

          if (data.length === 0) {
            hasNextPage = false;
            break;
          }

          for (const adv of data) {
            const severity = mapSeverity(adv.severity);
            const validIdTypes = new Set(["CVE", "GHSA", "OSV", "OTHER"]);
            const identifiers: VulnerabilityIdentifier[] = (adv.identifiers ?? [])
              .map((x) => {
                const t = String(x.type ?? "OTHER").toUpperCase();
                return {
                  type: (validIdTypes.has(t) ? t : "OTHER") as VulnerabilityIdentifier["type"],
                  value: String(x.value ?? ""),
                };
              })
              .filter((x) => x.value);

            const cveId = adv.cve_id ?? identifiers.find((i) => i.type === "CVE")?.value;
            const ghsaId = adv.ghsa_id ?? identifiers.find((i) => i.type === "GHSA")?.value;
            const canonicalId = (cveId ?? ghsaId ?? `GH:${adv.id ?? ""}`).toUpperCase();

            for (const v of adv.vulnerabilities ?? []) {
              const pkg = v?.package;
              if (!pkg || String(pkg.ecosystem ?? "").toLowerCase() !== "npm") continue;

              const name = String(pkg.name ?? "");
              const range = v.vulnerable_version_range;

              if (p.name !== name) continue;
              if (range && !satisfies(p.version, range)) continue;

              const key = `${p.name}@${p.version}`;
              const dedupKey = `${key}:${canonicalId}`;
              if (seen.has(dedupKey)) continue;
              seen.add(dedupKey);
              (perPkg[key] ??= []).push({
                id: canonicalId,
                source: "github",
                packageName: p.name,
                packageVersion: p.version,
                title: adv.summary,
                url: adv.html_url,
                severity,
                affectedRange: range,
                fixedVersion:
                  typeof v.first_patched_version === "string"
                    ? v.first_patched_version
                    : v.first_patched_version?.identifier,
              });
            }
          }

          if (data.length < 100) {
            hasNextPage = false;
          } else {
            page++;
          }
        }
      } catch (e: unknown) {
        errors.push(`${p.name}@${p.version}: ${e instanceof Error ? e.message : String(e)}`);
      }
    };

    // Run queries with limited concurrency
    for (let i = 0; i < targets.length; i += MAX_CONCURRENT) {
      await Promise.all(targets.slice(i, i + MAX_CONCURRENT).map(queryPackage));
    }

    // Cache and collect results (parallel writes with dynamic TTL)
    const baseTtl = ctx.cfg.cache?.ttlSeconds ?? 3600;
    await Promise.all(
      targets.map(p => {
        const key = `${p.name}@${p.version}`;
        const fs = perPkg[key] ?? [];
        findings.push(...fs);
        return ctx.cache.set(`github:${key}`, fs, ttlForFindings(baseTtl, fs));
      })
    );

    if (errors.length > 0) {
      if (errors.length === targets.length) {
        // All queries failed
        return { source: this.id, ok: false, error: errors[0], durationMs: Date.now() - start, findings };
      }
      // Partial failure - some queries succeeded, but fail-closed for security
      return {
        source: this.id,
        ok: false,
        error: `Partial failure: ${errors.length}/${targets.length} packages failed`,
        durationMs: Date.now() - start,
        findings,
      };
    }

    return { source: this.id, ok: true, durationMs: Date.now() - start, findings };
  }
}
