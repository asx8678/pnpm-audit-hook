import type { VulnerabilitySource, SourceContext, SourceResult } from "./connector";
import type { FindingSource, PackageRef, VulnerabilityFinding, VulnerabilityIdentifier } from "../types";
import { satisfies } from "../utils/semver";
import { mapSeverity } from "../utils/severity";

export class GitHubAdvisorySource implements VulnerabilitySource {
  id: FindingSource = "github";

  isEnabled(cfg: any, env: Record<string, string | undefined>): boolean {
    return cfg.sources?.github?.enabled !== false && env.PNPM_AUDIT_DISABLE_GITHUB !== "true";
  }

  async query(pkgs: PackageRef[], ctx: SourceContext): Promise<SourceResult> {
    const start = Date.now();
    const findings: VulnerabilityFinding[] = [];

    // Check cache first
    const targets: PackageRef[] = [];
    for (const p of pkgs) {
      const key = `${p.name}@${p.version}`;
      const cached = await ctx.cache.get(`github:${key}`);
      if (cached?.value) {
        findings.push(...(cached.value as VulnerabilityFinding[]));
        continue;
      }
      targets.push(p);
    }

    if (targets.length === 0) {
      return { source: this.id, ok: true, durationMs: Date.now() - start, findings };
    }

    const token = ctx.env.GITHUB_TOKEN || ctx.env.GH_TOKEN;
    const headers: Record<string, string> = {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      ...(token && { Authorization: `Bearer ${token}` }),
    };

    const ttl = ctx.cfg.cache?.ttlSeconds ?? 3600;

    try {
      // Query all packages in one request (GitHub API limit is 100 per_page)
      const params = new URLSearchParams({ ecosystem: "npm", per_page: "100" });
      for (const p of targets.slice(0, 100)) {
        params.append("affects[]", `${p.name}@${p.version}`);
      }

      const url = `https://api.github.com/advisories?${params}`;
      const data = await ctx.http.getJson<any[]>(url, headers);

      const perPkg: Record<string, VulnerabilityFinding[]> = {};
      for (const p of targets) perPkg[`${p.name}@${p.version}`] = [];

      for (const adv of data ?? []) {
        const severity = mapSeverity(adv.severity);

        const identifiers: VulnerabilityIdentifier[] = (adv.identifiers ?? [])
          .map((x: any) => ({ type: String(x.type ?? "OTHER"), value: String(x.value ?? "") }))
          .filter((x: VulnerabilityIdentifier) => x.value);

        const cveId = adv.cve_id ?? identifiers.find((i) => i.type === "CVE")?.value;
        const ghsaId = adv.ghsa_id ?? identifiers.find((i) => i.type === "GHSA")?.value;
        const canonicalId = (cveId ?? ghsaId ?? `GH:${adv.id ?? ""}`).toUpperCase();

        for (const v of adv.vulnerabilities ?? []) {
          const pkg = v?.package;
          if (!pkg || String(pkg.ecosystem ?? "").toLowerCase() !== "npm") continue;

          const name = String(pkg.name ?? "");
          const range = v.vulnerable_version_range;

          for (const p of targets) {
            if (p.name !== name) continue;
            if (range && !satisfies(p.version, range)) continue;

            const key = `${p.name}@${p.version}`;
            (perPkg[key] ??= []).push({
              id: canonicalId,
              source: "github",
              packageName: p.name,
              packageVersion: p.version,
              title: adv.summary,
              url: adv.html_url,
              severity,
              affectedRange: range,
              fixedVersion: v.first_patched_version?.identifier ?? v.first_patched_version,
            });
          }
        }
      }

      // Cache and collect results
      for (const p of targets) {
        const key = `${p.name}@${p.version}`;
        const fs = perPkg[key] ?? [];
        await ctx.cache.set(`github:${key}`, fs, ttl);
        findings.push(...fs);
      }

      return { source: this.id, ok: true, durationMs: Date.now() - start, findings };
    } catch (e: any) {
      const error = String(e?.message ?? e);
      return { source: this.id, ok: false, error, durationMs: Date.now() - start, findings };
    }
  }
}
