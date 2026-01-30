import type { VulnerabilitySource, SourceContext, SourceResult } from "./connector";
import type { FindingSource, PackageRef, VulnerabilityFinding, VulnerabilityIdentifier } from "../types";
import { npmPurl } from "../utils/semver";
import { severityFromCvssScore } from "../utils/cvss";

function buildAuthHeader(env: Record<string, string | undefined>): string | undefined {
  const { OSSINDEX_USERNAME: user, OSSINDEX_TOKEN: token } = env;
  return user && token ? `Basic ${Buffer.from(`${user}:${token}`).toString("base64")}` : undefined;
}

export class OssIndexSource implements VulnerabilitySource {
  id: FindingSource = "ossindex";

  isEnabled(cfg: any, env: Record<string, string | undefined>): boolean {
    return cfg.sources?.ossIndex?.enabled === true || env.PNPM_AUDIT_OSSINDEX_ENABLED === "true";
  }

  async query(pkgs: PackageRef[], ctx: SourceContext): Promise<SourceResult> {
    const start = Date.now();
    const findings: VulnerabilityFinding[] = [];
    const unknown = new Set<string>();

    const coords = pkgs.map((p) => npmPurl(p.name, p.version));
    const ttl = ctx.cfg.cache?.ttlSeconds ?? 3600;

    const auth = buildAuthHeader(ctx.env);
    const endpoint = `https://ossindex.sonatype.org/api/v3/${auth ? "authorized/" : ""}component-report`;
    const missing: string[] = [];
    const cached: Record<string, any> = {};

    for (const c of coords) {
      const ce = await ctx.cache.get(`ossindex:${c}`);
      if (ce?.value) cached[c] = ce.value;
      else if (ctx.offline) unknown.add(c);
      else missing.push(c);
    }

    try {
      for (let i = 0; i < missing.length; i += 128) {
        const batch = missing.slice(i, i + 128);
        const res = await ctx.http.postJson<any[]>(endpoint, { coordinates: batch }, auth ? { Authorization: auth } : {});
        for (const item of res ?? []) {
          const c = String(item.coordinates ?? "");
          if (c) { cached[c] = item; await ctx.cache.set(`ossindex:${c}`, item, ttl); }
        }
      }
    } catch (e: any) {
      const error = String(e?.message ?? e);
      if (ctx.networkPolicy === "fail-closed") {
        return { source: this.id, ok: false, error, durationMs: Date.now() - start, findings: [] };
      }
      missing.forEach((c) => unknown.add(c));
    }

    for (const p of pkgs) {
      const c = npmPurl(p.name, p.version);
      const vulns = cached[c]?.vulnerabilities ?? [];
      for (const v of vulns) {
        const cvssScore = typeof v.cvssScore === "number" ? v.cvssScore : undefined;
        const identifiers: VulnerabilityIdentifier[] = [
          ...(v.cve ? [{ type: "CVE" as const, value: v.cve.toUpperCase() }] : []),
          ...(v.id ? [{ type: "SONATYPE" as const, value: v.id }] : []),
        ];
        findings.push({
          id: identifiers.find((i) => i.type === "CVE")?.value ?? String(v.id ?? "SONATYPE"),
          source: "ossindex",
          packageName: p.name,
          packageVersion: p.version,
          title: v.title,
          url: v.reference ?? v.externalReference,
          description: v.description,
          severity: severityFromCvssScore(cvssScore),
          cvssScore,
          cvssVector: v.cvssVector,
          identifiers: identifiers.length ? identifiers : undefined,
          publishedAt: v.published,
          modifiedAt: v.modified,
          raw: { coordinates: c, sonatypeId: v.id },
        });
      }
    }
    return { source: this.id, ok: true, durationMs: Date.now() - start, findings, unknownDataForPackages: unknown.size ? unknown : undefined };
  }
}
