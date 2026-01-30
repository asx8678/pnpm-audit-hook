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
import { npmPurl } from "../utils/semver";
import { severityFromCvssScore } from "../utils/cvss";

function buildAuthHeader(
  env: Record<string, string | undefined>,
): string | undefined {
  const user = env.OSSINDEX_USERNAME;
  const token = env.OSSINDEX_TOKEN;
  if (!user || !token) return undefined;
  const b64 = Buffer.from(`${user}:${token}`, "utf-8").toString("base64");
  return `Basic ${b64}`;
}

export class OssIndexSource implements VulnerabilitySource {
  id: FindingSource = "ossindex";

  isEnabled(cfg: any, env: Record<string, string | undefined>): boolean {
    return (
      cfg.sources?.ossIndex?.enabled === true ||
      env.PNPM_AUDIT_OSSINDEX_ENABLED === "true"
    );
  }

  async query(pkgs: PackageRef[], ctx: SourceContext): Promise<SourceResult> {
    const start = Date.now();
    const findings: VulnerabilityFinding[] = [];
    const unknown = new Set<string>();

    const coords = pkgs.map((p) => npmPurl(p.name, p.version));
    const ttl = ctx.cfg.cache?.ttlSeconds ?? 3600;

    const auth = buildAuthHeader(ctx.env);
    const endpoint = auth
      ? "https://ossindex.sonatype.org/api/v3/authorized/component-report"
      : "https://ossindex.sonatype.org/api/v3/component-report";

    // Check cache per coordinate
    const missing: string[] = [];
    const cached: Record<string, any> = {};

    for (const c of coords) {
      const cacheKey = `ossindex:${c}`;
      const ce = await ctx.cache.get(cacheKey);
      if (ce?.value) cached[c] = ce.value;
      else if (ctx.offline) unknown.add(c);
      else missing.push(c);
    }

    // Fetch missing in batches (max 128)
    const batchSize = 128;
    try {
      for (let i = 0; i < missing.length; i += batchSize) {
        const batch = missing.slice(i, i + batchSize);
        const body = { coordinates: batch };

        const extraHeaders: Record<string, string> = {};
        if (auth) extraHeaders.Authorization = auth;

        const res = await ctx.http.postJson<any[]>(
          endpoint,
          body,
          extraHeaders,
        );

        if (Array.isArray(res)) {
          for (const item of res) {
            const c = String(item.coordinates ?? "");
            if (!c) continue;
            cached[c] = item;
            await ctx.cache.set(`ossindex:${c}`, item, ttl);
          }
        }
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
      for (const c of missing) unknown.add(c);
      // Continue with partial
    }

    // Build findings per package
    for (const p of pkgs) {
      const c = npmPurl(p.name, p.version);
      const item = cached[c];
      if (!item) continue;
      const vulns = Array.isArray(item.vulnerabilities)
        ? item.vulnerabilities
        : [];
      for (const v of vulns) {
        const cvssScore =
          typeof v.cvssScore === "number" ? v.cvssScore : undefined;
        const severity: Severity = severityFromCvssScore(cvssScore);

        const identifiers: VulnerabilityIdentifier[] = [];
        if (typeof v.cve === "string" && v.cve)
          identifiers.push({ type: "CVE", value: v.cve.toUpperCase() });
        if (typeof v.id === "string" && v.id)
          identifiers.push({ type: "SONATYPE", value: v.id });

        const canonicalId =
          identifiers.find((i) => i.type === "CVE")?.value ??
          String(v.id ?? "SONATYPE");

        const finding: VulnerabilityFinding = {
          id: canonicalId,
          source: "ossindex",
          packageName: p.name,
          packageVersion: p.version,
          title: typeof v.title === "string" ? v.title : undefined,
          url:
            typeof v.reference === "string"
              ? v.reference
              : typeof v.externalReference === "string"
                ? v.externalReference
                : undefined,
          description:
            typeof v.description === "string" ? v.description : undefined,
          severity,
          cvssScore,
          cvssVector:
            typeof v.cvssVector === "string" ? v.cvssVector : undefined,
          identifiers: identifiers.length ? identifiers : undefined,
          publishedAt:
            typeof v.published === "string" ? v.published : undefined,
          modifiedAt: typeof v.modified === "string" ? v.modified : undefined,
          raw: { coordinates: c, sonatypeId: v.id },
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
