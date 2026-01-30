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
import { retry } from "../utils/retry";
import { HttpError } from "../utils/http";
import { ttlForFindings } from "../cache/ttl";
import { mapSeverity } from "../utils/severity";

function buildGithubHeaders(
  env: Record<string, string | undefined>,
): Record<string, string> {
  const token = env.GITHUB_TOKEN || env.GH_TOKEN || env.GITHUB_ADVISORY_TOKEN;
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": env.GITHUB_API_VERSION || "2022-11-28",
    "User-Agent": "pnpm-audit-hook",
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

function parseLinkHeader(link: string | null): Record<string, string> {
  // RFC 5988-ish: <url>; rel="next", <url>; rel="last"
  if (!link) return {};
  const out: Record<string, string> = {};
  for (const part of link.split(",")) {
    const m = part.match(/<([^>]+)>\s*;\s*rel="([^"]+)"/);
    if (m && m[1] && m[2]) out[m[2]] = m[1];
  }
  return out;
}

export class GitHubAdvisorySource implements VulnerabilitySource {
  id: FindingSource = "github";

  isEnabled(cfg: any, env: Record<string, string | undefined>): boolean {
    // GitHub endpoint is public but rate limited heavily without token.
    // We keep it enabled by default unless config disables it.
    return (
      cfg.sources?.github?.enabled !== false &&
      env.PNPM_AUDIT_DISABLE_GITHUB !== "true"
    );
  }

  async query(pkgs: PackageRef[], ctx: SourceContext): Promise<SourceResult> {
    const start = Date.now();
    const findings: VulnerabilityFinding[] = [];
    const unknown = new Set<string>();

    // Cache per package@version
    const targets: PackageRef[] = [];
    const cachedFindings: VulnerabilityFinding[] = [];

    for (const p of pkgs) {
      const cacheKey = `github:${p.name}@${p.version}`;
      const cached = await ctx.cache.get(cacheKey);
      if (cached?.value) {
        cachedFindings.push(...(cached.value as VulnerabilityFinding[]));
        continue;
      }
      if (ctx.offline) {
        unknown.add(`${p.name}@${p.version}`);
        continue;
      }
      targets.push(p);
    }

    findings.push(...cachedFindings);

    if (targets.length === 0) {
      return {
        source: this.id,
        ok: true,
        durationMs: Date.now() - start,
        findings,
        unknownDataForPackages: unknown.size ? unknown : undefined,
      };
    }

    // Batch affects[] params to avoid URL length issues.
    const batchSize = 80;

    const headers = buildGithubHeaders(ctx.env ?? process.env);

    const fetchPage = async (
      url: string,
    ): Promise<{ data: any[]; next?: string }> => {
      const controller = new AbortController();
      const t = setTimeout(
        () => controller.abort(),
        ctx.cfg.performance?.timeoutMs ?? 15000,
      );
      try {
        const res = await fetch(url, { headers, signal: controller.signal });
        if (!res.ok) {
          const retryAfter = res.headers.get("retry-after") ?? undefined;
          const text = await res.text().catch(() => "");
          throw new HttpError(`GitHub HTTP ${res.status} ${res.statusText}`, {
            url,
            status: res.status,
            retryAfter,
            responseText: text,
          });
        }
        const link = res.headers.get("link");
        const links = parseLinkHeader(link);
        const data = (await res.json()) as any[];
        return { data, next: links.next };
      } finally {
        clearTimeout(t);
      }
    };

    const ttlBase = ctx.cfg.cache?.ttlSeconds ?? 3600;

    try {
      for (let i = 0; i < targets.length; i += batchSize) {
        const batch = targets.slice(i, i + batchSize);

        const params = new URLSearchParams();
        params.set("ecosystem", "npm");
        params.set("per_page", "100");
        for (const p of batch) {
          // affects can be "package" or "package@version"
          params.append("affects[]", `${p.name}@${p.version}`);
        }

        let url = `https://api.github.com/advisories?${params.toString()}`;

        const perPkg: Record<string, VulnerabilityFinding[]> = {};
        for (const p of batch) perPkg[`${p.name}@${p.version}`] = [];

        // Paginate (cursor-based)
        // GitHub uses Link header with ?after= cursor.
        // We stop after a safety cap to avoid infinite loops.
        let pages = 0;
        while (url && pages < 20) {
          pages += 1;

          const page = await retry(() => fetchPage(url), {
            retries: 3,
            minDelayMs: 500,
            maxDelayMs: 8000,
            factor: 2,
            jitter: 0.2,
            retryOn: (err) => {
              if (err instanceof HttpError) {
                const s = err.status;
                return (
                  s === 429 || (typeof s === "number" && s >= 500) || s === 403
                );
              }
              return true;
            },
          });

          for (const adv of page.data ?? []) {
            const severity: Severity = mapSeverity(adv.severity);
            const cvssScore: number | undefined =
              typeof adv.cvss?.score === "number" ? adv.cvss.score : undefined;
            const cvssVector: string | undefined =
              typeof adv.cvss?.vector_string === "string"
                ? adv.cvss.vector_string
                : undefined;

            const identifiers: VulnerabilityIdentifier[] = Array.isArray(
              adv.identifiers,
            )
              ? adv.identifiers
                  .map((x: any) => ({
                    type: String(x.type ?? "OTHER") as any,
                    value: String(x.value ?? ""),
                  }))
                  .filter((x: any) => x.value)
              : [];

            const cveId: string | undefined =
              typeof adv.cve_id === "string"
                ? adv.cve_id
                : identifiers.find((i) => i.type === "CVE")?.value;
            const ghsaId: string | undefined =
              typeof adv.ghsa_id === "string"
                ? adv.ghsa_id
                : identifiers.find((i) => i.type === "GHSA")?.value;
            const canonicalId = (
              cveId ??
              ghsaId ??
              `GH:${String(adv.id ?? "")}`
            ).toUpperCase();

            const vulnerabilities = Array.isArray(adv.vulnerabilities)
              ? adv.vulnerabilities
              : [];
            for (const v of vulnerabilities) {
              const pkg = v?.package;
              if (!pkg) continue;
              if (String(pkg.ecosystem ?? "").toLowerCase() !== "npm") continue;
              const name = String(pkg.name ?? "");
              if (!name) continue;

              const range: string | undefined =
                typeof v.vulnerable_version_range === "string"
                  ? v.vulnerable_version_range
                  : undefined;

              // Apply to every requested version of this package in this batch if it matches range.
              for (const p of batch) {
                if (p.name !== name) continue;
                if (range && !satisfies(p.version, range)) continue;

                const fixed: string | undefined =
                  typeof v.first_patched_version === "string"
                    ? v.first_patched_version
                    : typeof v.first_patched_version?.identifier === "string"
                      ? v.first_patched_version.identifier
                      : undefined;

                const key = `${p.name}@${p.version}`;

                const finding: VulnerabilityFinding = {
                  id: canonicalId,
                  source: "github",
                  packageName: p.name,
                  packageVersion: p.version,
                  title:
                    typeof adv.summary === "string" ? adv.summary : undefined,
                  url:
                    typeof adv.html_url === "string"
                      ? adv.html_url
                      : typeof adv.url === "string"
                        ? adv.url
                        : undefined,
                  description:
                    typeof adv.description === "string"
                      ? adv.description
                      : undefined,
                  severity,
                  cvssScore,
                  cvssVector,
                  publishedAt:
                    typeof adv.published_at === "string"
                      ? adv.published_at
                      : undefined,
                  modifiedAt:
                    typeof adv.updated_at === "string"
                      ? adv.updated_at
                      : undefined,
                  identifiers: identifiers.length ? identifiers : undefined,
                  references: Array.isArray(adv.references)
                    ? adv.references.map(String)
                    : undefined,
                  affectedRange: range,
                  fixedVersion: fixed,
                  raw: { ghsa_id: adv.ghsa_id, cve_id: adv.cve_id },
                };

                perPkg[key] = perPkg[key] ?? [];
                perPkg[key].push(finding);
              }
            }
          }

          url = page.next ?? "";
        }

        // Cache per package@version
        for (const p of batch) {
          const key = `${p.name}@${p.version}`;
          const fs = perPkg[key] ?? [];
          await ctx.cache.set(`github:${key}`, fs, ttlForFindings(ttlBase, fs));
          findings.push(...fs);
        }
      }

      return {
        source: this.id,
        ok: true,
        durationMs: Date.now() - start,
        findings,
        unknownDataForPackages: unknown.size ? unknown : undefined,
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

      for (const p of targets) unknown.add(`${p.name}@${p.version}`);

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
