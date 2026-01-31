import type { VulnerabilitySource, SourceContext, SourceResult, VulnerabilitySourceOptions } from "./connector";
import type { AuditConfig, FindingSource, PackageRef, VulnerabilityFinding, VulnerabilityIdentifier } from "../types";
import type { StaticDbReader } from "../static-db/reader";
import { ttlForFindings } from "../cache/ttl";
import { satisfies } from "../utils/semver";
import { mapSeverity } from "../utils/severity";
import { logger } from "../utils/logger";
import { errorMessage } from "../utils/error";
import { mapWithConcurrency } from "../utils/concurrency";

const CACHE_READ_CONCURRENCY = 50;
const CACHE_WRITE_CONCURRENCY = 25;
const STATIC_DB_CONCURRENCY = 10;

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

/**
 * Options for configuring the GitHub Advisory source.
 */
export interface GitHubAdvisoryOptions {
  /** Static database reader for historical vulnerabilities */
  staticDb?: StaticDbReader | null;
  /** Cutoff date for static DB (ISO date string, e.g., "2025-12-31") */
  cutoffDate?: string;
}

export class GitHubAdvisorySource implements VulnerabilitySource {
  id: FindingSource = "github";
  private staticDb: StaticDbReader | null;
  private cutoffDate: string | null;

  constructor(options: GitHubAdvisoryOptions = {}) {
    this.staticDb = options.staticDb ?? null;
    this.cutoffDate = options.cutoffDate ?? null;
  }

  isEnabled(cfg: AuditConfig, env: Record<string, string | undefined>): boolean {
    return cfg.sources?.github?.enabled !== false && env.PNPM_AUDIT_DISABLE_GITHUB !== "true";
  }

  private cacheKey(ctx: SourceContext, pkg: PackageRef): string {
    return `github:${ctx.registryUrl}:${pkg.name}@${pkg.version}`;
  }

  /**
   * Query GitHub Advisory Database for vulnerabilities affecting the given packages.
   *
   * Uses a hybrid approach when static DB is available:
   * 1. Query static DB for historical vulnerabilities
   * 2. Query GitHub API for recent vulnerabilities (after cutoff date)
   * 3. Merge and deduplicate results (API data preferred over static DB)
   *
   * Falls back to full API query if static DB is not available.
   *
   * @param pkgs - Packages to check for vulnerabilities
   * @param ctx - Source context with configuration, HTTP client, and cache
   * @param options - Optional query filters
   * @param options.publishedAfter - Only return advisories published after this ISO 8601 date (YYYY-MM-DD)
   *                                  Uses GitHub API's `published=>YYYY-MM-DD` parameter
   * @returns Source result with findings and status
   */
  async query(pkgs: PackageRef[], ctx: SourceContext, options?: VulnerabilitySourceOptions): Promise<SourceResult> {
    const start = Date.now();
    const findings: VulnerabilityFinding[] = [];

    // Check cache first (parallel reads)
    const targets: PackageRef[] = [];
    const cacheResults = await mapWithConcurrency(
      pkgs,
      CACHE_READ_CONCURRENCY,
      (p) => ctx.cache.get(this.cacheKey(ctx, p)),
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

    // Track findings per package for caching
    const perPkg: Record<string, VulnerabilityFinding[]> = {};
    for (const p of targets) perPkg[`${p.name}@${p.version}`] = [];

    const errors: string[] = [];
    const seen = new Set<string>();

    // Step 1: Query static DB for historical vulnerabilities (if available)
    const staticDbAvailable = this.staticDb?.isReady() ?? false;
    if (staticDbAvailable) {
      try {
        const staticFindings = await this.queryStaticDb(targets, seen, perPkg);
        logger.debug(`Static DB returned ${staticFindings.length} findings for ${targets.length} packages`);
      } catch (e) {
        logger.warn(`Static DB query failed, falling back to full API: ${errorMessage(e)}`);
        // Continue with API query - don't fail the entire operation
      }
    } else if (ctx.cfg.staticBaseline?.enabled) {
      logger.warn("Static DB was expected but is not available, falling back to full API query");
    }

    // Step 2: Query GitHub API for vulnerabilities
    // If static DB is available, only query for recent vulnerabilities (after cutoff)
    // Otherwise, query for all vulnerabilities
    const apiQueryStart = Date.now();

    // Determine API query options
    // Use publishedAfter from options, or from cutoff date if static DB is available
    const apiOptions: VulnerabilitySourceOptions = { ...options };
    if (staticDbAvailable && this.cutoffDate && !apiOptions.publishedAfter) {
      apiOptions.publishedAfter = this.cutoffDate;
    }

    const apiErrors = await this.queryGitHubApi(targets, ctx, seen, perPkg, apiOptions);
    errors.push(...apiErrors);
    logger.debug(`GitHub API query took ${Date.now() - apiQueryStart}ms`);

    // Cache and collect results (parallel writes with dynamic TTL)
    const baseTtl = ctx.cfg.cache?.ttlSeconds ?? 3600;
    const perTarget = targets.map((p) => {
      const key = `${p.name}@${p.version}`;
      const pkgFindings = perPkg[key] ?? [];
      return { pkg: p, findings: pkgFindings };
    });
    for (const entry of perTarget) {
      findings.push(...entry.findings);
    }
    const cacheWriteResults = await mapWithConcurrency(
      perTarget,
      CACHE_WRITE_CONCURRENCY,
      async (entry) => {
        try {
          await ctx.cache.set(
            this.cacheKey(ctx, entry.pkg),
            entry.findings,
            ttlForFindings(baseTtl, entry.findings),
          );
          return { status: "fulfilled" as const };
        } catch (reason) {
          return { status: "rejected" as const, reason };
        }
      },
    );

    // Log cache write failures (non-fatal, but useful for debugging)
    for (let i = 0; i < cacheWriteResults.length; i++) {
      const result = cacheWriteResults[i];
      if (result?.status === "rejected") {
        const target = perTarget[i]?.pkg;
        const reason = errorMessage(result.reason);
        logger.warn(`Cache write failed for github:${target?.name}@${target?.version}: ${reason}`);
      }
    }

    if (errors.length > 0) {
      // When static DB is available and was queried successfully, API failures are less critical
      // because the static DB covers historical vulnerabilities. The API is primarily needed
      // for very recent vulnerabilities published after the cutoff date.
      const hasStaticDbFindings = findings.length > 0 && staticDbAvailable;

      if (errors.length === targets.length) {
        // All API queries failed
        if (hasStaticDbFindings) {
          // Static DB returned findings, so we have coverage for historical vulnerabilities
          // Log warning but return success with static DB findings
          logger.warn(`GitHub API failed for all packages, but static DB returned ${findings.length} findings`);
          return { source: this.id, ok: true, durationMs: Date.now() - start, findings };
        }
        return { source: this.id, ok: false, error: errors[0], durationMs: Date.now() - start, findings };
      }

      // Partial failure - some queries succeeded
      if (hasStaticDbFindings) {
        // Static DB has findings, treat API partial failure as non-fatal
        logger.warn(`GitHub API partial failure: ${errors.length}/${targets.length} packages failed, but static DB has findings`);
        return { source: this.id, ok: true, durationMs: Date.now() - start, findings };
      }

      // No static DB findings - fail-closed for security
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

  /**
   * Query static database for historical vulnerabilities.
   */
  private async queryStaticDb(
    targets: PackageRef[],
    seen: Set<string>,
    perPkg: Record<string, VulnerabilityFinding[]>,
  ): Promise<VulnerabilityFinding[]> {
    if (!this.staticDb) return [];

    const allFindings: VulnerabilityFinding[] = [];
    const db = this.staticDb;

    // Parallelize static DB queries with a concurrency cap to avoid I/O spikes
    const staticResults = await mapWithConcurrency(
      targets,
      STATIC_DB_CONCURRENCY,
      async (p) => ({
        pkg: p,
        findings: await db.queryPackageWithOptions(p.name, { version: p.version }),
      }),
    );

    for (const { pkg: p, findings: staticFindings } of staticResults) {
      for (const finding of staticFindings) {
        const key = `${p.name}@${p.version}`;
        const dedupKey = `${key}:${finding.id}`;
        if (seen.has(dedupKey)) continue;
        seen.add(dedupKey);

        // Ensure the finding has the correct package info
        const adjustedFinding: VulnerabilityFinding = {
          ...finding,
          packageName: p.name,
          packageVersion: p.version,
        };

        (perPkg[key] ??= []).push(adjustedFinding);
        allFindings.push(adjustedFinding);
      }
    }

    return allFindings;
  }

  /**
   * Query GitHub API for vulnerabilities.
   * Returns array of error messages for failed packages.
   */
  private async queryGitHubApi(
    targets: PackageRef[],
    ctx: SourceContext,
    seen: Set<string>,
    perPkg: Record<string, VulnerabilityFinding[]>,
    options?: VulnerabilitySourceOptions,
  ): Promise<string[]> {
    const token = ctx.env.GITHUB_TOKEN || ctx.env.GH_TOKEN;
    const headers: Record<string, string> = {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      ...(token && { Authorization: `Bearer ${token}` }),
    };

    const errors: string[] = [];

    // Query each package individually - GitHub API returns incomplete results
    // when multiple `affects` parameters are used in a single request
    const configured = Number(ctx.env.PNPM_AUDIT_GITHUB_CONCURRENCY);
    const defaultConcurrency = token ? 10 : 3;
    const MAX_CONCURRENT =
      Number.isFinite(configured) && configured > 0
        ? Math.min(50, Math.floor(configured))
        : defaultConcurrency;
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

          // Add date filtering if publishedAfter is specified
          // GitHub API uses `published=>YYYY-MM-DD` format for "after" date filtering
          if (options?.publishedAfter) {
            params.set("published", `>${options.publishedAfter}`);
          }

          const url = `https://api.github.com/advisories?${params}`;
          const response = await ctx.http.getRaw(url, headers);
          let data: GitHubAdvisory[];
          try {
            data = (await response.json()) as GitHubAdvisory[];
          } catch (parseError) {
            throw new Error(`GitHub API returned invalid JSON response: ${parseError instanceof Error ? parseError.message : String(parseError)}`);
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

              // Deduplication: prefer API data over static DB (more recent)
              // If we've already seen this from static DB, replace it
              if (seen.has(dedupKey)) {
                // Check if this is from static DB by looking for it in perPkg
                const pkgFindings = perPkg[key] ?? [];
                const existingIdx = pkgFindings.findIndex(f => f.id === canonicalId);
                const existingFinding = existingIdx >= 0 ? pkgFindings[existingIdx] : undefined;
                if (existingIdx >= 0 && existingFinding) {
                  // Replace static DB entry with API data (more recent)
                  pkgFindings[existingIdx] = {
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
                    publishedAt: adv.published_at,
                    modifiedAt: adv.updated_at,
                  };
                }
                continue;
              }

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
                publishedAt: adv.published_at,
                modifiedAt: adv.updated_at,
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
        errors.push(`${p.name}@${p.version}: ${errorMessage(e)}`);
      }
    };

    // Run queries with limited concurrency
    for (let i = 0; i < targets.length; i += MAX_CONCURRENT) {
      await Promise.all(targets.slice(i, i + MAX_CONCURRENT).map(queryPackage));
    }

    return errors;
  }
}
