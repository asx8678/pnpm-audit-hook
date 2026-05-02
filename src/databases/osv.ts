import type { VulnerabilitySource, SourceContext, SourceResult, VulnerabilitySourceOptions } from "./connector";
import type { AuditConfig, FindingSource, PackageRef, VulnerabilityFinding, VulnerabilityIdentifier } from "../types";
import { ttlForFindings } from "../cache/ttl";
import { isVersionAffectedByOsvSemverRange } from "../utils/semver";
import { mapSeverity } from "../utils/severity";
import { logger } from "../utils/logger";
import { errorMessage } from "../utils/error";
import { mapWithConcurrency } from "../utils/concurrency";

const CACHE_READ_CONCURRENCY = 50;
const CACHE_WRITE_CONCURRENCY = 25;
const API_CONCURRENCY = 5;
const VALID_ID_TYPES = new Set(["CVE", "GHSA", "OSV", "OTHER"]);

const OSV_API_URL = "https://api.osv.dev/v1/query";

/** OSV.dev API response shape (subset we care about). */
interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { name?: string; ecosystem?: string; purl?: string };
    ranges?: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
    }>;
    versions?: string[];
  }>;
  references?: Array<{ type: string; url: string }>;
  published?: string;
  modified?: string;
}

interface OsvQueryResponse {
  vulns?: OsvVuln[];
}

/** Structured error for failed package queries. */
interface PackageQueryError {
  pkg: PackageRef;
  message: string;
}

/**
 * Validate that a cached value has the expected shape for VulnerabilityFinding[].
 */
function isValidCachedFindings(value: unknown): value is VulnerabilityFinding[] {
  if (!Array.isArray(value)) return false;
  if (value.length > 0) {
    const first = value[0];
    return (
      first &&
      typeof first === "object" &&
      typeof first.id === "string" &&
      typeof first.packageName === "string" &&
      typeof first.severity === "string"
    );
  }
  return true;
}

/** Derive a human-readable severity from OSV CVSS / severity vector. */
function severityFromOsv(vuln: OsvVuln): string {
  for (const s of vuln.severity ?? []) {
    if (s.type === "CVSS_V3") {
      try {
        const score = parseFloat(s.score.split("/")[0] ?? "0");
        if (score >= 9.0) return "critical";
        if (score >= 7.0) return "high";
        if (score >= 4.0) return "medium";
        if (score > 0) return "low";
      } catch {
        // fall through
      }
    }
  }
  return "unknown";
}

/** Extract the best URL from OSV references (prefer "ADVISORY" type). */
function urlFromOsv(vuln: OsvVuln): string | undefined {
  const adv = vuln.references?.find((r) => r.type === "ADVISORY");
  if (adv) return adv.url;
  return vuln.references?.[0]?.url;
}

/** Build identifiers from OSV vuln ID and any cross-references. */
function identifiersFromOsv(vuln: OsvVuln): VulnerabilityIdentifier[] {
  const ids: VulnerabilityIdentifier[] = [];
  const osvId = vuln.id?.toUpperCase() ?? "";

  // The OSV id itself
  if (osvId) {
    ids.push({ type: "OSV", value: osvId });
  }

  // OSV ids often start with "CVE-" or "GHSA-" — promote those
  if (osvId.startsWith("CVE-")) {
    ids.unshift({ type: "CVE", value: osvId });
  } else if (osvId.startsWith("GHSA-")) {
    ids.unshift({ type: "GHSA", value: osvId });
  }

  // Deduplicate
  const seen = new Set<string>();
  return ids.filter((i) => {
    const key = `${i.type}:${i.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * OSV.dev vulnerability source connector.
 *
 * Queries the free OSV.dev API (no auth required) for npm package vulnerabilities.
 * Uses `isVersionAffectedByOsvSemverRange()` for semver-based range evaluation,
 * which handles OSV's introduced/fixed/last_affected event model.
 */
export class OsvSource implements VulnerabilitySource {
  id: FindingSource = "osv";

  isEnabled(cfg: AuditConfig, env: Record<string, string | undefined>): boolean {
    return cfg.sources?.osv?.enabled !== false && env.PNPM_AUDIT_DISABLE_OSV !== "true";
  }

  private cacheKey(ctx: SourceContext, pkg: PackageRef): string {
    return `osv:${ctx.registryUrl}:${pkg.name}@${pkg.version}`;
  }

  async query(pkgs: PackageRef[], ctx: SourceContext, options?: VulnerabilitySourceOptions): Promise<SourceResult> {
    const start = Date.now();
    const findings: VulnerabilityFinding[] = [];
    const isOffline = options?.offline ?? false;

    // Check cache first (parallel reads)
    const targets: PackageRef[] = [];
    const cacheResults = await mapWithConcurrency(
      pkgs,
      CACHE_READ_CONCURRENCY,
      (p) => ctx.cache.get(this.cacheKey(ctx, p)),
    );
    pkgs.forEach((p, i) => {
      const cached = cacheResults[i];
      if (cached?.value && isValidCachedFindings(cached.value)) {
        findings.push(...cached.value);
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

    const errors: PackageQueryError[] = [];
    const seen = new Set<string>();

    // Step: Query OSV API (skip in offline mode)
    if (!isOffline) {
      const apiErrors = await this.queryOsvApi(targets, ctx, seen, perPkg);
      errors.push(...apiErrors);
    } else {
      logger.debug("OSV: offline mode — skipping live API queries");
    }

    // Cache and collect results
    const baseTtl = ctx.cfg.cache?.ttlSeconds ?? 3600;
    const perTarget = targets.map((p) => {
      const key = `${p.name}@${p.version}`;
      const pkgFindings = perPkg[key] ?? [];
      return { pkg: p, findings: pkgFindings };
    });
    for (const entry of perTarget) {
      findings.push(...entry.findings);
    }

    // Parallel cache writes
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

    for (let i = 0; i < cacheWriteResults.length; i++) {
      const result = cacheWriteResults[i];
      if (result?.status === "rejected") {
        const target = perTarget[i]?.pkg;
        logger.warn(`OSV: cache write failed for ${target?.name}@${target?.version}: ${errorMessage(result.reason)}`);
      }
    }

    if (errors.length > 0) {
      if (errors.length === targets.length) {
        return { source: this.id, ok: false, error: errors[0]!.message, durationMs: Date.now() - start, findings };
      }
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
   * Query OSV.dev API for vulnerabilities.
   * Returns array of structured errors for failed packages.
   */
  private async queryOsvApi(
    targets: PackageRef[],
    ctx: SourceContext,
    seen: Set<string>,
    perPkg: Record<string, VulnerabilityFinding[]>,
  ): Promise<PackageQueryError[]> {
    const errors: PackageQueryError[] = [];
    let completed = 0;
    const total = targets.length;

    const queryPackage = async (p: PackageRef) => {
      try {
        const requestBody = {
          package: { name: p.name, ecosystem: "npm" },
          version: p.version,
        };

        const data = await ctx.http.postJson<OsvQueryResponse>(OSV_API_URL, requestBody);

        if (!data || typeof data !== "object") {
          throw new Error("OSV API returned invalid response format");
        }

        const vulns = data.vulns;
        if (!Array.isArray(vulns)) return;

        for (const vuln of vulns) {
          if (!vuln.id) continue;

          const osvId = vuln.id.toUpperCase();
          const severity = severityFromOsv(vuln);
          const identifiers = identifiersFromOsv(vuln);

          // Use CVE/GHSA id as canonical if available, otherwise OSV id
          const cveId = identifiers.find((i) => i.type === "CVE")?.value;
          const ghsaId = identifiers.find((i) => i.type === "GHSA")?.value;
          const canonicalId = cveId ?? ghsaId ?? osvId;

          for (const affected of vuln.affected ?? []) {
            const pkg = affected.package;
            // Filter to npm ecosystem only
            if (pkg?.ecosystem && pkg.ecosystem.toLowerCase() !== "npm") continue;

            // If the package name in the affected entry exists, verify it matches
            if (pkg?.name && pkg.name.toLowerCase() !== p.name.toLowerCase()) continue;

            let isAffected = false;
            let affectedRange: string | undefined;
            let fixedVersion: string | undefined;

            // Check SEMVER-type ranges using the dedicated OSV semver evaluator
            for (const range of affected.ranges ?? []) {
              if (range.type === "SEMVER") {
                if (isVersionAffectedByOsvSemverRange(p.version, range.events)) {
                  isAffected = true;
                  // Build a human-readable range description
                  affectedRange = formatOsvRange(range.events);
                  // Extract the first "fixed" event as the fixed version
                  const fixed = range.events.find((e) => e.fixed !== undefined);
                  if (fixed?.fixed) fixedVersion = fixed.fixed;
                }
              }
            }

            // Also check explicit version lists
            if (!isAffected && affected.versions?.length) {
              if (affected.versions.includes(p.version)) {
                isAffected = true;
                affectedRange = affected.versions.join(", ");
              }
            }

            // If no ranges or versions at all, include as potentially affected (fail-closed)
            if (!isAffected && !affected.ranges?.length && !affected.versions?.length) {
              isAffected = true;
            }

            if (!isAffected) continue;

            const key = `${p.name}@${p.version}`;
            const dedupKey = `${key}:${canonicalId}`;

            if (seen.has(dedupKey)) continue;
            seen.add(dedupKey);

            const finding: VulnerabilityFinding = {
              id: canonicalId,
              source: "osv",
              packageName: p.name,
              packageVersion: p.version,
              title: vuln.summary,
              url: urlFromOsv(vuln),
              description: vuln.details,
              severity: severity as VulnerabilityFinding["severity"],
              identifiers: identifiers.length > 0 ? identifiers : undefined,
              affectedRange,
              fixedVersion,
              publishedAt: vuln.published,
              modifiedAt: vuln.modified,
            };

            (perPkg[key] ??= []).push(finding);
          }
        }
      } catch (e: unknown) {
        errors.push({ pkg: p, message: errorMessage(e) });
      } finally {
        completed++;
        if (total > 10) {
          logger.progress(completed, total, `Querying OSV.dev (${completed}/${total})`);
        }
      }
    };

    await mapWithConcurrency(targets, API_CONCURRENCY, queryPackage);
    return errors;
  }
}

/** Format OSV semver range events into a human-readable string. */
function formatOsvRange(
  events: Array<{ introduced?: string; fixed?: string; last_affected?: string }>,
): string {
  const parts: string[] = [];
  let intro: string | null = null;

  for (const ev of events) {
    if (ev.introduced !== undefined) {
      intro = ev.introduced;
    }
    if (ev.fixed !== undefined && intro) {
      parts.push(`>=${intro} <${ev.fixed}`);
      intro = null;
    }
    if (ev.last_affected !== undefined && intro) {
      parts.push(`>=${intro} <=${ev.last_affected}`);
      intro = null;
    }
  }

  if (intro) parts.push(`>=${intro}`);

  return parts.join(" || ") || "unknown";
}
