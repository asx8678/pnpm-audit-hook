import path from "node:path";
import type { PackageAuditResult, PnpmLockfile, PolicyDecision, RuntimeOptions, SourceStatus, VulnerabilityFinding } from "./types";
import { loadConfig } from "./config";
import { isVerbose, logger } from "./utils/logger";
import { FileCache } from "./cache/file-cache";
import { aggregateVulnerabilities } from "./databases/aggregator";
import { extractPackagesFromLockfile } from "./utils/lockfile";
import { evaluatePackagePolicies } from "./policies/policy-engine";
import { buildSummary, outputResults } from "./utils/output-formatter";

const CACHE_DIR = ".pnpm-audit-cache";

/** Exit codes for audit results */
export const EXIT_CODES = {
  SUCCESS: 0,
  BLOCKED: 1,
  WARNINGS: 2,
  SOURCE_ERROR: 3,
} as const;

export interface AuditResult {
  blocked: boolean;
  warnings: boolean;
  decisions: PolicyDecision[];
  exitCode: number;
  findings: VulnerabilityFinding[];
  sourceStatus: Record<string, SourceStatus>;
  totalPackages: number;
  durationMs: number;
}

export async function runAudit(lockfile: PnpmLockfile, runtime: RuntimeOptions): Promise<AuditResult> {
  const startTime = Date.now();
  const { cwd, env, registryUrl } = runtime;
  const cfg = await loadConfig({ cwd, env });
  const cache = new FileCache({ dir: path.resolve(cwd, CACHE_DIR) });

  const { packages } = extractPackagesFromLockfile(lockfile);

  if (isVerbose()) {
    logger.verbose(`Starting audit of ${packages.length} packages`);
  }

  const agg = await aggregateVulnerabilities(packages, { cfg, env, cache, registryUrl });

  // Group findings by package
  const findingsByPkg = new Map<string, VulnerabilityFinding[]>();
  for (const finding of agg.findings) {
    const key = `${finding.packageName}@${finding.packageVersion}`;
    if (!findingsByPkg.has(key)) {
      findingsByPkg.set(key, []);
    }
    findingsByPkg.get(key)!.push(finding);
  }

  // Build package results and evaluate policies
  const decisions: PolicyDecision[] = [];
  for (const p of packages) {
    const pkgResult: PackageAuditResult = {
      pkg: p,
      findings: findingsByPkg.get(`${p.name}@${p.version}`) ?? [],
      decisions: [],
    };
    const evaluated = evaluatePackagePolicies(pkgResult, cfg);
    decisions.push(...evaluated.decisions);
  }

  // Block on source failures if configured to fail-closed
  const failedSources = Object.entries(agg.sources).filter(([, v]) => !v.ok);
  const hasSourceError = failedSources.length > 0;
  if (hasSourceError) {
    const srcList = failedSources.map(([k, v]) => `${k}: ${v.error ?? "unknown"}`).join("; ");
    const action = cfg.failOnSourceError !== false ? "block" : "warn";
    decisions.push({
      action,
      reason: `Source failure: ${srcList}`,
      source: "source",
      at: new Date().toISOString(),
    });
  }

  const blocked = decisions.some((d) => d.action === "block");
  const warnings = decisions.some((d) => d.action === "warn");
  const durationMs = Date.now() - startTime;

  // Determine exit code
  let exitCode: number;
  if (hasSourceError && cfg.failOnSourceError !== false) {
    exitCode = EXIT_CODES.SOURCE_ERROR;
  } else if (blocked) {
    exitCode = EXIT_CODES.BLOCKED;
  } else if (warnings) {
    exitCode = EXIT_CODES.WARNINGS;
  } else {
    exitCode = EXIT_CODES.SUCCESS;
  }

  // Build summary and output results
  const summary = buildSummary(packages.length, agg.findings, decisions, agg.sources);
  outputResults(
    {
      summary,
      findings: agg.findings,
      decisions,
      blocked,
      warnings,
      exitCode,
    },
    env,
  );

  return {
    blocked,
    warnings,
    decisions,
    exitCode,
    findings: agg.findings,
    sourceStatus: agg.sources,
    totalPackages: packages.length,
    durationMs,
  };
}
