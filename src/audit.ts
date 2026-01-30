import path from "node:path";
import type { PackageAuditResult, PolicyDecision, RuntimeOptions, VulnerabilityFinding } from "./types";
import { loadConfig } from "./config";
import { logger } from "./utils/logger";
import { FileCache } from "./cache/file-cache";
import { aggregateVulnerabilities } from "./databases/aggregator";
import { extractPackagesFromLockfile } from "./utils/lockfile";
import { evaluatePackagePolicies } from "./policies/policy-engine";

const CACHE_DIR = ".pnpm-audit-cache";

export interface AuditResult {
  blocked: boolean;
  warnings: boolean;
  decisions: PolicyDecision[];
}

export async function runAudit(lockfile: Record<string, unknown>, runtime: RuntimeOptions): Promise<AuditResult> {
  const { cwd, env, registryUrl } = runtime;
  const cfg = await loadConfig({ cwd, env });
  const cache = new FileCache({ dir: path.resolve(cwd, CACHE_DIR) });

  const { packages } = extractPackagesFromLockfile(lockfile);
  const agg = await aggregateVulnerabilities(packages, { cfg, env, cache, registryUrl });

  // Group findings by package
  const findingsByPkg = new Map<string, VulnerabilityFinding[]>();
  for (const f of agg.findings) {
    const key = `${f.packageName}@${f.packageVersion}`;
    (findingsByPkg.get(key) ?? findingsByPkg.set(key, []).get(key)!).push(f);
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

  // Block on source failures
  const failedSources = Object.entries(agg.sources).filter(([, v]) => !v.ok);
  if (failedSources.length) {
    const srcList = failedSources.map(([k, v]) => `${k}: ${v.error ?? "unknown"}`).join("; ");
    decisions.push({ action: "block", reason: `Source failure: ${srcList}`, source: "source", at: new Date().toISOString() });
  }

  const blocked = decisions.some((d) => d.action === "block");
  const warnings = decisions.some((d) => d.action === "warn");

  if (blocked) logger.error("Audit blocked installation");
  else if (warnings) logger.warn("Audit has warnings");

  return { blocked, warnings, decisions };
}
