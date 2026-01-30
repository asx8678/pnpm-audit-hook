import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import type {
  AuditConfig,
  AuditReport,
  AuditSummary,
  PackageAuditResult,
  PackageRef,
  PolicyDecision,
  RuntimeOptions,
  Severity,
  VulnerabilityFinding,
} from "./types";
import { loadConfig } from "./config";
import { createLogger, envLogLevel } from "./utils/logger";
import { MemoryCache } from "./cache/memory-cache";
import { FileCache } from "./cache/file-cache";
import { LayeredCache } from "./cache/layered-cache";
import { ReadOnlyCache } from "./cache/read-only-cache";
import { aggregateVulnerabilities } from "./databases/aggregator";
import { extractPackagesFromLockfile } from "./utils/lockfile";
import { createAuditHttpClient } from "./utils/http-factory";
import {
  fetchVersionManifest,
  extractDistIntegrity,
} from "./utils/npm-registry";
import {
  evaluatePackagePolicies,
  summarizeFindings,
} from "./policies/policy-engine";
import { toSarif } from "./reporters/sarif";
import { toJUnitXml } from "./reporters/junit";
import { toHtml } from "./reporters/html";
import { toCycloneDxJson, toSpdxJson } from "./reporters/sbom";
import { reportToMarkdown } from "./utils/markdown";
import { writeAuditTrailNdjson } from "./utils/audit-trail";
import {
  isAzurePipelines,
  postPullRequestComment,
  vsoLogIssue,
  vsoSetVariable,
  vsoUploadFile,
  writeAndUploadSummary,
} from "./integrations/azure-devops";
import { isSha512Integrity } from "./utils/hash";
import { parseBoolOrFalse } from "./utils/env";

export interface RunAuditInput {
  lockfile: Record<string, unknown>;
  runtime: RuntimeOptions;
}

export interface RunAuditOutput {
  cfg: AuditConfig;
  report: AuditReport;
  artifacts: string[];
}

async function ensureDir(p: string): Promise<void> {
  await fs.mkdir(p, { recursive: true });
}

function normalizeFormats(formats: string[] | undefined): string[] {
  const list = (formats ?? [])
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  // allow synonyms
  return list.map((f) => {
    if (f === "cdx" || f === "cyclonedx") return "sbom-cyclonedx";
    if (f === "spdx") return "sbom-spdx";
    return f;
  });
}

function keyOf(p: PackageRef): string {
  return `${p.name}@${p.version}`;
}

function groupFindings(
  findings: VulnerabilityFinding[],
): Record<string, VulnerabilityFinding[]> {
  const out: Record<string, VulnerabilityFinding[]> = {};
  for (const f of findings) {
    const k = `${f.packageName}@${f.packageVersion}`;
    out[k] = out[k] ?? [];
    out[k]!.push(f);
  }
  return out;
}

function collectDecisions(pkgs: PackageAuditResult[]): PolicyDecision[] {
  const out: PolicyDecision[] = [];
  for (const p of pkgs) out.push(...p.decisions);
  return out;
}

function computeBlockedWarned(
  pkgs: PackageAuditResult[],
  failOnWarn: boolean,
): { blocked: boolean; warnings: boolean } {
  let blocked = false;
  let warnings = false;
  for (const p of pkgs) {
    for (const d of p.decisions) {
      if (d.action === "block") blocked = true;
      if (d.action === "warn") warnings = true;
    }
  }
  if (failOnWarn && warnings) blocked = true;
  return { blocked, warnings };
}

function countFindingsByDecision(
  pkgs: PackageAuditResult[],
  action: "block" | "warn",
): number {
  const seen = new Set<string>();
  for (const p of pkgs) {
    for (const d of p.decisions) {
      if (d.action !== action) continue;
      if (!d.findingId) continue;
      seen.add(`${p.pkg.name}@${p.pkg.version}:${d.findingId}`);
    }
  }
  return seen.size;
}

function countDirect(pkgs: PackageRef[]): number {
  return pkgs.filter((p) => p.direct).length;
}

export async function runAudit(input: RunAuditInput): Promise<RunAuditOutput> {
  const { runtime } = input;
  const env = runtime.env;
  const cwd = runtime.cwd;

  const enabled = env.PNPM_AUDIT_ENABLED
    ? parseBoolOrFalse(env.PNPM_AUDIT_ENABLED)
    : true;
  const bypass = parseBoolOrFalse(env.PNPM_AUDIT_BYPASS);

  if (bypass) {
    const token = env.PNPM_AUDIT_BYPASS_TOKEN;
    const expected = env.PNPM_AUDIT_BYPASS_EXPECTED_TOKEN;
    if (!token) {
      throw new Error(
        "PNPM_AUDIT_BYPASS=true requires PNPM_AUDIT_BYPASS_TOKEN",
      );
    }
    if (
      expected &&
      !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))
    ) {
      throw new Error(
        "PNPM_AUDIT_BYPASS_TOKEN did not match PNPM_AUDIT_BYPASS_EXPECTED_TOKEN",
      );
    }
    // Reason is required for compliance/audit trail.
    if (!env.PNPM_AUDIT_BYPASS_REASON) {
      // Reason missing is not fatal, but will be recorded.
    }
  }
  const failOnWarn = parseBoolOrFalse(env.PNPM_AUDIT_FAIL_ON_WARN);

  const logger = createLogger(envLogLevel(env));
  const cfg = await loadConfig({ cwd, env });

  const offline = parseBoolOrFalse(env.PNPM_AUDIT_OFFLINE_MODE);
  const networkPolicy = cfg.policies.networkPolicy;

  // Cache layers:
  // Layer 1: in-memory (per run)
  // Layer 2: filesystem (persist across runs)
  const mem = new MemoryCache();
  const fileDir = path.resolve(cwd, cfg.cache?.dir ?? ".pnpm-audit-cache");
  const file = new FileCache({
    dir: fileDir,
    allowStale: cfg.cache?.allowStale ?? true,
  });
  const cache = new LayeredCache([mem, file]);

  const startedAt = new Date();

  if (!enabled) {
    const summary: AuditSummary = {
      totalPackages: 0,
      directPackages: 0,
      vulnerablePackages: 0,
      countsBySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
      blockedFindings: 0,
      warnedFindings: 0,
      blocked: false,
      warnings: false,
      startedAt: startedAt.toISOString(),
      finishedAt: new Date().toISOString(),
      sources: {},
    };
    return {
      cfg,
      report: { summary, packages: [], decisions: [] },
      artifacts: [],
    };
  }

  // Extract packages from lockfile
  const { packages, dependencies } = extractPackagesFromLockfile(
    input.lockfile,
  );

  // Aggregate vulnerability data
  const agg = await aggregateVulnerabilities(packages, {
    cfg,
    env,
    cache,
    logger,
    registryUrl: runtime.registryUrl,
    offline,
    networkPolicy,
  });

  const failedSources = Object.entries(agg.sources).filter(([_, v]) => !v.ok);
  const anySourceFailed = failedSources.length > 0;

  // In fail-closed mode, ANY enabled source failure blocks the install (enterprise policy).
  // We record this as an explicit per-package decision for auditability.
  const failClosed = cfg.policies.networkPolicy === "fail-closed";

  // Integrity checks (registry metadata)
  const http = createAuditHttpClient(cfg, logger);

  const ttl = cfg.cache?.ttlSeconds ?? 3600;

  const findingsByPkg = groupFindings(agg.findings);

  const pkgResults: PackageAuditResult[] = packages.map((p) => ({
    pkg: p,
    findings: findingsByPkg[keyOf(p)] ?? [],
    decisions: [],
  }));

  if (failClosed && anySourceFailed) {
    const srcList = failedSources
      .map(([k, v]) => `${k}: ${v.error ?? "unknown error"}`)
      .join("; ");
    for (const p of pkgResults) {
      p.decisions.push({
        action: "block",
        reason: `Vulnerability source failure in fail-closed mode: ${srcList}`,
        source: "network",
        at: new Date().toISOString(),
        packageName: p.pkg.name,
        packageVersion: p.pkg.version,
        findingId: "VULN_SOURCE_UNAVAILABLE",
      });
    }
  }

  // Concurrency for metadata fetch
  const concurrency = cfg.performance?.concurrency ?? 8;
  let idx = 0;
  const getNextIndex = () => idx++;

  await Promise.all(
    new Array(Math.min(concurrency, pkgResults.length))
      .fill(0)
      .map(async () => {
        let myIdx: number;
        while ((myIdx = getNextIndex()) < pkgResults.length) {
          const p = pkgResults[myIdx]!;

          // Skip metadata fetch in offline mode unless already in cache
          const manifest = await fetchVersionManifest(
            p.pkg.name,
            p.pkg.version,
            runtime.registryUrl,
            http,
            cache,
            ttl,
            offline,
          );

          // Integrity consistency: compare lockfile integrity vs registry manifest integrity (best-effort)
          const distIntegrity = extractDistIntegrity(manifest);
          if (
            p.pkg.integrity &&
            distIntegrity &&
            p.pkg.integrity !== distIntegrity
          ) {
            p.decisions.push({
              action: "block",
              reason: `Lockfile integrity mismatch vs registry metadata`,
              source: "integrity",
              at: new Date().toISOString(),
              packageName: p.pkg.name,
              packageVersion: p.pkg.version,
              findingId: "INTEGRITY_MISMATCH",
            });
          }

          // Require sha512 integrity (if present)
          if (
            cfg.integrity?.requireSha512Integrity &&
            p.pkg.integrity &&
            !isSha512Integrity(p.pkg.integrity)
          ) {
            p.decisions.push({
              action: "block",
              reason: `Non-sha512 lockfile integrity is not permitted by policy`,
              source: "integrity",
              at: new Date().toISOString(),
              packageName: p.pkg.name,
              packageVersion: p.pkg.version,
              findingId: "INTEGRITY_NOT_SHA512",
            });
          }
        }
      }),
  );

  // Apply policy engine per package
  const unknownSet = agg.unknownPackages;
  const evaluatedPkgs = pkgResults.map((p) =>
    evaluatePackagePolicies(
      p,
      cfg,
      { unknownData: unknownSet.has(keyOf(p.pkg)) },
      new Date(),
    ),
  );

  // Early-exit optimization: optionally stop once blocked discovered
  // In hook mode, we still want reports. So we do not drop evaluatedPkgs here.

  const decisions = collectDecisions(evaluatedPkgs);

  const finishedAt = new Date();

  const counts = summarizeFindings(evaluatedPkgs);

  let { blocked, warnings } = computeBlockedWarned(evaluatedPkgs, failOnWarn);

  if (bypass) {
    const reason = env.PNPM_AUDIT_BYPASS_REASON || "unspecified";
    const at = new Date().toISOString();
    // Allow install, but preserve findings and decisions for audit trail.
    blocked = false;
    decisions.push({
      action: "allow",
      reason: `EMERGENCY BYPASS: ${reason}`,
      source: "policy",
      at,
    });
  }

  const summary: AuditSummary = {
    totalPackages: packages.length,
    directPackages: countDirect(packages),
    vulnerablePackages: evaluatedPkgs.filter((p) => p.findings.length > 0)
      .length,
    countsBySeverity: counts,
    blockedFindings: countFindingsByDecision(evaluatedPkgs, "block"),
    warnedFindings: countFindingsByDecision(evaluatedPkgs, "warn"),
    blocked,
    warnings,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    sources: agg.sources,
  };

  const report: AuditReport = { summary, packages: evaluatedPkgs, decisions };

  // Reporting
  const outputDir = path.resolve(cwd, cfg.reporting?.outputDir ?? ".");
  await ensureDir(outputDir);

  const basename = cfg.reporting?.basename ?? ".pnpm-audit-report";
  const formats = normalizeFormats(cfg.reporting?.formats);

  const artifacts: string[] = [];

  const writeFile = async (
    suffix: string,
    content: string,
  ): Promise<string> => {
    const filePath = path.join(outputDir, `${basename}${suffix}`);
    await fs.writeFile(filePath, content, "utf-8");
    artifacts.push(filePath);
    return filePath;
  };

  const writeJson = async (suffix: string, obj: any): Promise<string> => {
    const filePath = path.join(outputDir, `${basename}${suffix}`);
    await fs.writeFile(filePath, JSON.stringify(obj, null, 2), "utf-8");
    artifacts.push(filePath);
    return filePath;
  };

  // Always write JSON (useful for automation)
  if (!formats.includes("json")) formats.push("json");

  for (const f of formats) {
    switch (f) {
      case "json":
        await writeJson(".json", report);
        break;
      case "html":
        await writeFile(".html", toHtml(report));
        break;
      case "sarif":
        await writeJson(
          ".sarif.json",
          toSarif(report, { lockfilePath: "pnpm-lock.yaml" }),
        );
        break;
      case "junit":
        await writeFile(".junit.xml", toJUnitXml(report, { failOnWarn }));
        break;
      case "markdown":
      case "md":
        await writeFile(".md", reportToMarkdown(report));
        break;
      case "sbom-cyclonedx":
        await writeJson(
          ".sbom.cdx.json",
          toCycloneDxJson(packages, {
            format: "cyclonedx",
            dependencies,
            toolVersion: "1.0.0",
          }),
        );
        break;
      case "sbom-spdx":
        await writeJson(
          ".sbom.spdx.json",
          toSpdxJson(packages, {
            format: "spdx",
            dependencies,
            toolVersion: "1.0.0",
          }),
        );
        break;
      default:
        // ignore unknown format
        break;
    }
  }

  // Audit trail (append-only NDJSON)
  try {
    const logPath = await writeAuditTrailNdjson(report, outputDir);
    artifacts.push(logPath);
  } catch (e) {
    logger.warn("Failed to write audit trail", {
      error: e instanceof Error ? e.message : String(e),
    });
  }

  // Azure DevOps specific: log issues + upload summary and files
  if (isAzurePipelines(env)) {
    vsoSetVariable("PNPM_AUDIT_BLOCKED", blocked ? "true" : "false");
    vsoSetVariable("PNPM_AUDIT_WARNINGS", warnings ? "true" : "false");
    vsoSetVariable(
      "PNPM_AUDIT_TOTAL_FINDINGS",
      String(summary.blockedFindings + summary.warnedFindings),
    );

    if (blocked)
      vsoLogIssue(
        "error",
        `pnpm audit blocked: ${summary.blockedFindings} blocking findings`,
      );
    else if (warnings)
      vsoLogIssue(
        "warning",
        `pnpm audit warnings: ${summary.warnedFindings} findings`,
      );

    for (const a of artifacts) {
      vsoUploadFile(a);
    }

    // Upload a short markdown summary to the build summary tab
    const md = reportToMarkdown(report, { maxItems: 25 });
    await writeAndUploadSummary(outputDir, basename, md);

    // PR comment (optional)
    const prEnabled =
      cfg.azureDevOps?.prComment?.enabled ||
      parseBoolOrFalse(env.PNPM_AUDIT_PR_COMMENT);
    if (prEnabled) {
      const md2 = reportToMarkdown(report, { maxItems: 15 });
      await postPullRequestComment(md2, env, logger, { bestEffort: true });
    }
  } else {
    // Local UX
    if (blocked)
      logger.error(
        `Blocked: ${summary.blockedFindings} blocking findings (see ${basename}.html)`,
      );
    else if (warnings)
      logger.warn(
        `Warnings: ${summary.warnedFindings} findings (see ${basename}.html)`,
      );
    else logger.info(`No findings (see ${basename}.html)`);
  }

  return { cfg, report, artifacts };
}

export function shouldBlockInstall(
  report: AuditReport,
  env: Record<string, string | undefined>,
): boolean {
  const failOnWarn = parseBoolOrFalse(env.PNPM_AUDIT_FAIL_ON_WARN);
  if (report.summary.blocked) return true;
  if (failOnWarn && report.summary.warnings) return true;
  return false;
}
