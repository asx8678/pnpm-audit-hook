import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import type { AuditConfig, AuditReport, AuditSummary, PackageAuditResult, PolicyDecision, RuntimeOptions, VulnerabilityFinding } from "./types";
import { loadConfig, DEFAULT_CONFIG } from "./config";
import { createLogger, envLogLevel } from "./utils/logger";
import { MemoryCache } from "./cache/memory-cache";
import { FileCache } from "./cache/file-cache";
import { LayeredCache } from "./cache/layered-cache";
import { ReadOnlyCache } from "./cache/read-only-cache";
import { aggregateVulnerabilities } from "./databases/aggregator";
import { extractPackagesFromLockfile } from "./utils/lockfile";
import { createAuditHttpClient } from "./utils/http-factory";
import { fetchVersionManifest, extractDistIntegrity } from "./utils/npm-registry";
import { evaluatePackagePolicies, summarizeFindings } from "./policies/policy-engine";
import { processWithConcurrencyVoid } from "./utils/concurrency";
import { toSarif } from "./reporters/sarif";
import { toJUnitXml } from "./reporters/junit";
import { toHtml } from "./reporters/html";
import { toCycloneDxJson, toSpdxJson } from "./reporters/sbom";
import { reportToMarkdown } from "./utils/markdown";
import { writeAuditTrailNdjson } from "./utils/audit-trail";
import { isAzurePipelines, postPullRequestComment, vsoLogIssue, vsoSetVariable, vsoUploadFile, writeAndUploadSummary } from "./integrations/azure-devops";
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
  return (formats ?? [])
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
    .map((f) =>
      f === "cdx" || f === "cyclonedx" ? "sbom-cyclonedx" : f === "spdx" ? "sbom-spdx" : f,
    );
}

function groupFindings(findings: VulnerabilityFinding[]): Record<string, VulnerabilityFinding[]> {
  const out: Record<string, VulnerabilityFinding[]> = {};
  for (const f of findings) (out[`${f.packageName}@${f.packageVersion}`] ??= []).push(f);
  return out;
}

function computeBlockedWarned(pkgs: PackageAuditResult[], failOnWarn: boolean): { blocked: boolean; warnings: boolean } {
  let blocked = false, warnings = false;
  for (const p of pkgs) for (const d of p.decisions) { if (d.action === "block") blocked = true; if (d.action === "warn") warnings = true; }
  if (failOnWarn && warnings) blocked = true;
  return { blocked, warnings };
}

function countFindingsByDecision(pkgs: PackageAuditResult[], action: "block" | "warn"): number {
  const seen = new Set<string>();
  for (const p of pkgs) for (const d of p.decisions) if (d.action === action && d.findingId) seen.add(`${p.pkg.name}@${p.pkg.version}:${d.findingId}`);
  return seen.size;
}

function safeTimingEqual(a: string, b: string): boolean {
  const aBuf = Buffer.from(a), bBuf = Buffer.from(b);
  return aBuf.length === bBuf.length && crypto.timingSafeEqual(aBuf, bBuf);
}

export async function runAudit(input: RunAuditInput): Promise<RunAuditOutput> {
  const { runtime } = input;
  const env = runtime.env;
  const cwd = runtime.cwd;

  const enabled = env.PNPM_AUDIT_ENABLED
    ? parseBoolOrFalse(env.PNPM_AUDIT_ENABLED)
    : true;

  // Early return when disabled - avoid loading config/caches
  if (!enabled) {
    const now = new Date().toISOString();
    return {
      cfg: DEFAULT_CONFIG,
      report: {
        summary: {
          totalPackages: 0,
          directPackages: 0,
          vulnerablePackages: 0,
          countsBySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
          blockedFindings: 0,
          warnedFindings: 0,
          blocked: false,
          warnings: false,
          startedAt: now,
          finishedAt: now,
          sources: {},
        },
        packages: [],
        decisions: [],
      },
      artifacts: [],
    };
  }

  const bypass = parseBoolOrFalse(env.PNPM_AUDIT_BYPASS);

  if (bypass) {
    const token = env.PNPM_AUDIT_BYPASS_TOKEN;
    const expected = env.PNPM_AUDIT_BYPASS_EXPECTED_TOKEN;
    if (!token) throw new Error("PNPM_AUDIT_BYPASS=true requires PNPM_AUDIT_BYPASS_TOKEN");
    if (expected && !safeTimingEqual(token, expected)) throw new Error("PNPM_AUDIT_BYPASS_TOKEN did not match PNPM_AUDIT_BYPASS_EXPECTED_TOKEN");
  }
  const failOnWarn = parseBoolOrFalse(env.PNPM_AUDIT_FAIL_ON_WARN);

  const logger = createLogger(envLogLevel(env));
  const cfg = await loadConfig({ cwd, env });

  const offline = parseBoolOrFalse(env.PNPM_AUDIT_OFFLINE_MODE);
  const networkPolicy = cfg.policies.networkPolicy;

  const mem = new MemoryCache();
  const fileDir = path.resolve(cwd, cfg.cache?.dir ?? ".pnpm-audit-cache");
  const file = new FileCache({ dir: fileDir, allowStale: cfg.cache?.allowStale ?? true });
  const offlineDbPath = env.PNPM_AUDIT_OFFLINE_DB_PATH;
  const cache = new LayeredCache(offlineDbPath ? [mem, file, new ReadOnlyCache(new FileCache({ dir: offlineDbPath, allowStale: true }))] : [mem, file]);

  const startedAt = new Date();

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
  const failClosed = cfg.policies.networkPolicy === "fail-closed";
  const http = createAuditHttpClient(cfg, logger);

  const ttl = cfg.cache?.ttlSeconds ?? 3600;

  const findingsByPkg = groupFindings(agg.findings);

  const pkgResults: PackageAuditResult[] = packages.map((p) => ({
    pkg: p,
    findings: findingsByPkg[`${p.name}@${p.version}`] ?? [],
    decisions: [],
  }));

  if (failClosed && failedSources.length) {
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

  await processWithConcurrencyVoid(pkgResults, concurrency, async (p) => {
    const manifest = await fetchVersionManifest(p.pkg.name, p.pkg.version, runtime.registryUrl, http, cache, ttl, offline);
    const distIntegrity = extractDistIntegrity(manifest);
    if (p.pkg.integrity && distIntegrity && p.pkg.integrity !== distIntegrity) {
      p.decisions.push({ action: "block", reason: `Lockfile integrity mismatch vs registry metadata`, source: "integrity", at: new Date().toISOString(), packageName: p.pkg.name, packageVersion: p.pkg.version, findingId: "INTEGRITY_MISMATCH" });
    }
    if (cfg.integrity?.requireSha512Integrity && p.pkg.integrity && !isSha512Integrity(p.pkg.integrity)) {
      p.decisions.push({ action: "block", reason: `Non-sha512 lockfile integrity is not permitted by policy`, source: "integrity", at: new Date().toISOString(), packageName: p.pkg.name, packageVersion: p.pkg.version, findingId: "INTEGRITY_NOT_SHA512" });
    }
  });

  const evaluatedPkgs = pkgResults.map((p) => evaluatePackagePolicies(p, cfg, { unknownData: agg.unknownPackages.has(`${p.pkg.name}@${p.pkg.version}`) }, new Date()));
  const decisions = evaluatedPkgs.flatMap((p) => p.decisions);
  const finishedAt = new Date();
  const counts = summarizeFindings(evaluatedPkgs);

  let { blocked, warnings } = computeBlockedWarned(evaluatedPkgs, failOnWarn);

  if (bypass) {
    blocked = false;
    decisions.push({
      action: "allow",
      reason: `EMERGENCY BYPASS: ${env.PNPM_AUDIT_BYPASS_REASON || "unspecified"}`,
      source: "policy",
      at: new Date().toISOString(),
    });
  }

  const summary: AuditSummary = {
    totalPackages: packages.length,
    directPackages: packages.filter((p) => p.direct).length,
    vulnerablePackages: evaluatedPkgs.filter((p) => p.findings.length)
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

  const writeArtifact = async (suffix: string, content: string | object): Promise<void> => {
    const filePath = path.join(outputDir, `${basename}${suffix}`);
    const data = typeof content === "string" ? content : JSON.stringify(content, null, 2);
    await fs.writeFile(filePath, data, "utf-8");
    artifacts.push(filePath);
  };

  if (!formats.includes("json")) formats.push("json");

  const formatHandlers: Record<string, () => [string, string | object]> = {
    json: () => [".json", report],
    html: () => [".html", toHtml(report)],
    sarif: () => [".sarif.json", toSarif(report, { lockfilePath: "pnpm-lock.yaml" })],
    junit: () => [".junit.xml", toJUnitXml(report, { failOnWarn })],
    markdown: () => [".md", reportToMarkdown(report)],
    md: () => [".md", reportToMarkdown(report)],
    "sbom-cyclonedx": () => [
      ".sbom.cdx.json",
      toCycloneDxJson(packages, { format: "cyclonedx", dependencies, toolVersion: "1.0.0" }),
    ],
    "sbom-spdx": () => [
      ".sbom.spdx.json",
      toSpdxJson(packages, { format: "spdx", dependencies, toolVersion: "1.0.0" }),
    ],
  };

  for (const f of formats) {
    const handler = formatHandlers[f];
    if (!handler) continue;
    const [suffix, content] = handler();
    await writeArtifact(suffix, content);
  }

  try {
    artifacts.push(await writeAuditTrailNdjson(report, outputDir));
  } catch (e) {
    logger.warn("Failed to write audit trail", { error: e instanceof Error ? e.message : String(e) });
  }

  if (isAzurePipelines(env)) {
    vsoSetVariable("PNPM_AUDIT_BLOCKED", String(blocked));
    vsoSetVariable("PNPM_AUDIT_WARNINGS", String(warnings));
    vsoSetVariable("PNPM_AUDIT_TOTAL_FINDINGS", String(summary.blockedFindings + summary.warnedFindings));

    if (blocked) vsoLogIssue("error", `pnpm audit blocked: ${summary.blockedFindings} blocking findings`);
    else if (warnings) vsoLogIssue("warning", `pnpm audit warnings: ${summary.warnedFindings} findings`);

    for (const a of artifacts) vsoUploadFile(a);

    await writeAndUploadSummary(outputDir, basename, reportToMarkdown(report, { maxItems: 25 }));

    if (cfg.azureDevOps?.prComment?.enabled || parseBoolOrFalse(env.PNPM_AUDIT_PR_COMMENT)) {
      await postPullRequestComment(reportToMarkdown(report, { maxItems: 15 }), env, logger, { bestEffort: true });
    }
  } else {
    if (blocked) logger.error(`Blocked: ${summary.blockedFindings} blocking findings (see ${basename}.html)`);
    else if (warnings) logger.warn(`Warnings: ${summary.warnedFindings} findings (see ${basename}.html)`);
    else logger.info(`No findings (see ${basename}.html)`);
  }

  return { cfg, report, artifacts };
}

export function shouldBlockInstall(
  report: AuditReport,
  env: Record<string, string | undefined>,
): boolean {
  return report.summary.blocked || (parseBoolOrFalse(env.PNPM_AUDIT_FAIL_ON_WARN) && report.summary.warnings);
}
