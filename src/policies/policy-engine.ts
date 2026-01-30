import type {
  AuditConfig,
  PackageAuditResult,
  PolicyAction,
  PolicyDecision,
  Severity,
} from "../types";
import { matchAllowlist } from "./allowlist";
import { isBlockedPackage } from "./blocklist";
import { mapSeverity } from "../utils/severity";

function nowIso(now: Date): string {
  return now.toISOString();
}

function daysBetween(a: Date, b: Date): number {
  return Math.floor((b.getTime() - a.getTime()) / (24 * 60 * 60 * 1000));
}

function actionForSeverity(
  sev: Severity,
  cfg: AuditConfig["policies"],
): PolicyAction {
  const s = mapSeverity(sev);
  if (cfg.block.includes(s)) return "block";
  if (cfg.warn.includes(s)) return "warn";
  // If not mentioned, default allow.
  return "allow";
}

export interface PackagePolicyContext {
  unknownData?: boolean;
}

export function evaluatePackagePolicies(
  pkgResult: PackageAuditResult,
  cfg: AuditConfig,
  ctx: PackagePolicyContext,
  now: Date = new Date(),
): PackageAuditResult {
  const decisions: PolicyDecision[] = [...pkgResult.decisions];

  // 1) Blocklist
  if (isBlockedPackage(pkgResult.pkg.name, cfg.policies.blocklist)) {
    decisions.push({
      action: "block",
      reason: `Package is blocklisted by organization policy`,
      source: "blocklist",
      at: nowIso(now),
      packageName: pkgResult.pkg.name,
      packageVersion: pkgResult.pkg.version,
    });
    return { ...pkgResult, decisions };
  }

  // 2) Unknown data handling
  if (ctx.unknownData) {
    const policy = cfg.policies.unknownVulnData;
    const action: PolicyAction =
      policy === "block" ? "block" : policy === "warn" ? "warn" : "allow";
    decisions.push({
      action,
      reason: `One or more vulnerability sources were unavailable; policy=unknownVulnData:${policy}`,
      source: "unknown",
      at: nowIso(now),
      packageName: pkgResult.pkg.name,
      packageVersion: pkgResult.pkg.version,
    });
  }

  // 3) Integrity enforcement (best-effort).
  if (cfg.integrity?.requireSha512Integrity && pkgResult.pkg.integrity) {
    if (!pkgResult.pkg.integrity.startsWith("sha512-")) {
      decisions.push({
        action: "block",
        reason: `Lockfile integrity is not sha512 (found: ${pkgResult.pkg.integrity.split("-")[0] ?? "unknown"})`,
        source: "integrity",
        at: nowIso(now),
        packageName: pkgResult.pkg.name,
        packageVersion: pkgResult.pkg.version,
      });
    }
  }

  // 4) Evaluate each vulnerability finding
  for (const f of pkgResult.findings) {
    const allow = matchAllowlist(f, cfg.policies, now);
    if (allow) {
      decisions.push({
        action: "allow",
        reason: `Allowlisted until ${allow.expires}: ${allow.reason}`,
        source: "allowlist",
        at: nowIso(now),
        findingId: f.id,
        packageName: f.packageName,
        packageVersion: f.packageVersion,
        allowlist: allow,
      });
      continue;
    }

    let action = actionForSeverity(f.severity, cfg.policies);

    // Grace period: downgrade non-critical blocks to warn if recently published.
    if (
      action === "block" &&
      f.severity !== "critical" &&
      cfg.policies.gracePeriod > 0 &&
      f.publishedAt
    ) {
      const pub = new Date(f.publishedAt);
      if (!Number.isNaN(pub.getTime())) {
        const ageDays = daysBetween(pub, now);
        if (ageDays >= 0 && ageDays <= cfg.policies.gracePeriod) {
          action = "warn";
          decisions.push({
            action,
            reason: `Within grace period (${cfg.policies.gracePeriod}d) for newly published vulnerability (age=${ageDays}d)`,
            source: "severity",
            at: nowIso(now),
            findingId: f.id,
            packageName: f.packageName,
            packageVersion: f.packageVersion,
          });
          continue;
        }
      }
    }

    decisions.push({
      action,
      reason: `Severity policy: ${f.severity}`,
      source: "severity",
      at: nowIso(now),
      findingId: f.id,
      packageName: f.packageName,
      packageVersion: f.packageVersion,
    });
  }

  return { ...pkgResult, decisions };
}

export function summarizePackageDecisions(pkg: PackageAuditResult): {
  blocked: boolean;
  warned: boolean;
} {
  let blocked = false;
  let warned = false;
  for (const d of pkg.decisions) {
    if (d.action === "block") blocked = true;
    if (d.action === "warn") warned = true;
  }
  return { blocked, warned };
}

export function summarizeFindings(
  pkgs: PackageAuditResult[],
): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
  };
  for (const p of pkgs) {
    for (const f of p.findings) {
      const sev = mapSeverity(f.severity);
      counts[sev] += 1;
    }
  }
  return counts;
}
