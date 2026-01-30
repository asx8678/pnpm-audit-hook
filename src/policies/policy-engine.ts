import type { AuditConfig, PackageAuditResult, PolicyAction, PolicyDecision, Severity } from "../types";
import { matchAllowlist } from "./allowlist";
import { isBlockedPackage } from "./blocklist";
import { mapSeverity } from "../utils/severity";

const MS_PER_DAY = 24 * 60 * 60 * 1000;

const daysBetween = (a: Date, b: Date): number =>
  Math.floor((b.getTime() - a.getTime()) / MS_PER_DAY);

const actionForSeverity = (sev: Severity, cfg: AuditConfig["policies"]): PolicyAction => {
  const s = mapSeverity(sev);
  if (cfg.block.includes(s)) return "block";
  if (cfg.warn.includes(s)) return "warn";
  return "allow";
};

type DecisionSource = PolicyDecision["source"];

interface DecisionParams {
  action: PolicyAction;
  reason: string;
  source: DecisionSource;
  now: Date;
  packageName: string;
  packageVersion: string;
  findingId?: string;
  allowlist?: PolicyDecision["allowlist"];
}

const makeDecision = ({
  action,
  reason,
  source,
  now,
  packageName,
  packageVersion,
  findingId,
  allowlist,
}: DecisionParams): PolicyDecision => ({
  action,
  reason,
  source,
  at: now.toISOString(),
  packageName,
  packageVersion,
  ...(findingId && { findingId }),
  ...(allowlist && { allowlist }),
});

export interface PackagePolicyContext {
  unknownData?: boolean;
}

export function evaluatePackagePolicies(
  pkgResult: PackageAuditResult,
  cfg: AuditConfig,
  ctx: PackagePolicyContext,
  now: Date = new Date(),
): PackageAuditResult {
  const { pkg, findings } = pkgResult;
  const { name: packageName, version: packageVersion } = pkg;
  const decisions: PolicyDecision[] = [...pkgResult.decisions];

  const addDecision = (
    action: PolicyAction,
    reason: string,
    source: DecisionSource,
    findingId?: string,
    allowlist?: PolicyDecision["allowlist"],
  ) => decisions.push(makeDecision({ action, reason, source, now, packageName, packageVersion, findingId, allowlist }));

  // 1) Blocklist
  if (isBlockedPackage(packageName, cfg.policies.blocklist)) {
    addDecision("block", "Package is blocklisted by organization policy", "blocklist");
    return { ...pkgResult, decisions };
  }

  // 2) Unknown data handling
  if (ctx.unknownData) {
    const policy = cfg.policies.unknownVulnData;
    addDecision(policy, `One or more vulnerability sources were unavailable; policy=unknownVulnData:${policy}`, "unknown");
  }

  // 3) Integrity enforcement
  if (cfg.integrity?.requireSha512Integrity && pkg.integrity && !pkg.integrity.startsWith("sha512-")) {
    const algo = pkg.integrity.split("-")[0] ?? "unknown";
    addDecision("block", `Lockfile integrity is not sha512 (found: ${algo})`, "integrity");
  }

  // 4) Evaluate each vulnerability finding
  for (const f of findings) {
    const allow = matchAllowlist(f, cfg.policies, now);
    if (allow) {
      addDecision("allow", `Allowlisted until ${allow.expires}: ${allow.reason}`, "allowlist", f.id, allow);
      continue;
    }

    let action = actionForSeverity(f.severity, cfg.policies);

    // Grace period: downgrade non-critical blocks to warn if recently published
    if (action === "block" && f.severity !== "critical" && cfg.policies.gracePeriod > 0 && f.publishedAt) {
      const pub = new Date(f.publishedAt);
      if (!Number.isNaN(pub.getTime())) {
        const ageDays = daysBetween(pub, now);
        if (ageDays >= 0 && ageDays <= cfg.policies.gracePeriod) {
          addDecision("warn", `Within grace period (${cfg.policies.gracePeriod}d) for newly published vulnerability (age=${ageDays}d)`, "severity", f.id);
          continue;
        }
      }
    }

    addDecision(action, `Severity policy: ${f.severity}`, "severity", f.id);
  }

  return { ...pkgResult, decisions };
}

export function summarizePackageDecisions(pkg: PackageAuditResult): { blocked: boolean; warned: boolean } {
  return { blocked: pkg.decisions.some((d) => d.action === "block"), warned: pkg.decisions.some((d) => d.action === "warn") };
}

export function summarizeFindings(pkgs: PackageAuditResult[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const p of pkgs) for (const f of p.findings) counts[mapSeverity(f.severity)] += 1;
  return counts;
}
