import type {
  AllowlistEntry,
  AuditConfig,
  PackageAuditResult,
  PolicyAction,
  PolicyDecision,
  Severity,
  VulnerabilityFinding,
} from "../types";
import { satisfies } from "../utils/semver";
import { mapSeverity } from "../utils/severity";

/**
 * Determines policy action based on severity.
 * Note: mapSeverity is called defensively because severity values may come from
 * external sources (vulnerability databases) and need normalization.
 */
function actionForSeverity(sev: Severity, cfg: AuditConfig["policy"]): PolicyAction {
  const s = mapSeverity(sev);
  if (cfg.block.includes(s)) return "block";
  if (cfg.warn.includes(s)) return "warn";
  return "allow";
}

/**
 * Checks if an allowlist entry has expired.
 * Invalid date formats are treated as expired (fail-closed) for security.
 */
function isExpired(entry: AllowlistEntry): boolean {
  if (!entry.expires) return false;
  const expiryDate = new Date(entry.expires);
  if (isNaN(expiryDate.getTime())) {
    // Invalid date format - treat as expired for safety (fail-closed)
    return true;
  }
  return expiryDate < new Date();
}

function findAllowlistMatch(
  finding: VulnerabilityFinding,
  allowlist: AllowlistEntry[]
): AllowlistEntry | undefined {
  for (const entry of allowlist) {
    if (isExpired(entry)) continue;

    // Match by vulnerability ID (case-insensitive)
    if (entry.id && entry.id.toUpperCase() === finding.id.toUpperCase()) {
      // If entry has version constraint, check it
      if (entry.version && !satisfies(finding.packageVersion, entry.version)) {
        continue; // Version doesn't match, try next entry
      }
      return entry;
    }

    // Match by package name (case-insensitive)
    if (entry.package && entry.package.toLowerCase() === finding.packageName.toLowerCase()) {
      // If entry has version constraint, check it
      if (entry.version && !satisfies(finding.packageVersion, entry.version)) {
        continue; // Version doesn't match, try next entry
      }
      return entry;
    }
  }
  return undefined;
}

export function evaluatePackagePolicies(pkgResult: PackageAuditResult, cfg: AuditConfig): PackageAuditResult {
  const { pkg, findings } = pkgResult;
  const decisions: PolicyDecision[] = [...pkgResult.decisions];
  const now = new Date().toISOString();
  const allowlist = cfg.policy.allowlist ?? [];

  for (const f of findings) {
    const allowMatch = findAllowlistMatch(f, allowlist);
    if (allowMatch) {
      const reason = allowMatch.reason ?? "Allowlisted";
      decisions.push({
        action: "allow",
        reason: `Allowlist: ${reason}`,
        source: "allowlist",
        at: now,
        packageName: pkg.name,
        packageVersion: pkg.version,
        findingId: f.id,
      });
      continue;
    }

    const action = actionForSeverity(f.severity, cfg.policy);
    // Record all decisions including "allow" for complete audit trail
    decisions.push({
      action,
      reason: `Severity policy: ${f.severity}`,
      source: "severity",
      at: now,
      packageName: pkg.name,
      packageVersion: pkg.version,
      findingId: f.id,
    });
  }

  return { ...pkgResult, decisions };
}
