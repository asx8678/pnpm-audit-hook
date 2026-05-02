import type {
  AllowlistEntry,
  AuditConfig,
  DependencyGraph,
  PackageAuditResult,
  PolicyAction,
  PolicyDecision,
  Severity,
  VulnerabilityFinding,
} from "../types";
import { satisfiesStrict } from "../utils/semver";
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

const DATE_ONLY_RE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Checks if an allowlist entry has expired.
 * Invalid date formats are treated as expired (fail-closed) for security.
 */
function isExpired(entry: AllowlistEntry): boolean {
  if (!entry.expires) return false;
  // If expires is a date-only string (YYYY-MM-DD), treat as end-of-day UTC
  // to avoid timezone-dependent early expiration
  if (DATE_ONLY_RE.test(entry.expires)) {
    const endOfDay = new Date(entry.expires + "T23:59:59.999Z");
    return endOfDay.getTime() < Date.now();
  }
  const expiryDate = new Date(entry.expires);
  if (isNaN(expiryDate.getTime())) {
    // Invalid date format - treat as expired for safety (fail-closed)
    return true;
  }
  return expiryDate.getTime() < Date.now();
}

function findAllowlistMatch(
  finding: VulnerabilityFinding,
  allowlist: AllowlistEntry[],
  graph?: DependencyGraph,
): AllowlistEntry | undefined {
  for (const entry of allowlist) {
    if (isExpired(entry)) continue;

    // directOnly entries only match when the graph confirms the package is direct
    if (entry.directOnly) {
      if (!graph) continue; // conservative: no graph means no match
      const keys = graph.byName.get(finding.packageName) ?? [];
      const isDirect = keys.some(k => graph.directKeys.has(k));
      if (!isDirect) continue;
    }

    // Match entry.id against finding.id AND finding.identifiers[]
    const idMatches = entry.id !== undefined && (
      entry.id.toUpperCase() === finding.id.toUpperCase() ||
      (finding.identifiers ?? []).some(
        ident => ident.value.toUpperCase() === entry.id!.toUpperCase()
      )
    );

    const packageMatches =
      entry.package !== undefined &&
      entry.package.toLowerCase() === finding.packageName.toLowerCase();

    // If both id and package are provided, require both to match
    if (entry.id && entry.package) {
      if (!idMatches || !packageMatches) continue;
      if (entry.version && !satisfiesStrict(finding.packageVersion, entry.version)) {
        continue;
      }
      return entry;
    }

    // Match by vulnerability ID (case-insensitive, checks identifiers too)
    if (entry.id && idMatches) {
      // If entry has version constraint, check it
      if (entry.version && !satisfiesStrict(finding.packageVersion, entry.version)) {
        continue; // Version doesn't match, try next entry
      }
      return entry;
    }

    // Match by package name (case-insensitive)
    if (entry.package && packageMatches) {
      // If entry has version constraint, check it
      if (entry.version && !satisfiesStrict(finding.packageVersion, entry.version)) {
        continue; // Version doesn't match, try next entry
      }
      return entry;
    }
  }
  return undefined;
}

/**
 * Downgrade a severity by one level for transitive dependency policy evaluation.
 * critical → high, high → medium, medium → low, low → low, unknown → unknown
 */
function downgradeSeverity(sev: Severity): Severity {
  switch (sev) {
    case "critical": return "high";
    case "high": return "medium";
    case "medium": return "low";
    case "low": return "low";
    case "unknown": return "unknown";
  }
}

export function evaluatePackagePolicies(
  pkgResult: PackageAuditResult,
  cfg: AuditConfig,
  graph?: DependencyGraph,
): PolicyDecision[] {
  const { pkg, findings } = pkgResult;
  const decisions: PolicyDecision[] = [];
  const now = new Date().toISOString();
  const allowlist = cfg.policy.allowlist ?? [];

  // Determine if this package is transitive (when graph is available)
  const pkgKeys = graph?.byName.get(pkg.name) ?? [];
  const isTransitive = graph ? !pkgKeys.some(k => graph.directKeys.has(k)) : false;

  for (const f of findings) {
    const allowMatch = findAllowlistMatch(f, allowlist, graph);
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
        findingSeverity: f.severity,
      });
      continue;
    }

    // Apply transitive severity downgrade when configured
    const effectiveSeverity =
      isTransitive && cfg.policy.transitiveSeverityOverride === 'downgrade-by-one'
        ? downgradeSeverity(f.severity)
        : f.severity;

    const action = actionForSeverity(effectiveSeverity, cfg.policy);
    // Record all decisions including "allow" for complete audit trail
    decisions.push({
      action,
      reason: effectiveSeverity !== f.severity
        ? `Severity policy: ${f.severity} (downgraded to ${effectiveSeverity} for transitive dep)`
        : `Severity policy: ${f.severity}`,
      source: "severity",
      at: now,
      packageName: pkg.name,
      packageVersion: pkg.version,
      findingId: f.id,
      findingSeverity: f.severity,
    });
  }

  return decisions;
}
