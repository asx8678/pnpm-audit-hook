import type { AuditConfig, PackageAuditResult, PolicyAction, PolicyDecision, Severity } from "../types";
import { mapSeverity } from "../utils/severity";

function actionForSeverity(sev: Severity, cfg: AuditConfig["policy"]): PolicyAction {
  const s = mapSeverity(sev);
  if (cfg.block.includes(s)) return "block";
  if (cfg.warn.includes(s)) return "warn";
  return "allow";
}

export function evaluatePackagePolicies(pkgResult: PackageAuditResult, cfg: AuditConfig): PackageAuditResult {
  const { pkg, findings } = pkgResult;
  const decisions: PolicyDecision[] = [...pkgResult.decisions];
  const now = new Date().toISOString();

  for (const f of findings) {
    const action = actionForSeverity(f.severity, cfg.policy);
    if (action !== "allow") {
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
  }

  return { ...pkgResult, decisions };
}
