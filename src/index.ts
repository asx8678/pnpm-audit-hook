import { runAudit } from "./audit";
import type { PnpmHookContext, PnpmLockfile, VulnerabilityFinding } from "./types";
import { getRegistryUrl } from "./utils/env";

/** Return type for pnpm hooks export */
export interface PnpmHooks {
  hooks: {
    afterAllResolved: (
      lockfile: PnpmLockfile,
      context: PnpmHookContext
    ) => Promise<PnpmLockfile>;
  };
}

/**
 * Build a rich error message with CVE IDs, severities, and fix info.
 */
function buildBlockedErrorMessage(
  decisions: Array<{ action: string; findingId?: string; findingSeverity?: string; packageName?: string; packageVersion?: string }>,
  findings: VulnerabilityFinding[],
): string {
  const blocked = decisions.filter(d => d.action === "block");
  const blockedCount = blocked.length;

  // Build finding details map for quick lookup
  const findingMap = new Map<string, VulnerabilityFinding>();
  for (const f of findings) {
    findingMap.set(`${f.packageName}@${f.packageVersion}:${f.id}`, f);
  }

  // Group by package, include CVE and fix info
  const details: string[] = [];
  const seenPkgs = new Set<string>();
  for (const d of blocked) {
    if (!d.packageName) continue;
    const pkgKey = `${d.packageName}@${d.packageVersion}`;
    const finding = d.findingId
      ? findingMap.get(`${pkgKey}:${d.findingId}`)
      : undefined;

    const sev = d.findingSeverity ?? finding?.severity ?? "";
    const sevStr = sev ? `[${sev.toUpperCase()}]` : "";
    const id = d.findingId ?? "";
    const fix = finding?.fixedVersion ? ` (fix: ${finding.fixedVersion})` : "";
    details.push(`  ${sevStr} ${pkgKey} ${id}${fix}`);
    seenPkgs.add(pkgKey);
  }

  const header = `pnpm-audit-hook blocked installation (${blockedCount} issue${blockedCount !== 1 ? "s" : ""} in ${seenPkgs.size} package${seenPkgs.size !== 1 ? "s" : ""})`;

  if (details.length === 0) return header;
  return `${header}:\n${details.join("\n")}`;
}

export function createPnpmHooks(): PnpmHooks {
  return {
    hooks: {
      afterAllResolved: async (lockfile: PnpmLockfile, context: PnpmHookContext) => {
        const env: Record<string, string | undefined> = process.env;
        const runtime = {
          cwd: context?.lockfileDir ?? process.cwd(),
          env,
          registryUrl: getRegistryUrl(env),
        };
        const result = await runAudit(lockfile, runtime);
        if (result.blocked) {
          throw new Error(
            buildBlockedErrorMessage(result.decisions, result.findings)
          );
        }
        return lockfile;
      },
    },
  };
}

export { runAudit, EXIT_CODES } from "./audit";
export type { AuditResult } from "./audit";
export type {
  AuditConfig,
  AuditConfigInput,
  PackageRef,
  PnpmLockfile,
  PnpmHookContext,
  PolicyDecision,
  RuntimeOptions,
  Severity,
  SourceStatus,
  VulnerabilityFinding,
} from "./types";
