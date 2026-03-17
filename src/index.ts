import { runAudit } from "./audit";
import type { PnpmHookContext, PnpmLockfile } from "./types";
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
          const blockedCount = result.decisions.filter(d => d.action === "block").length;
          const blockedPkgs = [...new Set(
            result.decisions
              .filter(d => d.action === "block" && d.packageName)
              .map(d => `${d.packageName}@${d.packageVersion}`),
          )];
          const detail = blockedPkgs.length > 0
            ? `: ${blockedPkgs.join(", ")}`
            : "";
          throw new Error(
            `pnpm-audit-hook blocked installation (${blockedCount} issue${blockedCount !== 1 ? "s" : ""})${detail}`
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
