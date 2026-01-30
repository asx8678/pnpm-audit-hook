import { runAudit, shouldBlockInstall } from "./audit";
import { createRuntimeFromEnv } from "./utils/runtime";

/**
 * Factory to create pnpm hooks.
 *
 * pnpm will call these hooks during resolution, before any package tarballs are downloaded.
 */
export function createPnpmHooks(): { hooks: Record<string, any> } {
  return {
    hooks: {
      /**
       * Runs after pnpm has resolved the full dependency graph (lockfile object)
       * but BEFORE it downloads packages.
       *
       * This is the earliest place we can audit the *exact* resolved versions.
       */
      afterAllResolved: async (lockfile: any, context: any) => {
        // Use lockfileDir from pnpm context when available (handles workspace subfolders).
        // Falls back to process.cwd() for compatibility with older pnpm versions.
        const runtime = createRuntimeFromEnv(context?.lockfileDir);

        const { report } = await runAudit({ lockfile, runtime });

        if (shouldBlockInstall(report, runtime.env)) {
          const top = report.summary;
          const msg = [
            `pnpm-audit-hook blocked installation`,
            `Blocking findings: ${top.blockedFindings}`,
            `Warnings: ${top.warnedFindings}`,
            `See audit artifacts in the configured outputDir (default: .pnpm-audit-report.html / .json / .sarif.json).`,
          ].join("\n");
          throw new Error(msg);
        }

        return lockfile;
      },
    },
  };
}

export * from "./audit";
export * from "./types";
