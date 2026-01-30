import type { RuntimeOptions } from "./types";
import { runAudit, shouldBlockInstall } from "./audit";
import { getRegistryUrl } from "./utils/env";

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
      afterAllResolved: async (lockfile: any, _context: any) => {
        const env = process.env as Record<string, string | undefined>;

        const runtime: RuntimeOptions = {
          cwd: process.cwd(),
          registryUrl: getRegistryUrl(env),
          env,
        };

        const { report } = await runAudit({ lockfile, runtime });

        if (shouldBlockInstall(report, env)) {
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
