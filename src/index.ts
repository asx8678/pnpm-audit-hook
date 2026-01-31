import { runAudit } from "./audit";
import type { PnpmHookContext, PnpmLockfile, RuntimeOptions } from "./types";
import { getRegistryUrl } from "./utils/env";
import { logger } from "./utils/logger";

/** Return type for pnpm hooks export */
export interface PnpmHooks {
  hooks: {
    afterAllResolved: (
      lockfile: PnpmLockfile,
      context: PnpmHookContext
    ) => Promise<PnpmLockfile>;
  };
}

function createRuntime(cwdOverride?: string): RuntimeOptions {
  // process.env is NodeJS.ProcessEnv which satisfies Record<string, string | undefined>
  const env: Record<string, string | undefined> = process.env;
  return {
    cwd: cwdOverride ?? process.cwd(),
    env,
    registryUrl: getRegistryUrl(env),
  };
}

export function createPnpmHooks(): PnpmHooks {
  return {
    hooks: {
      afterAllResolved: async (lockfile: PnpmLockfile, context: PnpmHookContext) => {
        const runtime = createRuntime(context?.lockfileDir);
        try {
          const result = await runAudit(lockfile, runtime);
          if (result.blocked) {
            throw new Error(
              "pnpm-audit-hook blocked installation due to security vulnerabilities"
            );
          }
          return lockfile;
        } catch (error) {
          logger.error(error instanceof Error ? error.message : String(error));
          throw error;
        }
      },
    },
  };
}

export * from "./audit";
export * from "./types";
