import { runAudit } from "./audit";
import type { RuntimeOptions } from "./types";
import { getRegistryUrl } from "./utils/env";

function createRuntime(cwdOverride?: string): RuntimeOptions {
  const env = process.env as Record<string, string | undefined>;
  return {
    cwd: cwdOverride ?? process.cwd(),
    env,
    registryUrl: getRegistryUrl(env),
  };
}

export function createPnpmHooks(): { hooks: Record<string, any> } {
  return {
    hooks: {
      afterAllResolved: async (lockfile: any, context: any) => {
        const runtime = createRuntime(context?.lockfileDir);
        const result = await runAudit(lockfile, runtime);

        if (result.blocked) {
          throw new Error("pnpm-audit-hook blocked installation due to security vulnerabilities");
        }

        return lockfile;
      },
    },
  };
}

export * from "./audit";
export * from "./types";
