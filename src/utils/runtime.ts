import type { RuntimeOptions } from "../types";
import { getRegistryUrl } from "./env";

/** Create RuntimeOptions from process environment */
export function createRuntimeFromEnv(cwdOverride?: string): RuntimeOptions {
  const env = process.env as Record<string, string | undefined>;
  return {
    cwd: cwdOverride ?? process.cwd(),
    env,
    registryUrl: getRegistryUrl(env),
  };
}
