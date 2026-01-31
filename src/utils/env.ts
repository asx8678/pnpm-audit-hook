import { logger } from "./logger";

const DEFAULT_REGISTRY = "https://registry.npmjs.org/";

/** Get npm registry URL from env */
export function getRegistryUrl(env: Record<string, string | undefined>): string {
  const reg = env.PNPM_REGISTRY || env.npm_config_registry || env.NPM_CONFIG_REGISTRY || DEFAULT_REGISTRY;
  try {
    const parsed = new URL(reg);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      logger.warn(`Invalid registry protocol: ${parsed.protocol}, using default`);
      return DEFAULT_REGISTRY;
    }
  } catch {
    logger.warn(`Invalid registry URL: ${reg}, using default`);
    return DEFAULT_REGISTRY;
  }
  return reg.endsWith("/") ? reg : `${reg}/`;
}

// No extra helpers needed here (keep this file minimal).
