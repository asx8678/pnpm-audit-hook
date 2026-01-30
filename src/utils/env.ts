/** Get npm registry URL from env */
export function getRegistryUrl(env: Record<string, string | undefined>): string {
  const reg = env.PNPM_REGISTRY || env.npm_config_registry || env.NPM_CONFIG_REGISTRY || "https://registry.npmjs.org/";
  return reg.endsWith("/") ? reg : `${reg}/`;
}

// No extra helpers needed here (keep this file minimal).
