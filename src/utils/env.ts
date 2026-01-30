/** Get npm registry URL from env */
export function getRegistryUrl(env: Record<string, string | undefined>): string {
  const reg = env.PNPM_REGISTRY || env.npm_config_registry || env.NPM_CONFIG_REGISTRY || "https://registry.npmjs.org/";
  return reg.endsWith("/") ? reg : `${reg}/`;
}

/** Parse boolean from env string */
export function parseBool(v: string | undefined): boolean | undefined {
  if (v == null) return undefined;
  const s = v.toLowerCase();
  if (["1", "true", "yes", "y", "on"].includes(s)) return true;
  if (["0", "false", "no", "n", "off"].includes(s)) return false;
  return undefined;
}

export const parseBoolOrFalse = (v: string | undefined) => parseBool(v) ?? false;
