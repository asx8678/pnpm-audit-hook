/**
 * Get the npm registry URL from environment variables.
 */
export function getRegistryUrl(
  env: Record<string, string | undefined>,
): string {
  const reg =
    env.PNPM_REGISTRY ||
    env.npm_config_registry ||
    env.NPM_CONFIG_REGISTRY ||
    "https://registry.npmjs.org/";
  return reg.endsWith("/") ? reg : reg + "/";
}

/**
 * Parse a boolean from an environment variable string.
 * Returns true for '1', 'true', 'yes', 'y', 'on' (case-insensitive).
 * Returns false for '0', 'false', 'no', 'n', 'off' (case-insensitive).
 * Returns undefined for undefined input or unrecognized values.
 */
export function parseBool(v: string | undefined): boolean | undefined {
  if (v === undefined) return undefined;
  const s = v.toLowerCase();
  if (["1", "true", "yes", "y", "on"].includes(s)) return true;
  if (["0", "false", "no", "n", "off"].includes(s)) return false;
  return undefined;
}

/**
 * Parse a boolean, defaulting to false for undefined/unrecognized values.
 */
export function parseBoolOrFalse(v: string | undefined): boolean {
  return parseBool(v) ?? false;
}
