import { getRegistryUrlFromEnv } from "./env-manager";

const DEFAULT_REGISTRY = "https://registry.npmjs.org/";

/**
 * Get npm registry URL from env.
 * For security, throws an error if an explicitly configured URL is invalid.
 * Only falls back to default when no registry is explicitly configured.
 */
export function getRegistryUrl(env: Record<string, string | undefined>): string {
  // Use env-manager for consistent environment variable handling
  const explicitReg = getRegistryUrlFromEnv(env);

  // No explicit config - use default
  if (!explicitReg) {
    return DEFAULT_REGISTRY;
  }

  // Validate explicitly configured URL
  let parsed: URL;
  try {
    parsed = new URL(explicitReg);
  } catch {
    throw new Error(
      `Invalid registry URL configured: "${explicitReg}". ` +
        `Please fix the registry URL or unset PNPM_REGISTRY/npm_config_registry/NPM_CONFIG_REGISTRY.`
    );
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error(
      `Invalid registry protocol "${parsed.protocol}" in URL: "${explicitReg}". ` +
        `Only http: and https: are allowed.`
    );
  }

  return explicitReg.endsWith("/") ? explicitReg : `${explicitReg}/`;
}

// No extra helpers needed here (keep this file minimal).
