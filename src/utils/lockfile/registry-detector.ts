/**
 * Registry detection and display name resolution.
 *
 * Maps known registry hostnames to short human-readable names
 * and extracts per-package registry info from lockfiles.
 */

import type { PnpmLockfile } from "../../types.js";
import { parsePnpmPackageKey } from "./package-key-parser.js";

/** Known registry hostnames and their display names */
const REGISTRY_DISPLAY_NAMES: Record<string, string> = {
  "registry.npmjs.org": "npmjs",
  "registry.yarnpkg.com": "npmjs", // yarn uses npmjs mirror
  "pkgs.dev.azure.com": "azure",
  "npm.pkg.github.com": "github",
};

/**
 * Extract the registry display name from a tarball URL.
 * Returns a short name like "npmjs", "azure", "github", or the raw hostname.
 */
function extractRegistryFromTarball(tarballUrl: string): string {
  try {
    const url = new URL(tarballUrl);
    return REGISTRY_DISPLAY_NAMES[url.hostname] ?? url.hostname;
  } catch {
    // If URL parsing fails, return empty string
    return "";
  }
}

/**
 * Get a human-readable display name for a registry URL.
 * e.g., "https://registry.npmjs.org/" → "npmjs"
 */
export function getRegistryDisplayName(registryUrl: string): string {
  try {
    const url = new URL(registryUrl);
    return REGISTRY_DISPLAY_NAMES[url.hostname] ?? url.hostname;
  } catch {
    // If URL parsing fails, return the raw string
    return registryUrl;
  }
}

/**
 * Extract per-package registry information from a lockfile.
 * Returns a Map from "name@version" key to registry display name.
 */
export function extractRegistryInfo(
  lockfile: PnpmLockfile,
  defaultRegistry?: string,
): Map<string, string> {
  const packages = lockfile.packages ?? {};
  const packageKeys = Object.keys(packages);
  const result = new Map<string, string>();

  const displayName = defaultRegistry ? getRegistryDisplayName(defaultRegistry) : "";

  for (let i = 0; i < packageKeys.length; i++) {
    const key = packageKeys[i]!;
    const entry = packages[key]!;
    const parsed = parsePnpmPackageKey(key);
    if (!parsed) continue;

    const graphKey = `${parsed.name}@${parsed.version}`;
    const resolution = entry.resolution;

    if (resolution?.tarball && resolution.tarball.startsWith("http")) {
      const registry = extractRegistryFromTarball(resolution.tarball);
      if (registry) {
        result.set(graphKey, registry);
      }
    } else if (displayName) {
      // For packages without tarball (integrity-only), use default registry
      result.set(graphKey, displayName);
    }
  }

  return result;
}
