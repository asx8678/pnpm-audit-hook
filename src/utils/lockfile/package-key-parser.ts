/**
 * Parse pnpm lockfile package keys into name + version pairs.
 *
 * Supports both old format (/react/18.2.0, react/18.2.0, /@types/node/20.10.0) and
 * new v9 format (react@18.2.0, @types/node@20.10.0).
 */

import { getParseCache } from "./cache.js";

const stripPeerSuffix = (v: string): string => {
  const idx = v.indexOf("(");
  return idx === -1 ? v : v.slice(0, idx);
};

/** Build a canonical "name@version" key for graph lookups. */
export const makeGraphKey = (name: string, version: string): string => {
  return `${name}@${stripPeerSuffix(version)}`;
};

/** Internal uncached implementation */
function _parsePnpmPackageKeyUncached(key: string): { name: string; version: string } | null {
  // Detect format: v9 uses @ separator, old uses / separator
  // For scoped packages: v9 is @scope/pkg@version, old is /@scope/pkg/version
  const raw = key.startsWith("/") ? key.slice(1) : key;

  // Check if this is v9 format by looking for @ after a potential scope
  // v9 format: lodash@4.17.21 or @types/node@20.10.0
  // old format: lodash/4.17.21 or @types/node/20.10.0
  const isScoped = raw.startsWith("@");
  const atIndex = isScoped ? raw.indexOf("@", 1) : raw.indexOf("@");
  const slashIndex = isScoped ? raw.indexOf("/", raw.indexOf("/") + 1) : raw.indexOf("/");

  // If @ comes before / (or there's no /), it's v9 format
  if (atIndex !== -1 && (slashIndex === -1 || atIndex < slashIndex)) {
    const name = raw.slice(0, atIndex);
    const version = raw.slice(atIndex + 1);
    if (!name || !version) return null;
    return { name, version: stripPeerSuffix(version) };
  }

  // Handle old format: package/version or @scope/package/version
  const parts = raw.split("/").filter(Boolean);

  if (parts.length < 2) return null;

  // Skip registry host prefix if present (heuristic)
  let i = 0;
  if (parts[0] && (parts[0].includes(".") || parts[0].includes(":"))) i = 1;

  if (parts[i]?.startsWith("@")) {
    const scope = parts[i]!;
    const name = parts[i + 1];
    const version = parts[i + 2];
    if (!name || !version) return null;
    return { name: `${scope}/${name}`, version: stripPeerSuffix(version) };
  }

  const name = parts[i];
  const version = parts[i + 1];
  if (!name || !version) return null;
  return { name, version: stripPeerSuffix(version) };
}

/**
 * Parse a pnpm lockfile package key into name + version.
 * Supports both old format (/react/18.2.0, react/18.2.0, /@types/node/20.10.0) and
 * new v9 format (react@18.2.0, @types/node@20.10.0)
 */
export function parsePnpmPackageKey(key: string): { name: string; version: string } | null {
  // Check cache first if enabled
  const cache = getParseCache();
  if (cache !== null) {
    const cached = cache.get(key);
    if (cached !== undefined) return cached;
  }

  const result = _parsePnpmPackageKeyUncached(key);

  if (cache !== null) {
    cache.set(key, result);
  }

  return result;
}
