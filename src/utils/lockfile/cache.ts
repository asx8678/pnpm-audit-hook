/**
 * Parse cache for pnpm package key parsing.
 *
 * Scoped per parse session — avoids re-parsing the same key when multiple
 * functions process the same lockfile (extractPackagesFromLockfile + buildDependencyGraph).
 */

let _parseCache: Map<string, { name: string; version: string } | null> | null = null;

/** Enable parse caching for the duration of a batch operation. */
export function enableParseCache(): void {
  _parseCache = new Map();
}

/** Clear and disable parse caching. */
export function disableParseCache(): void {
  _parseCache = null;
}

/** Get the current cache reference (or null if disabled). */
export function getParseCache(): Map<string, { name: string; version: string } | null> | null {
  return _parseCache;
}
