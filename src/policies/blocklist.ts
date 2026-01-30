/**
 * Blocklist matching.
 *
 * Supports:
 * - Exact matches: "event-stream"
 * - Simple wildcard suffix: "@scope/*" or "lodash*"
 */
export function isBlockedPackage(name: string, blocklist: string[]): boolean {
  for (const pattern of blocklist) {
    if (!pattern) continue;
    if (pattern === name) return true;
    if (pattern === "*") continue; // Skip bare wildcard - would block everything

    if (pattern.endsWith("*")) {
      const prefix = pattern.slice(0, -1);
      if (prefix && name.startsWith(prefix)) return true;
    }
  }
  return false;
}
