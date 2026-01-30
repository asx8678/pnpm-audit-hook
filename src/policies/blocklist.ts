/** Blocklist: exact matches ("event-stream") or wildcard suffix ("@scope/*", "lodash*") */
export function isBlockedPackage(name: string, blocklist: string[]): boolean {
  return blocklist.some((pattern) => {
    if (!pattern || pattern === "*") return false;
    if (pattern === name) return true;
    if (pattern.endsWith("*")) {
      const prefix = pattern.slice(0, -1);
      return prefix && name.startsWith(prefix);
    }
    return false;
  });
}
