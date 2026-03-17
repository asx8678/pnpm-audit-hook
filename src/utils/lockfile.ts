import type {
  LockfilePackageEntry,
  PackageRef,
  PnpmLockfile,
} from "../types";

export interface LockfileParseResult {
  packages: PackageRef[];
}

const stripPeerSuffix = (v: string) => {
  const idx = v.indexOf("(");
  return idx === -1 ? v : v.slice(0, idx);
};

/** Parse a pnpm lockfile package key into name + version.
 * Supports both old format (/react/18.2.0, react/18.2.0, /@types/node/20.10.0) and
 * new v9 format (react@18.2.0, @types/node@20.10.0)
 */
export function parsePnpmPackageKey(key: string): { name: string; version: string } | null {
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

function isRegistryPackage(entry: LockfilePackageEntry): boolean {
  const res = entry.resolution ?? {};
  if (res.type === "directory" || res.directory || res.path) return false;
  if (typeof res.tarball === "string") return res.tarball.startsWith("http");
  return typeof res.integrity === "string";
}

/** Extract registry packages from a pnpm lockfile object. */
export function extractPackagesFromLockfile(
  lockfile: PnpmLockfile | null | undefined,
): LockfileParseResult {
  const packages: PackageRef[] = [];

  const packageEntries: Record<string, LockfilePackageEntry> = lockfile?.packages ?? {};

  for (const [k, entry] of Object.entries(packageEntries)) {
    const parsed = parsePnpmPackageKey(k);
    if (!parsed) continue;
    if (!isRegistryPackage(entry)) continue;

    packages.push({ name: parsed.name, version: parsed.version });
  }

  return { packages };
}
