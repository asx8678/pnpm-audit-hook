/**
 * Package extraction from pnpm lockfiles.
 *
 * Filters and extracts registry packages from lockfile data,
 * producing a list of PackageRef objects for audit processing.
 */

import type { LockfilePackageEntry, PackageRef, PnpmLockfile } from "../../types.js";
import { parsePnpmPackageKey } from "./package-key-parser.js";

export interface LockfileParseResult {
  packages: PackageRef[];
}

function isRegistryPackage(entry: LockfilePackageEntry): boolean {
  const res = entry.resolution;
  if (!res) return false;
  if (res.type === "directory" || res.directory || res.path) return false;
  if (typeof res.tarball === "string") return res.tarball.startsWith("http");
  return typeof res.integrity === "string";
}

/** Extract registry packages from a pnpm lockfile object. */
export function extractPackagesFromLockfile(
  lockfile: PnpmLockfile | null | undefined,
): LockfileParseResult {
  const packageEntries = lockfile?.packages;
  if (!packageEntries) return { packages: [] };

  const keys = Object.keys(packageEntries);
  // Pre-allocate: most packages in a lockfile are registry packages
  const packages: PackageRef[] = new Array(keys.length);
  let count = 0;

  for (let i = 0; i < keys.length; i++) {
    const k = keys[i]!;
    const entry = packageEntries[k]!;
    const parsed = parsePnpmPackageKey(k);
    if (!parsed) continue;
    if (!isRegistryPackage(entry)) continue;

    packages[count++] = { name: parsed.name, version: parsed.version };
  }

  // Trim to actual size
  packages.length = count;
  return { packages };
}
