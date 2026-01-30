import type { PackageRef } from "../types";

export interface LockfileParseResult {
  packages: PackageRef[];
  dependencies: Record<string, string[]>; // key name@version -> dep keys
}

function stripPeerSuffix(v: string): string {
  const idx = v.indexOf("(");
  if (idx === -1) return v;
  return v.slice(0, idx);
}

/**
 * Parse a pnpm lockfile package key into name + version.
 *
 * Examples:
 * - /react/18.2.0
 * - /@types/node/20.10.0
 * - /eslint-plugin-react/7.33.2(eslint@8.56.0)
 * - registry.npmjs.org/react/18.2.0 (rare)
 */
export function parsePnpmPackageKey(
  key: string,
): { name: string; version: string } | null {
  const raw = key.startsWith("/") ? key.slice(1) : key;
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

function isRegistryPackage(entry: any): boolean {
  const res = entry?.resolution ?? {};
  // Lockfile can contain local directories / links / git. We treat them as non-registry.
  if (res.type === "directory" || res.directory || res.path) return false;
  if (typeof res.tarball === "string") {
    const t = res.tarball;
    // tarball URL indicates registry-like. We'll treat as registry.
    return t.startsWith("http:") || t.startsWith("https:");
  }
  // If we have an integrity hash, it's almost certainly fetched content.
  if (typeof res.integrity === "string") return true;

  return false;
}

function depsFromEntry(entry: any): Record<string, string> {
  return {
    ...(entry?.dependencies ?? {}),
    ...(entry?.optionalDependencies ?? {}),
    ...(entry?.peerDependencies ?? {}),
  };
}

function addDepEdge(
  graph: Record<string, string[]>,
  from: string,
  to: string,
): void {
  graph[from] = graph[from] ?? [];
  if (!graph[from]!.includes(to)) graph[from]!.push(to);
}

/**
 * Extract registry packages from a pnpm lockfile object.
 */
export function extractPackagesFromLockfile(
  lockfile: any,
): LockfileParseResult {
  const packages: PackageRef[] = [];
  const graph: Record<string, string[]> = {};

  const packageEntries: Record<string, any> = lockfile?.packages ?? {};
  const keyToRef: Record<string, PackageRef> = {};

  for (const [k, entry] of Object.entries(packageEntries)) {
    const parsed = parsePnpmPackageKey(k);
    if (!parsed) continue;
    if (!isRegistryPackage(entry)) continue;

    const res = entry?.resolution ?? {};
    const pkg: PackageRef = {
      name: parsed.name,
      version: parsed.version,
      integrity: typeof res.integrity === "string" ? res.integrity : undefined,
      tarball: typeof res.tarball === "string" ? res.tarball : undefined,
    };

    const key = `${pkg.name}@${pkg.version}`;
    packages.push(pkg);
    keyToRef[key] = pkg;
  }

  // Direct deps via importers
  const importers: Record<string, any> = lockfile?.importers ?? {};
  for (const [importerPath, imp] of Object.entries(importers)) {
    const deps = {
      ...(imp?.dependencies ?? {}),
      ...(imp?.devDependencies ?? {}),
      ...(imp?.optionalDependencies ?? {}),
    };
    for (const [depName, depVersion] of Object.entries(deps)) {
      const v = stripPeerSuffix(String(depVersion));
      const key = `${depName}@${v}`;
      const ref = keyToRef[key];
      if (ref) {
        ref.direct = true;
        ref.importers = ref.importers ?? [];
        if (!ref.importers.includes(importerPath))
          ref.importers.push(importerPath);
      }
    }
  }

  // Dependency edges
  for (const [k, entry] of Object.entries(packageEntries)) {
    const parsed = parsePnpmPackageKey(k);
    if (!parsed) continue;
    const fromKey = `${parsed.name}@${stripPeerSuffix(parsed.version)}`;
    if (!keyToRef[fromKey]) continue; // skip non-registry nodes

    const deps = depsFromEntry(entry);
    for (const [depName, depVer] of Object.entries(deps)) {
      const v = stripPeerSuffix(String(depVer));
      // Skip non-version references (link:, workspace:, etc)
      if (
        v.startsWith("link:") ||
        v.startsWith("workspace:") ||
        v.startsWith("file:") ||
        v.startsWith("patch:")
      )
        continue;
      const toKey = `${depName}@${v}`;
      if (!keyToRef[toKey]) continue;
      addDepEdge(graph, fromKey, toKey);
    }
  }

  return { packages, dependencies: graph };
}
