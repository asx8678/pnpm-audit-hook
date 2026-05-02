import type {
  DependencyGraph,
  DependencyNode,
  LockfilePackageEntry,
  PackageRef,
  PnpmLockfile,
} from "../types";

/** Known registry hostnames and their display names */
const REGISTRY_DISPLAY_NAMES: Record<string, string> = {
  "registry.npmjs.org": "npmjs",
  "registry.yarnpkg.com": "npmjs", // yarn uses npmjs mirror
  "pkgs.dev.azure.com": "azure",
  "npm.pkg.github.com": "github",
};

export interface LockfileParseResult {
  packages: PackageRef[];
}

const stripPeerSuffix = (v: string): string => {
  const idx = v.indexOf("(");
  return idx === -1 ? v : v.slice(0, idx);
};

/** Build a canonical "name@version" key for graph lookups. */
const makeGraphKey = (name: string, version: string): string => {
  return `${name}@${stripPeerSuffix(version)}`;
};

/**
 * Cache for parsePnpmPackageKey results, scoped per parse session.
 * Avoids re-parsing the same key when multiple functions process
 * the same lockfile (extractPackagesFromLockfile + buildDependencyGraph).
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

/** Parse a pnpm lockfile package key into name + version.
 * Supports both old format (/react/18.2.0, react/18.2.0, /@types/node/20.10.0) and
 * new v9 format (react@18.2.0, @types/node@20.10.0)
 */
export function parsePnpmPackageKey(key: string): { name: string; version: string } | null {
  // Check cache first if enabled
  if (_parseCache !== null) {
    const cached = _parseCache.get(key);
    if (cached !== undefined) return cached;
  }

  const result = _parsePnpmPackageKeyUncached(key);

  if (_parseCache !== null) {
    _parseCache.set(key, result);
  }

  return result;
}

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

/**
 * Collect direct dependency keys from an importer's dep record.
 * Handles both plain version strings (v6-v8) and { specifier, version } objects (v9).
 */
function collectDirect(
  deps: Record<string, string | { specifier?: string; version: string }>,
  targetSet: Set<string>,
  nodes: Map<string, DependencyNode>,
  directKeys: Set<string>,
): void {
  const depNames = Object.keys(deps);
  for (let i = 0; i < depNames.length; i++) {
    const depName = depNames[i]!;
    const depValue = deps[depName]!;
    // pnpm lockfile v9: deps values can be objects { specifier, version }
    // pnpm lockfile v6-v8: deps values are plain version strings
    const versionStr = typeof depValue === "string" ? depValue : depValue.version;
    if (!versionStr) continue;
    const depKey = makeGraphKey(depName, versionStr);
    if (nodes.has(depKey)) {
      targetSet.add(depKey);
      directKeys.add(depKey);
    }
  }
}

/**
 * Build a dependency graph from a pnpm lockfile.
 *
 * Walks the `packages` section to discover all packages and their forward edges,
 * and the `importers` section to identify direct vs transitive dependencies.
 *
 * Optimized: uses indexed iteration instead of Object.entries,
 * lazy reverse-edge allocation, and pre-resolved parse cache.
 */
export function buildDependencyGraph(lockfile: PnpmLockfile): DependencyGraph {
  const packages = lockfile.packages ?? {};
  const packageKeys = Object.keys(packages);
  const pkgCount = packageKeys.length;

  const nodes = new Map<string, DependencyNode>();
  const byName = new Map<string, string[]>();
  const dependents = new Map<string, Set<string>>();
  const directKeys = new Set<string>();

  // ── Step 1: Create a node for every package entry ──
  for (let i = 0; i < pkgCount; i++) {
    const pkgKey = packageKeys[i]!;
    const parsed = parsePnpmPackageKey(pkgKey);
    if (!parsed) continue;

    const nodeKey = makeGraphKey(parsed.name, parsed.version);
    if (nodes.has(nodeKey)) continue;

    const node: DependencyNode = {
      name: parsed.name,
      version: parsed.version,
      isDirect: false,
      isDev: false,
      dependencies: [],
    };

    nodes.set(nodeKey, node);

    const existing = byName.get(parsed.name);
    if (existing) {
      existing.push(nodeKey);
    } else {
      byName.set(parsed.name, [nodeKey]);
    }

    // Pre-initialize reverse-edges set (empty for nodes with no dependents)
    dependents.set(nodeKey, new Set());
  }

  // ── Step 2: Build forward + reverse edges from package entries ──
  for (let i = 0; i < pkgCount; i++) {
    const pkgKey = packageKeys[i]!;
    const entry = packages[pkgKey]!;
    const parsed = parsePnpmPackageKey(pkgKey);
    if (!parsed) continue;

    const srcKey = makeGraphKey(parsed.name, parsed.version);
    const srcNode = nodes.get(srcKey);
    if (!srcNode) continue;

    const depFields = [
      entry.dependencies,
      entry.devDependencies,
      entry.optionalDependencies,
      entry.peerDependencies,
    ];

    for (let f = 0; f < depFields.length; f++) {
      const deps = depFields[f];
      if (!deps) continue;

      const depKeys = Object.keys(deps);
      for (let d = 0; d < depKeys.length; d++) {
        const depName = depKeys[d]!;
        const depVersion = (deps as Record<string, string>)[depName]!;
        const depKey = makeGraphKey(depName, depVersion);
        if (!nodes.has(depKey)) continue;

        srcNode.dependencies.push(depKey);
        // Build reverse edge (lazily create the dependent's set)
        let depReverse = dependents.get(depKey);
        if (!depReverse) {
          depReverse = new Set();
          dependents.set(depKey, depReverse);
        }
        depReverse.add(srcKey);
      }
    }
  }

  // ── Step 3: Identify direct dependencies from importers ──
  const directProdKeys = new Set<string>();
  const directOptKeys = new Set<string>();
  const directDevKeys = new Set<string>();

  const importers = lockfile.importers ?? {};
  const importerKeys = Object.keys(importers);

  for (let i = 0; i < importerKeys.length; i++) {
    const importer = importers[importerKeys[i]!]!;
    if (importer.dependencies) collectDirect(importer.dependencies, directProdKeys, nodes, directKeys);
    if (importer.optionalDependencies) collectDirect(importer.optionalDependencies, directOptKeys, nodes, directKeys);
    if (importer.devDependencies) collectDirect(importer.devDependencies, directDevKeys, nodes, directKeys);
  }

  // ── Step 4: Mark isDirect / isDev on nodes ──
  const directKeyArr = Array.from(directKeys);
  for (let i = 0; i < directKeyArr.length; i++) {
    const key = directKeyArr[i]!;
    const node = nodes.get(key);
    if (!node) continue;
    node.isDirect = true;
    // isDev only if the package appears *solely* in devDependencies
    node.isDev = directDevKeys.has(key)
      && !directProdKeys.has(key)
      && !directOptKeys.has(key);
  }

  return { nodes, byName, dependents, directKeys };
}

/**
 * Trace the dependency chain from a direct dependency to a vulnerable transitive package.
 * Returns an array of "name@version" keys from the direct dep to the target.
 * For direct dependencies, returns [targetKey].
 * Returns null if no path is found.
 *
 * Optimized: uses index-based queue traversal (O(1) dequeue) instead of
 * Array.shift() (O(n) dequeue), and pre-allocates Maps/Sets with size hints.
 */
export function traceDependencyChain(
  graph: DependencyGraph,
  targetKey: string,
): string[] | null {
  // Direct dependency — trivial single-element path
  if (graph.directKeys.has(targetKey)) {
    return [targetKey];
  }

  // BFS from target backwards through reverse edges (dependents)
  // Use index-based traversal to avoid O(n) shift() calls
  const queue: string[] = [targetKey];
  const visited = new Set<string>([targetKey]);
  const parent = new Map<string, string>();
  let head = 0;

  while (head < queue.length) {
    const current = queue[head++]!;
    const deps = graph.dependents.get(current);
    if (!deps) continue;

    const depsArr = Array.from(deps);
    for (let i = 0; i < depsArr.length; i++) {
      const dep = depsArr[i]!;
      if (visited.has(dep)) continue;
      visited.add(dep);
      parent.set(dep, current);

      if (graph.directKeys.has(dep)) {
        // Found a direct dependency — reconstruct path (reversed)
        const path: string[] = [dep];
        let cursor = current;
        while (cursor !== targetKey) {
          path.push(cursor);
          cursor = parent.get(cursor)!;
        }
        path.push(targetKey);
        return path;
      }

      queue.push(dep);
    }
  }

  return null;
}
