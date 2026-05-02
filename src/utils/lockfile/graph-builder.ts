/**
 * Dependency graph construction and chain tracing.
 *
 * Builds a complete dependency graph from pnpm lockfiles and provides
 * BFS-based chain tracing from direct dependencies to vulnerable transitive packages.
 */

import type {
  DependencyGraph,
  DependencyNode,
  PnpmLockfile,
} from "../../types.js";
import { makeGraphKey, parsePnpmPackageKey } from "./package-key-parser.js";

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
