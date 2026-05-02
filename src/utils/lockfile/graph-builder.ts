/**
 * Dependency graph construction, chain tracing, and impact analysis.
 *
 * Builds a complete dependency graph from pnpm lockfiles and provides:
 * - BFS-based chain tracing (shortest path)
 * - All path enumeration for complete analysis
 * - Impact analysis (count of dependent packages)
 * - Risk assessment based on dependency depth and breadth
 */

import type {
  DependencyGraph,
  DependencyNode,
  DependencyChainAnalysis,
  ImpactAnalysis,
  PnpmLockfile,
} from "../../types.js";
import { parsePnpmPackageKey, makeGraphKey } from "./package-key-parser.js";

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

/**
 * Trace ALL dependency chains from direct dependencies to a target package.
 * Returns an array of paths (each path is an array of "name@version" keys).
 * For direct dependencies, returns [[targetKey]].
 * Returns empty array if no path is found.
 *
 * Uses DFS with backtracking to enumerate all simple paths.
 */
export function traceAllDependencyChains(
  graph: DependencyGraph,
  targetKey: string,
): string[][] {
  // Direct dependency — trivial single-element path
  if (graph.directKeys.has(targetKey)) {
    return [[targetKey]];
  }

  const allPaths: string[][] = [];
  const visited = new Set<string>();

  // DFS from each direct dependency forward through edges (dependencies)
  // to find all paths to targetKey
  function dfs(current: string, path: string[]): void {
    if (current === targetKey) {
      allPaths.push([...path]);
      return;
    }

    const deps = graph.nodes.get(current)?.dependencies;
    if (!deps) return;

    for (const dep of deps) {
      if (!visited.has(dep)) {
        visited.add(dep);
        path.push(dep);
        dfs(dep, path);
        path.pop();
        visited.delete(dep);
      }
    }
  }

  // Start DFS from each direct dependency
  const directKeyArr = Array.from(graph.directKeys);
  for (const directKey of directKeyArr) {
    if (!graph.nodes.has(directKey)) continue;
    visited.clear();
    visited.add(directKey);
    dfs(directKey, [directKey]);
  }

  return allPaths;
}

/**
 * Analyze the impact of a vulnerable package.
 * Returns how many packages depend on it (directly and transitively).
 */
export function analyzeImpact(
  graph: DependencyGraph,
  targetKey: string,
): ImpactAnalysis {
  const node = graph.nodes.get(targetKey);
  if (!node) {
    return {
      targetKey,
      directDependents: 0,
      totalDependents: 0,
      depth: 0,
      breadth: 0,
      riskScore: 0,
    };
  }

  // BFS to count all dependents
  const visited = new Set<string>([targetKey]);
  const queue: string[] = [targetKey];
  let head = 0;
  let directDependents = 0;
  let totalDependents = 0;
  let maxDepth = 0;
  const depthMap = new Map<string, number>();
  depthMap.set(targetKey, 0);

  while (head < queue.length) {
    const current = queue[head++]!;
    const currentDepth = depthMap.get(current) ?? 0;
    const deps = graph.dependents.get(current);
    if (!deps) continue;

    const depsArr = Array.from(deps);
    for (const dep of depsArr) {
      if (!visited.has(dep)) {
        visited.add(dep);
        queue.push(dep);
        depthMap.set(dep, currentDepth + 1);
        totalDependents++;
        if (graph.directKeys.has(dep)) {
          directDependents++;
        }
        maxDepth = Math.max(maxDepth, currentDepth + 1);
      }
    }
  }

  // Calculate breadth (max number of dependents at any level)
  const depthCounts = new Map<number, number>();
  for (const depth of depthMap.values()) {
    depthCounts.set(depth, (depthCounts.get(depth) ?? 0) + 1);
  }
  let breadth = 0;
  for (const count of depthCounts.values()) {
    breadth = Math.max(breadth, count);
  }

  // Calculate risk score based on impact factors
  // Formula: weighted sum of direct dependents, total dependents, and depth
  const riskScore = Math.min(10,
    (directDependents * 2) + // Direct dependents are more critical
    (Math.log2(totalDependents + 1) * 3) + // Logarithmic scale for total
    (maxDepth * 1.5) // Deeper chains are riskier
  );

  return {
    targetKey,
    directDependents,
    totalDependents,
    depth: maxDepth,
    breadth,
    riskScore: Math.round(riskScore * 10) / 10, // Round to 1 decimal
  };
}

/**
 * Get the complete dependency tree for a package (all transitive dependencies).
 * Returns an array of dependency keys in BFS order.
 */
export function getDependencyTree(
  graph: DependencyGraph,
  targetKey: string,
  maxDepth: number = 10,
): string[] {
  const node = graph.nodes.get(targetKey);
  if (!node) return [];

  const result: string[] = [];
  const visited = new Set<string>([targetKey]);
  const queue: Array<{ key: string; depth: number }> = [{ key: targetKey, depth: 0 }];
  let head = 0;

  while (head < queue.length) {
    const { key, depth } = queue[head++]!;
    if (depth > 0) { // Skip the target itself
      result.push(key);
    }
    if (depth >= maxDepth) continue;

    const deps = graph.nodes.get(key)?.dependencies;
    if (!deps) continue;

    for (const dep of deps) {
      if (!visited.has(dep)) {
        visited.add(dep);
        queue.push({ key: dep, depth: depth + 1 });
      }
    }
  }

  return result;
}

/**
 * Comprehensive dependency chain analysis for a vulnerable package.
 * Combines chain tracing, impact analysis, and risk assessment.
 */
export function analyzeDependencyChain(
  graph: DependencyGraph,
  targetKey: string,
): DependencyChainAnalysis {
  const shortestChain = traceDependencyChain(graph, targetKey);
  const allChains = traceAllDependencyChains(graph, targetKey);
  const impact = analyzeImpact(graph, targetKey);
  const dependencyTree = getDependencyTree(graph, targetKey);

  return {
    targetKey,
    shortestChain,
    allChains,
    impact,
    dependencyTree,
    isDirect: graph.directKeys.has(targetKey),
  };
}
