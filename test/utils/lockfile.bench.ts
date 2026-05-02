import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import {
  parsePnpmPackageKey,
  extractPackagesFromLockfile,
  buildDependencyGraph,
  traceDependencyChain,
} from "../../src/utils/lockfile";
import type { PnpmLockfile } from "../../src/types";

/** Generate a synthetic pnpm lockfile for benchmarking */
function generateLockfile(packageCount: number, avgDepsPerPkg: number): PnpmLockfile {
  const packages: Record<string, any> = {};
  const pkgNames: Array<{ name: string; version: string }> = [];

  for (let i = 0; i < packageCount; i++) {
    const isScoped = i % 5 === 0;
    const name = isScoped ? `@scope/pkg${i}` : `pkg${i}`;
    const version = `${1 + (i % 10)}.0.${i}`;
    pkgNames.push({ name, version });
  }

  for (let i = 0; i < packageCount; i++) {
    const { name, version } = pkgNames[i]!;
    const deps: Record<string, string> = {};
    const depCount = Math.min(avgDepsPerPkg, packageCount - 1);
    for (let d = 0; d < depCount; d++) {
      const depIdx = (i + d + 1) % packageCount;
      deps[pkgNames[depIdx]!.name] = pkgNames[depIdx]!.version;
    }

    packages[`${name}@${version}`] = {
      resolution: { integrity: `sha512-${i}` },
      dependencies: Object.keys(deps).length > 0 ? deps : undefined,
      optionalDependencies: i % 20 === 0 ? { fsevents: "2.3.3" } : undefined,
      peerDependencies: i % 15 === 0 ? { react: "18.2.0" } : undefined,
    };
  }

  const importerDeps: Record<string, string> = {};
  for (let i = 0; i < Math.min(20, packageCount); i++) {
    importerDeps[pkgNames[i]!.name] = pkgNames[i]!.version;
  }

  return {
    lockfileVersion: "9.0",
    packages,
    importers: {
      ".": {
        dependencies: importerDeps,
        devDependencies: { vitest: "1.0.0" },
      },
      "packages/app-a": {
        dependencies: { [pkgNames[0]!.name]: `${1}.0.0` },
      },
    },
  };
}

describe("lockfile performance benchmarks", () => {
  it("parsePnpmPackageKey performance", () => {
    const iterations = 10000;
    const keys = [
      "/lodash/4.17.21",
      "@types/node@20.10.0",
      "react-dom@18.2.0(react@18.2.0)",
      "/@babel/core@7.23.0",
      "/registry.npmjs.org/lodash/4.17.21",
    ];

    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      for (const key of keys) {
        parsePnpmPackageKey(key);
      }
    }
    const elapsed = performance.now() - start;
    const opsPerSec = Math.round((iterations * keys.length) / (elapsed / 1000));
    console.log(`  parsePnpmPackageKey: ${opsPerSec.toLocaleString()} ops/sec (${elapsed.toFixed(2)}ms for ${iterations * keys.length} parses)`);
    assert.ok(elapsed < 5000, `Should parse ${iterations} * ${keys.length} keys in under 5s, took ${elapsed.toFixed(2)}ms`);
  });

  it("buildDependencyGraph with 500 packages", () => {
    const lockfile = generateLockfile(500, 3);
    const start = performance.now();
    const graph = buildDependencyGraph(lockfile);
    const elapsed = performance.now() - start;
    console.log(`  buildDependencyGraph (500 pkgs): ${elapsed.toFixed(2)}ms, nodes: ${graph.nodes.size}`);
    assert.ok(elapsed < 2000, `Should build graph in under 2s, took ${elapsed.toFixed(2)}ms`);
  });

  it("buildDependencyGraph with 2000 packages", () => {
    const lockfile = generateLockfile(2000, 5);
    const start = performance.now();
    const graph = buildDependencyGraph(lockfile);
    const elapsed = performance.now() - start;
    console.log(`  buildDependencyGraph (2000 pkgs): ${elapsed.toFixed(2)}ms, nodes: ${graph.nodes.size}`);
    assert.ok(elapsed < 5000, `Should build graph in under 5s, took ${elapsed.toFixed(2)}ms`);
  });

  it("traceDependencyChain performance", () => {
    const lockfile = generateLockfile(1000, 5);
    const graph = buildDependencyGraph(lockfile);
    const targetKeys = Array.from(graph.nodes.keys()).slice(0, 100);

    const start = performance.now();
    for (const key of targetKeys) {
      traceDependencyChain(graph, key);
    }
    const elapsed = performance.now() - start;
    console.log(`  traceDependencyChain (100 lookups, 1000-node graph): ${elapsed.toFixed(2)}ms`);
    assert.ok(elapsed < 2000, `Should trace 100 chains in under 2s, took ${elapsed.toFixed(2)}ms`);
  });

  it("extractPackagesFromLockfile with 500 packages", () => {
    const lockfile = generateLockfile(500, 3);
    const start = performance.now();
    const result = extractPackagesFromLockfile(lockfile);
    const elapsed = performance.now() - start;
    console.log(`  extractPackagesFromLockfile (500 pkgs): ${elapsed.toFixed(2)}ms, extracted: ${result.packages.length}`);
    assert.ok(elapsed < 500, `Should extract packages in under 500ms, took ${elapsed.toFixed(2)}ms`);
  });

  it("full audit pipeline simulation", () => {
    const lockfile = generateLockfile(1000, 4);
    
    const start = performance.now();
    
    const { packages } = extractPackagesFromLockfile(lockfile);
    const graph = buildDependencyGraph(lockfile);
    
    // Simulate tracing chains for some findings
    for (let i = 0; i < Math.min(50, graph.nodes.size); i++) {
      const key = Array.from(graph.nodes.keys())[i]!;
      traceDependencyChain(graph, key);
    }
    
    const elapsed = performance.now() - start;
    console.log(`  Full pipeline (1000 pkgs): ${elapsed.toFixed(2)}ms (${packages.length} packages, ${graph.nodes.size} nodes)`);
    assert.ok(elapsed < 5000, `Should complete pipeline in under 5s, took ${elapsed.toFixed(2)}ms`);
  });
});
