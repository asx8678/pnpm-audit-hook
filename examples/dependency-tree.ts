#!/usr/bin/env tsx
// =============================================================================
// dependency-tree.ts — Dependency Tree Visualization Demo
// =============================================================================
//
// Demonstrates dependency tree building and rendering:
//   - Building a tree from a CycloneDX SBOM
//   - Building a tree from a pnpm lockfile
//   - Rendering as ASCII art with box-drawing characters
//   - Rendering as JSON output
//   - Limiting tree traversal depth
//   - Highlighting vulnerable packages with markers
//
// Prerequisites:
//   - Node.js >= 18
//   - Project dependencies installed (`pnpm install`)
//   - Run from project root: npx tsx examples/dependency-tree.ts
// =============================================================================

// ---------------------------------------------------------------------------
// Imports from pnpm-audit-hook source (relative to this file)
// ---------------------------------------------------------------------------
import {
  generateSbom,
  buildTreeFromSbom,
  buildTreeFromLockfile,
  renderTree,
  renderTreeJson,
} from "../src/index";

import type { PackageRef, VulnerabilityFinding } from "../src/index";
import type { TreeOptions, TreeNode, TreeJsonOutput } from "../src/sbom/types";

// ---------------------------------------------------------------------------
// Sample package graph with deep nesting to showcase the tree.
// Express → body-parser → debug → ms (3 levels deep).
// Axios → follow-redirects → debug → ms (shares the same debug node).
// ---------------------------------------------------------------------------
const PACKAGES: PackageRef[] = [
  // Root app
  {
    name: "my-app",
    version: "1.0.0",
    dependencies: ["express", "lodash", "axios"],
  },
  // Express chain
  {
    name: "express",
    version: "4.18.2",
    dependencies: ["body-parser", "cookie", "router"],
  },
  {
    name: "body-parser",
    version: "1.20.2",
    dependencies: ["debug", "bytes"],
  },
  {
    name: "debug",
    version: "4.3.4",
    dependencies: ["ms"],
  },
  { name: "ms", version: "2.1.2" },
  { name: "bytes", version: "3.1.2" },
  { name: "cookie", version: "0.6.0" },
  {
    name: "router",
    version: "2.0.0",
    dependencies: ["debug"],
  },
  // Lodash (no children — leaf node)
  { name: "lodash", version: "4.17.21" },
  // Axios chain
  {
    name: "axios",
    version: "1.6.2",
    dependencies: ["follow-redirects", "form-data"],
  },
  {
    name: "follow-redirects",
    version: "1.15.4",
    dependencies: ["debug"],
  },
  {
    name: "form-data",
    version: "4.0.0",
    dependencies: ["mime-types"],
  },
  {
    name: "mime-types",
    version: "2.1.35",
    dependencies: ["mime-db"],
  },
  { name: "mime-db", version: "1.52.0" },
];

/** Simulated vulnerability findings for two packages */
const FINDINGS: VulnerabilityFinding[] = [
  {
    id: "CVE-2023-26159",
    source: "github",
    packageName: "debug",
    packageVersion: "4.3.4",
    severity: "medium",
    cvssScore: 5.3,
    title: "ReDoS in debug",
  },
  {
    id: "CVE-2024-28849",
    source: "github",
    packageName: "follow-redirects",
    packageVersion: "1.15.4",
    severity: "high",
    cvssScore: 7.4,
    title: "Authorization header leak",
  },
];

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║     pnpm-audit-hook — Dependency Tree Example              ║");
  console.log("╚══════════════════════════════════════════════════════════════╝\n");

  // -------------------------------------------------------------------------
  // Step 1: Generate a CycloneDX SBOM with dependency relationships
  // -------------------------------------------------------------------------
  console.log("▸ Step 1: Generating CycloneDX SBOM…\n");

  const sbomResult = generateSbom(PACKAGES, FINDINGS, {
    format: "cyclonedx",
    includeDependencies: true,
    includeVulnerabilities: true,
    projectName: "tree-demo",
    projectVersion: "1.0.0",
  });

  const bom = JSON.parse(sbomResult.content);
  console.log(`  SBOM generated: ${sbomResult.componentCount} components\n`);

  // -------------------------------------------------------------------------
  // Step 2: Build a full dependency tree from the SBOM
  // -------------------------------------------------------------------------
  console.log("▸ Step 2: Building full dependency tree…\n");

  /**
   * buildTreeFromSbom() parses a CycloneDX BOM and builds a TreeNode
   * hierarchy. Options control version display, vulnerability markers, etc.
   */
  const fullTree: TreeNode = buildTreeFromSbom(bom, {
    showVersions: true,
    showVulnerabilities: true,
    highlightVulnerable: true,
  });

  console.log(`  Root: ${fullTree.name}@${fullTree.version}`);
  console.log(`  Direct dependencies: ${fullTree.children.length}`);
  console.log(`  Tree depth: ${measureDepth(fullTree)}`);
  console.log();

  // -------------------------------------------------------------------------
  // Step 3: Render as ASCII art
  // -------------------------------------------------------------------------
  console.log("▸ Step 3: ASCII tree rendering (full depth)…\n");

  /**
   * renderTree() produces a string with box-drawing characters for a
   * pretty terminal-friendly tree display.
   */
  const asciiTree = renderTree(fullTree);
  const asciiLines = asciiTree.split("\n");
  for (const line of asciiLines.slice(0, 30)) {
    console.log(`  ${line}`);
  }
  if (asciiLines.length > 30) {
    console.log(`  … (${asciiLines.length - 30} more lines)`);
  }
  console.log();

  // -------------------------------------------------------------------------
  // Step 4: Render as JSON
  // -------------------------------------------------------------------------
  console.log("▸ Step 4: JSON tree rendering…\n");

  /**
   * renderTreeJson() produces a structured TreeJsonOutput suitable for
   * piping into other tools, writing to files, or further processing.
   */
  const jsonTree: TreeJsonOutput = renderTreeJson(fullTree);
  const jsonStr = JSON.stringify(jsonTree, null, 2);
  const jsonLines = jsonStr.split("\n");
  for (const line of jsonLines.slice(0, 30)) {
    console.log(`  ${line}`);
  }
  if (jsonLines.length > 30) {
    console.log(`  … (${jsonLines.length - 30} more lines)`);
  }
  console.log();

  // -------------------------------------------------------------------------
  // Step 5: Limit tree depth
  // -------------------------------------------------------------------------
  console.log("▸ Step 5: Depth-limited trees…\n");

  /**
   * maxDepth limits how many levels of the dependency tree are traversed.
   * Useful for summarizing large dependency graphs.
   */
  for (const depth of [1, 2, 3]) {
    const limitedTree = buildTreeFromSbom(bom, {
      maxDepth: depth,
      showVersions: true,
      showVulnerabilities: true,
    });

    const rendered = renderTree(limitedTree);
    const lines = rendered.split("\n");
    const nodeCount = countNodes(limitedTree);

    console.log(`  Depth limit: ${depth} (${nodeCount} nodes)`);
    for (const line of lines) {
      console.log(`    ${line}`);
    }
    console.log();
  }

  // -------------------------------------------------------------------------
  // Step 6: Show vulnerability markers in the tree
  // -------------------------------------------------------------------------
  console.log("▸ Step 6: Vulnerability analysis from tree…\n");

  const vulnTree = buildTreeFromSbom(bom, {
    showVersions: true,
    showVulnerabilities: true,
    highlightVulnerable: true,
  });

  const vulnNodes = findVulnerableNodes(vulnTree);
  console.log(`  Found ${vulnNodes.length} vulnerable node(s) in the tree:\n`);

  for (const node of vulnNodes) {
    console.log(`  ⚠️  ${node.name}@${node.version}`);
    if (node.vulnerabilities) {
      for (const v of node.vulnerabilities) {
        console.log(`      └─ ${v.id} (${v.severity})`);
      }
    }
  }
  console.log();

  // -------------------------------------------------------------------------
  // Step 7: Build tree from a pnpm lockfile
  // -------------------------------------------------------------------------
  console.log("▸ Step 7: Building tree from a pnpm lockfile…\n");

  /**
   * buildTreeFromLockfile() parses a raw pnpm lockfile structure directly,
   * bypassing SBOM generation. Useful when you already have the lockfile
   * and don't need SBOM output.
   */
  const lockfileTree = buildTreeFromLockfile(
    {
      lockfileVersion: "9.0",
      importers: {
        ".": {
          dependencies: {
            express: { version: "4.18.2" },
            lodash: { version: "4.17.21" },
          },
        },
      },
      packages: {
        "express@4.18.2": {
          dependencies: { "body-parser": "1.20.2" },
        },
        "body-parser@1.20.2": {
          dependencies: { "debug": "4.3.4", "bytes": "3.1.2" },
        },
        "debug@4.3.4": {
          dependencies: { "ms": "2.1.2" },
        },
        "ms@2.1.2": {},
        "bytes@3.1.2": {},
        "lodash@4.17.21": {},
      },
    },
    { showVersions: true },
  );

  console.log("  Tree from lockfile:");
  const lockfileAscii = renderTree(lockfileTree);
  for (const line of lockfileAscii.split("\n")) {
    console.log(`    ${line}`);
  }
  console.log();

  // -------------------------------------------------------------------------
  // Step 8: Different options for rendering
  // -------------------------------------------------------------------------
  console.log("▸ Step 8: Different rendering options…\n");

  // Without versions — cleaner look for large trees
  const noVersions = buildTreeFromSbom(bom, {
    showVersions: false,
    showVulnerabilities: false,
  });
  const noVersionsAscii = renderTree(noVersions);
  console.log("  Without versions or vulnerability markers:");
  for (const line of noVersionsAscii.split("\n").slice(0, 10)) {
    console.log(`    ${line}`);
  }
  console.log();

  // JSON output without vulnerabilities
  const cleanJson = renderTreeJson(noVersions);
  console.log("  JSON output (no versions, no vulnerabilities):");
  const cleanJsonLines = JSON.stringify(cleanJson, null, 2).split("\n");
  for (const line of cleanJsonLines.slice(0, 12)) {
    console.log(`    ${line}`);
  }
  console.log();

  // -------------------------------------------------------------------------
  // Done!
  // -------------------------------------------------------------------------
  console.log("─".repeat(62));
  console.log("Done! Dependency tree visualization completed. 🐶");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Measure the maximum depth of a tree (0 = leaf node).
 *
 * @param node - Root node to measure from
 * @returns Maximum depth in levels
 */
function measureDepth(node: TreeNode): number {
  if (node.children.length === 0) return 0;
  return 1 + Math.max(...node.children.map(measureDepth));
}

/**
 * Count total nodes in a tree (including the root).
 *
 * @param node - Root node to count from
 * @returns Total number of nodes
 */
function countNodes(node: TreeNode): number {
  return 1 + node.children.reduce((sum, c) => sum + countNodes(c), 0);
}

/**
 * Recursively find all nodes that have vulnerability markers.
 *
 * @param node - Root node to search from
 * @returns Array of nodes with vulnerabilities
 */
function findVulnerableNodes(node: TreeNode): TreeNode[] {
  const result: TreeNode[] = [];
  if (node.vulnerabilities && node.vulnerabilities.length > 0) {
    result.push(node);
  }
  for (const child of node.children) {
    result.push(...findVulnerableNodes(child));
  }
  return result;
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------
main().catch((err) => {
  console.error("Unhandled error:", err);
  process.exit(1);
});
