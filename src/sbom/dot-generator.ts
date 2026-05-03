/**
 * SBOM Graphviz DOT Diagram Generator.
 *
 * Generates Graphviz DOT format dependency graphs from CycloneDX/SPDX SBOM
 * documents. Builds on the tree structure from dependency-tree.ts and produces
 * valid DOT syntax with node styling, vulnerability highlighting, and
 * configurable layout options.
 *
 * @module sbom/dot-generator
 *
 * @example
 * ```typescript
 * import { generateDotFromSbom } from './sbom/dot-generator';
 *
 * const dot = generateDotFromSbom(cyclonedxBom, {
 *   rankdir: 'LR',
 *   highlightVulnerable: true,
 *   title: 'My Project Dependencies',
 * });
 * console.log(dot);
 * // Can be piped to `dot -Tsvg -o graph.svg`
 * ```
 */

import { buildTreeFromSbom } from "./dependency-tree";
import type { DotOptions, TreeNode, TreeVulnerability } from "./types";

// ============================================================================
// Constants
// ============================================================================

/** Default DOT generation options */
const DEFAULT_DOT_OPTIONS: Required<DotOptions> = {
  rankdir: "TB",
  showVersions: true,
  highlightVulnerable: true,
  title: "",
  maxDepth: Infinity,
};

// ============================================================================
// DOT ID Sanitization & Label Escaping
// ============================================================================

/**
 * Sanitize a package name for use as a DOT node ID.
 *
 * DOT node IDs can contain alphanumerics and underscores, but must start
 * with a letter or underscore. We prefix with `pkg_` and replace any
 * non-alphanumeric characters (except underscore) with underscores.
 * Multiple consecutive underscores are collapsed.
 */
function sanitizeId(name: string): string {
  const sanitized = `pkg_${name.replace(/[^A-Za-z0-9_]/g, "_")}`;
  return sanitized.replace(/_+/g, "_");
}

/**
 * Escape a label string for use in DOT syntax.
 *
 * DOT labels enclosed in double-quotes require escaping of:
 * - Double quotes (`"` → `\"`)
 * - Backslashes (`\` → `\\`)
 * - Angle brackets (`<` → `\u003c`, `>` → `\u003e`) for label-only safety
 */
function escapeLabel(text: string): string {
  return text
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e");
}

// ============================================================================
// Tree Walking & Node/Edge Collection
// ============================================================================

interface CollectedNode {
  /** Sanitized DOT node ID */
  id: string;
  /** Display label (name@version) */
  label: string;
  /** Vulnerabilities attached to this node */
  vulnerabilities: TreeVulnerability[];
  /** Maximum severity string (for color lookup) */
  maxSeverity: string | null;
}

interface CollectedEdge {
  /** Parent node sanitized ID */
  from: string;
  /** Child node sanitized ID */
  to: string;
}

/**
 * Walk the tree and collect all unique nodes and edges.
 * Handles cycles via the `visited` set and respects maxDepth.
 */
function collectNodesAndEdges(
  root: TreeNode,
  options: Required<DotOptions>,
): { nodes: CollectedNode[]; edges: CollectedEdge[] } {
  const nodes: CollectedNode[] = [];
  const edges: CollectedEdge[] = [];
  const seenIds = new Set<string>();

  const SEVERITY_RANK: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    unknown: 0,
  };

  function addNode(node: TreeNode): string {
    const fullName = node.group
      ? `${node.group}/${node.name}`
      : node.name;
    const label =
      options.showVersions && node.version
        ? `${fullName}@${node.version}`
        : fullName;
    const id = sanitizeId(fullName);

    if (!seenIds.has(id)) {
      seenIds.add(id);

      const vulns = node.vulnerabilities ?? [];
      let maxSeverity: string | null = null;
      let maxRank = -1;
      for (const v of vulns) {
        const rank = SEVERITY_RANK[v.severity] ?? -1;
        if (rank > maxRank) {
          maxRank = rank;
          maxSeverity = v.severity;
        }
      }

      nodes.push({ id, label, vulnerabilities: vulns, maxSeverity });
    }

    return id;
  }

  function walk(node: TreeNode, depth: number): string {
    if (depth > options.maxDepth) return "";
    const parentId = addNode(node);

    for (const child of node.children) {
      if (depth + 1 > options.maxDepth) continue;
      const childId = addNode(child);
      edges.push({ from: parentId, to: childId });
      walk(child, depth + 1);
    }

    return parentId;
  }

  walk(root, 0);

  return { nodes, edges };
}

// ============================================================================
// DOT Syntax Generation
// ============================================================================

/** Severity → fillcolor mapping for DOT node attributes. */
const SEVERITY_FILLCOLORS: Record<string, string> = {
  critical: "#ffcdd2",
  high: "#ffcdd2",
  medium: "#ffe0b2",
  low: "#fff9c4",
  unknown: "#dee2e6",
};

const SAFE_FILLCOLOR = "#e8f5e9";
const DEFAULT_VULN_FILLCOLOR = "#dee2e6";

/** Look up the fill color for a severity string. */
function getSeverityFillColor(severity: string | null): string {
  if (severity === null) return SAFE_FILLCOLOR;
  return SEVERITY_FILLCOLORS[severity] ?? DEFAULT_VULN_FILLCOLOR;
}

/**
 * Generate a valid Graphviz DOT dependency graph string from a tree.
 *
 * @param sbom - Parsed SBOM JSON document (CycloneDX or SPDX)
 * @param options - DOT generation options
 * @returns Valid DOT syntax string
 */
export function generateDotFromSbom(
  sbom: Record<string, unknown>,
  options?: DotOptions,
): string {
  const opts: Required<DotOptions> = {
    ...DEFAULT_DOT_OPTIONS,
    ...options,
  };

  // Build the dependency tree from the SBOM document
  const root = buildTreeFromSbom(sbom, {
    maxDepth: opts.maxDepth,
    showVersions: opts.showVersions,
    showVulnerabilities: opts.highlightVulnerable,
    highlightVulnerable: opts.highlightVulnerable,
  });

  // Collect all nodes and edges from the tree
  const { nodes, edges } = collectNodesAndEdges(root, opts);

  const lines: string[] = [];

  // Start the digraph
  lines.push("digraph dependencies {");

  // Graph attributes
  lines.push(`    rankdir=${opts.rankdir};`);

  if (opts.title) {
    lines.push(`    label="${escapeLabel(opts.title)}";`);
    lines.push("    labelloc=t;");
    lines.push('    fontname="Helvetica-Bold";');
    lines.push("    fontsize=16;");
  }

  // Default node attributes
  lines.push(
    '    node [shape=box, style="rounded,filled", fontname="Helvetica"];',
  );

  // Default edge attributes
  lines.push('    edge [color="#666666"];');

  lines.push("");

  // Handle empty graph (no nodes at all)
  if (nodes.length === 0) {
    const fallbackLabel = opts.title
      ? escapeLabel(opts.title)
      : "Empty Graph";
    lines.push(`    empty [label="${fallbackLabel}"];`);
    lines.push("}");
    return lines.join("\n");
  }

  // Node definitions
  for (const node of nodes) {
    const escapedLabel = escapeLabel(node.label);
    const fillColor = opts.highlightVulnerable
      ? getSeverityFillColor(node.maxSeverity)
      : SAFE_FILLCOLOR;
    lines.push(
      `    ${node.id} [label="${escapedLabel}", fillcolor="${fillColor}"];`,
    );
  }

  lines.push("");

  // Edge definitions
  for (const edge of edges) {
    lines.push(`    ${edge.from} -> ${edge.to};`);
  }

  lines.push("}");

  return lines.join("\n");
}
