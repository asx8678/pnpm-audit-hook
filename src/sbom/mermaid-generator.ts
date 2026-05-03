/**
 * SBOM Mermaid Diagram Generator.
 *
 * Generates Mermaid.js dependency graphs from CycloneDX/SPDX SBOM documents.
 * Builds on the tree structure from dependency-tree.ts and produces valid
 * Mermaid syntax with node styling, vulnerability highlighting, and
 * configurable layout options.
 *
 * @module sbom/mermaid-generator
 *
 * @example
 * ```typescript
 * import { generateMermaidFromSbom } from './sbom/mermaid-generator';
 *
 * const mermaid = generateMermaidFromSbom(cyclonedxBom, {
 *   direction: 'TB',
 *   highlightVulnerable: true,
 *   title: 'My Project Dependencies',
 * });
 * console.log(mermaid);
 * ```
 */

import { buildTreeFromSbom } from "./dependency-tree";
import type { MermaidOptions, TreeNode, TreeVulnerability } from "./types";

// ============================================================================
// Constants
// ============================================================================

/** Default Mermaid generation options */
const DEFAULT_MERMAID_OPTIONS: Required<MermaidOptions> = {
  direction: "TB",
  showVersions: true,
  highlightVulnerable: true,
  title: "",
  maxDepth: Infinity,
};

// ============================================================================
// Mermaid ID Sanitization
// ============================================================================

/**
 * Sanitize a package name for use as a Mermaid node ID.
 *
 * Mermaid IDs must match `[A-Za-z][A-Za-z0-9_]*`. We prefix with `pkg_`
 * and replace any non-alphanumeric characters (except underscore) with
 * underscores.
 */
function sanitizeId(name: string): string {
  // Prefix to ensure valid starting character, replace invalid chars
  const sanitized = `pkg_${name.replace(/[^A-Za-z0-9_]/g, "_")}`;
  // Collapse multiple consecutive underscores
  return sanitized.replace(/_+/g, "_");
}

/**
 * Escape a Mermaid node label string.
 * Double-quotes in labels must be escaped with `&quot;`.
 * Other HTML-sensitive characters are escaped for safety.
 */
function escapeLabel(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/#/g, "___HASH___");
}

// ============================================================================
// Tree Walking & Node/Edge Collection
// ============================================================================

interface CollectedNode {
  /** Sanitized Mermaid ID */
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
  options: Required<MermaidOptions>,
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
    const label = options.showVersions && node.version
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
// Mermaid Syntax Generation
// ============================================================================

/** Severity → color pairs for Mermaid style directives. */
const SEVERITY_COLORS: Record<string, { fill: string; color: string }> = {
  critical: { fill: "#ff6b6b", color: "#fff" },
  high:     { fill: "#ff6b6b", color: "#fff" },
  medium:   { fill: "#ffa94d", color: "#fff" },
  low:      { fill: "#ffd43b", color: "#000" },
  unknown:  { fill: "#dee2e6", color: "#333" },
};

const DEFAULT_VULN_COLOR = { fill: "#dee2e6", color: "#333" } as const;

/** Look up the color pair for a severity string, falling back to grey. */
function getSeverityColor(severity: string): { fill: string; color: string } {
  const entry = SEVERITY_COLORS[severity];
  if (entry !== undefined) return entry;
  return DEFAULT_VULN_COLOR;
}

/**
 * Generate a Mermaid `style` directive line for a vulnerable node.
 */
function styleLine(id: string, severity: string): string {
  const colors = getSeverityColor(severity);
  return `    style ${id} fill:${colors.fill},color:${colors.color}`;
}

/**
 * Generate a valid Mermaid dependency graph string from a tree.
 *
 * @param root - Root TreeNode (from buildTreeFromSbom)
 * @param options - Mermaid generation options
 * @returns Valid Mermaid syntax string
 */
export function generateMermaidFromSbom(
  sbom: Record<string, unknown>,
  options?: MermaidOptions,
): string {
  const opts: Required<MermaidOptions> = {
    ...DEFAULT_MERMAID_OPTIONS,
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

  // Handle empty SBOM (no components)
  if (nodes.length === 0) {
    const lines: string[] = [];
    if (opts.title) {
      lines.push("---");
      lines.push(`title: ${opts.title}`);
      lines.push("---");
    }
    lines.push(`graph ${opts.direction}`);
    lines.push('    empty["No dependencies"]');
    return lines.join("\n");
  }

  // Start building the Mermaid output
  const lines: string[] = [];

  // Optional title block
  if (opts.title) {
    lines.push("---");
    lines.push(`title: ${opts.title}`);
    lines.push("---");
  }

  // Graph declaration
  lines.push(`graph ${opts.direction}`);
  lines.push("");

  // Node definitions (quoted labels)
  for (const node of nodes) {
    const escapedLabel = escapeLabel(node.label);
    lines.push(`    ${node.id}["${escapedLabel}"]`);
  }

  lines.push("");

  // Edge definitions
  for (const edge of edges) {
    lines.push(`    ${edge.from} --> ${edge.to}`);
  }

  // Vulnerability style directives
  if (opts.highlightVulnerable) {
    const styledNodes = nodes.filter((n) => n.maxSeverity !== null);
    if (styledNodes.length > 0) {
      lines.push("");
      for (const node of styledNodes) {
        lines.push(styleLine(node.id, node.maxSeverity!));
      }
    }
  }

  return lines.join("\n");
}
