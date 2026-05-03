/**
 * SBOM Dependency Tree Visualization.
 *
 * Builds and renders dependency trees from CycloneDX/SPDX SBOM documents
 * or pnpm lockfiles. Supports ASCII (box-drawing) and JSON output formats.
 *
 * @module sbom/dependency-tree
 *
 * @example
 * ```typescript
 * import { buildTreeFromSbom, renderTree } from './sbom/dependency-tree';
 *
 * const tree = buildTreeFromSbom(cyclonedxBom, { maxDepth: 3 });
 * console.log(renderTree(tree));
 * ```
 */

import * as fs from "node:fs";
import type {
  CycloneDXBom,
  CycloneDXDependency,
  CycloneDXVulnerability,
  SPDXDocument,
  SPDXPackage,
  SPDXRelationship,
  TreeNode,
  TreeJsonOutput,
  TreeOptions,
  TreeVulnerability,
} from "./types";

// ============================================================================
// Purl Parsing Helpers
// ============================================================================

/** Parse a purl string into { name, version, group }. Returns null if invalid. */
function parsePurl(
  purl: string,
): { name: string; version: string; group?: string } | null {
  // Format: pkg:npm/name@version  or  pkg:npm/%40scope/name@version
  const match = purl.match(/^pkg:npm\/(.+)@(.+)$/);
  if (!match) return null;

  let name = decodeURIComponent(match[1]!);
  const version = match[2]!;

  let group: string | undefined;
  if (name.startsWith("@")) {
    const slashIdx = name.indexOf("/");
    if (slashIdx !== -1) {
      group = name.slice(0, slashIdx);
      name = name.slice(slashIdx + 1);
    }
  }

  return { name, version, group };
}

/** Strip version suffix from purl to get the base purl for dependency refs. */
function purlToBaseRef(purl: string): string {
  const atIdx = purl.lastIndexOf("@");
  if (atIdx === -1) return purl;
  return purl.slice(0, atIdx);
}

/** Build a bom-ref for a component. Matches CycloneDX generator format. */
function makeBomRef(name: string, version: string): string {
  return `pkg:npm/${encodeURIComponent(name)}@${version}`;
}

/** Extract name from a bom-ref or purl. */
function nameFromRef(ref: string): string {
  const match = ref.match(/^pkg:npm\/(.+)@(.+)$/);
  if (!match) return ref;
  let name = decodeURIComponent(match[1]!);
  if (name.startsWith("@")) {
    const slashIdx = name.indexOf("/");
    if (slashIdx !== -1) {
      name = name.slice(slashIdx + 1);
    }
  }
  return name;
}

// ============================================================================
// CycloneDX Tree Builder
// ============================================================================

/** Build a dependency tree from a CycloneDX BOM document. */
function buildTreeFromCycloneDX(
  bom: CycloneDXBom,
  options: Required<TreeOptions>,
): TreeNode {
  const components = bom.components ?? [];
  const dependencies = bom.dependencies ?? [];
  const vulnerabilities = bom.vulnerabilities ?? [];

  // Index components by bom-ref (both encoded and decoded forms for robust matching)
  const componentByRef = new Map<string, (typeof components)[0]>();
  const componentByDecodedRef = new Map<string, (typeof components)[0]>();
  for (const cmp of components) {
    componentByRef.set(cmp["bom-ref"], cmp);
    // Also store with decoded name for matching non-encoded refs in dependsOn
    const decoded = decodeURIComponent(cmp["bom-ref"]);
    if (decoded !== cmp["bom-ref"]) {
      componentByDecodedRef.set(decoded, cmp);
    }
  }

  // Index dependencies by ref
  const dependsOnByRef = new Map<string, string[]>();
  for (const dep of dependencies) {
    dependsOnByRef.set(dep.ref, dep.dependsOn ?? []);
  }

  // Helper to resolve a component ref with fallback to decoded form
  function resolveComponent(ref: string): (typeof components)[0] | undefined {
    return componentByRef.get(ref) ?? componentByDecodedRef.get(decodeURIComponent(ref));
  }

  // Index vulnerabilities by bom-ref
  const vulnsByRef = new Map<string, TreeVulnerability[]>();
  for (const vuln of vulnerabilities) {
    for (const affect of vuln.affects ?? []) {
      const severity =
        vuln.ratings?.[0]?.severity ?? "unknown";
      const entry: TreeVulnerability = {
        id: vuln.id,
        severity,
      };
      const existing = vulnsByRef.get(affect.ref);
      if (existing) {
        existing.push(entry);
      } else {
        vulnsByRef.set(affect.ref, [entry]);
      }
    }
  }

  // Find the root component (from metadata.component) or use the first component
  let rootRef: string | undefined;
  if (bom.metadata.component) {
    rootRef = bom.metadata.component["bom-ref"];
  }

  // If no root component, find a component that nothing depends on
  if (!rootRef && components.length > 0) {
    const allDependedOn = new Set<string>();
    for (const dep of dependencies) {
      for (const d of dep.dependsOn ?? []) {
        allDependedOn.add(d);
        // Also add encoded form for scoped package matching
        const encoded = encodeURIComponent(decodeURIComponent(d));
        if (encoded !== d) allDependedOn.add(encoded);
        // And decoded form
        const decoded = decodeURIComponent(d);
        if (decoded !== d) allDependedOn.add(decoded);
      }
    }
    for (const cmp of components) {
      const bomRef = cmp["bom-ref"];
      if (
        !allDependedOn.has(bomRef) &&
        !allDependedOn.has(decodeURIComponent(bomRef))
      ) {
        rootRef = bomRef;
        break;
      }
    }
    // Fallback: just use the first component
    if (!rootRef) {
      rootRef = components[0]!["bom-ref"];
    }
  }

  // Build root node
  const rootComponent = rootRef ? componentByRef.get(rootRef) : undefined;
  const rootName = rootComponent
    ? rootComponent.name
    : bom.metadata.component?.name ?? "project";
  const rootVersion = rootComponent?.version ?? bom.metadata.component?.version ?? "0.0.0";

  const visited = new Set<string>();

  function buildNode(
    ref: string,
    depth: number,
  ): TreeNode | null {
    if (depth > options.maxDepth) return null;
    if (visited.has(ref)) {
      // Cycle detected — still show the node, but with empty children
      const cmp = resolveComponent(ref);
      if (!cmp) return null;
      const parsed = parsePurl(cmp.purl);
      return {
        name: parsed?.name ?? cmp.name,
        version: options.showVersions ? cmp.version : "",
        group: parsed?.group,
        purl: cmp.purl,
        children: [],
        vulnerabilities: options.showVulnerabilities
          ? (vulnsByRef.get(ref) ?? [])
          : undefined,
        depth,
      };
    }
    visited.add(ref);

    const cmp = resolveComponent(ref);
    if (!cmp) return null;

    const parsed = parsePurl(cmp.purl);
    const childRefs = dependsOnByRef.get(ref) ?? [];
    const children: TreeNode[] = [];

    for (const childRef of childRefs) {
      const childNode = buildNode(childRef, depth + 1);
      if (childNode) {
        children.push(childNode);
      }
    }

    return {
      name: parsed?.name ?? cmp.name,
      version: options.showVersions ? cmp.version : "",
      group: parsed?.group,
      purl: cmp.purl,
      children,
      vulnerabilities: options.showVulnerabilities
        ? (vulnsByRef.get(ref) ?? [])
        : undefined,
      depth,
    };
  }

  const rootNode = buildNode(rootRef ?? "", 0);
  if (rootNode) return rootNode;

  // Fallback if no root found
  return {
    name: bom.metadata.component?.name ?? rootName,
    version: options.showVersions
      ? (bom.metadata.component?.version ?? rootVersion)
      : "",
    children: [],
    depth: 0,
  };
}

// ============================================================================
// SPDX Tree Builder
// ============================================================================

/** Build a dependency tree from an SPDX document. */
function buildTreeFromSpdx(
  doc: SPDXDocument,
  options: Required<TreeOptions>,
): TreeNode {
  const packages = doc.packages ?? [];
  const relationships = doc.relationships ?? [];

  // Index packages by SPDXID
  const pkgBySpdxId = new Map<string, SPDXPackage>();
  for (const pkg of packages) {
    pkgBySpdxId.set(pkg.SPDXID, pkg);
  }

  // Build dependency map: parent SPDXID → [child SPDXID]
  const depsBySpdxId = new Map<string, string[]>();
  for (const rel of relationships) {
    if (rel.RelationshipType === "DEPENDS_ON" || rel.RelationshipType === "DESCRIBES") {
      const existing = depsBySpdxId.get(rel.SPDXElementID);
      if (existing) {
        existing.push(rel.RelatedSPDXElement);
      } else {
        depsBySpdxId.set(rel.SPDXElementID, [rel.RelatedSPDXElement]);
      }
    }
  }

  // Find root: DOCUMENT package first, then DESCRIBES source
  let rootSpdxId: string | undefined;
  let hasDocumentPkg = false;
  for (const pkg of packages) {
    if (pkg.SPDXID === "SPDXRef-DOCUMENT") {
      rootSpdxId = pkg.SPDXID;
      hasDocumentPkg = true;
      break;
    }
  }
  if (!rootSpdxId) {
    // Find the source of a DESCRIBES relationship
    for (const rel of relationships) {
      if (rel.RelationshipType === "DESCRIBES") {
        rootSpdxId = rel.SPDXElementID;
        break;
      }
    }
  }

  const visited = new Set<string>();

  function buildNode(
    spdxId: string,
    depth: number,
  ): TreeNode | null {
    if (depth > options.maxDepth) return null;
    if (visited.has(spdxId)) return null;
    visited.add(spdxId);

    const pkg = pkgBySpdxId.get(spdxId);
    if (!pkg) return null;

    // Skip the DOCUMENT node — treat its DESCRIBES targets as root children
    if (pkg.SPDXID === "SPDXRef-DOCUMENT") {
      const childSpdxIds = depsBySpdxId.get(spdxId) ?? [];
      const children: TreeNode[] = [];
      for (const childId of childSpdxIds) {
        const childNode = buildNode(childId, depth);
        if (childNode) children.push(childNode);
      }
      return {
        name: pkg.name,
        version: options.showVersions ? pkg.versionInfo : "",
        children,
        depth,
      };
    }

    // Extract purl from externalRefs
    let purl: string | undefined;
    for (const ref of pkg.externalRefs ?? []) {
      if (ref.referenceType === "purl") {
        purl = ref.referenceLocator;
        break;
      }
    }

    const parsed = purl ? parsePurl(purl) : null;
    const childSpdxIds = depsBySpdxId.get(spdxId) ?? [];
    const children: TreeNode[] = [];

    for (const childId of childSpdxIds) {
      const childNode = buildNode(childId, depth + 1);
      if (childNode) children.push(childNode);
    }

    return {
      name: parsed?.name ?? pkg.name,
      version: options.showVersions ? pkg.versionInfo : "",
      group: parsed?.group,
      purl,
      children,
      depth,
    };
  }

  // If no root package found but document has relationships, build from all DESCRIBES targets
  if (!rootSpdxId && relationships.length > 0) {
    const children: TreeNode[] = [];
    for (const rel of relationships) {
      if (rel.RelationshipType === "DESCRIBES") {
        const childNode = buildNode(rel.RelatedSPDXElement, 0);
        if (childNode) children.push(childNode);
      }
    }
    if (children.length > 0) {
      return {
        name: doc.name ?? "unknown",
        version: "",
        children,
        depth: 0,
      };
    }
  }

  if (rootSpdxId) {
    const root = buildNode(rootSpdxId, 0);
    if (root) return root;
  }

  // Fallback: just return the document info
  return {
    name: doc.name ?? "unknown",
    version: "",
    children: [],
    depth: 0,
  };
}

// ============================================================================
// Public API
// ============================================================================

/**
 * Default options for tree building and rendering.
 */
const DEFAULT_OPTIONS: Required<TreeOptions> = {
  maxDepth: Infinity,
  showVersions: true,
  showVulnerabilities: true,
  highlightVulnerable: true,
  format: "ascii",
};

/**
 * Build a dependency tree from an SBOM document (CycloneDX or SPDX).
 *
 * @param sbom - Parsed SBOM JSON document
 * @param options - Tree building options
 * @returns Root tree node
 */
export function buildTreeFromSbom(
  sbom: Record<string, unknown>,
  options?: TreeOptions,
): TreeNode {
  const opts = { ...DEFAULT_OPTIONS, ...options };

  // Detect format
  if (sbom.bomFormat === "CycloneDX" || sbom.specVersion) {
    return buildTreeFromCycloneDX(sbom as unknown as CycloneDXBom, opts);
  }
  if (sbom.spdxVersion || sbom.SPDXID) {
    return buildTreeFromSpdx(sbom as unknown as SPDXDocument, opts);
  }

  throw new Error(
    "Unrecognized SBOM format. Expected CycloneDX (bomFormat: 'CycloneDX') or SPDX (spdxVersion).",
  );
}

/**
 * Build a dependency tree from a pnpm lockfile path.
 *
 * Parses the lockfile and constructs the dependency tree using
 * the same extraction logic as SBOM generation.
 *
 * @param lockfilePath - Path to pnpm-lock.yaml
 * @param options - Tree building options
 * @returns Root tree node
 */
export function buildTreeFromLockfile(
  lockfilePath: string,
  options?: TreeOptions,
): TreeNode {
  const opts = { ...DEFAULT_OPTIONS, ...options };

  const YAML = require("yaml");
  const content = fs.readFileSync(lockfilePath, "utf-8");
  const lockfile = YAML.parse(content);

  if (!lockfile || typeof lockfile !== "object") {
    throw new Error("Invalid lockfile format");
  }

  // Parse lockfile packages into a tree structure
  const packages = lockfile.packages ?? ({} as Record<string, unknown>);
  const importers = lockfile.importers ?? ({} as Record<string, unknown>);

  // Build package lookup: "name@version" → { name, version, deps }
  interface PkgInfo {
    name: string;
    version: string;
    dependencies: Record<string, string>;
  }

  const pkgLookup = new Map<string, PkgInfo>();
  const pkgKeys = Object.keys(packages);

  for (let i = 0; i < pkgKeys.length; i++) {
    const key = pkgKeys[i]!;
    const entry = (packages as Record<string, Record<string, unknown>>)[key]!;
    const parsed = parseLockfileKey(key);
    if (!parsed) continue;

    const deps: Record<string, string> = {};
    const depFields = ["dependencies", "devDependencies", "optionalDependencies"];
    for (const field of depFields) {
      const fieldDeps = entry[field] as Record<string, string> | undefined;
      if (fieldDeps) {
        for (const depName of Object.keys(fieldDeps)) {
          deps[depName] = fieldDeps[depName]!;
        }
      }
    }

    const graphKey = `${parsed.name}@${parsed.version}`;
    pkgLookup.set(graphKey, { name: parsed.name, version: parsed.version, dependencies: deps });
  }

  // Find direct dependencies from importers
  const directDeps: Array<{ name: string; version: string }> = [];
  const importerKeys = Object.keys(importers);

  for (let i = 0; i < importerKeys.length; i++) {
    const importer = (importers as Record<string, Record<string, unknown>>)[importerKeys[i]!]!;
    const depFields = ["dependencies", "devDependencies", "optionalDependencies"];
    for (const field of depFields) {
      const fieldDeps = importer[field] as Record<string, { specifier?: string; version: string } | string> | undefined;
      if (!fieldDeps) continue;
      for (const depName of Object.keys(fieldDeps)) {
        const depValue = fieldDeps[depName]!;
        const version = typeof depValue === "string" ? depValue : depValue.version;
        if (version) {
          directDeps.push({ name: depName, version });
        }
      }
    }
  }

  // Build tree nodes
  const visited = new Set<string>();

  function buildNodeFromLockfile(
    name: string,
    version: string,
    depth: number,
  ): TreeNode | null {
    if (depth > opts.maxDepth) return null;
    const key = `${name}@${version}`;

    if (visited.has(key)) {
      // Cycle: show node but don't recurse further
      return {
        name,
        version: opts.showVersions ? version : "",
        children: [],
        depth,
      };
    }
    visited.add(key);

    const pkgInfo = pkgLookup.get(key);
    const childDeps = pkgInfo?.dependencies ?? {};
    const childNames = Object.keys(childDeps);
    const children: TreeNode[] = [];

    for (const childName of childNames) {
      const childVersion = childDeps[childName]!;
      const childNode = buildNodeFromLockfile(childName, childVersion, depth + 1);
      if (childNode) children.push(childNode);
    }

    return {
      name,
      version: opts.showVersions ? version : "",
      children,
      depth,
    };
  }

  // Determine the project name
  let projectName = "project";
  if (directDeps.length > 0) {
    // Try to find from the first importer
    const firstImporter = importerKeys[0];
    if (firstImporter && firstImporter !== ".") {
      projectName = firstImporter;
    }
  }

  // Build root node
  const rootChildren: TreeNode[] = [];
  for (const dep of directDeps) {
    const node = buildNodeFromLockfile(dep.name, dep.version, 1);
    if (node) rootChildren.push(node);
  }

  // Check package.json for project name
  const path = require("node:path");
  const dir = path.dirname(lockfilePath);
  try {
    const pkgJson = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf-8"));
    if (pkgJson.name) projectName = pkgJson.name;
  } catch {
    // Ignore — use default
  }

  return {
    name: projectName,
    version: opts.showVersions ? "1.0.0" : "",
    children: rootChildren,
    depth: 0,
  };
}

/**
 * Parse a pnpm lockfile package key into name + version.
 * Supports both old format (/react/18.2.0) and v9 format (react@18.2.0).
 */
function parseLockfileKey(
  key: string,
): { name: string; version: string } | null {
  const raw = key.startsWith("/") ? key.slice(1) : key;

  const isScoped = raw.startsWith("@");
  const atIndex = isScoped ? raw.indexOf("@", 1) : raw.indexOf("@");
  const slashIndex = isScoped
    ? raw.indexOf("/", raw.indexOf("/") + 1)
    : raw.indexOf("/");

  // v9 format: uses @ separator
  if (atIndex !== -1 && (slashIndex === -1 || atIndex < slashIndex)) {
    const name = raw.slice(0, atIndex);
    const version = raw.slice(atIndex + 1);
    if (!name || !version) return null;
    return { name, version: stripPeerSuffix(version) };
  }

  // Old format: uses / separator
  const parts = raw.split("/").filter(Boolean);
  if (parts.length < 2) return null;

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

/** Strip peer dependency version suffix, e.g. "1.0.0(debug@2.6.9)" → "1.0.0" */
function stripPeerSuffix(v: string): string {
  const idx = v.indexOf("(");
  return idx === -1 ? v : v.slice(0, idx);
}

// ============================================================================
// ASCII Rendering
// ============================================================================

/** Severity emoji / label map for tree output. */
const SEVERITY_LABELS: Record<string, string> = {
  critical: "🔴 critical",
  high: "🟠 high",
  medium: "🟡 medium",
  low: "🔵 low",
  unknown: "⚪ unknown",
};

/**
 * Render a tree node as ASCII art using box-drawing characters.
 *
 * @param root - Root tree node
 * @param options - Rendering options
 * @returns ASCII tree string
 */
export function renderTree(
  root: TreeNode,
  options?: TreeOptions,
): string {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const lines: string[] = [];

  // Root line (no prefix)
  let rootLabel = root.name;
  if (opts.showVersions && root.version) {
    rootLabel += `@${root.version}`;
  }
  if (
    opts.showVulnerabilities &&
    root.vulnerabilities &&
    root.vulnerabilities.length > 0
  ) {
    const vulnStrs = root.vulnerabilities.map(
      (v) => `⚠️ ${v.id} (${v.severity})`,
    );
    rootLabel += ` ${vulnStrs.join(", ")}`;
  }
  lines.push(rootLabel);

  // Render children
  renderChildren(root.children, "", lines, opts);

  return lines.join("\n");
}

function renderChildren(
  children: TreeNode[],
  prefix: string,
  lines: string[],
  opts: Required<TreeOptions>,
): void {
  for (let i = 0; i < children.length; i++) {
    const child = children[i]!;
    const isLast = i === children.length - 1;
    const connector = isLast ? "└── " : "├── ";
    const childPrefix = isLast ? "    " : "│   ";

    let label = child.name;
    if (opts.showVersions && child.version) {
      label += `@${child.version}`;
    }

    // Vulnerability markers
    if (
      opts.showVulnerabilities &&
      child.vulnerabilities &&
      child.vulnerabilities.length > 0
    ) {
      const vulnStrs = child.vulnerabilities.map(
        (v) => `⚠️ ${v.id} (${v.severity})`,
      );
      label += ` ${vulnStrs.join(", ")}`;
    }

    lines.push(`${prefix}${connector}${label}`);

    if (child.children.length > 0) {
      renderChildren(child.children, `${prefix}${childPrefix}`, lines, opts);
    }
  }
}

// ============================================================================
// JSON Rendering
// ============================================================================

/**
 * Render a tree node as a structured JSON object.
 *
 * @param root - Root tree node
 * @param options - Rendering options (showVersions, showVulnerabilities)
 * @returns Structured JSON tree
 */
export function renderTreeJson(
  root: TreeNode,
  options?: Pick<TreeOptions, "showVersions" | "showVulnerabilities">,
): TreeJsonOutput {
  const showVersions = options?.showVersions ?? true;
  const showVulns = options?.showVulnerabilities ?? true;

  function nodeToJson(node: TreeNode): TreeJsonOutput {
    const out: TreeJsonOutput = {
      name: node.name,
    };

    if (showVersions && node.version) {
      out.version = node.version;
    }
    if (node.group) {
      out.group = node.group;
    }
    if (node.purl) {
      out.purl = node.purl;
    }
    if (showVulns && node.vulnerabilities && node.vulnerabilities.length > 0) {
      out.vulnerabilities = node.vulnerabilities;
    }
    if (node.children.length > 0) {
      out.children = node.children.map(nodeToJson);
    }

    return out;
  }

  return nodeToJson(root);
}
