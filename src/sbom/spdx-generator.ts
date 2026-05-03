/**
 * SPDX 2.3 SBOM generator.
 *
 * Generates SPDX (Software Package Data Exchange) documents from audit results.
 * SPDX is a Linux Foundation standard (ISO/IEC 5962:2021) for communicating
 * software bill of materials information.
 *
 * @module sbom/spdx-generator
 *
 * @see {@link https://spdx.org/} - SPDX specification
 * @see {@link https://spdx.dev/specification} - Specification details
 */

import type { VulnerabilityFinding, PackageRef } from "../types";
import type {
  SPDXDocument,
  SPDXPackage,
  SPDXRelationship,
  SPDXAnnotation,
  SbomComponent,
  SbomOptions,
  SbomResult,
  ComponentVulnerabilityMap,
} from "./types";

/** SPDX document namespace prefix */
const SPDX_NS_PREFIX = "https://spdx.org/spdxdocs";

/**
 * Generate a unique SPDX document namespace.
 * Format: <prefix>/<uuid>-<timestamp>
 */
function generateDocumentNamespace(): string {
  try {
    const crypto = require("node:crypto");
    const uuid = crypto.randomUUID();
    return `${SPDX_NS_PREFIX}/${uuid}`;
  } catch {
    return `${SPDX_NS_PREFIX}/${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
  }
}

/**
 * Sanitize a package name for use as SPDX ID.
 * SPDX IDs must match: [A-Za-z0-9-.]+
 *
 * @param name - Package name to sanitize
 * @returns SPDX-compatible ID string
 */
function sanitizeSpdxId(name: string): string {
  return name
    .replace(/^@/, "") // Remove leading scope marker
    .replace(/[/\\]/g, "-") // Replace slashes with dashes
    .replace(/[^A-Za-z0-9.\-]/g, "-") // Replace invalid chars
    .replace(/-+/g, "-") // Collapse multiple dashes
    .replace(/^-|-$/g, ""); // Trim leading/trailing dashes
}

/**
 * Convert a component to SPDX package format.
 */
function toSPDXPackage(
  component: SbomComponent,
  index: number,
): SPDXPackage {
  const spdxId = `SPDXRef-Package-${sanitizeSpdxId(component.name)}-${sanitizeSpdxId(component.version)}`;

  const pkg: SPDXPackage = {
    SPDXID: spdxId,
    name: component.name,
    versionInfo: component.version,
    downloadLocation: component.repository || component.homepage || "NOASSERTION",
    filesAnalyzed: false,
    licenseConcluded: component.license || "NOASSERTION",
    licenseDeclared: component.license || "NOASSERTION",
    copyrightText: "NOASSERTION",
  };

  // Add external references for purl
  pkg.externalRefs = [
    {
      referenceCategory: "PACKAGE-MANAGER",
      referenceType: "purl",
      referenceLocator: component.purl,
    },
  ];

  // Add checksums if available
  if (component.hashes && component.hashes.length > 0) {
    pkg.checksums = component.hashes.map((hash) => ({
      algorithm: hash.algorithm.toUpperCase(),
      checksumValue: hash.value,
    }));
  }

  // Add comment with description if available
  if (component.description) {
    pkg.comment = component.description.slice(0, 1024);
  }

  return pkg;
}

/**
 * Convert vulnerability findings to SPDX annotations.
 *
 * SPDX doesn't have a native vulnerability field, so we use annotations
 * to document security findings. For better interoperability, we also
 * add external references to vulnerability databases.
 */
function toSPDXAnnotations(
  component: SbomComponent,
  findings: VulnerabilityFinding[],
): SPDXAnnotation[] {
  const timestamp = new Date().toISOString();
  const spdxId = `SPDXRef-Package-${sanitizeSpdxId(component.name)}-${sanitizeSpdxId(component.version)}`;

  return findings.map((finding) => ({
    SPDXDataCreated: timestamp,
    SPDXID: spdxId,
    Annotator: "Tool: pnpm-audit-hook",
    AnnotationType: "OTHER" as const,
    Comment: [
      `[${finding.severity.toUpperCase()}] ${finding.id}`,
      finding.title ? `Title: ${finding.title}` : "",
      finding.description ? `Description: ${finding.description}` : "",
      finding.fixedVersion ? `Fixed in: ${finding.fixedVersion}` : "",
      finding.url ? `Reference: ${finding.url}` : "",
    ]
      .filter(Boolean)
      .join("; "),
  }));
}

/**
 * Generate SPDX 2.3 document.
 *
 * @param components - Array of SBOM components with package info
 * @param vulnerabilities - Component vulnerability map
 * @param options - SBOM generation options
 * @returns SPDX document structure
 */
export function generateSPDX(
  components: SbomComponent[],
  vulnMap: ComponentVulnerabilityMap,
  options: SbomOptions,
): SPDXDocument {
  const timestamp = new Date().toISOString();
  const namespace = generateDocumentNamespace();
  const docName = options.projectName
    ? `SPDX-${options.projectName}-SBOM`
    : "SPDX-Document";

  // Create root document package
  const rootPackage: SPDXPackage = {
    SPDXID: "SPDXRef-DOCUMENT",
    name: options.projectName ?? "pnpm-project",
    versionInfo: options.projectVersion ?? "NOASSERTION",
    downloadLocation: "NOASSERTION",
    filesAnalyzed: false,
    licenseConcluded: "NOASSERTION",
    licenseDeclared: "NOASSERTION",
    copyrightText: "NOASSERTION",
  };

  // Build package list
  const packages: SPDXPackage[] = [rootPackage];
  const relationships: SPDXRelationship[] = [];
  const annotations: SPDXAnnotation[] = [];

  // Add all component packages
  for (const component of components) {
    const pkg = toSPDXPackage(component, packages.length);
    packages.push(pkg);

    // Add relationship: DOCUMENT contains PACKAGE
    relationships.push({
      SPDXElementID: "SPDXRef-DOCUMENT",
      RelationshipType: "CONTAINS",
      RelatedSPDXElement: pkg.SPDXID,
    });

    // Add dependency relationships if requested
    if (options.includeDependencies !== false && component.dependencies) {
      for (const dep of component.dependencies) {
        const depPkg = components.find((c) => c.name === dep);
        if (depPkg) {
          const depSpdxId = `SPDXRef-Package-${sanitizeSpdxId(depPkg.name)}-${sanitizeSpdxId(depPkg.version)}`;
          relationships.push({
            SPDXElementID: pkg.SPDXID,
            RelationshipType: "DEPENDS_ON",
            RelatedSPDXElement: depSpdxId,
          });
        }
      }
    }

    // Add vulnerability annotations if requested
    if (options.includeVulnerabilities !== false) {
      const pkgKey = `${component.name}@${component.version}`;
      const findings = vulnMap.get(pkgKey) ?? [];

      if (findings.length > 0) {
        annotations.push(...toSPDXAnnotations(component, findings));

        // Add external references for vulnerabilities
        const vulnRefs = findings.map((f) => ({
          referenceCategory: "SECURITY",
          referenceType: "vulnerability",
          referenceLocator: f.url || `https://github.com/advisories/${f.id}`,
        }));

        if (!pkg.externalRefs) {
          pkg.externalRefs = [];
        }
        pkg.externalRefs.push(...vulnRefs);
      }
    }
  }

  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: docName,
    documentNamespace: namespace,
    creationInfo: {
      created: timestamp,
      creators: [
        "Tool: pnpm-audit-hook-1.4.3",
        "Organization: pnpm-audit-hook",
      ],
      documentNamespace: namespace,
    },
    documentDescribes: ["SPDXRef-DOCUMENT"],
    packages,
    relationships,
    annotations: annotations.length > 0 ? annotations : undefined,
  };
}

/**
 * Generate SPDX SBOM and format as JSON string.
 *
 * @param components - Array of SBOM components with package info
 * @param vulnerabilities - Component vulnerability map
 * @param options - SBOM generation options
 * @returns SBOM generation result with content string
 */
export function generateSPDXSbom(
  components: SbomComponent[],
  vulnMap: ComponentVulnerabilityMap,
  options: SbomOptions,
): SbomResult {
  const startTime = Date.now();

  const doc = generateSPDX(components, vulnMap, options);
  const content = JSON.stringify(doc, null, 2);

  // Count vulnerabilities across all packages
  let vulnerabilityCount = 0;
  if (doc.annotations) {
    vulnerabilityCount = doc.annotations.filter((a) =>
      a.Comment.startsWith("["),
    ).length;
  }

  return {
    content,
    format: "spdx",
    componentCount: doc.packages.length - 1, // Exclude root document package
    vulnerabilityCount,
    outputPath: options.outputPath,
    durationMs: Date.now() - startTime,
  };
}
