/**
 * CycloneDX 1.5 SBOM generator.
 *
 * Generates CycloneDX BOM (Bill of Materials) documents from audit results.
 * CycloneDX is an OWASP standard widely used in security tooling.
 *
 * @module sbom/cyclonedx-generator
 *
 * @see {@link https://cyclonedx.org/} - CycloneDX specification
 * @see {@link https://github.com/CycloneDX/specification} - Spec repository
 */

import type { VulnerabilityFinding, PackageRef } from "../types";
import type {
  CycloneDXBom,
  CycloneDXComponent,
  CycloneDXDependency,
  CycloneDXVulnerability,
  SbomComponent,
  SbomOptions,
  SbomResult,
  ComponentVulnerabilityMap,
} from "./types";

/** Tool metadata for SBOM generation */
const TOOL_INFO = {
  vendor: "pnpm-audit-hook",
  name: "pnpm-audit-hook",
  version: "1.4.3", // Will be updated at runtime
} as const;

/**
 * Get tool version from package.json at runtime.
 * Falls back to hardcoded version if package.json is not accessible.
 */
function getToolVersion(): string {
  try {
    const fs = require("node:fs");
    const path = require("node:path");
    const pkgPath = path.resolve(__dirname, "..", "..", "package.json");
    if (fs.existsSync(pkgPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
      return pkg.version ?? TOOL_INFO.version;
    }
  } catch {
    // Ignore errors - use fallback version
  }
  return TOOL_INFO.version;
}

/**
 * Generate a unique serial number for the BOM document.
 * Uses crypto.randomUUID() for UUID v4 format.
 */
function generateSerialNumber(): string {
  try {
    const crypto = require("node:crypto");
    return `urn:uuid:${crypto.randomUUID()}`;
  } catch {
    // Fallback for older Node.js
    return `urn:uuid:${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
  }
}

/**
 * Convert a component to CycloneDX format.
 */
function toCycloneDXComponent(
  component: SbomComponent,
  index: number,
): CycloneDXComponent {
  const bomRef = `pkg:npm/${encodeURIComponent(component.name)}@${component.version}`;

  const cdxCmp: CycloneDXComponent = {
    type: "library",
    "bom-ref": bomRef,
    name: component.name,
    version: component.version,
    purl: component.purl,
  };

  // Add description if available
  if (component.description) {
    // CycloneDX allows up to 1024 characters for description
    cdxCmp.description = component.description.slice(0, 1024);
  }

  // Add license information
  if (component.license) {
    cdxCmp.licenses = [
      {
        license: {
          id: component.license,
        },
      },
    ];
  }

  // Add external references
  const externalRefs: Array<{ type: string; url: string }> = [];
  if (component.homepage) {
    externalRefs.push({ type: "website", url: component.homepage });
  }
  if (component.repository) {
    externalRefs.push({ type: "source-code-repository", url: component.repository });
  }
  if (externalRefs.length > 0) {
    cdxCmp.externalReferences = externalRefs;
  }

  // Add hashes if available
  if (component.hashes && component.hashes.length > 0) {
    cdxCmp.hashes = component.hashes.map((hash) => ({
      alg: hash.algorithm.toLowerCase().replace("-", ""),
      content: hash.value,
    }));
  }

  return cdxCmp;
}

/**
 * Convert vulnerability findings to CycloneDX vulnerability format.
 *
 * Maps our internal VulnerabilityFinding to CycloneDX 1.5 vulnerability schema.
 */
function toCycloneDXVulnerability(
  finding: VulnerabilityFinding,
  componentBomRef: string,
): CycloneDXVulnerability {
  // Map severity to CycloneDX score
  const severityMap: Record<string, { score?: number; severity: string }> = {
    critical: { score: 10, severity: "critical" },
    high: { score: 8.5, severity: "high" },
    medium: { score: 5.5, severity: "medium" },
    low: { score: 2.5, severity: "low" },
    unknown: { severity: "unknown" },
  };

  const ratingInfo = severityMap[finding.severity] ?? { severity: "unknown" };
  const rating: CycloneDXVulnerability["ratings"][0] = {
    source: finding.source
      ? { name: finding.source, url: undefined }
      : undefined,
    severity: ratingInfo.severity,
    vector: finding.cvssVector,
  };

  // Add CVSS score if available, otherwise use severity-based score
  if (typeof finding.cvssScore === "number") {
    rating.score = finding.cvssScore;
  } else if (ratingInfo && "score" in ratingInfo && ratingInfo.score !== undefined) {
    rating.score = ratingInfo.score;
  }

  const vuln: CycloneDXVulnerability = {
    id: finding.id,
    source: finding.url
      ? { name: finding.source ?? "unknown", url: finding.url }
      : undefined,
    ratings: [rating],
    affects: [{ ref: componentBomRef }],
  };

  // Add description
  if (finding.description) {
    vuln.description = finding.description.slice(0, 2048);
  } else if (finding.title) {
    vuln.description = finding.title;
  }

  // Add timestamps
  if (finding.publishedAt) {
    vuln.published = finding.publishedAt;
  }
  if (finding.modifiedAt) {
    vuln.updated = finding.modifiedAt;
  }

  // Add problem type from title
  if (finding.title) {
    vuln.problemTypes = [
      {
        descriptions: [{ lang: "en", value: finding.title }],
      },
    ];
  }

  // Add references
  if (finding.url) {
    vuln.references = [
      {
        url: finding.url,
      },
    ];
  }

  return vuln;
}

/**
 * Generate a CycloneDX 1.5 BOM document.
 *
 * @param components - Array of SBOM components with package info
 * @param vulnerabilities - Component vulnerability map
 * @param options - SBOM generation options
 * @returns CycloneDX BOM document
 */
export function generateCycloneDX(
  components: SbomComponent[],
  vulnMap: ComponentVulnerabilityMap,
  options: SbomOptions,
): CycloneDXBom {
  const version = getToolVersion();
  const timestamp = new Date().toISOString();

  // Build component list
  const cdxComponents: CycloneDXComponent[] = components.map((cmp, idx) =>
    toCycloneDXComponent(cmp, idx),
  );

  // Build vulnerability list if requested
  let cdxVulnerabilities: CycloneDXVulnerability[] | undefined;
  if (options.includeVulnerabilities !== false) {
    cdxVulnerabilities = [];

    for (const component of components) {
      const pkgKey = `${component.name}@${component.version}`;
      const findings = vulnMap.get(pkgKey) ?? [];

      if (findings.length === 0) continue;

      const bomRef = `pkg:npm/${encodeURIComponent(component.name)}@${component.version}`;

      for (const finding of findings) {
        cdxVulnerabilities.push(
          toCycloneDXVulnerability(finding, bomRef),
        );
      }
    }

    // Only include vulnerabilities array if there are any
    if (cdxVulnerabilities.length === 0) {
      cdxVulnerabilities = undefined;
    }
  }

  // Build dependency relationships if requested
  let cdxDependencies: CycloneDXDependency[] | undefined;
  if (options.includeDependencies !== false) {
    cdxDependencies = [];

    for (const component of components) {
      const bomRef = `pkg:npm/${encodeURIComponent(component.name)}@${component.version}`;
      const dependencies = component.dependencies ?? [];

      if (dependencies.length > 0) {
        cdxDependencies.push({
          ref: bomRef,
          dependsOn: dependencies.map((dep) => `pkg:npm/${encodeURIComponent(dep)}`),
        });
      }
    }

    if (cdxDependencies.length === 0) {
      cdxDependencies = undefined;
    }
  }

  // Build the BOM document
  const bom: CycloneDXBom = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: generateSerialNumber(),
    version: 1,
    metadata: {
      timestamp,
      tools: [
        {
          vendor: TOOL_INFO.vendor,
          name: TOOL_INFO.name,
          version,
        },
      ],
    },
    components: cdxComponents,
  };

  // Add root component if project info is provided
  if (options.projectName) {
    bom.metadata.component = {
      type: "application",
      "bom-ref": `pkg:npm/${encodeURIComponent(options.projectName)}@${options.projectVersion ?? "0.0.0"}`,
      name: options.projectName,
      version: options.projectVersion ?? "0.0.0",
      purl: `pkg:npm/${encodeURIComponent(options.projectName)}@${options.projectVersion ?? "0.0.0"}`,
      description: options.projectDescription,
    };
  }

  // Add vulnerabilities if present
  if (cdxVulnerabilities) {
    bom.vulnerabilities = cdxVulnerabilities;
  }

  // Add dependencies if present
  if (cdxDependencies) {
    bom.dependencies = cdxDependencies;
  }

  return bom;
}

/**
 * Escape XML special characters.
 *
 * @param text - Text to escape
 * @returns Escaped XML text
 */
function escapeXml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/**
 * Indent XML content with the given indentation level.
 */
function indentXml(lines: string[], level: number): string[] {
  const pad = "  ".repeat(level);
  return lines.map((line) => (line.trim() ? `${pad}${line.trim()}` : line));
}

/**
 * Build XML lines for a CycloneDX component.
 */
function componentToXml(component: CycloneDXComponent, indent: number): string[] {
  const pad = "  ".repeat(indent);
  const lines: string[] = [];

  lines.push(`${pad}<component type="${escapeXml(component.type)}" bom-ref="${escapeXml(component["bom-ref"])}">`);
  lines.push(`${pad}  <name>${escapeXml(component.name)}</name>`);
  lines.push(`${pad}  <version>${escapeXml(component.version)}</version>`);

  if (component.description) {
    lines.push(`${pad}  <description>${escapeXml(component.description)}</description>`);
  }

  lines.push(`${pad}  <purl>${escapeXml(component.purl)}</purl>`);

  // Hashes
  if (component.hashes && component.hashes.length > 0) {
    lines.push(`${pad}  <hashes>`);
    for (const hash of component.hashes) {
      lines.push(`${pad}    <hash alg="${escapeXml(hash.alg)}">${escapeXml(hash.content)}</hash>`);
    }
    lines.push(`${pad}  </hashes>`);
  }

  // Licenses
  if (component.licenses && component.licenses.length > 0) {
    lines.push(`${pad}  <licenses>`);
    for (const lic of component.licenses) {
      lines.push(`${pad}    <license>`);
      if (lic.license.id) {
        lines.push(`${pad}      <id>${escapeXml(lic.license.id)}</id>`);
      }
      if (lic.license.name) {
        lines.push(`${pad}      <name>${escapeXml(lic.license.name)}</name>`);
      }
      if (lic.license.url) {
        lines.push(`${pad}      <url>${escapeXml(lic.license.url)}</url>`);
      }
      lines.push(`${pad}    </license>`);
    }
    lines.push(`${pad}  </licenses>`);
  }

  // External references
  if (component.externalReferences && component.externalReferences.length > 0) {
    lines.push(`${pad}  <externalReferences>`);
    for (const ref of component.externalReferences) {
      lines.push(`${pad}    <reference type="${escapeXml(ref.type)}">`);
      lines.push(`${pad}      <url>${escapeXml(ref.url)}</url>`);
      lines.push(`${pad}    </reference>`);
    }
    lines.push(`${pad}  </externalReferences>`);
  }

  lines.push(`${pad}</component>`);
  return lines;
}

/**
 * Build XML lines for a CycloneDX vulnerability.
 */
function vulnerabilityToXml(vuln: CycloneDXVulnerability, indent: number): string[] {
  const pad = "  ".repeat(indent);
  const lines: string[] = [];

  lines.push(`${pad}<vulnerability>`);
  lines.push(`${pad}  <id>${escapeXml(vuln.id)}</id>`);

  // Source
  if (vuln.source) {
    lines.push(`${pad}  <source>`);
    lines.push(`${pad}    <name>${escapeXml(vuln.source.name)}</name>`);
    if (vuln.source.url) {
      lines.push(`${pad}    <url>${escapeXml(vuln.source.url)}</url>`);
    }
    lines.push(`${pad}  </source>`);
  }

  // Ratings
  if (vuln.ratings && vuln.ratings.length > 0) {
    lines.push(`${pad}  <ratings>`);
    for (const rating of vuln.ratings) {
      lines.push(`${pad}    <rating>`);
      if (rating.source) {
        lines.push(`${pad}      <source>`);
        lines.push(`${pad}        <name>${escapeXml(rating.source.name)}</name>`);
        lines.push(`${pad}      </source>`);
      }
      if (typeof rating.score === "number") {
        lines.push(`${pad}      <score>${rating.score}</score>`);
      }
      if (rating.severity) {
        lines.push(`${pad}      <severity>${escapeXml(rating.severity)}</severity>`);
      }
      if (rating.vector) {
        lines.push(`${pad}      <vector>${escapeXml(rating.vector)}</vector>`);
      }
      lines.push(`${pad}    </rating>`);
    }
    lines.push(`${pad}  </ratings>`);
  }

  // Description
  if (vuln.description) {
    lines.push(`${pad}  <description>${escapeXml(vuln.description)}</description>`);
  }

  // Published / Updated
  if (vuln.published) {
    lines.push(`${pad}  <published>${escapeXml(vuln.published)}</published>`);
  }
  if (vuln.updated) {
    lines.push(`${pad}  <updated>${escapeXml(vuln.updated)}</updated>`);
  }

  // Affects
  if (vuln.affects && vuln.affects.length > 0) {
    lines.push(`${pad}  <affects>`);
    for (const affect of vuln.affects) {
      lines.push(`${pad}    <affect ref="${escapeXml(affect.ref)}" />`);
    }
    lines.push(`${pad}  </affects>`);
  }

  // Problem types
  if (vuln.problemTypes && vuln.problemTypes.length > 0) {
    lines.push(`${pad}  <problemTypes>`);
    for (const pt of vuln.problemTypes) {
      lines.push(`${pad}    <problemType>`);
      lines.push(`${pad}      <descriptions>`);
      for (const desc of pt.descriptions) {
        lines.push(`${pad}        <description lang="${escapeXml(desc.lang)}">${escapeXml(desc.value)}</description>`);
      }
      lines.push(`${pad}      </descriptions>`);
      lines.push(`${pad}    </problemType>`);
    }
    lines.push(`${pad}  </problemTypes>`);
  }

  // References
  if (vuln.references && vuln.references.length > 0) {
    lines.push(`${pad}  <references>`);
    for (const ref of vuln.references) {
      lines.push(`${pad}    <reference url="${escapeXml(ref.url)}" />`);
    }
    lines.push(`${pad}  </references>`);
  }

  lines.push(`${pad}</vulnerability>`);
  return lines;
}

/**
 * Build XML lines for a CycloneDX dependency.
 */
function dependencyToXml(dep: CycloneDXDependency, indent: number): string[] {
  const pad = "  ".repeat(indent);
  const lines: string[] = [];

  lines.push(`${pad}<dependency ref="${escapeXml(dep.ref)}">`);
  if (dep.dependsOn && dep.dependsOn.length > 0) {
    for (const d of dep.dependsOn) {
      lines.push(`${pad}  <depends-on ref="${escapeXml(d)}" />`);
    }
  }
  lines.push(`${pad}</dependency>`);
  return lines;
}

/**
 * Serialize a CycloneDX BOM document to XML (CycloneDX 1.5 XML format).
 *
 * @param bom - CycloneDX BOM document
 * @returns XML string following CycloneDX 1.5 XML specification
 */
export function serializeCycloneDXToXml(bom: CycloneDXBom): string {
  const lines: string[] = [];

  lines.push('<?xml version="1.0" encoding="UTF-8"?>');
  lines.push(
    `<bom xmlns="http://cyclonedx.org/schema/bom/1.5" serialNumber="${escapeXml(bom.serialNumber)}" version="${bom.version}" specVersion="${bom.specVersion}">`,
  );

  // Metadata
  lines.push("  <metadata>");
  lines.push(`    <timestamp>${escapeXml(bom.metadata.timestamp)}</timestamp>`);

  lines.push("    <tools>");
  for (const tool of bom.metadata.tools) {
    lines.push("      <tool>");
    lines.push(`        <vendor>${escapeXml(tool.vendor)}</vendor>`);
    lines.push(`        <name>${escapeXml(tool.name)}</name>`);
    lines.push(`        <version>${escapeXml(tool.version)}</version>`);
    lines.push("      </tool>");
  }
  lines.push("    </tools>");

  // Root component
  if (bom.metadata.component) {
    const cmpLines = componentToXml(bom.metadata.component, 2);
    // Wrap as <component> inside <metadata>
    lines.push("    <component>");
    // Get the inner lines of componentToXml (skip first and last lines which are the tags)
    for (let i = 1; i < cmpLines.length - 1; i++) {
      lines.push(`      ${cmpLines[i]?.trim() ?? ""}`);
    }
    lines.push("    </component>");
  }

  lines.push("  </metadata>");

  // Components
  if (bom.components && bom.components.length > 0) {
    lines.push("  <components>");
    for (const component of bom.components) {
      const cmpLines = componentToXml(component, 2);
      lines.push(...cmpLines);
    }
    lines.push("  </components>");
  }

  // Dependencies
  if (bom.dependencies && bom.dependencies.length > 0) {
    lines.push("  <dependencies>");
    for (const dep of bom.dependencies) {
      const depLines = dependencyToXml(dep, 2);
      lines.push(...depLines);
    }
    lines.push("  </dependencies>");
  }

  // Vulnerabilities
  if (bom.vulnerabilities && bom.vulnerabilities.length > 0) {
    lines.push("  <vulnerabilities>");
    for (const vuln of bom.vulnerabilities) {
      const vulnLines = vulnerabilityToXml(vuln, 2);
      lines.push(...vulnLines);
    }
    lines.push("  </vulnerabilities>");
  }

  lines.push("</bom>");
  return lines.join("\n");
}

/**
 * Generate CycloneDX SBOM and format as string.
 *
 * Supports both JSON and XML output formats:
 * - format: "cyclonedx" → JSON output
 * - format: "cyclonedx-xml" → XML output
 *
 * @param components - Array of SBOM components with package info
 * @param vulnerabilities - Component vulnerability map
 * @param options - SBOM generation options
 * @returns SBOM generation result with content string
 */
export function generateCycloneDXSbom(
  components: SbomComponent[],
  vulnMap: ComponentVulnerabilityMap,
  options: SbomOptions,
): SbomResult {
  const startTime = Date.now();

  const bom = generateCycloneDX(components, vulnMap, options);

  const isXml = options.format === "cyclonedx-xml";
  const content = isXml
    ? serializeCycloneDXToXml(bom)
    : JSON.stringify(bom, null, 2);

  const vulnerabilityCount = bom.vulnerabilities?.length ?? 0;

  return {
    content,
    format: options.format as "cyclonedx" | "cyclonedx-xml",
    componentCount: components.length,
    vulnerabilityCount,
    outputPath: options.outputPath,
    durationMs: Date.now() - startTime,
  };
}
