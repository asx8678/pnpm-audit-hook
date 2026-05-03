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
 * Generate CycloneDX SBOM and format as JSON string.
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
  const content = JSON.stringify(bom, null, 2);

  const vulnerabilityCount = bom.vulnerabilities?.length ?? 0;

  return {
    content,
    format: "cyclonedx",
    componentCount: components.length,
    vulnerabilityCount,
    outputPath: options.outputPath,
    durationMs: Date.now() - startTime,
  };
}
