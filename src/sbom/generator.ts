/**
 * SBOM (Software Bill of Materials) generator.
 *
 * Main entry point for generating SBOMs from audit results.
 * Supports CycloneDX 1.5 and SPDX 2.3 formats with optional
 * vulnerability enrichment.
 *
 * @module sbom/generator
 *
 * @example
 * ```typescript
 * import { generateSbom } from './sbom/generator';
 * import { extractPackagesFromLockfile } from './utils/lockfile';
 * import { aggregateVulnerabilities } from './databases/aggregator';
 *
 * const { packages } = extractPackagesFromLockfile(lockfile);
 * const { findings } = await aggregateVulnerabilities(packages, ctx);
 *
 * const result = generateSbom(packages, findings, {
 *   format: 'cyclonedx',
 *   includeVulnerabilities: true,
 *   projectName: 'my-project',
 *   projectVersion: '1.0.0',
 * });
 *
 * fs.writeFileSync('sbom.json', result.content);
 * ```
 */

import * as fs from "node:fs";
import type { PackageRef, VulnerabilityFinding } from "../types";
import type {
  HashAlgorithm,
  SbomComponent,
  SbomFormat,
  SbomOptions,
  SbomResult,
  ComponentVulnerabilityMap,
} from "./types";
import { generateCycloneDXSbom } from "./cyclonedx-generator";
import { generateSPDXSbom } from "./spdx-generator";
import { logger } from "../utils/logger";

/** Package version for tool metadata */
const TOOL_VERSION = "1.4.3";

/**
 * Build a vulnerability map for quick component lookup.
 *
 * @param findings - Array of vulnerability findings
 * @returns Map from "name@version" to findings array
 */
export function buildVulnerabilityMap(
  findings: VulnerabilityFinding[],
): ComponentVulnerabilityMap {
  const map = new Map<string, VulnerabilityFinding[]>();

  for (const finding of findings) {
    const key = `${finding.packageName}@${finding.packageVersion}`;
    const existing = map.get(key);
    if (existing) {
      existing.push(finding);
    } else {
      map.set(key, [finding]);
    }
  }

  return map;
}

/**
 * Convert PackageRef array to SBOM component format.
 *
 * @param packages - Package references from lockfile extraction
 * @returns SBOM components with purl identifiers
 */
export function packagesToSbomComponents(
  packages: PackageRef[],
): SbomComponent[] {
  return packages.map((pkg) => {
    const component: SbomComponent = {
      name: pkg.name,
      version: pkg.version,
      purl: `pkg:npm/${encodeURIComponent(pkg.name)}@${pkg.version}`,
    };

    // Add integrity hash if available
    if (pkg.integrity) {
      const [algorithm, value] = parseIntegrityHash(pkg.integrity);
      if (algorithm && value) {
        component.hashes = [{ algorithm: algorithm as HashAlgorithm, value }];
      }
    }

    // Add dependencies if available
    if (pkg.dependencies && pkg.dependencies.length > 0) {
      component.dependencies = pkg.dependencies;
    }

    return component;
  });
}

/**
 * Parse an npm integrity hash string.
 * Format: "algorithm-base64value" (e.g., "sha512-abc123...")
 *
 * @param integrity - npm integrity hash string
 * @returns Tuple of [algorithm, hexValue] or [null, null] if invalid
 */
function parseIntegrityHash(integrity: string): [string | null, string | null] {
  const match = integrity.match(/^(sha1|sha256|sha512)-([A-Za-z0-9+/=]+)$/);
  if (!match) {
    return [null, null];
  }

  const algorithm = match[1]?.toUpperCase();
  const base64 = match[2];
  if (!algorithm || !base64) {
    return [null, null];
  }

  try {
    const hex = Buffer.from(base64, "base64").toString("hex");
    return [algorithm, hex];
  } catch {
    return [null, null];
  }
}

/**
 * Generate SBOM from audit results.
 *
 * This is the main entry point for SBOM generation. It:
 * 1. Converts packages to SBOM component format
 * 2. Builds vulnerability map from findings
 * 3. Generates SBOM in the requested format
 * 4. Optionally writes to file
 *
 * @param packages - Package references from lockfile extraction
 * @param findings - Vulnerability findings from audit
 * @param options - SBOM generation options
 * @returns SBOM generation result
 */
export function generateSbom(
  packages: PackageRef[],
  findings: VulnerabilityFinding[],
  options: SbomOptions,
): SbomResult {
  const startTime = Date.now();

  // Validate options
  if (!options.format) {
    throw new Error("SBOM format is required");
  }

  if (packages.length === 0) {
    logger.warn("No packages found for SBOM generation");
  }

  // Convert packages to SBOM components
  const components = packagesToSbomComponents(packages);

  // Build vulnerability map
  const vulnMap = buildVulnerabilityMap(findings);

  // Log generation info
  logger.debug(
    `Generating ${options.format.toUpperCase()} SBOM: ` +
    `${components.length} components, ` +
    `${Array.from(vulnMap.values()).reduce((sum, v) => sum + v.length, 0)} vulnerabilities`,
  );

  // Generate SBOM in requested format
  let result: SbomResult;
  switch (options.format) {
    case "cyclonedx":
      result = generateCycloneDXSbom(components, vulnMap, {
        ...options,
        projectVersion: options.projectVersion ?? TOOL_VERSION,
      });
      break;
    case "spdx":
      result = generateSPDXSbom(components, vulnMap, {
        ...options,
        projectVersion: options.projectVersion ?? TOOL_VERSION,
      });
      break;
    default:
      throw new Error(`Unsupported SBOM format: ${options.format}`);
  }

  // Write to file if output path is specified
  if (options.outputPath) {
    try {
      const dir = require("node:path").dirname(options.outputPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(options.outputPath, result.content, "utf-8");
      logger.debug(`SBOM written to ${options.outputPath}`);
    } catch (err) {
      logger.error(`Failed to write SBOM to ${options.outputPath}: ${err}`);
      throw new Error(`Failed to write SBOM: ${(err as Error).message}`);
    }
  }

  result.durationMs = Date.now() - startTime;
  return result;
}

// Re-export types and generators for direct access
export type { SbomFormat, SbomOptions, SbomResult } from "./types";
export { generateCycloneDXSbom } from "./cyclonedx-generator";
export { generateSPDXSbom } from "./spdx-generator";
