/**
 * SBOM (Software Bill of Materials) module.
 *
 * Provides SBOM generation capabilities for pnpm audit results.
 * Supports CycloneDX 1.5 and SPDX 2.3 output formats with optional
 * vulnerability enrichment.
 *
 * @module sbom
 *
 * @example
 * ```typescript
 * import { generateSbom, SbomFormat } from './sbom';
 *
 * // Generate CycloneDX SBOM
 * const result = generateSbom(packages, findings, {
 *   format: 'cyclonedx',
 *   includeVulnerabilities: true,
 *   projectName: 'my-project',
 * });
 *
 * // Write to file
 * fs.writeFileSync('sbom.json', result.content);
 * ```
 */

export {
  generateSbom,
  packagesToSbomComponents,
  buildVulnerabilityMap,
} from "./generator";

export {
  validateSbom,
  isValidSbom,
} from "./schema-validator";

export type {
  SbomFormat,
  SbomOptions,
  SbomResult,
  SbomComponent,
  PackageHash,
  HashAlgorithm,
  ComponentVulnerabilityMap,
  ValidationResult,
  ValidationError,
} from "./types";
