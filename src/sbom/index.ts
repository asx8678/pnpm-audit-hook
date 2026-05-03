/**
 * SBOM (Software Bill of Materials) module.
 *
 * Provides SBOM generation capabilities for pnpm audit results.
 * Supports CycloneDX 1.5, SPDX 2.3, and SWID (ISO/IEC 19770-2) output
 * formats with optional vulnerability enrichment.
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
  generateCycloneDX,
  generateCycloneDXSbom,
  serializeCycloneDXToXml,
} from "./cyclonedx-generator";

export {
  validateSbom,
  isValidSbom,
} from "./schema-validator";

export {
  generateSwidSbom,
  generateSwidTags,
  serializeSwidTagToXml,
  serializeSwidTagSetToXml,
} from "./swid-generator";

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
  SwidTag,
  SwidTagSet,
  SwidEntity,
  SwidLink,
  SwidOptions,
} from "./types";
