/**
 * SBOM (Software Bill of Materials) diffing module.
 *
 * Compares two SBOM documents and detects added, removed, updated,
 * and unchanged dependencies. Supports both CycloneDX and SPDX formats,
 * including cross-format comparisons.
 *
 * @module sbom/diff
 *
 * @example
 * ```typescript
 * import { diffSbom } from './sbom/diff';
 * import { readFileSync } from 'node:fs';
 *
 * const oldSbom = JSON.parse(readFileSync('old-sbom.json', 'utf-8'));
 * const newSbom = JSON.parse(readFileSync('new-sbom.json', 'utf-8'));
 *
 * const result = diffSbom(oldSbom, newSbom);
 * console.log(`Added: ${result.summary.totalAdded}`);
 * console.log(`Removed: ${result.summary.totalRemoved}`);
 * console.log(`Updated: ${result.summary.totalUpdated}`);
 * ```
 */

import type {
  CycloneDXBom,
  CycloneDXComponent,
  SPDXDocument,
  SPDXPackage,
  NormalizedPackage,
  SbomDiffEntry,
  SbomDiffMetadata,
  SbomDiffOptions,
  SbomDiffResult,
  SbomDiffSummary,
} from "./types";

// ============================================================================
// Format Detection
// ============================================================================

/** SBOM format identifiers */
type DetectedFormat = "cyclonedx" | "spdx" | "swid" | "unknown";

/**
 * Detect the SBOM format from a parsed JSON document.
 *
 * @param doc - Parsed SBOM JSON document
 * @returns Detected format string
 */
function detectFormat(doc: Record<string, unknown>): DetectedFormat {
  // CycloneDX detection
  if (doc.bomFormat === "CycloneDX" || doc.specVersion) {
    return "cyclonedx";
  }

  // SPDX detection
  if (doc.spdxVersion || doc.SPDXID) {
    return "spdx";
  }

  // SWID detection (tagId indicates SWID tag, or tags array for tag sets)
  if (doc.tagId && doc.softwareIdentificationScheme) {
    return "swid";
  }
  if (doc.tags && Array.isArray(doc.tags)) {
    return "swid";
  }

  return "unknown";
}

// ============================================================================
// Package Normalization
// ============================================================================

/**
 * Extract packages from a CycloneDX BOM document.
 *
 * @param bom - CycloneDX BOM document
 * @returns Array of normalized packages
 */
function extractFromCycloneDX(bom: CycloneDXBom): NormalizedPackage[] {
  const components = bom.components ?? [];
  return components.map((comp: CycloneDXComponent) =>
    normalizeCycloneDXComponent(comp),
  );
}

/**
 * Normalize a CycloneDX component to a generic package representation.
 *
 * @param comp - CycloneDX component
 * @returns Normalized package
 */
function normalizeCycloneDXComponent(comp: CycloneDXComponent): NormalizedPackage {
  const purl = comp.purl ?? comp["bom-ref"] ?? undefined;
  const { group, name } = parsePurlOrName(comp.name, purl);

  return {
    name: comp.name,
    version: comp.version,
    purl,
    group,
  };
}

/**
 * Extract packages from an SPDX document.
 *
 * Skips the root document package (SPDXRef-DOCUMENT).
 *
 * @param doc - SPDX document
 * @returns Array of normalized packages
 */
function extractFromSPDX(doc: SPDXDocument): NormalizedPackage[] {
  const packages = doc.packages ?? [];
  return packages
    .filter((pkg: SPDXPackage) => pkg.SPDXID !== "SPDXRef-DOCUMENT")
    .map((pkg: SPDXPackage) => normalizeSPDXPackage(pkg));
}

/**
 * Normalize an SPDX package to a generic package representation.
 *
 * @param pkg - SPDX package
 * @returns Normalized package
 */
function normalizeSPDXPackage(pkg: SPDXPackage): NormalizedPackage {
  // Try to extract purl from externalRefs
  const purlRef = pkg.externalRefs?.find(
    (ref) => ref.referenceType === "purl",
  );
  const purl = purlRef?.referenceLocator ?? undefined;
  const { group, name } = parsePurlOrName(pkg.name, purl);

  return {
    name: pkg.name,
    version: pkg.versionInfo === "NOASSERTION" ? "0.0.0" : pkg.versionInfo,
    purl,
    group,
  };
}

/**
 * Parse a package name and purl to extract group and name.
 *
 * @param rawName - Raw package name
 * @param purl - Optional Package URL
 * @returns Parsed group and name
 */
function parsePurlOrName(
  rawName: string,
  purl?: string,
): { group?: string; name: string } {
  // If name contains @scope/ pattern, extract it
  if (rawName.startsWith("@") && rawName.includes("/")) {
    const slashIndex = rawName.indexOf("/");
    return {
      group: rawName.slice(0, slashIndex),
      name: rawName,
    };
  }

  // Try to extract from purl
  if (purl) {
    const match = purl.match(/^pkg:npm\/(%40[^/]+%2F|@[^/]+\/)?(.+)@/);
    if (match) {
      const encodedGroup = match[1];
      const name = match[2];
      if (encodedGroup && name) {
        const group = decodeURIComponent(encodedGroup.replace(/\/$/, ""));
        return { group, name: rawName };
      }
    }
  }

  return { name: rawName };
}

// ============================================================================
// Package Index & Diffing
// ============================================================================

/**
 * Build an index of packages by their unique key.
 *
 * @param packages - Array of normalized packages
 * @param keyFn - Function to generate unique key
 * @returns Map from key to package
 */
function buildPackageIndex(
  packages: NormalizedPackage[],
  keyFn: (pkg: NormalizedPackage) => string,
): Map<string, NormalizedPackage> {
  const index = new Map<string, NormalizedPackage>();
  for (const pkg of packages) {
    index.set(keyFn(pkg), pkg);
  }
  return index;
}

/**
 * Generate a unique key for a package.
 *
 * Uses the package identity from purl (without version) if available,
 * otherwise falls back to name. This ensures version changes are
 * detected as updates rather than add+remove.
 *
 * @param pkg - Normalized package
 * @returns Unique key string (without version)
 */
function defaultKeyFn(pkg: NormalizedPackage): string {
  if (pkg.purl) {
    // Strip version from purl: pkg:npm/lodash@4.17.21 -> pkg:npm/lodash
    const atIdx = pkg.purl.lastIndexOf("@");
    if (atIdx > 0) {
      return pkg.purl.slice(0, atIdx);
    }
    return pkg.purl;
  }
  return pkg.name;
}

// ============================================================================
// Diff Engine
// ============================================================================

/**
 * Compare two SBOM documents and produce a structured diff report.
 *
 * Supports:
 * - CycloneDX vs CycloneDX
 * - SPDX vs SPDX
 * - CycloneDX vs SPDX (cross-format)
 * - SPDX vs CycloneDX (cross-format)
 *
 * @param oldSbom - The older/reference SBOM document (parsed JSON)
 * @param newSbom - The newer/current SBOM document (parsed JSON)
 * @param options - Diff configuration options
 * @returns Structured diff result with added, removed, updated, and unchanged entries
 * @throws {Error} If either document is not a recognized SBOM format
 */
export function diffSbom(
  oldSbom: Record<string, unknown>,
  newSbom: Record<string, unknown>,
  options?: SbomDiffOptions,
): SbomDiffResult {
  const startTime = Date.now();

  // Validate inputs
  if (!oldSbom || typeof oldSbom !== "object" || Array.isArray(oldSbom)) {
    throw new Error("Invalid old SBOM: expected a parsed JSON object");
  }
  if (!newSbom || typeof newSbom !== "object" || Array.isArray(newSbom)) {
    throw new Error("Invalid new SBOM: expected a parsed JSON object");
  }

  // Detect formats
  const oldFormat = detectFormat(oldSbom);
  const newFormat = detectFormat(newSbom);

  if (oldFormat === "unknown") {
    throw new Error(
      "Unrecognized old SBOM format. Expected CycloneDX (bomFormat: 'CycloneDX') or SPDX (spdxVersion).",
    );
  }
  if (newFormat === "unknown") {
    throw new Error(
      "Unrecognized new SBOM format. Expected CycloneDX (bomFormat: 'CycloneDX') or SPDX (spdxVersion).",
    );
  }

  // Extract normalized packages from both documents
  const oldPackages = extractPackages(oldSbom, oldFormat);
  const newPackages = extractPackages(newSbom, newFormat);

  // Build package indexes
  const keyFn = options?.keyFn ?? defaultKeyFn;
  const oldIndex = buildPackageIndex(oldPackages, keyFn);
  const newIndex = buildPackageIndex(newPackages, keyFn);

  // Compute diff categories
  const added: SbomDiffEntry[] = [];
  const removed: SbomDiffEntry[] = [];
  const updated: SbomDiffEntry[] = [];
  const unchanged: SbomDiffEntry[] = [];

  const ignoreVersions = options?.ignoreVersions ?? false;

  // Find added and updated packages
  for (const [key, newPkg] of newIndex) {
    const oldPkg = oldIndex.get(key);

    if (!oldPkg) {
      // Package is new
      added.push({
        name: newPkg.name,
        version: newPkg.version,
        purl: newPkg.purl,
        group: newPkg.group,
      });
    } else if (!ignoreVersions && oldPkg.version !== newPkg.version) {
      // Package version changed
      updated.push({
        name: newPkg.name,
        version: newPkg.version,
        previousVersion: oldPkg.version,
        purl: newPkg.purl,
        group: newPkg.group,
      });
    } else {
      // Package is unchanged
      unchanged.push({
        name: newPkg.name,
        version: newPkg.version,
        purl: newPkg.purl,
        group: newPkg.group,
      });
    }
  }

  // Find removed packages
  for (const [key, oldPkg] of oldIndex) {
    if (!newIndex.has(key)) {
      removed.push({
        name: oldPkg.name,
        version: oldPkg.version,
        purl: oldPkg.purl,
        group: oldPkg.group,
      });
    }
  }

  // Sort entries alphabetically by name for stable output
  const sortByName = (a: SbomDiffEntry, b: SbomDiffEntry) =>
    a.name.localeCompare(b.name);
  added.sort(sortByName);
  removed.sort(sortByName);
  updated.sort(sortByName);
  unchanged.sort(sortByName);

  // Build summary
  const summary: SbomDiffSummary = {
    totalAdded: added.length,
    totalRemoved: removed.length,
    totalUpdated: updated.length,
    totalUnchanged: unchanged.length,
  };

  // Build metadata
  const metadata: SbomDiffMetadata = {
    oldFormat,
    newFormat,
    comparedAt: new Date(startTime).toISOString(),
  };

  return {
    added,
    removed,
    updated,
    unchanged,
    summary,
    metadata,
  };
}

// ============================================================================
// Helpers
// ============================================================================

/**
 * Extract normalized packages from an SBOM document.
 *
 * @param doc - Parsed SBOM document
 * @param format - Detected format
 * @returns Array of normalized packages
 */
function extractPackages(
  doc: Record<string, unknown>,
  format: string,
): NormalizedPackage[] {
  switch (format) {
    case "cyclonedx":
      return extractFromCycloneDX(doc as unknown as CycloneDXBom);
    case "spdx":
      return extractFromSPDX(doc as unknown as SPDXDocument);
    case "swid":
      // SWID tags don't have a standard package list format for diffing
      // Extract tag names as packages if available
      return extractFromSwid(doc);
    default:
      throw new Error(`Unsupported SBOM format for diffing: ${format}`);
  }
}

/**
 * Extract packages from SWID tag format (limited support).
 *
 * @param doc - SWID document
 * @returns Array of normalized packages
 */
function extractFromSwid(doc: Record<string, unknown>): NormalizedPackage[] {
  // SWID tags typically have a single software identity per tag
  // For tag sets, we look for a 'tags' array
  const tags = (doc as { tags?: Array<{ name?: string; tagVersion?: string; tagId?: string }> }).tags;
  if (Array.isArray(tags)) {
    return tags
      .filter((tag) => tag.name)
      .map((tag) => ({
        name: tag.name!,
        version: tag.tagVersion ?? "0.0.0",
        purl: tag.tagId,
      }));
  }

  // Single tag document
  const name = (doc as { name?: string }).name;
  const tagVersion = (doc as { tagVersion?: string }).tagVersion;
  const tagId = (doc as { tagId?: string }).tagId;
  if (name) {
    return [
      {
        name,
        version: tagVersion ?? "0.0.0",
        purl: tagId,
      },
    ];
  }

  return [];
}

/**
 * Format a diff result as a human-readable string.
 *
 * @param result - Diff result from diffSbom()
 * @returns Formatted string
 */
export function formatDiffResult(result: SbomDiffResult): string {
  const lines: string[] = [];

  lines.push("SBOM Diff Report");
  lines.push("================");
  lines.push(`Compared at: ${result.metadata.comparedAt}`);
  lines.push(`Old format:  ${result.metadata.oldFormat}`);
  lines.push(`New format:  ${result.metadata.newFormat}`);
  lines.push("");

  lines.push("Summary");
  lines.push("-------");
  lines.push(`  Added:     ${result.summary.totalAdded}`);
  lines.push(`  Removed:   ${result.summary.totalRemoved}`);
  lines.push(`  Updated:   ${result.summary.totalUpdated}`);
  lines.push(`  Unchanged: ${result.summary.totalUnchanged}`);
  lines.push(
    `  Total:     ${result.summary.totalAdded + result.summary.totalRemoved + result.summary.totalUpdated + result.summary.totalUnchanged}`,
  );
  lines.push("");

  if (result.added.length > 0) {
    lines.push("Added Dependencies");
    lines.push("-------------------");
    for (const entry of result.added) {
      const purlStr = entry.purl ? ` (${entry.purl})` : "";
      lines.push(`  + ${entry.name}@${entry.version}${purlStr}`);
    }
    lines.push("");
  }

  if (result.removed.length > 0) {
    lines.push("Removed Dependencies");
    lines.push("---------------------");
    for (const entry of result.removed) {
      const purlStr = entry.purl ? ` (${entry.purl})` : "";
      lines.push(`  - ${entry.name}@${entry.version}${purlStr}`);
    }
    lines.push("");
  }

  if (result.updated.length > 0) {
    lines.push("Updated Dependencies");
    lines.push("---------------------");
    for (const entry of result.updated) {
      const purlStr = entry.purl ? ` (${entry.purl})` : "";
      lines.push(
        `  ~ ${entry.name}@${entry.previousVersion} -> ${entry.version}${purlStr}`,
      );
    }
    lines.push("");
  }

  if (result.unchanged.length > 0) {
    lines.push(`Unchanged Dependencies (${result.unchanged.length})`);
    lines.push("-----------------------");
    for (const entry of result.unchanged) {
      lines.push(`    ${entry.name}@${entry.version}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}
