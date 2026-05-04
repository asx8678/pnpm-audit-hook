/**
 * Static DB Consistency Analyzer
 *
 * Reads the index and scans shard files to detect inconsistencies:
 *   - orphanShards: shard files on disk not referenced in the index
 *   - missingShards: packages in the index without a corresponding shard file
 *   - countMismatches: index vulnerability count differs from actual shard count
 *   - packageNameMismatches: decoded shard file name does not match the
 *     packageName/name field inside the shard JSON
 *   - metadataMismatches: index metadata (totalPackages, totalVulnerabilities)
 *     disagrees with the actual data
 *
 * Handles both plain JSON and gzip-compressed files via readMaybeCompressed.
 * Handles both optimized (pkg/v) and normal shard formats.
 */

import { readdir } from "node:fs/promises";
import { join, relative } from "node:path";
import {
  readMaybeCompressed,
  expandIndex,
  type OptimizedIndex,
} from "./optimizer";
import type { StaticDbIndex } from "./types";

// ---------------------------------------------------------------------------
// Public report type
// ---------------------------------------------------------------------------

export interface StaticDbConsistencyReport {
  /** Whether the index.json was loaded successfully */
  indexLoaded: boolean;
  /** Total packages listed in the index (Object.keys) */
  indexedPackageCount: number;
  /** Total package count reported by the index metadata (totalPackages field) */
  indexTotalPackages: number;
  /** Total vulnerability count reported by the index metadata */
  indexTotalVulnerabilities: number;
  /** Sum of individual package counts from the index */
  sumIndexCounts: number;
  /** Total shard-like files found on disk (excluding index, README, etc.) */
  shardFileCount: number;
  /** Shard files that exist on disk but are NOT listed in the index */
  orphanShards: string[];
  /** Packages listed in the index that have NO corresponding shard file */
  missingShards: string[];
  /** Packages where index count !== actual vulnerability count in shard */
  countMismatches: Array<{
    packageName: string;
    indexCount: number;
    shardCount: number;
  }>;
  /** Shard files whose decoded name does not match the inner packageName/name */
  packageNameMismatches: Array<{
    shardPath: string;
    decodedName: string;
    actualName: string;
  }>;
  /** Index metadata mismatches (totalPackages, totalVulnerabilities) */
  metadataMismatches: Array<{
    field: string;
    expected: number;
    actual: number;
  }>;
  /** Non-fatal errors encountered during analysis */
  errors: string[];
  /** Whether the DB appears fully consistent */
  isConsistent: boolean;
}

// ---------------------------------------------------------------------------
// Decode a shard file path -> package name
// ---------------------------------------------------------------------------

/**
 * Decode a shard file path (relative to data dir) into a package name.
 *
 * Examples:
 *   lodash.json              -> lodash
 *   @angular/core.json       -> @angular/core
 *   @angular/core.json.gz    -> @angular/core
 *   101.json                 -> 101
 *
 * Normalizes backslashes to forward slashes for Windows portability.
 */
export function decodeShardPath(relPath: string): string {
  // Normalize backslashes to forward slashes for cross-platform compatibility
  let normalized = relPath.replace(/\\/g, "/");

  // Strip .gz extension if present
  if (normalized.endsWith(".gz")) {
    normalized = normalized.slice(0, -3);
  }

  // Must end with .json
  if (!normalized.endsWith(".json")) {
    return normalized;
  }

  // Remove .json suffix
  const noExt = normalized.slice(0, -5);

  // If the path contains a directory separator before the filename,
  // it's a scoped package: @scope/name -> @scope/name
  const sepIdx = noExt.lastIndexOf("/");
  if (sepIdx > 0 && noExt[0] === "@") {
    // It's already in @scope/name form
    return noExt;
  }

  // Unscoped: just the filename without extension
  return noExt;
}

// ---------------------------------------------------------------------------
// Read and normalize a single shard (supports both formats)
// ---------------------------------------------------------------------------

/**
 * Attempt to read a shard file and extract the package name + vulnerability count.
 *
 * Normalizes .json.gz paths to base .json before calling readMaybeCompressed
 * (which already tries both .json and .json.gz internally).
 *
 * Returns null if the file cannot be read or parsed.
 */
async function readShardInfo(
  filePath: string,
): Promise<{ packageName: string; vulnCount: number } | null> {
  try {
    // readMaybeCompressed expects a base .json path — it internally tries .json.gz too.
    // If filePath already ends in .json.gz, strip it to avoid .json.gz.gz attempts.
    const basePath = filePath.endsWith(".gz")
      ? filePath.slice(0, -3)
      : filePath;

    const data = await readMaybeCompressed<Record<string, unknown>>(basePath);
    if (!data) return null;

    // Optimized shard format: { pkg, v }
    if (typeof data.pkg === "string" && Array.isArray(data.v)) {
      return {
        packageName: data.pkg as string,
        vulnCount: (data.v as unknown[]).length,
      };
    }

    // Normal shard format: { packageName|name, vulnerabilities }
    const packageName =
      typeof data.packageName === "string"
        ? data.packageName
        : typeof data.name === "string"
          ? data.name
          : null;

    if (!packageName) return null;

    const vulns = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
    return { packageName, vulnCount: vulns.length };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Main analyzer
// ---------------------------------------------------------------------------

/**
 * Scan the static DB directory and produce a consistency report.
 *
 * @param dataPath  Absolute path to the static-db/data/ directory
 */
export async function analyzeStaticDbConsistency(
  dataPath: string,
): Promise<StaticDbConsistencyReport> {
  const errors: string[] = [];

  // 1. Load index
  const indexPath = join(dataPath, "index.json");
  const rawIndex = await readMaybeCompressed<StaticDbIndex | OptimizedIndex>(
    indexPath,
  );

  let index: StaticDbIndex | null = null;
  const indexLoaded = rawIndex !== null;

  if (rawIndex) {
    if ("ver" in rawIndex) {
      index = expandIndex(rawIndex as OptimizedIndex);
    } else {
      index = rawIndex as StaticDbIndex;
    }
  }

  if (!indexLoaded) {
    errors.push("Index file not found or unreadable (index.json / index.json.gz)");
  }

  const indexedPackageCount = index ? Object.keys(index.packages).length : 0;
  const indexTotalPackages = index?.totalPackages ?? 0;
  const indexTotalVulnerabilities = index?.totalVulnerabilities ?? 0;

  // Compute sum of individual vulnerability counts from index entries
  let sumIndexCounts = 0;
  if (index) {
    for (const entry of Object.values(index.packages)) {
      sumIndexCounts += entry.count;
    }
  }

  // 2. Discover shard files recursively
  const shardFiles: string[] = [];

  try {
    await collectShardFiles(dataPath, shardFiles);
  } catch {
    errors.push("Unable to read data directory");
  }

  const shardFileCount = shardFiles.length;

  // 3. Decode shard paths to package names
  const shardPackageNames = new Set<string>();
  const shardPathToName = new Map<string, string>();

  for (const sf of shardFiles) {
    // Get relative path from dataDir
    const rel = relative(dataPath, sf);
    const decoded = decodeShardPath(rel);
    shardPackageNames.add(decoded);
    shardPathToName.set(sf, decoded);
  }

  // 4. Indexed package names
  const indexedPackages = index ? new Set(Object.keys(index.packages)) : new Set<string>();

  // 5. Compute orphan shards (on disk, not in index)
  const orphanShards: string[] = [];
  for (const [filePath, decodedName] of shardPathToName) {
    if (!indexedPackages.has(decodedName)) {
      orphanShards.push(relative(dataPath, filePath));
    }
  }
  orphanShards.sort();

  // 6. Compute missing shards (in index, not on disk)
  const missingShards: string[] = [];
  for (const pkg of indexedPackages) {
    if (!shardPackageNames.has(pkg)) {
      missingShards.push(pkg);
    }
  }
  missingShards.sort();

  // 7. Compute count mismatches
  const countMismatches: Array<{
    packageName: string;
    indexCount: number;
    shardCount: number;
  }> = [];

  if (index) {
    for (const [pkgName, entry] of Object.entries(index.packages)) {
      // Find the shard file for this package
      let shardPath: string | null = null;
      if (pkgName.startsWith("@")) {
        const slashIdx = pkgName.indexOf("/");
        if (slashIdx !== -1) {
          const scope = pkgName.slice(0, slashIdx);
          const name = pkgName.slice(slashIdx + 1);
          shardPath = join(dataPath, scope, `${name}.json`);
        }
      } else {
        shardPath = join(dataPath, `${pkgName}.json`);
      }

      if (!shardPath) continue;

      const info = await readShardInfo(shardPath);
      if (info) {
        const indexCount = entry.count;
        if (info.vulnCount !== indexCount) {
          countMismatches.push({
            packageName: pkgName,
            indexCount,
            shardCount: info.vulnCount,
          });
        }
      }
      // If shard doesn't exist, it's already in missingShards
    }
  }
  countMismatches.sort((a, b) => a.packageName.localeCompare(b.packageName));

  // 8. Compute package name mismatches (decoded name != internal name)
  const packageNameMismatches: Array<{
    shardPath: string;
    decodedName: string;
    actualName: string;
  }> = [];

  for (const sf of shardFiles) {
    const decodedName = shardPathToName.get(sf) ?? "";
    const info = await readShardInfo(sf);
    if (info && info.packageName !== decodedName) {
      packageNameMismatches.push({
        shardPath: relative(dataPath, sf),
        decodedName,
        actualName: info.packageName,
      });
    }
  }
  packageNameMismatches.sort((a, b) => a.shardPath.localeCompare(b.shardPath));

  // 9. Compute metadata mismatches
  const metadataMismatches: Array<{
    field: string;
    expected: number;
    actual: number;
  }> = [];

  if (index) {
    // Check totalPackages vs actual number of entries
    if (index.totalPackages !== indexedPackageCount) {
      metadataMismatches.push({
        field: "totalPackages",
        expected: index.totalPackages,
        actual: indexedPackageCount,
      });
    }

    // Check totalVulnerabilities vs sum of individual counts
    if (index.totalVulnerabilities !== sumIndexCounts) {
      metadataMismatches.push({
        field: "totalVulnerabilities",
        expected: index.totalVulnerabilities,
        actual: sumIndexCounts,
      });
    }
  }

  // 10. Determine overall consistency
  const isConsistent =
    indexLoaded &&
    orphanShards.length === 0 &&
    missingShards.length === 0 &&
    countMismatches.length === 0 &&
    packageNameMismatches.length === 0 &&
    metadataMismatches.length === 0;

  return {
    indexLoaded,
    indexedPackageCount,
    indexTotalPackages,
    indexTotalVulnerabilities,
    sumIndexCounts,
    shardFileCount,
    orphanShards,
    missingShards,
    countMismatches,
    packageNameMismatches,
    metadataMismatches,
    errors,
    isConsistent,
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Recursively collect shard files (.json and .json.gz) from the data directory.
 * Skips index.json, index.json.gz, README.md, and other non-shard files.
 */
async function collectShardFiles(
  dirPath: string,
  result: string[],
): Promise<void> {
  let entries;
  try {
    entries = await readdir(dirPath, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = join(dirPath, entry.name);

    if (entry.isDirectory()) {
      // Recurse into subdirectories (for scoped packages @scope/)
      await collectShardFiles(fullPath, result);
    } else if (entry.isFile()) {
      const name = entry.name;

      // Skip non-JSON files
      if (!name.endsWith(".json") && !name.endsWith(".json.gz")) continue;

      // Skip index files
      if (name === "index.json" || name === "index.json.gz") continue;

      // Skip README
      if (name === "README.md" || name.startsWith("README.")) continue;

      result.push(fullPath);
    }
  }
}
