/**
 * Package extraction from pnpm lockfiles.
 *
 * Filters and extracts registry packages from lockfile data,
 * producing a list of PackageRef objects for audit processing.
 * Supports both direct extraction and streaming for large lockfiles.
 */

import type { LockfilePackageEntry, PackageRef, PnpmLockfile } from "../../types.js";
import { parsePnpmPackageKey } from "./package-key-parser.js";
import {
  StreamingLockfileParser,
  type StreamingParserOptions,
  type StreamingParseResult,
} from "./streaming-parser.js";

export interface LockfileParseResult {
  packages: PackageRef[];
}

/** Default threshold (number of packages) for switching to streaming parser */
const STREAMING_THRESHOLD = 1000;

function isRegistryPackage(entry: LockfilePackageEntry): boolean {
  const res = entry.resolution;
  if (!res) return false;
  if (res.type === "directory" || res.directory || res.path) return false;
  if (typeof res.tarball === "string") return res.tarball.startsWith("http");
  return typeof res.integrity === "string";
}

/** Extract registry packages from a pnpm lockfile object. */
export function extractPackagesFromLockfile(
  lockfile: PnpmLockfile | null | undefined,
): LockfileParseResult {
  const packageEntries = lockfile?.packages;
  if (!packageEntries) return { packages: [] };

  const keys = Object.keys(packageEntries);
  // Pre-allocate: most packages in a lockfile are registry packages
  const packages: PackageRef[] = new Array(keys.length);
  let count = 0;

  for (let i = 0; i < keys.length; i++) {
    const k = keys[i]!;
    const entry = packageEntries[k]!;
    const parsed = parsePnpmPackageKey(k);
    if (!parsed) continue;
    if (!isRegistryPackage(entry)) continue;

    packages[count++] = { name: parsed.name, version: parsed.version };
  }

  // Trim to actual size
  packages.length = count;
  return { packages };
}

/**
 * Extract packages from lockfile using streaming parser for large lockfiles.
 *
 * Automatically selects the appropriate parsing strategy:
 * - For small lockfiles (< threshold): uses standard extraction
 * - For large lockfiles (>= threshold): uses streaming batch processing
 *
 * @param lockfile - The pnpm lockfile to parse
 * @param options - Streaming parser configuration (optional)
 * @param threshold - Package count threshold for streaming (default: 1000)
 * @returns Parse result with packages and detailed statistics
 *
 * @example
 * ```typescript
 * const result = extractPackagesFromLockfileStreaming(largeLockfile, {
 *   batchSize: 500,
 *   onProgress: (processed, total) => {
 *     console.log(`Processing: ${processed}/${total}`);
 *   },
 * });
 *
 * console.log(`Found ${result.stats.registryPackages} packages`);
 * console.log(`Memory used: ${result.stats.peakMemoryMB.toFixed(2)} MB`);
 * ```
 */
export function extractPackagesFromLockfileStreaming(
  lockfile: PnpmLockfile | null | undefined,
  options: Partial<StreamingParserOptions> = {},
  threshold: number = STREAMING_THRESHOLD,
): StreamingParseResult {
  const packageEntries = lockfile?.packages;
  const totalPackages = packageEntries ? Object.keys(packageEntries).length : 0;

  // For small lockfiles, use standard extraction (more efficient)
  if (totalPackages < threshold) {
    const startTime = performance.now();
    const { packages } = extractPackagesFromLockfile(lockfile);
    const durationMs = performance.now() - startTime;

    return {
      packages,
      stats: {
        totalProcessed: totalPackages,
        registryPackages: packages.length,
        skippedPackages: totalPackages - packages.length,
        durationMs,
        peakMemoryMB: process.memoryUsage().heapUsed / (1024 * 1024),
      },
    };
  }

  // For large lockfiles, use streaming parser
  const parser = new StreamingLockfileParser(options);
  return parser.parse(lockfile);
}
