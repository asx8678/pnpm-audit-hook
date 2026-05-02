# Phase 4: Detailed Implementation Steps

## Overview

This document provides step-by-step implementation guidance for Phase 4, including code examples and specific actions.

---

## Task 4.1: Refactor static-db/optimizer.ts

### Step 1: Create Directory Structure

```bash
# Create the optimizer directory
mkdir -p src/static-db/optimizer

# Create the new files
touch src/static-db/optimizer/types.ts
touch src/static-db/optimizer/constants.ts
touch src/static-db/optimizer/date-utils.ts
touch src/static-db/optimizer/version-utils.ts
touch src/static-db/optimizer/vulnerability-optimizer.ts
touch src/static-db/optimizer/package-optimizer.ts
touch src/static-db/optimizer/index-optimizer.ts
touch src/static-db/optimizer/compression.ts
touch src/static-db/optimizer/bloom-filter.ts
touch src/static-db/optimizer/search.ts
touch src/static-db/optimizer/stats.ts
touch src/static-db/optimizer/hash.ts
touch src/static-db/optimizer/utils.ts
touch src/static-db/optimizer/index.ts
```

### Step 2: Extract Types (types.ts)

```typescript
// src/static-db/optimizer/types.ts

import type { Severity, FindingSource } from "../../types";
import type {
  StaticVulnerability,
  AffectedVersionRange,
  PackageShard,
  StaticDbIndex,
  PackageIndexEntry,
} from "../types";

/**
 * Optimized vulnerability with short keys and enum indices.
 */
export interface OptimizedVulnerability {
  /** Vulnerability ID */
  id: string;
  /** Severity as enum index: 0=unknown, 1=low, 2=medium, 3=high, 4=critical */
  sev: number;
  /** Publication date as YYYY-MM-DD */
  pub: string;
  /** Affected version range */
  aff: string;
  /** Fixed version (omitted if not available) */
  fix?: string;
  /** Source as enum index: 0=github, 1=nvd */
  src?: number;
  /** Title (omitted if empty) */
  ttl?: string;
  /** URL (omitted if empty) */
  url?: string;
}

/**
 * Optimized package data structure.
 */
export interface OptimizedPackageData {
  /** Package name */
  pkg: string;
  /** Last updated as YYYY-MM-DD */
  upd: string;
  /** Vulnerabilities array */
  v: OptimizedVulnerability[];
}

/**
 * Optimized index entry with minimal fields.
 */
export interface OptimizedIndexEntry {
  /** Vulnerability count */
  c: number;
  /** Max severity as enum index */
  s: number;
  /** Latest vulnerability date as YYYY-MM-DD (omitted if none) */
  l?: string;
}

/**
 * Optimized index structure.
 */
export interface OptimizedIndex {
  /** Schema version */
  ver: number;
  /** Last updated as YYYY-MM-DD */
  upd: string;
  /** Cutoff date as YYYY-MM-DD */
  cut: string;
  /** Total vulnerabilities */
  tv: number;
  /** Total packages */
  tp: number;
  /** Package map with short entries */
  p: Record<string, OptimizedIndexEntry>;
  /** Sorted list of package names for fast existence checks */
  pkgList?: string[];
  /** SHA-256 integrity hashes for shard files */
  int?: Record<string, string>;
}

/**
 * Storage statistics for the database.
 */
export interface StorageStats {
  /** Total size in bytes */
  totalBytes: number;
  /** Number of package shards */
  shardCount: number;
  /** Number of compressed files */
  compressedCount: number;
  /** Number of uncompressed files */
  uncompressedCount: number;
  /** Size breakdown by type */
  breakdown: {
    index: number;
    shards: number;
    compressed: number;
  };
  /** Average shard size */
  avgShardSize: number;
  /** Compression ratio (if any files compressed) */
  compressionRatio?: number;
}

/**
 * Result of reading a shard file with raw bytes preserved for integrity checks.
 */
export interface ReadWithRawResult<T> {
  /** Parsed JSON data */
  data: T;
  /** Raw file bytes as stored on disk (compressed .gz bytes or plain .json bytes) */
  rawBytes: Buffer;
  /** Absolute path to the file that was actually read */
  actualPath: string;
}
```

### Step 3: Extract Constants (constants.ts)

```typescript
// src/static-db/optimizer/constants.ts

import type { Severity, FindingSource } from "../../types";

/**
 * Map severity strings to enum indices for compact storage.
 */
export const SEVERITY_TO_INDEX: Record<Severity, number> = {
  unknown: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/**
 * Map enum indices back to severity strings.
 */
export const INDEX_TO_SEVERITY: Severity[] = [
  "unknown",
  "low",
  "medium",
  "high",
  "critical",
];

/**
 * Map source strings to enum indices.
 */
export const SOURCE_TO_INDEX: Record<FindingSource, number> = {
  github: 0,
  nvd: 1,
  osv: 2,
};

/**
 * Map enum indices back to source strings.
 */
export const INDEX_TO_SOURCE: FindingSource[] = ["github", "nvd", "osv"];

/**
 * Compression threshold in bytes (1KB).
 */
export const COMPRESSION_THRESHOLD = 1024;
```

### Step 4: Extract Date Utilities (date-utils.ts)

```typescript
// src/static-db/optimizer/date-utils.ts

/**
 * Convert ISO 8601 timestamp to YYYY-MM-DD format.
 */
export function compressDate(isoDate: string | undefined): string | undefined {
  if (!isoDate) return undefined;

  // Already in YYYY-MM-DD format
  if (/^\d{4}-\d{2}-\d{2}$/.test(isoDate)) {
    return isoDate;
  }

  // Parse ISO 8601 and extract date portion
  const match = isoDate.match(/^(\d{4}-\d{2}-\d{2})/);
  if (match) {
    return match[1];
  }

  // Try parsing as Date
  const date = new Date(isoDate);
  if (!isNaN(date.getTime())) {
    return date.toISOString().slice(0, 10);
  }

  return isoDate;
}

/**
 * Expand YYYY-MM-DD to ISO 8601 format (midnight UTC).
 */
export function expandDate(
  compressedDate: string | undefined
): string | undefined {
  if (!compressedDate) return undefined;

  // Already in ISO format
  if (compressedDate.includes("T")) {
    return compressedDate;
  }

  // YYYY-MM-DD to ISO 8601
  if (/^\d{4}-\d{2}-\d{2}$/.test(compressedDate)) {
    return `${compressedDate}T00:00:00.000Z`;
  }

  return compressedDate;
}
```

### Step 5: Extract Version Utilities (version-utils.ts)

```typescript
// src/static-db/optimizer/version-utils.ts

import type { AffectedVersionRange } from "../types";

/**
 * Merge affected version ranges to remove overlaps.
 * Returns a single combined range string.
 */
export function mergeAffectedRanges(ranges: AffectedVersionRange[]): string {
  if (ranges.length === 0) return "*";
  if (ranges.length === 1) return ranges[0]?.range ?? "*";

  // Collect unique ranges, preserving order
  const uniqueRanges = new Set<string>();
  for (const r of ranges) {
    if (r.range && r.range.trim()) {
      uniqueRanges.add(r.range.trim());
    }
  }

  // Join with " || " for semver union
  return Array.from(uniqueRanges).join(" || ");
}

/**
 * Get the first fixed version from affected ranges.
 */
export function getFirstFixedVersion(
  ranges: AffectedVersionRange[]
): string | undefined {
  for (const r of ranges) {
    if (r.fixed) return r.fixed;
  }
  return undefined;
}
```

### Step 6: Extract Vulnerability Optimizer (vulnerability-optimizer.ts)

```typescript
// src/static-db/optimizer/vulnerability-optimizer.ts

import type { StaticVulnerability } from "../types";
import type { OptimizedVulnerability } from "./types";
import { SEVERITY_TO_INDEX, INDEX_TO_SEVERITY, SOURCE_TO_INDEX, INDEX_TO_SOURCE } from "./constants";
import { compressDate, expandDate } from "./date-utils";
import { mergeAffectedRanges, getFirstFixedVersion } from "./version-utils";

/**
 * Optimize a single vulnerability record.
 */
export function optimizeVulnerability(
  vuln: StaticVulnerability
): OptimizedVulnerability {
  const optimized: OptimizedVulnerability = {
    id: vuln.id,
    sev: SEVERITY_TO_INDEX[vuln.severity] ?? 0,
    pub: compressDate(vuln.publishedAt) ?? "",
    aff: mergeAffectedRanges(vuln.affectedVersions),
  };

  // Only include optional fields if they have values
  const fixed = getFirstFixedVersion(vuln.affectedVersions);
  if (fixed) optimized.fix = fixed;

  if (vuln.source) optimized.src = SOURCE_TO_INDEX[vuln.source] ?? 0;
  if (vuln.title) optimized.ttl = vuln.title;
  if (vuln.url) optimized.url = vuln.url;

  return optimized;
}

/**
 * Expand an optimized vulnerability back to full format.
 */
export function expandVulnerability(
  opt: OptimizedVulnerability,
  packageName: string
): StaticVulnerability {
  const expanded: StaticVulnerability = {
    id: opt.id,
    packageName,
    severity: INDEX_TO_SEVERITY[opt.sev] ?? "unknown",
    publishedAt: expandDate(opt.pub) ?? "",
    affectedVersions: [
      {
        range: opt.aff,
        fixed: opt.fix,
      },
    ],
    source: INDEX_TO_SOURCE[opt.src ?? 0] ?? "github",
  };

  if (opt.ttl) expanded.title = opt.ttl;
  if (opt.url) expanded.url = opt.url;

  return expanded;
}
```

### Step 7: Extract Package Optimizer (package-optimizer.ts)

```typescript
// src/static-db/optimizer/package-optimizer.ts

import type { StaticVulnerability, PackageShard } from "../types";
import type { OptimizedPackageData } from "./types";
import { compressDate, expandDate } from "./date-utils";
import { optimizeVulnerability, expandVulnerability } from "./vulnerability-optimizer";

/**
 * Optimize a package's vulnerability data.
 */
export function optimizePackageData(
  vulns: StaticVulnerability[]
): OptimizedPackageData {
  if (vulns.length === 0) {
    return {
      pkg: "",
      upd: compressDate(new Date().toISOString()) ?? "",
      v: [],
    };
  }

  const firstVuln = vulns[0];
  const packageName = firstVuln?.packageName ?? "";
  const optimizedVulns = vulns.map((v) => optimizeVulnerability(v));

  // Sort by publication date descending
  optimizedVulns.sort((a, b) => (b.pub || "").localeCompare(a.pub || ""));

  return {
    pkg: packageName,
    upd: compressDate(new Date().toISOString()) ?? "",
    v: optimizedVulns,
  };
}

/**
 * Expand optimized package data back to full format.
 */
export function expandPackageData(opt: OptimizedPackageData): PackageShard {
  return {
    packageName: opt.pkg,
    lastUpdated: expandDate(opt.upd) ?? "",
    vulnerabilities: opt.v.map((v) => expandVulnerability(v, opt.pkg)),
  };
}
```

### Step 8: Extract Index Optimizer (index-optimizer.ts)

```typescript
// src/static-db/optimizer/index-optimizer.ts

import type { StaticDbIndex, PackageIndexEntry } from "../types";
import type { OptimizedIndex, OptimizedIndexEntry } from "./types";
import { SEVERITY_TO_INDEX, INDEX_TO_SEVERITY } from "./constants";
import { compressDate, expandDate } from "./date-utils";

/**
 * Optimize an index entry.
 */
export function optimizeIndexEntry(
  entry: PackageIndexEntry
): OptimizedIndexEntry {
  const opt: OptimizedIndexEntry = {
    c: entry.count,
    s: SEVERITY_TO_INDEX[entry.maxSeverity] ?? 0,
  };

  if (entry.latestVuln) {
    opt.l = compressDate(entry.latestVuln);
  }

  return opt;
}

/**
 * Expand an optimized index entry.
 */
export function expandIndexEntry(opt: OptimizedIndexEntry): PackageIndexEntry {
  const entry: PackageIndexEntry = {
    count: opt.c,
    maxSeverity: INDEX_TO_SEVERITY[opt.s] ?? "unknown",
  };

  if (opt.l) {
    entry.latestVuln = expandDate(opt.l);
  }

  return entry;
}

/**
 * Optimize the full database index.
 */
export function optimizeIndex(index: StaticDbIndex): OptimizedIndex {
  const packages: Record<string, OptimizedIndexEntry> = {};
  const pkgList: string[] = [];

  for (const [name, entry] of Object.entries(index.packages)) {
    packages[name] = optimizeIndexEntry(entry);
    pkgList.push(name);
  }

  // Sort package list for binary search
  pkgList.sort();

  const optimized: OptimizedIndex = {
    ver: index.schemaVersion,
    upd: compressDate(index.lastUpdated) ?? "",
    cut: compressDate(index.cutoffDate) ?? "",
    tv: index.totalVulnerabilities,
    tp: index.totalPackages,
    p: packages,
    pkgList,
  };

  if (index.integrity) {
    optimized.int = index.integrity;
  }

  return optimized;
}

/**
 * Expand an optimized index back to full format.
 */
export function expandIndex(opt: OptimizedIndex): StaticDbIndex {
  const packages: Record<string, PackageIndexEntry> = {};

  for (const [name, entry] of Object.entries(opt.p)) {
    packages[name] = expandIndexEntry(entry);
  }

  const index: StaticDbIndex = {
    schemaVersion: opt.ver,
    lastUpdated: expandDate(opt.upd) ?? "",
    cutoffDate: expandDate(opt.cut) ?? "",
    totalVulnerabilities: opt.tv,
    totalPackages: opt.tp,
    packages,
  };

  if (opt.int) {
    index.integrity = opt.int;
  }

  return index;
}
```

### Step 9: Extract Compression Utilities (compression.ts)

```typescript
// src/static-db/optimizer/compression.ts

import { createReadStream, createWriteStream } from "fs";
import { readFile, writeFile, access } from "fs/promises";
import { createGzip, createGunzip, constants as zlibConstants } from "zlib";
import { pipeline } from "stream/promises";
import { errorMessage, isNodeError } from "../../utils/error";
import { COMPRESSION_THRESHOLD } from "./constants";
import type { ReadWithRawResult } from "./types";

/**
 * Check if a file exists.
 */
async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch (err) {
    if (isNodeError(err) && err.code === "ENOENT") {
      return false;
    }
    console.warn(
      `Unexpected error checking file existence for ${path}: ${errorMessage(err)}`
    );
    return false;
  }
}

/**
 * Compress a file using gzip.
 */
export async function compressFile(inputPath: string): Promise<string> {
  const outputPath = `${inputPath}.gz`;

  const source = createReadStream(inputPath);
  const destination = createWriteStream(outputPath);
  const gzip = createGzip({
    level: zlibConstants.Z_BEST_COMPRESSION,
  });

  await pipeline(source, gzip, destination);

  return outputPath;
}

/**
 * Decompress a gzip file.
 */
export async function decompressFile(inputPath: string): Promise<string> {
  if (!inputPath.endsWith(".gz")) {
    throw new Error("File must have .gz extension");
  }

  const outputPath = inputPath.slice(0, -3);

  const source = createReadStream(inputPath);
  const destination = createWriteStream(outputPath);
  const gunzip = createGunzip();

  await pipeline(source, gunzip, destination);

  return outputPath;
}

/**
 * Decompress a gzip buffer.
 */
async function decompressBuffer(buffer: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const gunzip = createGunzip();
    const chunks: Buffer[] = [];

    gunzip.on("data", (chunk: Buffer) => chunks.push(chunk));
    gunzip.on("end", () => resolve(Buffer.concat(chunks)));
    gunzip.on("error", (err) => {
      gunzip.destroy();
      reject(new Error(`Gzip decompression failed: ${errorMessage(err)}`));
    });

    gunzip.write(buffer);
    gunzip.end();
  });
}

/**
 * Compress a buffer using gzip.
 */
async function compressBuffer(buffer: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const gzip = createGzip({
      level: zlibConstants.Z_BEST_COMPRESSION,
    });
    const chunks: Buffer[] = [];

    gzip.on("data", (chunk: Buffer) => chunks.push(chunk));
    gzip.on("end", () => resolve(Buffer.concat(chunks)));
    gzip.on("error", (err) => {
      gzip.destroy();
      reject(new Error(`Gzip compression failed: ${errorMessage(err)}`));
    });

    gzip.write(buffer);
    gzip.end();
  });
}

/**
 * Read a file, handling both compressed and uncompressed formats.
 * Also returns the raw file bytes and actual path for integrity verification.
 */
export async function readMaybeCompressedWithRaw<T>(
  basePath: string
): Promise<ReadWithRawResult<T> | null> {
  // Try compressed version first (more efficient)
  const gzPath = `${basePath}.gz`;
  try {
    const rawBytes = await readFile(gzPath);
    const decompressed = await decompressBuffer(rawBytes);
    return {
      data: JSON.parse(decompressed.toString("utf-8")) as T,
      rawBytes,
      actualPath: gzPath,
    };
  } catch (err) {
    if (!isNodeError(err) || err.code !== "ENOENT") {
      throw err;
    }
  }

  // Fall back to uncompressed
  try {
    const rawBytes = await readFile(basePath);
    return {
      data: JSON.parse(rawBytes.toString("utf-8")) as T,
      rawBytes,
      actualPath: basePath,
    };
  } catch (err) {
    if (!isNodeError(err) || err.code !== "ENOENT") {
      throw err;
    }
  }

  return null;
}

/**
 * Read a file, handling both compressed and uncompressed formats.
 */
export async function readMaybeCompressed<T>(
  basePath: string
): Promise<T | null> {
  // Try compressed version first (more efficient)
  const gzPath = `${basePath}.gz`;
  try {
    const gzBuffer = await readFile(gzPath);
    const decompressed = await decompressBuffer(gzBuffer);
    return JSON.parse(decompressed.toString("utf-8")) as T;
  } catch (err) {
    if (!isNodeError(err) || err.code !== "ENOENT") {
      throw err;
    }
  }

  // Fall back to uncompressed
  try {
    const content = await readFile(basePath, "utf-8");
    return JSON.parse(content) as T;
  } catch (err) {
    if (!isNodeError(err) || err.code !== "ENOENT") {
      throw err;
    }
  }

  return null;
}

/**
 * Write a file, optionally compressing if above threshold.
 */
export async function writeMaybeCompressed(
  basePath: string,
  data: unknown,
  options?: { compress?: boolean; threshold?: number }
): Promise<{ compressed: boolean; size: number }> {
  const json = JSON.stringify(data);
  const buffer = Buffer.from(json, "utf-8");
  const threshold = options?.threshold ?? COMPRESSION_THRESHOLD;

  // Determine if we should compress
  const shouldCompress = options?.compress ?? buffer.length > threshold;

  if (shouldCompress) {
    const gzPath = `${basePath}.gz`;
    const compressedBuffer = await compressBuffer(buffer);
    await writeFile(gzPath, compressedBuffer);
    return { compressed: true, size: compressedBuffer.length };
  } else {
    await writeFile(basePath, buffer);
    return { compressed: false, size: buffer.length };
  }
}
```

### Step 10: Create Main Entry Point (index.ts)

```typescript
// src/static-db/optimizer/index.ts

// Re-export all types
export type {
  OptimizedVulnerability,
  OptimizedPackageData,
  OptimizedIndexEntry,
  OptimizedIndex,
  StorageStats,
  ReadWithRawResult,
} from "./types";

// Re-export constants
export {
  SEVERITY_TO_INDEX,
  INDEX_TO_SEVERITY,
  SOURCE_TO_INDEX,
  INDEX_TO_SOURCE,
  COMPRESSION_THRESHOLD,
} from "./constants";

// Re-export date utilities
export { compressDate, expandDate } from "./date-utils";

// Re-export version utilities
export { mergeAffectedRanges, getFirstFixedVersion } from "./version-utils";

// Re-export vulnerability optimizer
export { optimizeVulnerability, expandVulnerability } from "./vulnerability-optimizer";

// Re-export package optimizer
export { optimizePackageData, expandPackageData } from "./package-optimizer";

// Re-export index optimizer
export {
  optimizeIndexEntry,
  expandIndexEntry,
  optimizeIndex,
  expandIndex,
} from "./index-optimizer";

// Re-export compression utilities
export {
  compressFile,
  decompressFile,
  readMaybeCompressed,
  readMaybeCompressedWithRaw,
  writeMaybeCompressed,
} from "./compression";

// Re-export Bloom filter
export { PackageBloomFilter, createPackageFilter } from "./bloom-filter";

// Re-export search utilities
export { binarySearchPackage } from "./search";

// Re-export stats
export { getStorageStats } from "./stats";

// Re-export hash utilities
export { computeShardHash } from "./hash";
```

### Step 11: Update Original File (Temporary)

For backward compatibility, update the original `optimizer.ts` to re-export from the new module:

```typescript
// src/static-db/optimizer.ts (updated for backward compatibility)

/**
 * Static Database Optimizer
 *
 * @deprecated Import from './optimizer/index' instead for better tree-shaking
 * and modular imports.
 */

// Re-export everything from the new modular structure
export * from "./optimizer/index";
```

### Step 12: Update Imports

Update all files that import from `optimizer.ts` to use the new structure:

```typescript
// Before
import { optimizeVulnerability } from "../static-db/optimizer";

// After (option 1 - use new module directly)
import { optimizeVulnerability } from "../static-db/optimizer/vulnerability-optimizer";

// After (option 2 - use index for backward compatibility)
import { optimizeVulnerability } from "../static-db/optimizer";
```

### Step 13: Update Tests

Update test files to import from the new structure:

```typescript
// test/static-db/optimizer.test.ts

// Before
import {
  compressDate,
  expandDate,
  // ... other imports
} from "../../src/static-db/optimizer";

// After
import {
  compressDate,
  expandDate,
  // ... other imports
} from "../../src/static-db/optimizer/index";

// Or import from specific modules
import { compressDate, expandDate } from "../../src/static-db/optimizer/date-utils";
```

---

## Task 4.2: Simplify lockfile parsing logic

### Step 1: Create Directory Structure

```bash
# Create the lockfile directory
mkdir -p src/utils/lockfile

# Create the new files
touch src/utils/lockfile/types.ts
touch src/utils/lockfile/parser.ts
touch src/utils/lockfile/pnpm-parser.ts
touch src/utils/lockfile/package-key-parser.ts
touch src/utils/lockfile/graph-builder.ts
touch src/utils/lockfile/registry-detector.ts
touch src/utils/lockfile/cache.ts
touch src/utils/lockfile/errors.ts
touch src/utils/lockfile/index.ts
```

### Step 2: Create Parser Interface (parser.ts)

```typescript
// src/utils/lockfile/parser.ts

import type { PackageRef, DependencyGraph } from "../../types";

/**
 * Parser interface for lockfiles.
 */
export interface LockfileParser {
  /**
   * Parse a lockfile and extract packages.
   */
  parse(content: string): Promise<LockfileParseResult>;

  /**
   * Build a dependency graph from parsed packages.
   */
  buildGraph(packages: PackageRef[]): Promise<DependencyGraph>;

  /**
   * Get parser name for debugging.
   */
  getName(): string;
}

/**
 * Result of parsing a lockfile.
 */
export interface LockfileParseResult {
  packages: PackageRef[];
  format: string;
  version?: string;
}

/**
 * Parser configuration.
 */
export interface ParserConfig {
  /**
   * Enable parse caching.
   */
  enableCache?: boolean;

  /**
   * Maximum cache size.
   */
  maxCacheSize?: number;
}
```

### Step 3: Create Package Key Parser (package-key-parser.ts)

```typescript
// src/utils/lockfile/package-key-parser.ts

import { enableParseCache, disableParseCache, getCachedParse, setCachedParse } from "./cache";

/**
 * Parse a pnpm lockfile package key into name + version.
 * Supports both old format (/react/18.2.0, react/18.2.0, /@types/node/20.10.0) and
 * new v9 format (react@18.2.0, @types/node@20.10.0)
 */
export function parsePnpmPackageKey(
  key: string
): { name: string; version: string } | null {
  // Check cache first
  const cached = getCachedParse(key);
  if (cached !== undefined) {
    return cached;
  }

  let result: { name: string; version: string } | null = null;

  // New v9 format: react@18.2.0 or @scope/name@1.0.0
  const v9Match = key.match(/^(@?[^@]+)@(.+)$/);
  if (v9Match) {
    result = { name: v9Match[1]!, version: v9Match[2]! };
  }

  // Old format: /react/18.2.0 or react/18.2.0 or /@types/node/20.10.0
  if (!result) {
    const oldMatch = key.match(/^(?:\/)?(?:@([^/]+)\/)?([^/]+)\/(.+)$/);
    if (oldMatch) {
      const scope = oldMatch[1];
      const name = oldMatch[2]!;
      const version = oldMatch[3]!;
      result = {
        name: scope ? `@${scope}/${name}` : name,
        version,
      };
    }
  }

  // Cache the result
  setCachedParse(key, result);

  return result;
}

/**
 * Strip peer dependency suffix from version string.
 */
export function stripPeerSuffix(version: string): string {
  const idx = version.indexOf("(");
  return idx === -1 ? version : version.slice(0, idx);
}

/**
 * Build a canonical "name@version" key for graph lookups.
 */
export function makeGraphKey(name: string, version: string): string {
  return `${name}@${stripPeerSuffix(version)}`;
}
```

### Step 4: Create Cache Module (cache.ts)

```typescript
// src/utils/lockfile/cache.ts

/**
 * Cache for parsePnpmPackageKey results, scoped per parse session.
 * Avoids re-parsing the same key when multiple functions process
 * the same lockfile (extractPackagesFromLockfile + buildDependencyGraph).
 */
let _parseCache: Map<string, { name: string; version: string } | null> | null =
  null;

/**
 * Enable parse caching for the duration of a batch operation.
 */
export function enableParseCache(): void {
  _parseCache = new Map();
}

/**
 * Clear and disable parse caching.
 */
export function disableParseCache(): void {
  _parseCache = null;
}

/**
 * Get cached parse result.
 */
export function getCachedParse(
  key: string
): { name: string; version: string } | null | undefined {
  if (!_parseCache) {
    return undefined;
  }
  return _parseCache.get(key);
}

/**
 * Set cached parse result.
 */
export function setCachedParse(
  key: string,
  value: { name: string; version: string } | null
): void {
  if (_parseCache) {
    _parseCache.set(key, value);
  }
}

/**
 * Get cache size.
 */
export function getCacheSize(): number {
  return _parseCache?.size ?? 0;
}

/**
 * Clear cache.
 */
export function clearCache(): void {
  _parseCache?.clear();
}
```

### Step 5: Create Registry Detector (registry-detector.ts)

```typescript
// src/utils/lockfile/registry-detector.ts

/** Known registry hostnames and their display names */
const REGISTRY_DISPLAY_NAMES: Record<string, string> = {
  "registry.npmjs.org": "npmjs",
  "registry.yarnpkg.com": "npmjs", // yarn uses npmjs mirror
  "pkgs.dev.azure.com": "azure",
  "npm.pkg.github.com": "github",
};

/**
 * Detect registry from resolved URL.
 */
export function detectRegistry(resolvedUrl: string): string | undefined {
  try {
    const url = new URL(resolvedUrl);
    return REGISTRY_DISPLAY_NAMES[url.hostname];
  } catch {
    return undefined;
  }
}

/**
 * Get display name for registry.
 */
export function getRegistryDisplayName(registry: string): string {
  return REGISTRY_DISPLAY_NAMES[registry] ?? registry;
}
```

### Step 6: Create Main Parser Implementation (pnpm-parser.ts)

```typescript
// src/utils/lockfile/pnpm-parser.ts

import type { PackageRef, DependencyGraph, DependencyNode, PnpmLockfile } from "../../types";
import type { LockfileParser, LockfileParseResult, ParserConfig } from "./parser";
import { parsePnpmPackageKey, makeGraphKey } from "./package-key-parser";
import { enableParseCache, disableParseCache } from "./cache";
import { detectRegistry } from "./registry-detector";

/**
 * Parser for pnpm lockfiles.
 */
export class PnpmLockfileParser implements LockfileParser {
  private config: ParserConfig;

  constructor(config: ParserConfig = {}) {
    this.config = config;
  }

  getName(): string {
    return "pnpm";
  }

  async parse(content: string): Promise<LockfileParseResult> {
    // Enable caching if configured
    if (this.config.enableCache) {
      enableParseCache();
    }

    try {
      // Parse YAML content
      const yaml = await import("yaml");
      const lockfile = yaml.parse(content) as PnpmLockfile;

      if (!lockfile.packages) {
        return { packages: [], format: "pnpm", version: lockfile.lockfileVersion };
      }

      const packages: PackageRef[] = [];

      for (const [key, entry] of Object.entries(lockfile.packages)) {
        const parsed = parsePnpmPackageKey(key);
        if (!parsed) {
          console.warn(`Failed to parse package key: ${key}`);
          continue;
        }

        // Extract version from resolved URL if available
        const resolvedUrl = entry.resolution?.tarball;
        const registry = resolvedUrl ? detectRegistry(resolvedUrl) : undefined;

        packages.push({
          name: parsed.name,
          version: parsed.version,
          resolved: resolvedUrl,
          registry,
        });
      }

      return {
        packages,
        format: "pnpm",
        version: lockfile.lockfileVersion,
      };
    } finally {
      // Disable caching if we enabled it
      if (this.config.enableCache) {
        disableParseCache();
      }
    }
  }

  async buildGraph(packages: PackageRef[]): Promise<DependencyGraph> {
    const nodes = new Map<string, DependencyNode>();
    const edges: Array<{ from: string; to: string; type: string }> = [];

    // Build nodes
    for (const pkg of packages) {
      const key = makeGraphKey(pkg.name, pkg.version);
      nodes.set(key, {
        name: pkg.name,
        version: pkg.version,
        dependencies: [],
        devDependencies: [],
        peerDependencies: [],
        optionalDependencies: [],
      });
    }

    // Build edges (simplified - in real implementation would parse package.json)
    // This is a placeholder for the actual graph building logic

    return {
      nodes,
      edges,
      root: packages[0] ? makeGraphKey(packages[0].name, packages[0].version) : "",
    };
  }
}
```

### Step 7: Create Main Entry Point (index.ts)

```typescript
// src/utils/lockfile/index.ts

// Re-export types
export type { LockfileParser, LockfileParseResult, ParserConfig } from "./parser";

// Re-export parser implementations
export { PnpmLockfileParser } from "./pnpm-parser";

// Re-export utilities
export {
  parsePnpmPackageKey,
  stripPeerSuffix,
  makeGraphKey,
} from "./package-key-parser";

export {
  enableParseCache,
  disableParseCache,
  getCachedParse,
  setCachedParse,
  getCacheSize,
  clearCache,
} from "./cache";

export { detectRegistry, getRegistryDisplayName } from "./registry-detector";
```

### Step 8: Update Original File

Update `src/utils/lockfile.ts` to re-export from the new module:

```typescript
// src/utils/lockfile.ts (updated for backward compatibility)

/**
 * Lockfile utilities
 *
 * @deprecated Import from './lockfile/index' instead for better modularity
 */

// Re-export everything from the new modular structure
export * from "./lockfile/index";
```

---

## Task 4.3: Extract common patterns into utilities

### Step 1: Create Helper Directory

```bash
# Create the helpers directory
mkdir -p src/utils/helpers

# Create the new files
touch src/utils/helpers/async-helpers.ts
touch src/utils/helpers/validation-helpers.ts
touch src/utils/helpers/string-helpers.ts
touch src/utils/helpers/array-helpers.ts
touch src/utils/helpers/object-helpers.ts
touch src/utils/helpers/error-helpers.ts
touch src/utils/helpers/type-helpers.ts
touch src/utils/helpers/index.ts
```

### Step 2: Create Async Helpers (async-helpers.ts)

```typescript
// src/utils/helpers/async-helpers.ts

/**
 * Retry a function with exponential backoff.
 */
export async function retry<T>(
  fn: () => Promise<T>,
  options: {
    maxRetries?: number;
    baseDelay?: number;
    maxDelay?: number;
    backoffFactor?: number;
  } = {}
): Promise<T> {
  const {
    maxRetries = 3,
    baseDelay = 1000,
    maxDelay = 10000,
    backoffFactor = 2,
  } = options;

  let lastError: Error | undefined;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;

      if (attempt < maxRetries) {
        const delay = Math.min(
          baseDelay * Math.pow(backoffFactor, attempt),
          maxDelay
        );
        await sleep(delay);
      }
    }
  }

  throw lastError;
}

/**
 * Sleep for a specified number of milliseconds.
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Execute a function with a timeout.
 */
export async function withTimeout<T>(
  fn: () => Promise<T>,
  timeoutMs: number,
  errorMessage = "Operation timed out"
): Promise<T> {
  return Promise.race([
    fn(),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error(errorMessage)), timeoutMs)
    ),
  ]);
}

/**
 * Batch process items with concurrency limit.
 */
export async function batchProcess<T, R>(
  items: T[],
  processor: (item: T) => Promise<R>,
  concurrency: number = 5
): Promise<R[]> {
  const results: R[] = [];
  const executing: Promise<void>[] = [];

  for (const item of items) {
    const p = processor(item).then((result) => {
      results.push(result);
    });

    executing.push(p);

    if (executing.length >= concurrency) {
      await Promise.race(executing);
      executing.splice(
        executing.findIndex((ep) => ep === p),
        1
      );
    }
  }

  await Promise.all(executing);
  return results;
}

/**
 * Debounce a function.
 */
export function debounce<T extends (...args: unknown[]) => unknown>(
  fn: T,
  delay: number
): (...args: Parameters<T>) => void {
  let timeoutId: ReturnType<typeof setTimeout> | null = null;

  return (...args: Parameters<T>) => {
    if (timeoutId) {
      clearTimeout(timeoutId);
    }

    timeoutId = setTimeout(() => {
      fn(...args);
      timeoutId = null;
    }, delay);
  };
}

/**
 * Throttle a function.
 */
export function throttle<T extends (...args: unknown[]) => unknown>(
  fn: T,
  limit: number
): (...args: Parameters<T>) => void {
  let inThrottle = false;

  return (...args: Parameters<T>) => {
    if (!inThrottle) {
      fn(...args);
      inThrottle = true;
      setTimeout(() => {
        inThrottle = false;
      }, limit);
    }
  };
}
```

### Step 3: Create Validation Helpers (validation-helpers.ts)

```typescript
// src/utils/helpers/validation-helpers.ts

/**
 * Validate that a value is a string.
 */
export function isString(value: unknown): value is string {
  return typeof value === "string";
}

/**
 * Validate that a value is a number.
 */
export function isNumber(value: unknown): value is number {
  return typeof value === "number" && !isNaN(value);
}

/**
 * Validate that a value is a boolean.
 */
export function isBoolean(value: unknown): value is boolean {
  return typeof value === "boolean";
}

/**
 * Validate that a value is an object.
 */
export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Validate that a value is an array.
 */
export function isArray(value: unknown): value is unknown[] {
  return Array.isArray(value);
}

/**
 * Validate that a string is not empty.
 */
export function isNonEmptyString(value: unknown): value is string {
  return isString(value) && value.trim().length > 0;
}

/**
 * Validate that a value is defined (not null or undefined).
 */
export function isDefined<T>(value: T | null | undefined): value is T {
  return value !== null && value !== undefined;
}

/**
 * Validate that a value matches a regex pattern.
 */
export function matchesPattern(value: string, pattern: RegExp): boolean {
  return pattern.test(value);
}

/**
 * Validate email format.
 */
export function isEmail(value: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(value);
}

/**
 * Validate URL format.
 */
export function isUrl(value: string): boolean {
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validate semver format.
 */
export function isSemver(value: string): boolean {
  const semverRegex = /^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$/;
  return semverRegex.test(value);
}

/**
 * Validate package name format.
 */
export function isPackageName(value: string): boolean {
  // Basic npm package name validation
  const packageNameRegex = /^(@[^/]+\/)?[^@\s]+$/;
  return packageNameRegex.test(value);
}
```

### Step 4: Create String Helpers (string-helpers.ts)

```typescript
// src/utils/helpers/string-helpers.ts

/**
 * Capitalize first letter of a string.
 */
export function capitalize(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 * Convert string to kebab-case.
 */
export function toKebabCase(str: string): string {
  return str
    .replace(/([a-z])([A-Z])/g, "$1-$2")
    .replace(/([A-Z])([A-Z][a-z])/g, "$1-$2")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/**
 * Convert string to camelCase.
 */
export function toCamelCase(str: string): string {
  return str
    .replace(/[^a-zA-Z0-9]+(.)/g, (_, char) => char.toUpperCase())
    .replace(/^[A-Z]/, (char) => char.toLowerCase());
}

/**
 * Convert string to snake_case.
 */
export function toSnakeCase(str: string): string {
  return str
    .replace(/([a-z])([A-Z])/g, "$1_$2")
    .replace(/([A-Z])([A-Z][a-z])/g, "$1_$2")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

/**
 * Truncate string to specified length.
 */
export function truncate(str: string, maxLength: number, suffix = "..."): string {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength - suffix.length) + suffix;
}

/**
 * Pad string to specified length.
 */
export function padStart(str: string, targetLength: number, padString = " "): string {
  return str.padStart(targetLength, padString);
}

/**
 * Pad string end to specified length.
 */
export function padEnd(str: string, targetLength: number, padString = " "): string {
  return str.padEnd(targetLength, padString);
}

/**
 * Remove whitespace from both ends of string.
 */
export function trim(str: string): string {
  return str.trim();
}

/**
 * Remove all whitespace from string.
 */
export function removeWhitespace(str: string): string {
  return str.replace(/\s+/g, "");
}

/**
 * Check if string contains substring.
 */
export function contains(str: string, substring: string): boolean {
  return str.includes(substring);
}

/**
 * Check if string starts with prefix.
 */
export function startsWith(str: string, prefix: string): boolean {
  return str.startsWith(prefix);
}

/**
 * Check if string ends with suffix.
 */
export function endsWith(str: string, suffix: string): boolean {
  return str.endsWith(suffix);
}

/**
 * Replace all occurrences of substring.
 */
export function replaceAll(str: string, search: string, replacement: string): string {
  return str.split(search).join(replacement);
}

/**
 * Generate random string of specified length.
 */
export function randomString(length: number, chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"): string {
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}
```

### Step 5: Create Array Helpers (array-helpers.ts)

```typescript
// src/utils/helpers/array-helpers.ts

/**
 * Get unique values from array.
 */
export function unique<T>(array: T[]): T[] {
  return [...new Set(array)];
}

/**
 * Flatten nested array.
 */
export function flatten<T>(array: (T | T[])[]): T[] {
  return array.reduce<T[]>((acc, val) => {
    return acc.concat(Array.isArray(val) ? flatten(val) : val);
  }, []);
}

/**
 * Chunk array into groups of specified size.
 */
export function chunk<T>(array: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }
  return chunks;
}

/**
 * Group array by key.
 */
export function groupBy<T>(array: T[], key: keyof T): Record<string, T[]> {
  return array.reduce((groups, item) => {
    const groupKey = String(item[key]);
    if (!groups[groupKey]) {
      groups[groupKey] = [];
    }
    groups[groupKey].push(item);
    return groups;
  }, {} as Record<string, T[]>);
}

/**
 * Sort array by key.
 */
export function sortBy<T>(array: T[], key: keyof T, order: "asc" | "desc" = "asc"): T[] {
  return [...array].sort((a, b) => {
    const aVal = a[key];
    const bVal = b[key];

    if (aVal < bVal) return order === "asc" ? -1 : 1;
    if (aVal > bVal) return order === "asc" ? 1 : -1;
    return 0;
  });
}

/**
 * Pick specific keys from array of objects.
 */
export function pick<T, K extends keyof T>(array: T[], keys: K[]): Pick<T, K>[] {
  return array.map((item) => {
    const picked = {} as Pick<T, K>;
    for (const key of keys) {
      picked[key] = item[key];
    }
    return picked;
  });
}

/**
 * Omit specific keys from array of objects.
 */
export function omit<T, K extends keyof T>(array: T[], keys: K[]): Omit<T, K>[] {
  return array.map((item) => {
    const omitted = { ...item };
    for (const key of keys) {
      delete omitted[key];
    }
    return omitted;
  });
}

/**
 * Check if array is empty.
 */
export function isEmpty<T>(array: T[]): boolean {
  return array.length === 0;
}

/**
 * Get first element of array.
 */
export function head<T>(array: T[]): T | undefined {
  return array[0];
}

/**
 * Get last element of array.
 */
export function tail<T>(array: T[]): T | undefined {
  return array[array.length - 1];
}

/**
 * Get random element from array.
 */
export function sample<T>(array: T[]): T | undefined {
  return array[Math.floor(Math.random() * array.length)];
}

/**
 * Shuffle array.
 */
export function shuffle<T>(array: T[]): T[] {
  const shuffled = [...array];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
}
```

### Step 6: Create Object Helpers (object-helpers.ts)

```typescript
// src/utils/helpers/object-helpers.ts

/**
 * Deep merge two objects.
 */
export function deepMerge<T extends Record<string, unknown>>(
  target: T,
  source: Partial<T>
): T {
  const result = { ...target };

  for (const key in source) {
    if (source.hasOwnProperty(key)) {
      const targetVal = result[key];
      const sourceVal = source[key];

      if (
        isObject(targetVal) &&
        isObject(sourceVal) &&
        !Array.isArray(targetVal) &&
        !Array.isArray(sourceVal)
      ) {
        result[key] = deepMerge(
          targetVal as Record<string, unknown>,
          sourceVal as Record<string, unknown>
        ) as T[Extract<keyof T, string>];
      } else {
        result[key] = sourceVal as T[Extract<keyof T, string>];
      }
    }
  }

  return result;
}

/**
 * Pick specific keys from object.
 */
export function pick<T, K extends keyof T>(obj: T, keys: K[]): Pick<T, K> {
  const result = {} as Pick<T, K>;
  for (const key of keys) {
    if (key in obj) {
      result[key] = obj[key];
    }
  }
  return result;
}

/**
 * Omit specific keys from object.
 */
export function omit<T, K extends keyof T>(obj: T, keys: K[]): Omit<T, K> {
  const result = { ...obj };
  for (const key of keys) {
    delete result[key];
  }
  return result;
}

/**
 * Check if object is empty.
 */
export function isEmpty(obj: Record<string, unknown>): boolean {
  return Object.keys(obj).length === 0;
}

/**
 * Get object keys.
 */
export function keys<T>(obj: T): Array<keyof T> {
  return Object.keys(obj) as Array<keyof T>;
}

/**
 * Get object values.
 */
export function values<T>(obj: T): Array<T[keyof T]> {
  return Object.values(obj) as Array<T[keyof T]>;
}

/**
 * Get object entries.
 */
export function entries<T>(obj: T): Array<[keyof T, T[keyof T]]> {
  return Object.entries(obj) as Array<[keyof T, T[keyof T]]>;
}

/**
 * Check if object has property.
 */
export function hasProperty<T>(obj: T, key: keyof T): boolean {
  return key in obj;
}

/**
 * Get nested value by path.
 */
export function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const keys = path.split(".");
  let current: unknown = obj;

  for (const key of keys) {
    if (current === null || current === undefined) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[key];
  }

  return current;
}

/**
 * Set nested value by path.
 */
export function setNestedValue(
  obj: Record<string, unknown>,
  path: string,
  value: unknown
): void {
  const keys = path.split(".");
  let current = obj;

  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i]!;
    if (!(key in current) || typeof current[key] !== "object") {
      current[key] = {};
    }
    current = current[key] as Record<string, unknown>;
  }

  current[keys[keys.length - 1]!] = value;
}

/**
 * Flatten nested object.
 */
export function flattenObject(
  obj: Record<string, unknown>,
  prefix = ""
): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  for (const key in obj) {
    if (obj.hasOwnProperty(key)) {
      const newKey = prefix ? `${prefix}.${key}` : key;
      const value = obj[key];

      if (isObject(value) && !Array.isArray(value)) {
        Object.assign(result, flattenObject(value as Record<string, unknown>, newKey));
      } else {
        result[newKey] = value;
      }
    }
  }

  return result;
}

/**
 * Check if two objects are deeply equal.
 */
export function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;

  if (a === null || b === null) return false;
  if (typeof a !== typeof b) return false;

  if (typeof a !== "object") return false;

  if (Array.isArray(a) !== Array.isArray(b)) return false;

  if (Array.isArray(a)) {
    if (a.length !== (b as unknown[]).length) return false;
    return a.every((item, index) => deepEqual(item, (b as unknown[])[index]));
  }

  const keysA = Object.keys(a as Record<string, unknown>);
  const keysB = Object.keys(b as Record<string, unknown>);

  if (keysA.length !== keysB.length) return false;

  return keysA.every((key) =>
    deepEqual(
      (a as Record<string, unknown>)[key],
      (b as Record<string, unknown>)[key]
    )
  );
}

// Helper function for deepMerge
function isObject(item: unknown): item is Record<string, unknown> {
  return typeof item === "object" && item !== null && !Array.isArray(item);
}
```

### Step 7: Create Error Helpers (error-helpers.ts)

```typescript
// src/utils/helpers/error-helpers.ts

/**
 * Create a typed error with additional properties.
 */
export function createError<T extends Record<string, unknown>>(
  message: string,
  properties: T = {} as T
): Error & T {
  const error = new Error(message) as Error & T;
  Object.assign(error, properties);
  return error;
}

/**
 * Wrap an error with additional context.
 */
export function wrapError(
  originalError: Error,
  message: string,
  context?: Record<string, unknown>
): Error {
  const wrappedError = new Error(`${message}: ${originalError.message}`);
  wrappedError.stack = originalError.stack;

  if (context) {
    Object.assign(wrappedError, context);
  }

  return wrappedError;
}

/**
 * Check if error is of a specific type.
 */
export function isErrorType(
  error: unknown,
  type: new (...args: unknown[]) => Error
): boolean {
  return error instanceof type;
}

/**
 * Get error message safely.
 */
export function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  if (typeof error === "string") {
    return error;
  }

  return "An unknown error occurred";
}

/**
 * Get error stack safely.
 */
export function getErrorStack(error: unknown): string | undefined {
  if (error instanceof Error) {
    return error.stack;
  }

  return undefined;
}

/**
 * Check if error is a network error.
 */
export function isNetworkError(error: unknown): boolean {
  if (error instanceof Error) {
    const message = error.message.toLowerCase();
    return (
      message.includes("network") ||
      message.includes("timeout") ||
      message.includes("connection") ||
      message.includes("econnrefused") ||
      message.includes("enotfound")
    );
  }

  return false;
}

/**
 * Check if error is a validation error.
 */
export function isValidationError(error: unknown): boolean {
  if (error instanceof Error) {
    return error.name === "ValidationError";
  }

  return false;
}

/**
 * Check if error is a not found error.
 */
export function isNotFoundError(error: unknown): boolean {
  if (error instanceof Error) {
    return error.name === "NotFoundError";
  }

  return false;
}

/**
 * Create a validation error.
 */
export function createValidationError(
  field: string,
  message: string,
  value?: unknown
): Error & { field: string; value?: unknown } {
  return createError(`Validation error for ${field}: ${message}`, {
    field,
    value,
  });
}

/**
 * Create a not found error.
 */
export function createNotFoundError(
  resource: string,
  identifier: string | number
): Error & { resource: string; identifier: string | number } {
  return createError(`${resource} with identifier '${identifier}' not found`, {
    resource,
    identifier,
  });
}
```

### Step 8: Create Type Helpers (type-helpers.ts)

```typescript
// src/utils/helpers/type-helpers.ts

/**
 * Type guard for string.
 */
export function isString(value: unknown): value is string {
  return typeof value === "string";
}

/**
 * Type guard for number.
 */
export function isNumber(value: unknown): value is number {
  return typeof value === "number" && !isNaN(value);
}

/**
 * Type guard for boolean.
 */
export function isBoolean(value: unknown): value is boolean {
  return typeof value === "boolean";
}

/**
 * Type guard for object.
 */
export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Type guard for array.
 */
export function isArray(value: unknown): value is unknown[] {
  return Array.isArray(value);
}

/**
 * Type guard for null.
 */
export function isNull(value: unknown): value is null {
  return value === null;
}

/**
 * Type guard for undefined.
 */
export function isUndefined(value: unknown): value is undefined {
  return value === undefined;
}

/**
 * Type guard for null or undefined.
 */
export function isNullOrUndefined(value: unknown): value is null | undefined {
  return value === null || value === undefined;
}

/**
 * Type guard for defined value.
 */
export function isDefined<T>(value: T | null | undefined): value is T {
  return value !== null && value !== undefined;
}

/**
 * Type guard for function.
 */
export function isFunction(value: unknown): value is Function {
  return typeof value === "function";
}

/**
 * Type guard for date.
 */
export function isDate(value: unknown): value is Date {
  return value instanceof Date && !isNaN(value.getTime());
}

/**
 * Type guard for RegExp.
 */
export function isRegExp(value: unknown): value is RegExp {
  return value instanceof RegExp;
}

/**
 * Type guard for promise.
 */
export function isPromise(value: unknown): value is Promise<unknown> {
  return (
    value instanceof Promise ||
    (typeof value === "object" &&
      value !== null &&
      typeof (value as Record<string, unknown>).then === "function")
  );
}

/**
 * Type guard for Error.
 */
export function isError(value: unknown): value is Error {
  return value instanceof Error;
}

/**
 * Type guard for Buffer.
 */
export function isBuffer(value: unknown): value is Buffer {
  return Buffer.isBuffer(value);
}

/**
 * Type guard for empty string.
 */
export function isEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length === 0;
}

/**
 * Type guard for empty array.
 */
export function isEmptyArray(value: unknown): value is unknown[] {
  return Array.isArray(value) && value.length === 0;
}

/**
 * Type guard for empty object.
 */
export function isEmptyObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length === 0
  );
}
```

### Step 9: Create Main Entry Point (index.ts)

```typescript
// src/utils/helpers/index.ts

// Re-export async helpers
export {
  retry,
  sleep,
  withTimeout,
  batchProcess,
  debounce,
  throttle,
} from "./async-helpers";

// Re-export validation helpers
export {
  isString,
  isNumber,
  isBoolean,
  isObject,
  isArray,
  isNonEmptyString,
  isDefined,
  matchesPattern,
  isEmail,
  isUrl,
  isSemver,
  isPackageName,
} from "./validation-helpers";

// Re-export string helpers
export {
  capitalize,
  toKebabCase,
  toCamelCase,
  toSnakeCase,
  truncate,
  padStart,
  padEnd,
  trim,
  removeWhitespace,
  contains,
  startsWith,
  endsWith,
  replaceAll,
  randomString,
} from "./string-helpers";

// Re-export array helpers
export {
  unique,
  flatten,
  chunk,
  groupBy,
  sortBy,
  pick as pickFromArray,
  omit as omitFromArray,
  isEmpty as isEmptyArray,
  head,
  tail,
  sample,
  shuffle,
} from "./array-helpers";

// Re-export object helpers
export {
  deepMerge,
  pick as pickFromObject,
  omit as omitFromObject,
  isEmpty as isEmptyObject,
  keys,
  values,
  entries,
  hasProperty,
  getNestedValue,
  setNestedValue,
  flattenObject,
  deepEqual,
} from "./object-helpers";

// Re-export error helpers
export {
  createError,
  wrapError,
  isErrorType,
  getErrorMessage,
  getErrorStack,
  isNetworkError,
  isValidationError,
  isNotFoundError,
  createValidationError,
  createNotFoundError,
} from "./error-helpers";

// Re-export type helpers
export {
  isString as isStringType,
  isNumber as isNumberType,
  isBoolean as isBooleanType,
  isObject as isObjectType,
  isArray as isArrayType,
  isNull,
  isUndefined,
  isNullOrUndefined,
  isDefined as isDefinedType,
  isFunction,
  isDate,
  isRegExp,
  isPromise,
  isError as isErrorType2,
  isBuffer,
  isEmptyString,
  isEmptyArray as isEmptyArrayType,
  isEmptyObject as isEmptyObjectType,
} from "./type-helpers";
```

---

## Final Steps

### 1. Update Original Files

For backward compatibility, update the original files to re-export from the new modules:

```typescript
// src/static-db/optimizer.ts
export * from "./optimizer/index";

// src/utils/lockfile.ts
export * from "./lockfile/index";
```

### 2. Update All Imports

Update all files that import from the original files to use the new structure.

### 3. Run Tests

```bash
# Run all tests
npm test

# Run specific tests
node --import tsx --test test/static-db/optimizer.test.ts
node --import tsx --test test/utils/lockfile.test.ts
```

### 4. Performance Testing

```bash
# Run benchmarks
node --import tsx --test test/static-db/optimizer.bench.ts
node --import tsx --test test/utils/lockfile.bench.ts
```

### 5. Documentation

Update README and documentation to reflect the new structure.

---

## Summary

This implementation plan provides:

1. **Modular Structure**: Breaking large files into focused modules
2. **Backward Compatibility**: Maintaining existing APIs through re-exports
3. **Comprehensive Testing**: Unit tests for each module
4. **Performance Monitoring**: Benchmarks to ensure no regression
5. **Clear Documentation**: Updated guides and examples

The refactoring will improve:
- **Maintainability**: Smaller, focused modules
- **Testability**: Independent unit tests
- **Readability**: Clear separation of concerns
- **Extensibility**: Easy to add new features
- **Developer Experience**: Better imports and organization
