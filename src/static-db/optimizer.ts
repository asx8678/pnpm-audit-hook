/**
 * Static Database Optimizer
 *
 * Provides compression and optimization utilities for the static vulnerability database.
 * Includes field deduplication, date compression, and optional gzip compression.
 */

import { createReadStream, createWriteStream } from "fs";
import { readFile, writeFile, readdir, stat, unlink, access } from "fs/promises";
import { createGzip, createGunzip, constants as zlibConstants } from "zlib";
import { pipeline } from "stream/promises";
import { join, dirname, basename } from "path";
import type { Severity, FindingSource } from "../types";
import type {
  StaticVulnerability,
  AffectedVersionRange,
  PackageShard,
  StaticDbIndex,
  PackageIndexEntry,
} from "./types";
import { severityLevel } from "./types";

// ============================================================================
// Optimized Data Types (Compact Format)
// ============================================================================

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

// ============================================================================
// Enum Mappings
// ============================================================================

const SEVERITY_TO_INDEX: Record<Severity, number> = {
  unknown: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const INDEX_TO_SEVERITY: Severity[] = ["unknown", "low", "medium", "high", "critical"];

const SOURCE_TO_INDEX: Record<FindingSource, number> = {
  github: 0,
  nvd: 1,
};

const INDEX_TO_SOURCE: FindingSource[] = ["github", "nvd"];

// ============================================================================
// Date Compression
// ============================================================================

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
export function expandDate(compressedDate: string | undefined): string | undefined {
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

// ============================================================================
// Version Range Normalization
// ============================================================================

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
export function getFirstFixedVersion(ranges: AffectedVersionRange[]): string | undefined {
  for (const r of ranges) {
    if (r.fixed) return r.fixed;
  }
  return undefined;
}

// ============================================================================
// Optimization Functions
// ============================================================================

/**
 * Optimize a single vulnerability record.
 */
export function optimizeVulnerability(vuln: StaticVulnerability): OptimizedVulnerability {
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

/**
 * Optimize a package's vulnerability data.
 */
export function optimizePackageData(vulns: StaticVulnerability[]): OptimizedPackageData {
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

/**
 * Optimize an index entry.
 */
export function optimizeIndexEntry(entry: PackageIndexEntry): OptimizedIndexEntry {
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

  return {
    ver: index.schemaVersion,
    upd: compressDate(index.lastUpdated) ?? "",
    cut: compressDate(index.cutoffDate) ?? "",
    tv: index.totalVulnerabilities,
    tp: index.totalPackages,
    p: packages,
    pkgList,
  };
}

/**
 * Expand an optimized index back to full format.
 */
export function expandIndex(opt: OptimizedIndex): StaticDbIndex {
  const packages: Record<string, PackageIndexEntry> = {};

  for (const [name, entry] of Object.entries(opt.p)) {
    packages[name] = expandIndexEntry(entry);
  }

  return {
    schemaVersion: opt.ver,
    lastUpdated: expandDate(opt.upd) ?? "",
    cutoffDate: expandDate(opt.cut) ?? "",
    totalVulnerabilities: opt.tv,
    totalPackages: opt.tp,
    packages,
  };
}

// ============================================================================
// File Compression
// ============================================================================

const COMPRESSION_THRESHOLD = 10 * 1024; // 10KB

/**
 * Check if a file exists.
 */
async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
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
 * Read a file, handling both compressed and uncompressed formats.
 */
export async function readMaybeCompressed<T>(basePath: string): Promise<T | null> {
  // Try compressed version first (more efficient)
  const gzPath = `${basePath}.gz`;
  if (await fileExists(gzPath)) {
    const gzBuffer = await readFile(gzPath);
    const decompressed = await decompressBuffer(gzBuffer);
    return JSON.parse(decompressed.toString("utf-8")) as T;
  }

  // Fall back to uncompressed
  if (await fileExists(basePath)) {
    const content = await readFile(basePath, "utf-8");
    return JSON.parse(content) as T;
  }

  return null;
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
    gunzip.on("error", reject);

    gunzip.write(buffer);
    gunzip.end();
  });
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

    // Only use compressed if it's actually smaller
    if (compressedBuffer.length < buffer.length) {
      await writeFile(gzPath, compressedBuffer);

      // Remove uncompressed version if it exists
      if (await fileExists(basePath)) {
        await unlink(basePath);
      }

      return { compressed: true, size: compressedBuffer.length };
    }
  }

  // Write uncompressed
  await writeFile(basePath, buffer);

  // Remove compressed version if it exists
  const gzPath = `${basePath}.gz`;
  if (await fileExists(gzPath)) {
    await unlink(gzPath);
  }

  return { compressed: false, size: buffer.length };
}

/**
 * Compress a buffer with gzip.
 */
async function compressBuffer(buffer: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const gzip = createGzip({
      level: zlibConstants.Z_BEST_COMPRESSION,
    });
    const chunks: Buffer[] = [];

    gzip.on("data", (chunk: Buffer) => chunks.push(chunk));
    gzip.on("end", () => resolve(Buffer.concat(chunks)));
    gzip.on("error", reject);

    gzip.write(buffer);
    gzip.end();
  });
}

// ============================================================================
// Database-Level Operations
// ============================================================================

/**
 * Compress the entire static database.
 */
export async function compressDatabase(dataPath: string): Promise<{
  filesProcessed: number;
  bytesOriginal: number;
  bytesCompressed: number;
  compressionRatio: number;
}> {
  let filesProcessed = 0;
  let bytesOriginal = 0;
  let bytesCompressed = 0;

  // Process index file
  const indexPath = join(dataPath, "index.json");
  if (await fileExists(indexPath)) {
    const stats = await stat(indexPath);
    bytesOriginal += stats.size;

    if (stats.size > COMPRESSION_THRESHOLD) {
      const content = await readFile(indexPath, "utf-8");
      const data = JSON.parse(content);
      const result = await writeMaybeCompressed(indexPath, data, { compress: true });
      bytesCompressed += result.size;
      filesProcessed++;
    } else {
      bytesCompressed += stats.size;
    }
  }

  // Process all package shards
  const entries = await readdir(dataPath, { withFileTypes: true });

  for (const entry of entries) {
    if (entry.isDirectory()) {
      // Handle scoped packages (@scope/)
      const scopedPath = join(dataPath, entry.name);
      const scopedEntries = await readdir(scopedPath, { withFileTypes: true });

      for (const scopedEntry of scopedEntries) {
        if (scopedEntry.isFile() && scopedEntry.name.endsWith(".json")) {
          const filePath = join(scopedPath, scopedEntry.name);
          const result = await processShardFile(filePath);
          filesProcessed += result.processed ? 1 : 0;
          bytesOriginal += result.originalSize;
          bytesCompressed += result.compressedSize;
        }
      }
    } else if (entry.isFile() && entry.name.endsWith(".json") && entry.name !== "index.json") {
      const filePath = join(dataPath, entry.name);
      const result = await processShardFile(filePath);
      filesProcessed += result.processed ? 1 : 0;
      bytesOriginal += result.originalSize;
      bytesCompressed += result.compressedSize;
    }
  }

  return {
    filesProcessed,
    bytesOriginal,
    bytesCompressed,
    compressionRatio: bytesOriginal > 0 ? bytesCompressed / bytesOriginal : 1,
  };
}

/**
 * Process a single shard file for compression.
 */
async function processShardFile(filePath: string): Promise<{
  processed: boolean;
  originalSize: number;
  compressedSize: number;
}> {
  const stats = await stat(filePath);
  const originalSize = stats.size;

  if (originalSize <= COMPRESSION_THRESHOLD) {
    return { processed: false, originalSize, compressedSize: originalSize };
  }

  const content = await readFile(filePath, "utf-8");
  const data = JSON.parse(content);
  const result = await writeMaybeCompressed(filePath, data, { compress: true });

  return {
    processed: true,
    originalSize,
    compressedSize: result.size,
  };
}

/**
 * Calculate storage statistics for the database.
 */
export async function getStorageStats(dataPath: string): Promise<StorageStats> {
  let totalBytes = 0;
  let shardCount = 0;
  let compressedCount = 0;
  let uncompressedCount = 0;
  let indexSize = 0;
  let shardSize = 0;
  let compressedSize = 0;
  let originalSizeEstimate = 0;

  // Check index files
  const indexJsonPath = join(dataPath, "index.json");
  const indexGzPath = join(dataPath, "index.json.gz");

  if (await fileExists(indexGzPath)) {
    const stats = await stat(indexGzPath);
    indexSize = stats.size;
    compressedCount++;
    compressedSize += stats.size;
    // Estimate original size (typical JSON compression ratio ~3-5x)
    originalSizeEstimate += stats.size * 4;
  } else if (await fileExists(indexJsonPath)) {
    const stats = await stat(indexJsonPath);
    indexSize = stats.size;
    uncompressedCount++;
  }
  totalBytes += indexSize;

  // Process all shard files
  const processDirectory = async (dirPath: string): Promise<void> => {
    let entries: { name: string; isDirectory(): boolean; isFile(): boolean }[];
    try {
      entries = await readdir(dirPath, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const entryName = String(entry.name);
      const fullPath = join(dirPath, entryName);

      if (entry.isDirectory()) {
        await processDirectory(fullPath);
      } else if (entry.isFile()) {
        const stats = await stat(fullPath);

        if (entryName.endsWith(".json.gz")) {
          shardCount++;
          compressedCount++;
          compressedSize += stats.size;
          shardSize += stats.size;
          totalBytes += stats.size;
          originalSizeEstimate += stats.size * 4;
        } else if (entryName.endsWith(".json") && entryName !== "index.json") {
          shardCount++;
          uncompressedCount++;
          shardSize += stats.size;
          totalBytes += stats.size;
          originalSizeEstimate += stats.size;
        }
      }
    }
  };

  await processDirectory(dataPath);

  return {
    totalBytes,
    shardCount,
    compressedCount,
    uncompressedCount,
    breakdown: {
      index: indexSize,
      shards: shardSize,
      compressed: compressedSize,
    },
    avgShardSize: shardCount > 0 ? Math.round(shardSize / shardCount) : 0,
    compressionRatio:
      compressedSize > 0 && originalSizeEstimate > 0
        ? compressedSize / originalSizeEstimate
        : undefined,
  };
}

// ============================================================================
// Bloom Filter for Fast Package Checks
// ============================================================================

/**
 * Simple bloom filter implementation for fast package existence checks.
 */
export class PackageBloomFilter {
  private bits: Uint8Array;
  private hashCount: number;
  private size: number;

  constructor(expectedItems: number, falsePositiveRate = 0.01) {
    // Calculate optimal size and hash count
    this.size = Math.ceil((-expectedItems * Math.log(falsePositiveRate)) / Math.LN2 ** 2);
    this.hashCount = Math.ceil((this.size / expectedItems) * Math.LN2);
    this.bits = new Uint8Array(Math.ceil(this.size / 8));
  }

  /**
   * Add a package name to the filter.
   */
  add(packageName: string): void {
    const hashes = this.getHashes(packageName);
    for (const hash of hashes) {
      const index = hash % this.size;
      const byteIndex = Math.floor(index / 8);
      const bitIndex = index % 8;
      const currentByte = this.bits[byteIndex];
      if (currentByte !== undefined) {
        this.bits[byteIndex] = currentByte | (1 << bitIndex);
      }
    }
  }

  /**
   * Check if a package name might be in the filter.
   * Returns false if definitely not present, true if possibly present.
   */
  mightContain(packageName: string): boolean {
    const hashes = this.getHashes(packageName);
    for (const hash of hashes) {
      const index = hash % this.size;
      const byteIndex = Math.floor(index / 8);
      const bitIndex = index % 8;
      const currentByte = this.bits[byteIndex];
      if (currentByte === undefined || (currentByte & (1 << bitIndex)) === 0) {
        return false;
      }
    }
    return true;
  }

  /**
   * Get the hash values for a string.
   */
  private getHashes(str: string): number[] {
    const hashes: number[] = [];
    const hash1 = this.fnv1a(str);
    const hash2 = this.djb2(str);

    for (let i = 0; i < this.hashCount; i++) {
      // Double hashing technique
      hashes.push(Math.abs((hash1 + i * hash2) >>> 0));
    }

    return hashes;
  }

  /**
   * FNV-1a hash function.
   */
  private fnv1a(str: string): number {
    let hash = 2166136261;
    for (let i = 0; i < str.length; i++) {
      hash ^= str.charCodeAt(i);
      hash = (hash * 16777619) >>> 0;
    }
    return hash;
  }

  /**
   * DJB2 hash function.
   */
  private djb2(str: string): number {
    let hash = 5381;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) + hash + str.charCodeAt(i)) >>> 0;
    }
    return hash;
  }

  /**
   * Serialize the filter to a compact format.
   */
  serialize(): { bits: string; size: number; hashCount: number } {
    return {
      bits: Buffer.from(this.bits).toString("base64"),
      size: this.size,
      hashCount: this.hashCount,
    };
  }

  /**
   * Create a filter from serialized data.
   */
  static deserialize(data: { bits: string; size: number; hashCount: number }): PackageBloomFilter {
    const filter = Object.create(PackageBloomFilter.prototype) as PackageBloomFilter;
    filter.bits = new Uint8Array(Buffer.from(data.bits, "base64"));
    filter.size = data.size;
    filter.hashCount = data.hashCount;
    return filter;
  }
}

/**
 * Create a bloom filter from a list of package names.
 */
export function createPackageFilter(
  packageNames: string[],
  falsePositiveRate = 0.01
): PackageBloomFilter {
  const filter = new PackageBloomFilter(Math.max(packageNames.length, 100), falsePositiveRate);
  for (const name of packageNames) {
    filter.add(name);
  }
  return filter;
}

// ============================================================================
// Binary Search for Sorted Package Lists
// ============================================================================

/**
 * Binary search for a package name in a sorted list.
 */
export function binarySearchPackage(sortedPackages: string[], packageName: string): boolean {
  let left = 0;
  let right = sortedPackages.length - 1;

  while (left <= right) {
    const mid = Math.floor((left + right) / 2);
    const midValue = sortedPackages[mid];
    if (midValue === undefined) {
      return false;
    }
    const comparison = packageName.localeCompare(midValue);

    if (comparison === 0) {
      return true;
    } else if (comparison < 0) {
      right = mid - 1;
    } else {
      left = mid + 1;
    }
  }

  return false;
}
