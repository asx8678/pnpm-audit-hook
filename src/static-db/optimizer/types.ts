/**
 * Type definitions for the static database optimizer.
 * These represent the compact/optimized format for vulnerability data.
 */

import type { StaticDbCoverage } from "../types";

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
  /** Optional coverage metadata (absent in legacy optimized indexes) */
  cov?: StaticDbCoverage;
  /** Sorted list of package names for fast existence checks */
  pkgList?: string[];
  /**
   * SHA-256 integrity hashes for shard files.
   * Maps relative shard paths to "sha256-<hex>" digests.
   * Short key follows the compact convention of other OptimizedIndex fields.
   */
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