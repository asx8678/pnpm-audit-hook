import { join } from "path";
import type { VulnerabilityFinding, Severity, FindingSource } from "../types";
import type {
  StaticDbIndex,
  PackageShard,
  StaticVulnerability,
  StaticDbQueryOptions,
} from "./types";
import { severityLevel } from "./types";
import {
  readMaybeCompressed,
  binarySearchPackage,
  PackageBloomFilter,
  expandPackageData,
  expandIndex,
  type OptimizedPackageData,
  type OptimizedIndex,
} from "./optimizer";

/**
 * Static vulnerability database reader.
 * Provides fast lookups for historical vulnerabilities from a pre-built database.
 * Supports both compressed (.json.gz) and uncompressed (.json) files.
 */
export interface StaticDbReader {
  /**
   * Query vulnerabilities for a specific package.
   * Returns all known vulnerabilities affecting any version of the package.
   */
  queryPackage(packageName: string): Promise<VulnerabilityFinding[]>;

  /**
   * Query vulnerabilities for a specific package with filtering options.
   */
  queryPackageWithOptions(
    packageName: string,
    options?: StaticDbQueryOptions
  ): Promise<VulnerabilityFinding[]>;

  /**
   * Check if a package has any known vulnerabilities.
   * Uses bloom filter or index for O(1) lookup.
   */
  hasVulnerabilities(packageName: string): Promise<boolean>;

  /**
   * Check if the static database is loaded and ready.
   */
  isReady(): boolean;

  /**
   * Get the cutoff date for the static database.
   * Vulnerabilities published after this date should be queried from live APIs.
   */
  getCutoffDate(): string;

  /**
   * Get the full database index.
   */
  getIndex(): StaticDbIndex | null;
}

/**
 * Configuration for creating a StaticDbReader.
 */
export interface StaticDbReaderConfig {
  /** Path to the static database directory */
  dataPath: string;
  /** Cutoff date for the static database (ISO date string) */
  cutoffDate: string;
  /** Whether to use optimized (compressed) format */
  useOptimized?: boolean;
}

/**
 * Internal implementation of StaticDbReader.
 */
class StaticDbReaderImpl implements StaticDbReader {
  private dataPath: string;
  private cutoffDate: string;
  private useOptimized: boolean;
  private index: StaticDbIndex | null = null;
  private optimizedIndex: OptimizedIndex | null = null;
  private packageCache: Map<string, PackageShard> = new Map();
  private bloomFilter: PackageBloomFilter | null = null;
  private ready = false;

  constructor(config: StaticDbReaderConfig) {
    this.dataPath = config.dataPath;
    this.cutoffDate = config.cutoffDate;
    this.useOptimized = config.useOptimized ?? true;
  }

  /**
   * Initialize the reader by loading the index.
   */
  async initialize(): Promise<void> {
    try {
      // Try to load optimized index first
      const indexPath = join(this.dataPath, "index.json");
      const data = await readMaybeCompressed<StaticDbIndex | OptimizedIndex>(indexPath);

      if (!data) {
        this.ready = false;
        return;
      }

      // Detect if it's optimized format (has 'ver' key instead of 'schemaVersion')
      if ("ver" in data) {
        this.optimizedIndex = data as OptimizedIndex;
        this.index = expandIndex(this.optimizedIndex);

        // Use the sorted package list for fast lookups
        if (this.optimizedIndex.pkgList && this.optimizedIndex.pkgList.length > 0) {
          // Create bloom filter from package list for even faster checks
          this.bloomFilter = new PackageBloomFilter(this.optimizedIndex.pkgList.length);
          for (const pkg of this.optimizedIndex.pkgList) {
            this.bloomFilter.add(pkg);
          }
        }
      } else {
        this.index = data as StaticDbIndex;
        this.optimizedIndex = null;

        // Create bloom filter from index packages
        const packages = Object.keys(this.index.packages);
        if (packages.length > 0) {
          this.bloomFilter = new PackageBloomFilter(packages.length);
          for (const pkg of packages) {
            this.bloomFilter.add(pkg);
          }
        }
      }

      this.ready = true;
    } catch {
      this.ready = false;
    }
  }

  isReady(): boolean {
    return this.ready;
  }

  getCutoffDate(): string {
    return this.index?.cutoffDate ?? this.cutoffDate;
  }

  getIndex(): StaticDbIndex | null {
    return this.index;
  }

  async hasVulnerabilities(packageName: string): Promise<boolean> {
    if (!this.ready) return false;

    // Fast check with bloom filter (no false negatives)
    if (this.bloomFilter && !this.bloomFilter.mightContain(packageName)) {
      return false;
    }

    // If we have optimized index with sorted list, use binary search
    if (this.optimizedIndex?.pkgList) {
      return binarySearchPackage(this.optimizedIndex.pkgList, packageName);
    }

    // Fall back to index lookup
    return this.index?.packages[packageName] !== undefined;
  }

  async queryPackage(packageName: string): Promise<VulnerabilityFinding[]> {
    return this.queryPackageWithOptions(packageName);
  }

  async queryPackageWithOptions(
    packageName: string,
    options?: StaticDbQueryOptions
  ): Promise<VulnerabilityFinding[]> {
    if (!this.ready) return [];

    // Fast check if package exists
    if (!(await this.hasVulnerabilities(packageName))) {
      return [];
    }

    // Load package shard
    const shard = await this.loadPackageShard(packageName);
    if (!shard) return [];

    // Convert to findings and apply filters
    let findings = shard.vulnerabilities.map((v) => this.vulnToFinding(v, options?.version));

    // Apply filters
    if (options?.publishedAfter) {
      const afterDate = new Date(options.publishedAfter);
      findings = findings.filter((f) => f.publishedAt && new Date(f.publishedAt) > afterDate);
    }

    if (options?.publishedBefore) {
      const beforeDate = new Date(options.publishedBefore);
      findings = findings.filter((f) => f.publishedAt && new Date(f.publishedAt) < beforeDate);
    }

    if (options?.minSeverity) {
      const minLevel = severityLevel(options.minSeverity);
      findings = findings.filter((f) => severityLevel(f.severity) >= minLevel);
    }

    return findings;
  }

  /**
   * Load a package shard from disk, with caching.
   */
  private async loadPackageShard(packageName: string): Promise<PackageShard | null> {
    // Check cache first
    const cached = this.packageCache.get(packageName);
    if (cached) return cached;

    // Determine file path
    const filePath = this.getShardPath(packageName);

    try {
      const data = await readMaybeCompressed<PackageShard | OptimizedPackageData>(filePath);
      if (!data) return null;

      // Detect optimized format
      let shard: PackageShard;
      if ("pkg" in data && "v" in data) {
        shard = expandPackageData(data as OptimizedPackageData);
      } else {
        shard = data as PackageShard;
      }

      // Cache for future lookups
      this.packageCache.set(packageName, shard);

      return shard;
    } catch {
      return null;
    }
  }

  /**
   * Get the file path for a package shard.
   */
  private getShardPath(packageName: string): string {
    // Handle scoped packages (@scope/package -> @scope/package.json)
    if (packageName.startsWith("@")) {
      const parts = packageName.split("/");
      if (parts.length === 2) {
        const scope = parts[0] ?? "";
        const name = parts[1] ?? "";
        return join(this.dataPath, scope, `${name}.json`);
      }
    }

    return join(this.dataPath, `${packageName}.json`);
  }

  /**
   * Convert a static vulnerability to a finding.
   */
  private vulnToFinding(vuln: StaticVulnerability, version?: string): VulnerabilityFinding {
    // Get the relevant affected range
    const affectedRange =
      vuln.affectedVersions.length > 0
        ? vuln.affectedVersions.map((v) => v.range).join(" || ")
        : undefined;

    const fixedVersion =
      vuln.affectedVersions.find((v) => v.fixed)?.fixed ?? undefined;

    return {
      id: vuln.id,
      source: vuln.source,
      packageName: vuln.packageName,
      packageVersion: version ?? "*",
      title: vuln.title,
      url: vuln.url,
      severity: vuln.severity,
      publishedAt: vuln.publishedAt,
      modifiedAt: vuln.modifiedAt,
      identifiers: vuln.identifiers,
      affectedRange,
      fixedVersion,
    };
  }
}

/**
 * Create a StaticDbReader instance.
 * Returns null if the database cannot be loaded.
 */
export async function createStaticDbReader(
  config: StaticDbReaderConfig
): Promise<StaticDbReader | null> {
  const reader = new StaticDbReaderImpl(config);
  await reader.initialize();

  if (!reader.isReady()) {
    return null;
  }

  return reader;
}
