import { join, relative, sep } from "path";
import type {
  VulnerabilityFinding,
  FindingSource,
  VulnerabilityIdentifier,
} from "../types";
import { logger } from "../utils/logger";
import { errorMessage } from "../utils/error";
import { mapSeverity } from "../utils/severity";
import { satisfies } from "../utils/semver";
import { isString, isArray, isObject } from "../utils/helpers/validation-helpers";
import { isSecurePackageName } from "../utils/security";
import { QueryPerformanceTracker } from "../utils/performance";
import type {
  StaticDbIndex,
  AffectedVersionRange,
  PackageIndexEntry,
  PackageShard,
  StaticVulnerability,
  StaticDbQueryOptions,
} from "./types";
import { severityLevel } from "./types";
import {
  readMaybeCompressed,
  readMaybeCompressedWithRaw,
  binarySearchPackage,
  PackageBloomFilter,
  expandPackageData,
  expandIndex,
  computeShardHash,
  type OptimizedPackageData,
  type OptimizedIndex,
} from "./optimizer";

/**
 * Maximum schema version this reader knows how to interpret.
 * Bump this when the on-disk format changes in a backwards-compatible way.
 */
const SUPPORTED_SCHEMA_VERSION = 1;

/**
 * Performance tracking instance for the static DB reader.
 * Shared across all reader instances for aggregate statistics.
 */
const globalPerformanceTracker = new QueryPerformanceTracker();

/**
 * LRU Cache implementation optimized for the static DB reader.
 * Uses a Map (which preserves insertion order in modern JS engines) for O(1) eviction.
 */
export class LruCache<K, V> {
  private cache = new Map<K, V>();
  private readonly maxSize: number;

  constructor(maxSize: number) {
    this.maxSize = Math.max(0, maxSize);
  }

  get(key: K): V | undefined {
    const value = this.cache.get(key);
    if (value !== undefined) {
      // Move to end (most recently used) by re-inserting
      this.cache.delete(key);
      this.cache.set(key, value);
    }
    return value;
  }

  set(key: K, value: V): void {
    if (this.cache.has(key)) {
      this.cache.delete(key);
    } else if (this.maxSize > 0 && this.cache.size >= this.maxSize) {
      // Evict oldest (first) entry
      const firstKey = this.cache.keys().next().value;
      if (firstKey !== undefined) {
        this.cache.delete(firstKey);
      }
    }
    this.cache.set(key, value);
  }

  has(key: K): boolean {
    return this.cache.has(key);
  }

  delete(key: K): boolean {
    return this.cache.delete(key);
  }

  get size(): number {
    return this.cache.size;
  }

  clear(): void {
    this.cache.clear();
  }

  /**
   * Get cache statistics for monitoring.
   */
  getStats(): { size: number; maxSize: number; utilization: number } {
    return {
      size: this.cache.size,
      maxSize: this.maxSize,
      utilization: this.maxSize > 0 ? this.cache.size / this.maxSize : 0,
    };
  }
}

/**
 * Validate that a package name matches npm naming conventions.
 * Delegates to the centralized security module for consistent validation.
 */
function isValidPackageName(name: string): boolean {
  return isSecurePackageName(name);
}

function normalizeFindingSource(value: unknown): FindingSource {
  return value === "nvd" || value === "github" || value === "osv" ? value : "github";
}

function normalizeIdentifiers(value: unknown): VulnerabilityIdentifier[] | undefined {
  if (!isArray(value)) return undefined;
  const identifiers: VulnerabilityIdentifier[] = [];
  for (const entry of value) {
    if (!entry || !isObject(entry)) continue;
    const type = isString(entry.type) ? entry.type : "";
    const val = isString(entry.value) ? entry.value : "";
    if (!type || !val) continue;
    identifiers.push({ type: type as VulnerabilityIdentifier["type"], value: val });
  }
  return identifiers.length > 0 ? identifiers : undefined;
}

function normalizeAffectedVersions(
  value: unknown,
  affectedRange?: unknown,
  fixedVersion?: unknown,
): AffectedVersionRange[] {
  if (isArray(value)) {
    const ranges: AffectedVersionRange[] = [];
    for (const entry of value) {
      if (!entry || !isObject(entry)) continue;
      const range = isString(entry.range) ? entry.range : "";
      if (!range) continue;
      const fixed = isString(entry.fixed) ? entry.fixed : undefined;
      ranges.push({ range, fixed });
    }
    return ranges;
  }

  if (isString(affectedRange) && affectedRange.length > 0) {
    const fixed = isString(fixedVersion) ? fixedVersion : undefined;
    return [{ range: affectedRange, fixed }];
  }

  return [];
}

function normalizeVulnerability(
  value: unknown,
  packageName: string,
): StaticVulnerability | null {
  if (!value || !isObject(value)) return null;
  const id = isString(value.id) ? value.id : "";
  if (!id) return null;

  const pkgName =
    isString(value.packageName) && value.packageName.length > 0
      ? value.packageName
      : packageName;

  return {
    id,
    packageName: pkgName,
    severity: mapSeverity(isString(value.severity) ? value.severity : undefined),
    publishedAt: isString(value.publishedAt) ? value.publishedAt : undefined,
    modifiedAt: isString(value.modifiedAt) ? value.modifiedAt : undefined,
    affectedVersions: normalizeAffectedVersions(
      value.affectedVersions,
      value.affectedRange,
      value.fixedVersion,
    ),
    source: normalizeFindingSource(value.source),
    title: isString(value.title) ? value.title : undefined,
    url: isString(value.url) ? value.url : undefined,
    description: isString(value.description) ? value.description : undefined,
    identifiers: normalizeIdentifiers(value.identifiers),
  };
}

function normalizePackageShardData(
  data: unknown,
  packageNameHint: string,
): PackageShard | null {
  if (!data || typeof data !== "object") return null;
  const obj = data as Record<string, unknown>;

  const packageName =
    typeof obj.packageName === "string"
      ? obj.packageName
      : typeof obj.name === "string"
        ? obj.name
        : packageNameHint;

  if (!packageName) return null;

  const vulnerabilitiesRaw = Array.isArray(obj.vulnerabilities) ? obj.vulnerabilities : [];
  const vulnerabilities = vulnerabilitiesRaw
    .map((v) => normalizeVulnerability(v, packageName))
    .filter((v): v is StaticVulnerability => v !== null);

  return {
    packageName,
    lastUpdated: typeof obj.lastUpdated === "string" ? obj.lastUpdated : "",
    vulnerabilities,
  };
}

function normalizeIndexData(index: StaticDbIndex): StaticDbIndex {
  const rawPackages = (index.packages ?? {}) as Record<string, unknown>;
  const packages: Record<string, PackageIndexEntry> = {};

  for (const [name, entry] of Object.entries(rawPackages)) {
    if (!entry || typeof entry !== "object") continue;
    const obj = entry as Record<string, unknown>;
    const count =
      typeof obj.count === "number"
        ? obj.count
        : typeof obj.vulnCount === "number"
          ? obj.vulnCount
          : 0;
    const latestVuln =
      typeof obj.latestVuln === "string"
        ? obj.latestVuln
        : typeof obj.lastModified === "string"
          ? obj.lastModified
          : undefined;
    const maxSeverity =
      typeof obj.maxSeverity === "string" ? mapSeverity(obj.maxSeverity) : "unknown";

    packages[name] = { count, latestVuln, maxSeverity };
  }

  return { ...index, packages };
}

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
   * Batch query vulnerabilities for multiple packages.
   * Optimized for reduced I/O by sharing cache lookups and shard reads.
   */
  queryPackagesBatch(
    packageNames: string[],
    options?: StaticDbQueryOptions
  ): Promise<Map<string, VulnerabilityFinding[]>>;

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
   * Get the database version identifier (lastUpdated timestamp from the index).
   * Used in cache keys to automatically invalidate caches when the DB is updated.
   * Returns empty string if the index is not loaded.
   */
  getDbVersion(): string;

  /**
   * Get the full database index.
   */
  getIndex(): StaticDbIndex | null;

  /**
   * Get performance metrics for the reader.
   */
  getPerformanceMetrics(): QueryPerformanceMetrics;
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
  /** Max package shards to keep in memory (0 disables caching). */
  packageCacheMaxEntries?: number;
  /** Max query results to cache (0 disables query caching). */
  queryCacheMaxEntries?: number;
}

/**
 * Performance metrics for the reader.
 */
export interface QueryPerformanceMetrics {
  shardCache: { size: number; maxSize: number; utilization: number };
  queryCache: { size: number; maxSize: number; utilization: number };
  queryPerformance: ReturnType<QueryPerformanceTracker["getMetrics"]>;
}

/**
 * Internal implementation of StaticDbReader.
 */
class StaticDbReaderImpl implements StaticDbReader {
  private dataPath: string;
  private cutoffDate: string;
  private index: StaticDbIndex | null = null;
  private optimizedIndex: OptimizedIndex | null = null;
  private packageCache: LruCache<string, PackageShard>;
  private queryCache: LruCache<string, VulnerabilityFinding[]>;
  private queryCacheMaxEntries: number;
  private bloomFilter: PackageBloomFilter | null = null;
  private ready = false;
  private performanceTracker: QueryPerformanceTracker;

  constructor(config: StaticDbReaderConfig) {
    this.dataPath = config.dataPath;
    this.cutoffDate = config.cutoffDate;
    const packageCacheMaxEntries = Math.max(0, config.packageCacheMaxEntries ?? 2000);
    this.packageCache = new LruCache<string, PackageShard>(packageCacheMaxEntries);
    this.queryCacheMaxEntries = Math.max(0, config.queryCacheMaxEntries ?? 1000);
    this.queryCache = new LruCache<string, VulnerabilityFinding[]>(this.queryCacheMaxEntries);
    this.performanceTracker = globalPerformanceTracker;
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
        this.index = normalizeIndexData(data as StaticDbIndex);
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

      // Guard: reject schemas newer than what we understand
      if (this.index && this.index.schemaVersion > SUPPORTED_SCHEMA_VERSION) {
        logger.warn(
          `[pnpm-audit-hook] DB schema version ${this.index.schemaVersion} is newer than supported version ${SUPPORTED_SCHEMA_VERSION}. Results may be incomplete.`,
        );
        this.ready = false;
        return;
      }

      this.ready = true;
    } catch (e) {
      logger.error(`Static DB initialization failed: ${errorMessage(e)}`);
      this.ready = false;
    }
  }

  isReady(): boolean {
    return this.ready;
  }

  getCutoffDate(): string {
    return this.index?.cutoffDate ?? this.cutoffDate;
  }

  getDbVersion(): string {
    return this.index?.lastUpdated ?? "";
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

    // Check query cache (key = packageName + serialized options)
    const cacheKey = this.buildQueryCacheKey(packageName, options);
    if (this.queryCacheMaxEntries > 0) {
      const cached = this.queryCache.get(cacheKey);
      if (cached) {
        this.performanceTracker.recordQuery(0, true);
        return cached;
      }
    }

    const startTime = performance.now();

    // Load package shard
    const shard = await this.loadPackageShard(packageName);
    if (!shard) {
      this.performanceTracker.recordQuery(performance.now() - startTime, false);
      return [];
    }

    let vulnerabilities = shard.vulnerabilities;

    // Apply filters - order filters by selectivity (most selective first)
    if (options?.version) {
      const version = options.version;
      vulnerabilities = vulnerabilities.filter((v) => {
        if (!v.affectedVersions || v.affectedVersions.length === 0) return true;
        return v.affectedVersions.some((av) => satisfies(version, av.range));
      });
    }

    if (options?.minSeverity) {
      const minLevel = severityLevel(options.minSeverity);
      vulnerabilities = vulnerabilities.filter((v) => severityLevel(v.severity) >= minLevel);
    }

    if (options?.publishedAfter) {
      const afterDate = new Date(options.publishedAfter);
      vulnerabilities = vulnerabilities.filter(
        (v) => v.publishedAt && new Date(v.publishedAt) > afterDate
      );
    }

    if (options?.publishedBefore) {
      const beforeDate = new Date(options.publishedBefore);
      vulnerabilities = vulnerabilities.filter(
        (v) => v.publishedAt && new Date(v.publishedAt) < beforeDate
      );
    }

    const findings = vulnerabilities.map((v) => this.vulnToFinding(v, options?.version));

    const durationMs = performance.now() - startTime;
    this.performanceTracker.recordQuery(durationMs, false);

    // Cache the result
    if (this.queryCacheMaxEntries > 0) {
      this.queryCache.set(cacheKey, findings);
    }

    return findings;
  }

  /**
   * Build a cache key for query results.
   */
  private buildQueryCacheKey(packageName: string, options?: StaticDbQueryOptions): string {
    if (!options) return packageName;
    // Use a compact serialization for the cache key
    const parts = [packageName];
    if (options.version) parts.push(`v:${options.version}`);
    if (options.publishedAfter) parts.push(`pa:${options.publishedAfter}`);
    if (options.publishedBefore) parts.push(`pb:${options.publishedBefore}`);
    if (options.minSeverity) parts.push(`s:${options.minSeverity}`);
    return parts.join("|");
  }

  /**
   * Batch query vulnerabilities for multiple packages.
   * Optimized for reduced I/O by deduplicating and sharing shard reads.
   */
  async queryPackagesBatch(
    packageNames: string[],
    options?: StaticDbQueryOptions
  ): Promise<Map<string, VulnerabilityFinding[]>> {
    const results = new Map<string, VulnerabilityFinding[]>();
    if (!this.ready || packageNames.length === 0) return results;

    // Filter to packages that exist using bloom filter + index
    const existingPackages: string[] = [];
    for (const name of packageNames) {
      if (await this.hasVulnerabilities(name)) {
        existingPackages.push(name);
      } else {
        results.set(name, []);
      }
    }

    // Check query cache for each package
    const toQuery: string[] = [];
    for (const name of existingPackages) {
      const cacheKey = this.buildQueryCacheKey(name, options);
      if (this.queryCacheMaxEntries > 0) {
        const cached = this.queryCache.get(cacheKey);
        if (cached) {
          results.set(name, cached);
          this.performanceTracker.recordQuery(0, true);
          continue;
        }
      }
      toQuery.push(name);
    }

    // Load and query remaining packages
    for (const name of toQuery) {
      const findings = await this.queryPackageWithOptions(name, options);
      results.set(name, findings);
    }

    return results;
  }

  /**
   * Load a package shard from disk, with caching.
   */
  private async loadPackageShard(packageName: string): Promise<PackageShard | null> {
    // Check LRU cache first
    const cached = this.packageCache.get(packageName);
    if (cached) {
      return cached;
    }

    const filePath = this.getShardPath(packageName);
    if (!filePath) return null;

    try {
      const result = await readMaybeCompressedWithRaw<PackageShard | OptimizedPackageData>(filePath);
      if (!result) {
        logger.warn(`Shard for ${packageName} not found at ${filePath}`);
        return null;
      }

      const { data, rawBytes, actualPath } = result;

      // Integrity check: verify SHA-256 hash against index's integrity map
      if (this.index?.integrity) {
        const relPath = relative(this.dataPath, actualPath).split(sep).join('/');
        const expectedHash = this.index.integrity[relPath];
        if (expectedHash) {
          const actualHash = computeShardHash(rawBytes);
          if (actualHash !== expectedHash) {
            logger.warn(
              `[pnpm-audit-hook] Shard integrity check failed for ${packageName}. DB may be tampered.`,
            );
            return null;
          }
        }
      }

      let shard: PackageShard | null = null;
      if (typeof data === "object" && data !== null && "pkg" in data && "v" in data) {
        shard = expandPackageData(data as OptimizedPackageData);
      } else {
        shard = normalizePackageShardData(data, packageName);
      }

      if (!shard) return null;

      // Cache for future lookups (LRU eviction handled by LruCache)
      this.packageCache.set(packageName, shard);

      return shard;
    } catch (e) {
      logger.warn(`Failed to load shard for ${packageName} from ${filePath}: ${errorMessage(e)}`);
      return null;
    }
  }

  /**
   * Get the canonical file path for a package shard.
   * Validates package name to prevent path traversal.
   *
   * Shard path encoding scheme (must match scripts/update-vuln-db.ts):
   *   - Unscoped packages:  dataPath/{name}.json          e.g. data/lodash.json
   *   - Scoped packages:    dataPath/@scope/{name}.json    e.g. data/@angular/core.json
   */
  private getShardPath(packageName: string): string | null {
    // Validate package name before using in file path
    if (!isValidPackageName(packageName)) {
      logger.warn(`Invalid package name rejected: ${packageName}`);
      return null;
    }

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
      description: vuln.description,
      severity: vuln.severity,
      publishedAt: vuln.publishedAt,
      modifiedAt: vuln.modifiedAt,
      identifiers: vuln.identifiers,
      affectedRange,
      fixedVersion,
    };
  }

  /**
   * Get performance metrics for the reader.
   */
  getPerformanceMetrics(): QueryPerformanceMetrics {
    return {
      shardCache: this.packageCache.getStats(),
      queryCache: this.queryCache.getStats(),
      queryPerformance: this.performanceTracker.getMetrics(),
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
