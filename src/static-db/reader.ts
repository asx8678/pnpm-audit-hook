import { join } from "path";
import type {
  VulnerabilityFinding,
  Severity,
  FindingSource,
  VulnerabilityIdentifier,
} from "../types";
import { logger } from "../utils/logger";
import { errorMessage } from "../utils/error";
import { mapSeverity } from "../utils/severity";
import { satisfies } from "../utils/semver";
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
  binarySearchPackage,
  PackageBloomFilter,
  expandPackageData,
  expandIndex,
  type OptimizedPackageData,
  type OptimizedIndex,
} from "./optimizer";

/**
 * Validate that a package name matches npm naming conventions.
 * Valid names: lowercase, may contain hyphens, underscores, dots.
 * Scoped packages: @scope/name where scope and name follow same rules.
 * This prevents path traversal via malicious package names.
 */
function isValidPackageName(name: string): boolean {
  // npm package name rules (simplified but secure):
  // - Must not be empty
  // - Max 214 characters
  // - Scoped packages start with @
  // - No path separators except in scoped packages (single /)
  // - No '..' sequences
  // - Must match allowed characters

  if (!name || name.length > 214) return false;
  if (name.includes("..")) return false;

  // Scoped package: @scope/name
  if (name.startsWith("@")) {
    const parts = name.split("/");
    if (parts.length !== 2) return false;
    const scope = parts[0]!.slice(1); // remove @
    const pkg = parts[1]!;
    return isValidNameSegment(scope) && isValidNameSegment(pkg);
  }

  // Unscoped package
  if (name.includes("/")) return false;
  return isValidNameSegment(name);
}

/**
 * Validate a single package name segment (scope or name).
 */
function isValidNameSegment(segment: string): boolean {
  if (!segment || segment.length === 0) return false;
  // Only allow lowercase alphanumeric, hyphens, underscores, dots
  // Must not start with dot or underscore
  if (segment.startsWith(".") || segment.startsWith("_")) return false;
  return /^[a-z0-9][a-z0-9._-]*$/.test(segment);
}

function normalizeFindingSource(value: unknown): FindingSource {
  return value === "nvd" || value === "github" ? value : "github";
}

function normalizeIdentifiers(value: unknown): VulnerabilityIdentifier[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const identifiers: VulnerabilityIdentifier[] = [];
  for (const entry of value) {
    if (!entry || typeof entry !== "object") continue;
    const obj = entry as Record<string, unknown>;
    const type = typeof obj.type === "string" ? obj.type : "";
    const val = typeof obj.value === "string" ? obj.value : "";
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
  if (Array.isArray(value)) {
    const ranges: AffectedVersionRange[] = [];
    for (const entry of value) {
      if (!entry || typeof entry !== "object") continue;
      const obj = entry as Record<string, unknown>;
      const range = typeof obj.range === "string" ? obj.range : "";
      if (!range) continue;
      const fixed = typeof obj.fixed === "string" ? obj.fixed : undefined;
      ranges.push({ range, fixed });
    }
    return ranges;
  }

  if (typeof affectedRange === "string" && affectedRange.length > 0) {
    const fixed = typeof fixedVersion === "string" ? fixedVersion : undefined;
    return [{ range: affectedRange, fixed }];
  }

  return [];
}

function normalizeVulnerability(
  value: unknown,
  packageName: string,
): StaticVulnerability | null {
  if (!value || typeof value !== "object") return null;
  const obj = value as Record<string, unknown>;
  const id = typeof obj.id === "string" ? obj.id : "";
  if (!id) return null;

  const pkgName =
    typeof obj.packageName === "string" && obj.packageName.length > 0
      ? obj.packageName
      : packageName;

  return {
    id,
    packageName: pkgName,
    severity: mapSeverity(typeof obj.severity === "string" ? obj.severity : undefined),
    publishedAt: typeof obj.publishedAt === "string" ? obj.publishedAt : undefined,
    modifiedAt: typeof obj.modifiedAt === "string" ? obj.modifiedAt : undefined,
    affectedVersions: normalizeAffectedVersions(
      obj.affectedVersions,
      obj.affectedRange,
      obj.fixedVersion,
    ),
    source: normalizeFindingSource(obj.source),
    title: typeof obj.title === "string" ? obj.title : undefined,
    url: typeof obj.url === "string" ? obj.url : undefined,
    description: typeof obj.description === "string" ? obj.description : undefined,
    identifiers: normalizeIdentifiers(obj.identifiers),
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
  /** Max package shards to keep in memory (0 disables caching). */
  packageCacheMaxEntries?: number;
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
  private packageCacheMaxEntries: number;
  private bloomFilter: PackageBloomFilter | null = null;
  private ready = false;

  constructor(config: StaticDbReaderConfig) {
    this.dataPath = config.dataPath;
    this.cutoffDate = config.cutoffDate;
    this.useOptimized = config.useOptimized ?? true;
    this.packageCacheMaxEntries = Math.max(0, config.packageCacheMaxEntries ?? 2000);
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

    let vulnerabilities = shard.vulnerabilities;

    if (options?.version) {
      const version = options.version;
      vulnerabilities = vulnerabilities.filter((v) => {
        if (!v.affectedVersions || v.affectedVersions.length === 0) return true;
        return v.affectedVersions.some((av) => satisfies(version, av.range));
      });
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

    if (options?.minSeverity) {
      const minLevel = severityLevel(options.minSeverity);
      vulnerabilities = vulnerabilities.filter((v) => severityLevel(v.severity) >= minLevel);
    }

    return vulnerabilities.map((v) => this.vulnToFinding(v, options?.version));
  }

  /**
   * Load a package shard from disk, with caching.
   */
  private async loadPackageShard(packageName: string): Promise<PackageShard | null> {
    // Check cache first
    if (this.packageCacheMaxEntries > 0) {
      const cached = this.packageCache.get(packageName);
      if (cached) {
        this.packageCache.delete(packageName);
        this.packageCache.set(packageName, cached);
        return cached;
      }
    }

    const filePaths = this.getShardPaths(packageName);
    if (filePaths.length === 0) return null;

    let lastError: unknown = null;

    for (const filePath of filePaths) {
      try {
        const data = await readMaybeCompressed<PackageShard | OptimizedPackageData>(filePath);
        if (!data) continue;

        let shard: PackageShard | null = null;
        if (typeof data === "object" && data !== null && "pkg" in data && "v" in data) {
          shard = expandPackageData(data as OptimizedPackageData);
        } else {
          shard = normalizePackageShardData(data, packageName);
        }

        if (!shard) continue;

        // Cache for future lookups (LRU eviction)
        if (this.packageCacheMaxEntries > 0) {
          if (this.packageCache.has(packageName)) {
            this.packageCache.delete(packageName);
          }
          this.packageCache.set(packageName, shard);
          if (this.packageCache.size > this.packageCacheMaxEntries) {
            let toEvict = this.packageCache.size - this.packageCacheMaxEntries;
            for (const staleKey of this.packageCache.keys()) {
              this.packageCache.delete(staleKey);
              if (--toEvict <= 0) break;
            }
          }
        }

        return shard;
      } catch (e) {
        lastError = e;
        logger.warn(`Failed to load shard for ${packageName} from ${filePath}: ${errorMessage(e)}`);
      }
    }

    if (lastError) {
      return null;
    }

    logger.warn(`Shard for ${packageName} not found (tried: ${filePaths.join(", ")})`);
    return null;
  }

  /**
   * Get the file path for a package shard.
   * Validates package name to prevent path traversal.
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

  private getLegacyShardPath(packageName: string): string | null {
    if (!isValidPackageName(packageName)) {
      return null;
    }
    const safeName = packageName.replace(/\//g, "__");
    return join(this.dataPath, "packages", `${safeName}.json`);
  }

  private getShardPaths(packageName: string): string[] {
    const paths: string[] = [];
    const primary = this.getShardPath(packageName);
    if (primary) paths.push(primary);
    const legacy = this.getLegacyShardPath(packageName);
    if (legacy && legacy !== primary) paths.push(legacy);
    return paths;
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
