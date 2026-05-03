/**
 * SBOM Component Cache with LRU eviction and optional persistence.
 *
 * Caches generated SBOM components between runs for faster incremental updates.
 * Uses integrity hash as part of the cache key to detect package content changes.
 *
 * @module sbom/component-cache
 *
 * @example
 * ```typescript
 * import { SbomComponentCache } from './component-cache';
 * import { packagesToSbomComponents } from './generator';
 *
 * const cache = new SbomComponentCache({
 *   maxEntries: 1000,
 *   cacheFilePath: '.sbom-cache.json',
 *   ttlMs: 24 * 60 * 60 * 1000, // 24 hours
 * });
 *
 * // Try to get components from cache
 * const cachedComponents = cache.getComponents(packages);
 * if (cachedComponents) {
 *   console.log('Cache hit! Using cached components');
 * } else {
 *   const components = packagesToSbomComponents(packages);
 *   cache.setComponents(packages, components);
 * }
 *
 * // Get cache statistics
 * console.log(cache.getStats());
 * ```
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { LruCache } from "../utils/lru-cache";
import type { PackageRef } from "../types";
import type { SbomComponent, PackageHash } from "./types";

/**
 * Options for the SBOM component cache.
 */
export interface ComponentCacheOptions {
  /** Maximum cache entries (default: 1000) */
  maxEntries?: number;
  /** Cache file path for persistence */
  cacheFilePath?: string;
  /** Cache TTL in milliseconds (default: 24 hours = 86400000ms) */
  ttlMs?: number;
  /** Enable debug logging (default: false) */
  debug?: boolean;
}

/**
 * A single cache entry containing the component and metadata.
 */
export interface CacheEntry {
  /** The cached SBOM component */
  component: SbomComponent;
  /** Timestamp when the entry was created/updated */
  timestamp: number;
  /** Integrity hash used for cache key generation */
  integrityHash: string;
}

/**
 * Cache statistics for monitoring and debugging.
 */
export interface CacheStats {
  /** Number of cache hits */
  hits: number;
  /** Number of cache misses */
  misses: number;
  /** Current number of entries in cache */
  size: number;
  /** Cache hit rate (hits / (hits + misses)) */
  hitRate: number;
}

/**
 * A cache entry persisted to disk.
 */
interface PersistedCacheEntry {
  name: string;
  version: string;
  component: SbomComponent;
  timestamp: number;
  integrityHash: string;
}

/**
 * The persisted cache file format.
 */
interface PersistedCache {
  version: number;
  entries: PersistedCacheEntry[];
  createdAt: string;
  updatedAt: string;
}

// Default cache options
const DEFAULT_OPTIONS: Required<ComponentCacheOptions> = {
  maxEntries: 1000,
  cacheFilePath: "",
  ttlMs: 24 * 60 * 60 * 1000, // 24 hours
  debug: false,
};

/**
 * Generate a cache key from package name and version.
 *
 * @param name - Package name
 * @param version - Package version
 * @returns Cache key string
 */
function generateCacheKey(name: string, version: string): string {
  return `${name}@${version}`;
}

/**
 * Generate an integrity hash from a PackageRef for cache validation.
 *
 * @param pkg - Package reference
 * @returns Integrity hash string or empty string if not available
 */
function getIntegrityHash(pkg: PackageRef): string {
  return pkg.integrity ?? "";
}

/**
 * SBOM Component Cache with LRU eviction and optional disk persistence.
 *
 * Provides fast lookups for previously generated SBOM components,
 * enabling incremental SBOM generation by only processing new or changed packages.
 */
export class SbomComponentCache {
  private cache: LruCache<string, CacheEntry>;
  private options: Required<ComponentCacheOptions>;
  private stats: CacheStats;
  private loaded: boolean;
  private dirty: boolean;

  constructor(options: ComponentCacheOptions = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
    this.cache = new LruCache<string, CacheEntry>(this.options.maxEntries);
    this.stats = { hits: 0, misses: 0, size: 0, hitRate: 0 };
    this.loaded = false;
    this.dirty = false;

    // Load from disk if persistence is enabled
    if (this.options.cacheFilePath) {
      this.loadFromDisk();
    }
  }

  /**
   * Get cached SBOM components for a list of packages.
   *
   * Returns cached components for all packages that have valid cache entries.
   * Packages with stale or missing cache entries are skipped.
   *
   * @param packages - Package references to look up
   * @returns Map from package key to cached component, or null if all miss
   */
  getComponents(
    packages: PackageRef[],
  ): Map<string, SbomComponent> | null {
    const results = new Map<string, SbomComponent>();
    let allCached = true;

    for (const pkg of packages) {
      const key = generateCacheKey(pkg.name, pkg.version);
      const entry = this.cache.get(key);

      if (entry) {
        // Check integrity hash match
        const currentIntegrity = getIntegrityHash(pkg);
        if (
          entry.integrityHash &&
          currentIntegrity &&
          entry.integrityHash !== currentIntegrity
        ) {
          // Integrity mismatch - cache invalidation
          this.debug(`Cache invalidation for ${key}: integrity mismatch`);
          this.cache.delete(key);
          this.dirty = true;
          this.stats.misses++;
          allCached = false;
          continue;
        }

        // Check TTL
        if (Date.now() - entry.timestamp > this.options.ttlMs) {
          this.debug(`Cache expiration for ${key}`);
          this.cache.delete(key);
          this.dirty = true;
          this.stats.misses++;
          allCached = false;
          continue;
        }

        // Cache hit
        results.set(key, entry.component);
        this.stats.hits++;
      } else {
        // Cache miss
        this.stats.misses++;
        allCached = false;
      }
    }

    this.updateStats();

    // Return null if no results or all misses
    if (results.size === 0 || allCached === false) {
      return results.size > 0 ? results : null;
    }

    return results;
  }

  /**
   * Get a single cached SBOM component by package name and version.
   *
   * @param name - Package name
   * @param version - Package version
   * @param integrity - Expected integrity hash for validation
   * @returns Cached component or undefined if not found/stale
   */
  getComponent(
    name: string,
    version: string,
    integrity?: string,
  ): SbomComponent | undefined {
    const key = generateCacheKey(name, version);
    const entry = this.cache.get(key);

    if (!entry) {
      this.stats.misses++;
      this.updateStats();
      return undefined;
    }

    // Check integrity hash match
    if (entry.integrityHash && integrity && entry.integrityHash !== integrity) {
      this.debug(`Cache invalidation for ${key}: integrity mismatch`);
      this.cache.delete(key);
      this.dirty = true;
      this.stats.misses++;
      this.updateStats();
      return undefined;
    }

    // Check TTL
    if (Date.now() - entry.timestamp > this.options.ttlMs) {
      this.debug(`Cache expiration for ${key}`);
      this.cache.delete(key);
      this.dirty = true;
      this.stats.misses++;
      this.updateStats();
      return undefined;
    }

    this.stats.hits++;
    this.updateStats();
    return entry.component;
  }

  /**
   * Store SBOM components in the cache.
   *
   * @param packages - Package references (used for integrity hashes)
   * @param components - SBOM components to cache
   */
  setComponents(packages: PackageRef[], components: SbomComponent[]): void {
    const now = Date.now();

    for (let i = 0; i < packages.length; i++) {
      const pkg = packages[i];
      const component = components[i];
      if (!pkg || !component) continue;

      const key = generateCacheKey(pkg.name, pkg.version);
      const entry: CacheEntry = {
        component,
        timestamp: now,
        integrityHash: getIntegrityHash(pkg),
      };

      this.cache.set(key, entry);
      this.dirty = true;
    }

    this.updateStats();

    // Auto-save if persistence is enabled
    if (this.options.cacheFilePath && this.dirty) {
      this.saveToDisk();
    }
  }

  /**
   * Store a single SBOM component in the cache.
   *
   * @param name - Package name
   * @param version - Package version
   * @param component - SBOM component to cache
   * @param integrity - Integrity hash for future validation
   */
  setComponent(
    name: string,
    version: string,
    component: SbomComponent,
    integrity?: string,
  ): void {
    const key = generateCacheKey(name, version);
    const entry: CacheEntry = {
      component,
      timestamp: Date.now(),
      integrityHash: integrity ?? "",
    };

    this.cache.set(key, entry);
    this.dirty = true;
    this.updateStats();

    // Auto-save if persistence is enabled
    if (this.options.cacheFilePath && this.dirty) {
      this.saveToDisk();
    }
  }

  /**
   * Remove a specific entry from the cache.
   *
   * @param name - Package name
   * @param version - Package version
   * @returns true if the entry was removed, false if not found
   */
  remove(name: string, version: string): boolean {
    const key = generateCacheKey(name, version);
    const result = this.cache.delete(key);
    if (result) {
      this.dirty = true;
      this.updateStats();
    }
    return result;
  }

  /**
   * Check if a package is in the cache.
   *
   * @param name - Package name
   * @param version - Package version
   * @returns true if the package is cached
   */
  has(name: string, version: string): boolean {
    const key = generateCacheKey(name, version);
    return this.cache.has(key);
  }

  /**
   * Clear all entries from the cache.
   */
  clear(): void {
    this.cache.clear();
    this.dirty = true;
    this.resetStats();

    // Clear disk cache if persistence is enabled
    if (this.options.cacheFilePath) {
      this.saveToDisk();
    }
  }

  /**
   * Get cache statistics.
   *
   * @returns Current cache statistics
   */
  getStats(): CacheStats {
    return { ...this.stats };
  }

  /**
   * Save the cache to disk.
   *
   * @returns true if successful, false otherwise
   */
  saveToDisk(): boolean {
    if (!this.options.cacheFilePath) {
      return false;
    }

    try {
      const dir = path.dirname(this.options.cacheFilePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      // Get all entries from the LRU cache using the iterator
      const entries: PersistedCacheEntry[] = [];
      for (const [key, entry] of this.cache.entries()) {
        // Split key carefully to handle scoped packages like @scope/package@1.0.0
        const lastAtIndex = key.lastIndexOf("@");
        if (lastAtIndex > 0) {
          const name = key.substring(0, lastAtIndex);
          const version = key.substring(lastAtIndex + 1);
          entries.push({
            name,
            version,
            component: entry.component,
            timestamp: entry.timestamp,
            integrityHash: entry.integrityHash,
          });
        }
      }

      const persistData: PersistedCache = {
        version: 1,
        entries,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      fs.writeFileSync(
        this.options.cacheFilePath,
        JSON.stringify(persistData, null, 2),
        "utf-8",
      );

      this.dirty = false;
      this.debug(`Cache saved to ${this.options.cacheFilePath}`);
      return true;
    } catch (err) {
      this.debug(`Failed to save cache: ${(err as Error).message}`);
      return false;
    }
  }

  /**
   * Load the cache from disk.
   *
   * @returns true if successful, false otherwise
   */
  loadFromDisk(): boolean {
    if (!this.options.cacheFilePath || this.loaded) {
      return false;
    }

    try {
      if (!fs.existsSync(this.options.cacheFilePath)) {
        this.debug(`Cache file not found: ${this.options.cacheFilePath}`);
        this.loaded = true;
        return false;
      }

      const data = fs.readFileSync(this.options.cacheFilePath, "utf-8");
      const persisted: PersistedCache = JSON.parse(data);

      if (persisted.version !== 1) {
        this.debug(`Unsupported cache version: ${persisted.version}`);
        this.loaded = true;
        return false;
      }

      const now = Date.now();
      let loadedCount = 0;

      for (const entry of persisted.entries) {
        // Skip expired entries
        if (now - entry.timestamp > this.options.ttlMs) {
          continue;
        }

        const key = generateCacheKey(entry.name, entry.version);
        this.cache.set(key, {
          component: entry.component,
          timestamp: entry.timestamp,
          integrityHash: entry.integrityHash,
        });
        loadedCount++;
      }

      this.updateStats();
      this.loaded = true;
      this.debug(`Loaded ${loadedCount} entries from cache`);
      return true;
    } catch (err) {
      this.debug(`Failed to load cache: ${(err as Error).message}`);
      this.loaded = true;
      return false;
    }
  }

  /**
   * Force save the cache to disk if there are pending changes.
   *
   * @returns true if saved, false otherwise
   */
  flush(): boolean {
    if (this.dirty && this.options.cacheFilePath) {
      return this.saveToDisk();
    }
    return false;
  }

  /**
   * Get the number of entries in the cache.
   */
  get size(): number {
    return this.cache.size;
  }

  /**
   * Debug logging helper.
   */
  private debug(message: string): void {
    if (this.options.debug) {
      console.debug(`[SBOM Cache] ${message}`);
    }
  }

  /**
   * Update cache statistics.
   */
  private updateStats(): void {
    this.stats.size = this.cache.size;
    const total = this.stats.hits + this.stats.misses;
    this.stats.hitRate = total > 0 ? this.stats.hits / total : 0;
  }

  /**
   * Reset cache statistics.
   */
  private resetStats(): void {
    this.stats = { hits: 0, misses: 0, size: 0, hitRate: 0 };
  }
}

/**
 * Create a new SbomComponentCache with default options.
 *
 * @param options - Cache configuration options
 * @returns Configured cache instance
 */
export function createComponentCache(
  options: ComponentCacheOptions = {},
): SbomComponentCache {
  return new SbomComponentCache(options);
}
