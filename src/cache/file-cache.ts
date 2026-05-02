import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { sha256Hex } from "../utils/hash";
import { errorMessage, isNodeError } from "../utils/error";
import { logger } from "../utils/logger";
import type { Cache, CacheEntry, CacheStatistics, CacheHealth } from "./types";

export interface FileCacheOptions {
  dir: string;
  /** Max entries to keep in the in-memory path cache (0 disables caching). */
  maxPathCacheEntries?: number;
  /** Max total cache size in bytes (0 disables size limit) */
  maxSizeBytes?: number;
  /** Max number of cache entries (0 disables count limit) */
  maxEntries?: number;
}

/**
 * Type guard to validate a parsed JSON object as a CacheEntry.
 * Returns true if the object has the required structure.
 */
function isCacheEntry<T>(parsed: unknown): parsed is CacheEntry<T> {
  if (!parsed || typeof parsed !== "object") return false;
  const obj = parsed as Record<string, unknown>;
  return (
    typeof obj.expiresAt === "number" &&
    typeof obj.storedAt === "number" &&
    "value" in obj
  );
}

export class FileCache<T = unknown> implements Cache<T> {
  private readonly dir: string;
  // In-memory cache for key-to-path mappings (SHA256 is CPU intensive)
  // Using LRU cache with access order tracking
  private readonly pathCache = new Map<string, string>();
  private readonly maxPathCacheEntries: number;
  private readonly maxSizeBytes: number;
  private readonly maxEntries: number;
  
  // Cache statistics
  private stats: CacheStatistics = {
    hits: 0,
    misses: 0,
    sets: 0,
    deletes: 0,
    evictions: 0,
    totalEntries: 0,
    totalSizeBytes: 0,
    averageReadTimeMs: 0,
    averageWriteTimeMs: 0,
    prunedEntries: 0,
  };
  
  // Performance tracking
  private readTimes: number[] = [];
  private writeTimes: number[] = [];
  private readonly performanceWindowSize = 100;

  constructor(opts: FileCacheOptions) {
    this.dir = opts.dir;
    this.maxPathCacheEntries = Math.max(0, opts.maxPathCacheEntries ?? 10000);
    this.maxSizeBytes = Math.max(0, opts.maxSizeBytes ?? 0);
    this.maxEntries = Math.max(0, opts.maxEntries ?? 0);
  }

  private filePathForKey(key: string): string {
    const cached = this.pathCache.get(key);
    if (cached) {
      // LRU: Move to end (most recently used) by deleting and re-inserting
      if (this.maxPathCacheEntries > 0) {
        this.pathCache.delete(key);
        this.pathCache.set(key, cached);
      }
      return cached;
    }

    const h = sha256Hex(key);
    // Two-level fanout to avoid too many files in one directory
    const filePath = path.join(this.dir, h.slice(0, 2), `${h}.json`);
    if (this.maxPathCacheEntries > 0) {
      this.pathCache.set(key, filePath);
      // LRU eviction: remove oldest entries when cache is full
      if (this.pathCache.size > this.maxPathCacheEntries) {
        let toEvict = this.pathCache.size - this.maxPathCacheEntries;
        for (const staleKey of this.pathCache.keys()) {
          this.pathCache.delete(staleKey);
          this.stats.evictions++;
          if (--toEvict <= 0) break;
        }
      }
    }
    return filePath;
  }

  private async isSymlink(filePath: string): Promise<boolean> {
    try {
      const stat = await fs.lstat(filePath);
      return stat.isSymbolicLink();
    } catch {
      return false;
    }
  }

  async get(key: string): Promise<CacheEntry<T> | null> {
    const startTime = Date.now();
    const filePath = this.filePathForKey(key);
    let handle: import("node:fs/promises").FileHandle | null = null;
    try {
      // Protect against symlink attacks: open file then verify via lstat on same path
      // Using lstat before open has a TOCTOU window; checking both before and after
      // the open narrows the race to be as small as practical without O_NOFOLLOW.
      const statBefore = await fs.lstat(filePath);
      if (statBefore.isSymbolicLink()) {
        logger.warn(`Symlink detected at cache path, ignoring: ${filePath}`);
        this.stats.misses++;
        return null;
      }

      handle = await fs.open(filePath, "r");
      // Verify the fd points to the same inode we lstat'd (detect swap between lstat and open)
      const fdStat = await handle.stat();
      if (fdStat.ino !== statBefore.ino || fdStat.dev !== statBefore.dev) {
        logger.warn(`Cache file inode changed between check and open, ignoring: ${filePath}`);
        this.stats.misses++;
        return null;
      }

      const raw = await handle.readFile("utf-8");
      const parsed: unknown = JSON.parse(raw);
      if (!isCacheEntry<T>(parsed)) {
        await this.deleteCorruptedFile(filePath);
        this.stats.misses++;
        return null;
      }
      if (parsed.expiresAt > Date.now()) {
        this.stats.hits++;
        this.updateReadPerformance(Date.now() - startTime);
        return parsed;
      }
      this.stats.misses++;
      return null;
    } catch (e) {
      // Log non-ENOENT errors as they may indicate real problems
      if (isNodeError(e) && e.code !== "ENOENT") {
        logger.error(`Cache read error for ${key}: ${e.message}`);
        // Delete corrupted cache file to prevent repeated failures
        await this.deleteCorruptedFile(filePath);
      }
      this.stats.misses++;
      return null;
    } finally {
      await handle?.close();
      this.updateReadPerformance(Date.now() - startTime);
    }
  }

  private updateReadPerformance(durationMs: number): void {
    this.readTimes.push(durationMs);
    if (this.readTimes.length > this.performanceWindowSize) {
      this.readTimes.shift();
    }
    this.stats.averageReadTimeMs = 
      this.readTimes.reduce((a, b) => a + b, 0) / this.readTimes.length;
  }

  private async deleteCorruptedFile(filePath: string): Promise<void> {
    try {
      await fs.unlink(filePath);
      logger.debug(`Deleted corrupted cache file: ${filePath}`);
    } catch (unlinkErr) {
      if (!isNodeError(unlinkErr) || unlinkErr.code !== "ENOENT") {
        logger.debug(`Failed to delete corrupted cache file: ${filePath}`);
      }
    }
  }

  async set(
    key: string,
    value: T,
    ttlSeconds: number,
    options?: { version?: string; dependencies?: string[] }
  ): Promise<void> {
    if (ttlSeconds <= 0 || !Number.isFinite(ttlSeconds)) {
      throw new Error(`Invalid TTL: ${ttlSeconds}`);
    }
    
    const startTime = Date.now();
    const filePath = this.filePathForKey(key);
    const dir = path.dirname(filePath);

    // Protect against symlink attacks on parent directory
    if (await this.isSymlink(dir)) {
      throw new Error(`Symlink detected at cache directory: ${dir}`);
    }

    await fs.mkdir(dir, { recursive: true, mode: 0o700 });

    // Best-effort symlink check on target file (TOCTOU window exists between
    // this check and the rename below, but atomic rename from tmp mitigates it)
    if (await this.isSymlink(filePath)) {
      throw new Error(`Symlink detected at cache file path: ${filePath}`);
    }

    const now = Date.now();
    const entry: CacheEntry<T> = {
      value,
      storedAt: now,
      expiresAt: now + ttlSeconds * 1000,
      version: options?.version,
      dependencies: options?.dependencies,
    };

    // Atomic-ish write: write temp then rename
    // Use crypto.randomBytes for secure temp file names
    const randomSuffix = crypto.randomBytes(16).toString("hex");
    const tmp = `${filePath}.${process.pid}.${randomSuffix}.tmp`;
    try {
      const content = JSON.stringify(entry);
      await fs.writeFile(tmp, content, { encoding: "utf-8", mode: 0o600 });
      await fs.rename(tmp, filePath);
      
      // Update statistics
      this.stats.sets++;
      this.stats.totalEntries++;
      this.stats.totalSizeBytes += content.length;
      this.updateWritePerformance(Date.now() - startTime);
      
      // Check size limits and prune if needed
      await this.enforceSizeLimits();
    } catch (e) {
      // Clean up temp file on failure
      try {
        await fs.unlink(tmp);
      } catch (cleanupErr) {
        logger.debug(`Failed to clean up temp file ${tmp}: ${errorMessage(cleanupErr)}`);
      }
      throw e;
    }
  }

  private updateWritePerformance(durationMs: number): void {
    this.writeTimes.push(durationMs);
    if (this.writeTimes.length > this.performanceWindowSize) {
      this.writeTimes.shift();
    }
    this.stats.averageWriteTimeMs = 
      this.writeTimes.reduce((a, b) => a + b, 0) / this.writeTimes.length;
  }

  private async enforceSizeLimits(): Promise<void> {
    // Enforce entry count limit
    if (this.maxEntries > 0 && this.stats.totalEntries > this.maxEntries) {
      await this.pruneByCount(this.stats.totalEntries - this.maxEntries);
    }
    
    // Enforce size limit
    if (this.maxSizeBytes > 0 && this.stats.totalSizeBytes > this.maxSizeBytes) {
      await this.pruneBySize(this.stats.totalSizeBytes - this.maxSizeBytes);
    }
  }

  private async pruneByCount(countToPrune: number): Promise<void> {
    // Collect all entries with their timestamps for LRU-like eviction
    const entries: Array<{ path: string; storedAt: number; isExpired: boolean }> = [];
    
    try {
      const subdirs = await fs.readdir(this.dir);
      for (const subdir of subdirs) {
        const subdirPath = path.join(this.dir, subdir);
        const stat = await fs.lstat(subdirPath);
        if (!stat.isDirectory() || stat.isSymbolicLink()) continue;

        const files = await fs.readdir(subdirPath);
        for (const file of files) {
          if (!file.endsWith(".json")) continue;
          const filePath = path.join(subdirPath, file);
          try {
            const raw = await fs.readFile(filePath, "utf-8");
            const parsed: unknown = JSON.parse(raw);
            if (isCacheEntry<unknown>(parsed)) {
              entries.push({
                path: filePath,
                storedAt: parsed.storedAt,
                isExpired: parsed.expiresAt <= Date.now(),
              });
            }
          } catch {
            // Skip files that can't be read
          }
        }
      }
    } catch {
      // Ignore errors during scanning
    }
    
    // Sort by storedAt ascending (oldest first) - expired entries first
    entries.sort((a, b) => {
      if (a.isExpired !== b.isExpired) return a.isExpired ? -1 : 1;
      return a.storedAt - b.storedAt;
    });
    
    // Remove oldest entries first
    let pruned = 0;
    for (let i = 0; i < entries.length && pruned < countToPrune; i++) {
      try {
        await fs.unlink(entries[i]!.path);
        pruned++;
        this.stats.evictions++;
        this.stats.totalEntries--;
      } catch {
        // Ignore errors during deletion
      }
    }
  }

  private async pruneBySize(bytesToPrune: number): Promise<void> {
    // This is a simplified implementation - in production you'd want to track
    // file sizes for more accurate pruning
    let bytesPruned = 0;
    try {
      const subdirs = await fs.readdir(this.dir);
      for (const subdir of subdirs) {
        if (bytesPruned >= bytesToPrune) break;
        const subdirPath = path.join(this.dir, subdir);
        const stat = await fs.lstat(subdirPath);
        if (!stat.isDirectory() || stat.isSymbolicLink()) continue;

        const files = await fs.readdir(subdirPath);
        for (const file of files) {
          if (bytesPruned >= bytesToPrune) break;
          if (!file.endsWith(".json")) continue;
          const filePath = path.join(subdirPath, file);
          try {
            const raw = await fs.readFile(filePath, "utf-8");
            const parsed: unknown = JSON.parse(raw);
            if (!isCacheEntry<unknown>(parsed) || parsed.expiresAt <= Date.now()) {
              const fileSize = (await fs.stat(filePath)).size;
              await fs.unlink(filePath);
              bytesPruned += fileSize;
              this.stats.evictions++;
            }
          } catch {
            // Skip files that can't be read
          }
        }
      }
    } catch {
      // Ignore errors during pruning
    }
  }

  async delete(key: string): Promise<boolean> {
    const filePath = this.filePathForKey(key);
    try {
      await fs.unlink(filePath);
      this.stats.deletes++;
      this.stats.totalEntries--;
      return true;
    } catch {
      return false;
    }
  }

  async has(key: string): Promise<boolean> {
    const entry = await this.get(key);
    return entry !== null;
  }

  async clear(): Promise<void> {
    try {
      const subdirs = await fs.readdir(this.dir);
      for (const subdir of subdirs) {
        const subdirPath = path.join(this.dir, subdir);
        const stat = await fs.lstat(subdirPath);
        if (!stat.isDirectory() || stat.isSymbolicLink()) continue;

        const files = await fs.readdir(subdirPath);
        for (const file of files) {
          if (!file.endsWith(".json")) continue;
          const filePath = path.join(subdirPath, file);
          try {
            await fs.unlink(filePath);
          } catch {
            // Ignore errors during cleanup
          }
        }
        // Remove empty subdirectory
        try {
          await fs.rmdir(subdirPath);
        } catch {
          // Ignore errors
        }
      }
      this.stats.totalEntries = 0;
      this.stats.totalSizeBytes = 0;
    } catch {
      // Ignore errors
    }
  }

  getStatistics(): CacheStatistics {
    return { ...this.stats };
  }

  async prune(): Promise<{ pruned: number; failed: number }> {
    const startTime = Date.now();
    let pruned = 0;
    let failed = 0;
    try {
      const subdirs = await fs.readdir(this.dir);
      for (const subdir of subdirs) {
        const subdirPath = path.join(this.dir, subdir);
        // Use lstat to prevent symlink traversal attacks
        const stat = await fs.lstat(subdirPath);
        if (!stat.isDirectory() || stat.isSymbolicLink()) continue;

        const files = await fs.readdir(subdirPath);
        for (const file of files) {
          if (!file.endsWith(".json")) continue;
          const filePath = path.join(subdirPath, file);
          // Skip symlinks for security
          const fileStat = await fs.lstat(filePath);
          if (fileStat.isSymbolicLink()) {
            logger.warn(`Symlink detected during prune, skipping: ${filePath}`);
            continue;
          }
          try {
            const raw = await fs.readFile(filePath, "utf-8");
            const parsed: unknown = JSON.parse(raw);
            if (!isCacheEntry<unknown>(parsed) || parsed.expiresAt <= Date.now()) {
              const fileSize = fileStat.size;
              await fs.unlink(filePath);
              pruned++;
              this.stats.totalSizeBytes -= fileSize;
              this.stats.totalEntries--;
            }
          } catch (readErr) {
            // If we can't read/parse, try to delete the corrupted file
            logger.warn(`Cache file unreadable, attempting deletion: ${filePath}`);
            try {
              const fileSize = fileStat.size;
              await fs.unlink(filePath);
              pruned++;
              this.stats.totalSizeBytes -= fileSize;
              this.stats.totalEntries--;
            } catch (unlinkErr) {
              failed++;
              logger.error(
                `Failed to delete corrupted cache file ${filePath}: ${errorMessage(unlinkErr)}`
              );
            }
          }
        }
      }
    } catch (e) {
      // Cache directory may not exist yet, which is not an error
      if (isNodeError(e) && e.code !== "ENOENT") {
        logger.error(`Cache prune error: ${e.message}`);
      }
    }
    
    this.stats.lastPruneTime = Date.now();
    this.stats.prunedEntries += pruned;
    return { pruned, failed };
  }

  getHealth(): CacheHealth {
    const hitRate = this.stats.hits + this.stats.misses > 0
      ? this.stats.hits / (this.stats.hits + this.stats.misses)
      : 0;
    
    const recommendations: string[] = [];
    
    if (hitRate < 0.5) {
      recommendations.push('Consider increasing TTL values to improve hit rate');
    }
    if (this.stats.totalSizeBytes > 100 * 1024 * 1024) { // 100MB
      recommendations.push('Cache size is large, consider reducing TTL or adding size limits');
    }
    if (this.stats.evictions > this.stats.hits) {
      recommendations.push('High eviction rate, consider increasing cache size limits');
    }
    
    let status: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';
    if (hitRate < 0.3) {
      status = 'unhealthy';
    } else if (hitRate < 0.6) {
      status = 'degraded';
    }
    
    return {
      status,
      hitRate,
      sizeBytes: this.stats.totalSizeBytes,
      entryCount: this.stats.totalEntries,
      recommendations,
    };
  }
}
