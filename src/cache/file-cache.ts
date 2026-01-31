import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { sha256Hex } from "../utils/hash";
import { logger } from "../utils/logger";
import type { Cache, CacheEntry } from "./types";

export interface FileCacheOptions {
  dir: string;
  /** Max entries to keep in the in-memory path cache (0 disables caching). */
  maxPathCacheEntries?: number;
}

/** Type guard for NodeJS.ErrnoException */
function isNodeError(e: unknown): e is NodeJS.ErrnoException {
  return e instanceof Error && "code" in e;
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
  private readonly pathCache = new Map<string, string>();
  private readonly maxPathCacheEntries: number;

  constructor(opts: FileCacheOptions) {
    this.dir = opts.dir;
    this.maxPathCacheEntries = Math.max(0, opts.maxPathCacheEntries ?? 10000);
  }

  private filePathForKey(key: string): string {
    const cached = this.pathCache.get(key);
    if (cached) {
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
      if (this.pathCache.size > this.maxPathCacheEntries) {
        let toEvict = this.pathCache.size - this.maxPathCacheEntries;
        for (const staleKey of this.pathCache.keys()) {
          this.pathCache.delete(staleKey);
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
    const filePath = this.filePathForKey(key);
    try {
      // Protect against symlink attacks
      if (await this.isSymlink(filePath)) {
        logger.warn(`Symlink detected at cache path, ignoring: ${filePath}`);
        return null;
      }

      const raw = await fs.readFile(filePath, "utf-8");
      const parsed: unknown = JSON.parse(raw);
      if (!isCacheEntry<T>(parsed)) {
        await this.deleteCorruptedFile(filePath);
        return null;
      }
      if (parsed.expiresAt > Date.now()) return parsed;
      return null;
    } catch (e) {
      // Log non-ENOENT errors as they may indicate real problems
      if (isNodeError(e) && e.code !== "ENOENT") {
        logger.error(`Cache read error for ${key}: ${e.message}`);
        // Delete corrupted cache file to prevent repeated failures
        await this.deleteCorruptedFile(filePath);
      }
      return null;
    }
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

  async set(key: string, value: T, ttlSeconds: number): Promise<void> {
    if (ttlSeconds <= 0 || !Number.isFinite(ttlSeconds)) {
      throw new Error(`Invalid TTL: ${ttlSeconds}`);
    }
    const filePath = this.filePathForKey(key);
    const dir = path.dirname(filePath);

    // Protect against symlink attacks on parent directory
    if (await this.isSymlink(dir)) {
      throw new Error(`Symlink detected at cache directory: ${dir}`);
    }

    await fs.mkdir(dir, { recursive: true, mode: 0o700 });

    const now = Date.now();
    const entry: CacheEntry<T> = {
      value,
      storedAt: now,
      expiresAt: now + ttlSeconds * 1000,
    };

    // Atomic-ish write: write temp then rename
    // Use crypto.randomBytes for secure temp file names
    const randomSuffix = crypto.randomBytes(16).toString("hex");
    const tmp = `${filePath}.${process.pid}.${randomSuffix}.tmp`;
    try {
      await fs.writeFile(tmp, JSON.stringify(entry), { encoding: "utf-8", mode: 0o600 });
      await fs.rename(tmp, filePath);
    } catch (e) {
      // Clean up temp file on failure
      try {
        await fs.unlink(tmp);
      } catch (cleanupErr) {
        logger.debug(`Failed to clean up temp file ${tmp}: ${cleanupErr instanceof Error ? cleanupErr.message : String(cleanupErr)}`);
      }
      throw e;
    }
  }

  async prune(): Promise<{ pruned: number; failed: number }> {
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
          try {
            const raw = await fs.readFile(filePath, "utf-8");
            const parsed: unknown = JSON.parse(raw);
            if (!isCacheEntry<unknown>(parsed) || parsed.expiresAt <= Date.now()) {
              await fs.unlink(filePath);
              pruned++;
            }
          } catch (readErr) {
            // If we can't read/parse, try to delete the corrupted file
            logger.warn(`Cache file unreadable, attempting deletion: ${filePath}`);
            try {
              await fs.unlink(filePath);
              pruned++;
            } catch (unlinkErr) {
              failed++;
              logger.error(
                `Failed to delete corrupted cache file ${filePath}: ${unlinkErr instanceof Error ? unlinkErr.message : String(unlinkErr)}`
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
    return { pruned, failed };
  }
}
