import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { sha256Hex } from "../utils/hash";
import { errorMessage, isNodeError } from "../utils/error";
import { logger } from "../utils/logger";
import type { Cache, CacheEntry } from "./types";

export interface FileCacheOptions {
  dir: string;
  /** Max entries to keep in the in-memory path cache (0 disables caching). */
  maxPathCacheEntries?: number;
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
    let handle: import("node:fs/promises").FileHandle | null = null;
    try {
      // Protect against symlink attacks: open file then verify via lstat on same path
      // Using lstat before open has a TOCTOU window; checking both before and after
      // the open narrows the race to be as small as practical without O_NOFOLLOW.
      const statBefore = await fs.lstat(filePath);
      if (statBefore.isSymbolicLink()) {
        logger.warn(`Symlink detected at cache path, ignoring: ${filePath}`);
        return null;
      }

      handle = await fs.open(filePath, "r");
      // Verify the fd points to the same inode we lstat'd (detect swap between lstat and open)
      const fdStat = await handle.stat();
      if (fdStat.ino !== statBefore.ino || fdStat.dev !== statBefore.dev) {
        logger.warn(`Cache file inode changed between check and open, ignoring: ${filePath}`);
        return null;
      }

      const raw = await handle.readFile("utf-8");
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
    } finally {
      await handle?.close();
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
        logger.debug(`Failed to clean up temp file ${tmp}: ${errorMessage(cleanupErr)}`);
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
    return { pruned, failed };
  }
}
