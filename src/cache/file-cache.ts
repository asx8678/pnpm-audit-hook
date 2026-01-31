import fs from "node:fs/promises";
import path from "node:path";
import { sha256Hex } from "../utils/hash";
import { logger } from "../utils/logger";
import type { Cache, CacheEntry } from "./types";

export interface FileCacheOptions {
  dir: string;
}

export class FileCache<T = unknown> implements Cache<T> {
  private readonly dir: string;

  constructor(opts: FileCacheOptions) {
    this.dir = opts.dir;
  }

  private filePathForKey(key: string): string {
    const h = sha256Hex(key);
    // Two-level fanout to avoid too many files in one directory
    return path.join(this.dir, h.slice(0, 2), `${h}.json`);
  }

  async get(key: string): Promise<CacheEntry<T> | null> {
    try {
      const raw = await fs.readFile(this.filePathForKey(key), "utf-8");
      const entry = JSON.parse(raw) as CacheEntry<T>;
      if (!entry || typeof entry !== "object") return null;
      if (typeof entry.expiresAt !== "number" || typeof entry.storedAt !== "number") return null;
      if (entry.expiresAt > Date.now()) return entry;
      return null;
    } catch (e) {
      // Log non-ENOENT errors as they may indicate real problems
      if (e instanceof Error && "code" in e && (e as NodeJS.ErrnoException).code !== "ENOENT") {
        logger.warn(`Cache read error for ${key}: ${e.message}`);
      }
      return null;
    }
  }

  async set(key: string, value: T, ttlSeconds: number): Promise<void> {
    const filePath = this.filePathForKey(key);
    const dir = path.dirname(filePath);
    await fs.mkdir(dir, { recursive: true });

    const now = Date.now();
    const entry: CacheEntry<T> = {
      value,
      storedAt: now,
      expiresAt: now + ttlSeconds * 1000,
    };

    // Atomic-ish write: write temp then rename
    const tmp = `${filePath}.${process.pid}.${Math.random().toString(16).slice(2)}.tmp`;
    try {
      await fs.writeFile(tmp, JSON.stringify(entry), "utf-8");
      await fs.rename(tmp, filePath);
    } catch (e) {
      // Clean up temp file on failure
      try {
        await fs.unlink(tmp);
      } catch {
        /* ignore cleanup errors */
      }
      throw e;
    }
  }

  async prune(): Promise<number> {
    let pruned = 0;
    try {
      const subdirs = await fs.readdir(this.dir);
      for (const subdir of subdirs) {
        const subdirPath = path.join(this.dir, subdir);
        const stat = await fs.stat(subdirPath);
        if (!stat.isDirectory()) continue;

        const files = await fs.readdir(subdirPath);
        for (const file of files) {
          if (!file.endsWith(".json")) continue;
          const filePath = path.join(subdirPath, file);
          try {
            const raw = await fs.readFile(filePath, "utf-8");
            const entry = JSON.parse(raw) as CacheEntry<unknown>;
            if (
              !entry ||
              typeof entry !== "object" ||
              typeof entry.expiresAt !== "number" ||
              entry.expiresAt <= Date.now()
            ) {
              await fs.unlink(filePath);
              pruned++;
            }
          } catch {
            // If we can't read/parse, delete the corrupted file
            try {
              await fs.unlink(filePath);
              pruned++;
            } catch {
              /* ignore */
            }
          }
        }
      }
    } catch {
      // Cache directory may not exist yet
    }
    return pruned;
  }
}
