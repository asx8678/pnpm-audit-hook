import fs from "node:fs/promises";
import path from "node:path";
import { sha256Hex } from "../utils/hash";
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
      if (entry.expiresAt > Date.now()) return entry;
      return null;
    } catch {
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
    await fs.writeFile(tmp, JSON.stringify(entry), "utf-8");
    await fs.rename(tmp, filePath);
  }
}
