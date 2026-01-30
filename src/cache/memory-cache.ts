export interface CacheEntry<T> {
  value: T;
  /** unix epoch milliseconds */
  expiresAt: number;
  /** unix epoch milliseconds */
  storedAt: number;
  /** If true, entry was returned stale (expired) due to offline/stale policy */
  stale?: boolean;
}

export interface Cache<T = unknown> {
  get(key: string): Promise<CacheEntry<T> | null>;
  set(key: string, value: T, ttlSeconds: number): Promise<void>;
}

export class MemoryCache<T = unknown> implements Cache<T> {
  private readonly map = new Map<string, CacheEntry<T>>();

  async get(key: string): Promise<CacheEntry<T> | null> {
    const e = this.map.get(key);
    if (!e) return null;
    return e;
  }

  async set(key: string, value: T, ttlSeconds: number): Promise<void> {
    const now = Date.now();
    this.map.set(key, {
      value,
      storedAt: now,
      expiresAt: now + ttlSeconds * 1000,
    });
  }
}
