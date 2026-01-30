import type { Cache, CacheEntry } from "./memory-cache";

/** Wrap a cache as read-only (set becomes a no-op). */
export class ReadOnlyCache<T = unknown> implements Cache<T> {
  private readonly inner: Cache<T>;
  constructor(inner: Cache<T>) {
    this.inner = inner;
  }

  async get(key: string): Promise<CacheEntry<T> | null> {
    return this.inner.get(key);
  }

  async set(_key: string, _value: T, _ttlSeconds: number): Promise<void> {
    // no-op
  }
}
