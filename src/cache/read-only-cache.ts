import type { Cache, CacheEntry } from "./memory-cache";

/** Wraps a cache to prevent writes - useful for offline DB snapshots */
export class ReadOnlyCache<T> implements Cache<T> {
  constructor(private inner: Cache<T>) {}
  get(key: string): Promise<CacheEntry<T> | null> { return this.inner.get(key); }
  set(): Promise<void> { return Promise.resolve(); }
  delete(): Promise<void> { return Promise.resolve(); }
  clear(): Promise<void> { return Promise.resolve(); }
}
