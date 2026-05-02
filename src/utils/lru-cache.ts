/**
 * Generic LRU (Least Recently Used) Cache implementation.
 * Uses a Map (which preserves insertion order in modern JS engines) for O(1) eviction.
 *
 * This is a generic utility — not tied to any domain logic.
 */

export class LruCache<K, V> {
  private cache = new Map<K, V>();
  private readonly maxSize: number;

  constructor(maxSize: number) {
    this.maxSize = Math.max(0, maxSize);
  }

  /**
   * Get a value by key. Moves the entry to the end (most recently used).
   */
  get(key: K): V | undefined {
    const value = this.cache.get(key);
    if (value !== undefined) {
      // Move to end (most recently used) by re-inserting
      this.cache.delete(key);
      this.cache.set(key, value);
    }
    return value;
  }

  /**
   * Set a value by key. Evicts the oldest entry if at capacity.
   */
  set(key: K, value: V): void {
    if (this.cache.has(key)) {
      this.cache.delete(key);
    } else if (this.maxSize > 0 && this.cache.size >= this.maxSize) {
      // Evict oldest (first) entry
      const firstKey = this.cache.keys().next().value;
      if (firstKey !== undefined) {
        this.cache.delete(firstKey);
      }
    }
    this.cache.set(key, value);
  }

  has(key: K): boolean {
    return this.cache.has(key);
  }

  delete(key: K): boolean {
    return this.cache.delete(key);
  }

  get size(): number {
    return this.cache.size;
  }

  clear(): void {
    this.cache.clear();
  }

  /**
   * Get cache statistics for monitoring.
   */
  getStats(): { size: number; maxSize: number; utilization: number } {
    return {
      size: this.cache.size,
      maxSize: this.maxSize,
      utilization: this.maxSize > 0 ? this.cache.size / this.maxSize : 0,
    };
  }
}
