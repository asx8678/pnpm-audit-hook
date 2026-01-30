import type { Cache, CacheEntry } from "./memory-cache";

/**
 * Simple multi-layer cache:
 * - get(): first hit wins, then backfills higher layers
 * - set(): write-through to all layers
 */
export class LayeredCache<T = unknown> implements Cache<T> {
  private readonly layers: Cache<T>[];

  constructor(layers: Cache<T>[]) {
    this.layers = layers;
  }

  /**
   * Get a value from the cache, checking layers in order.
   * Side effect: If found in a lower layer, backfills upper layers for faster future access.
   */
  async get(key: string): Promise<CacheEntry<T> | null> {
    for (let i = 0; i < this.layers.length; i++) {
      const layer = this.layers[i]!;
      const v = await layer.get(key);
      if (v) {
        // Backfill previous layers for speed
        for (let j = 0; j < i; j++) {
          const prev = this.layers[j]!;
          // Preserve TTL relative to expiresAt
          const ttlSeconds = Math.max(
            0,
            Math.floor((v.expiresAt - Date.now()) / 1000),
          );
          if (ttlSeconds > 0) await prev.set(key, v.value, ttlSeconds);
        }
        return v;
      }
    }
    return null;
  }

  async set(key: string, value: T, ttlSeconds: number): Promise<void> {
    await Promise.all(this.layers.map((l) => l.set(key, value, ttlSeconds)));
  }
}
