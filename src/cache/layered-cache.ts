import type { Cache, CacheEntry } from "./memory-cache";

/** Multi-layer cache: get() first hit wins + backfills; set() write-through to all layers */
export class LayeredCache<T = unknown> implements Cache<T> {
  private readonly layers: Cache<T>[];

  constructor(layers: Cache<T>[]) {
    this.layers = layers;
  }

  async get(key: string): Promise<CacheEntry<T> | null> {
    for (let i = 0; i < this.layers.length; i++) {
      const layer = this.layers[i]!;
      const v = await layer.get(key);
      if (v) {
        for (let j = 0; j < i; j++) {
          const ttlSeconds = Math.max(0, Math.floor((v.expiresAt - Date.now()) / 1000));
          if (ttlSeconds > 0) await this.layers[j]!.set(key, v.value, ttlSeconds);
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
