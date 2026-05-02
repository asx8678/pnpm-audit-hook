export interface CacheEntry<T> {
  value: T;
  /** unix epoch milliseconds */
  expiresAt: number;
  /** unix epoch milliseconds */
  storedAt: number;
  /** Optional version for cache invalidation */
  version?: string;
  /** Optional dependencies for dependency-based invalidation */
  dependencies?: string[];
}

export interface CacheStatistics {
  hits: number;
  misses: number;
  sets: number;
  deletes: number;
  evictions: number;
  totalEntries: number;
  totalSizeBytes: number;
  averageReadTimeMs: number;
  averageWriteTimeMs: number;
  lastPruneTime?: number;
  prunedEntries: number;
}

export interface Cache<T = unknown> {
  get(key: string): Promise<CacheEntry<T> | null>;
  set(key: string, value: T, ttlSeconds: number, options?: { version?: string; dependencies?: string[] }): Promise<void>;
  delete(key: string): Promise<boolean>;
  has(key: string): Promise<boolean>;
  clear(): Promise<void>;
  getStatistics(): CacheStatistics;
  prune(): Promise<{ pruned: number; failed: number }>;
  getHealth(): CacheHealth;
}

export interface CacheHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  hitRate: number;
  sizeBytes: number;
  entryCount: number;
  oldestEntryAge?: number;
  newestEntryAge?: number;
  recommendations: string[];
}
