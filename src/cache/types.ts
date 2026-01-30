export interface CacheEntry<T> {
  value: T;
  /** unix epoch milliseconds */
  expiresAt: number;
  /** unix epoch milliseconds */
  storedAt: number;
}

export interface Cache<T = unknown> {
  get(key: string): Promise<CacheEntry<T> | null>;
  set(key: string, value: T, ttlSeconds: number): Promise<void>;
}
