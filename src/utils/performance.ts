/**
 * Performance monitoring utilities for database queries and memory usage.
 * Provides tracking, statistics, and bottleneck identification.
 */

export interface QueryMetrics {
  queryCount: number;
  totalDurationMs: number;
  minDurationMs: number;
  maxDurationMs: number;
  avgDurationMs: number;
  p50DurationMs: number;
  p95DurationMs: number;
  p99DurationMs: number;
  cacheHits: number;
  cacheMisses: number;
  cacheHitRate: number;
}

export interface MemoryMetrics {
  heapUsedBytes: number;
  heapTotalBytes: number;
  externalBytes: number;
  rssBytes: number;
  arrayBuffersBytes: number;
  peakHeapBytes: number;
}

export interface PerformanceStats {
  queries: QueryMetrics;
  memory: MemoryMetrics;
  batchMetrics: {
    batchCount: number;
    avgBatchSize: number;
    totalItemsProcessed: number;
  };
}

/**
 * Tracks query performance metrics with minimal overhead.
 */
export class QueryPerformanceTracker {
  private durations: number[] = [];
  private cacheHits = 0;
  private cacheMisses = 0;
  private queryCount = 0;
  private totalDuration = 0;
  private minDuration = Infinity;
  private maxDuration = -Infinity;
  private readonly maxSamples: number;

  constructor(maxSamples = 1000) {
    this.maxSamples = maxSamples;
  }

  recordQuery(durationMs: number, cacheHit: boolean): void {
    this.queryCount++;
    this.totalDuration += durationMs;

    if (durationMs < this.minDuration) this.minDuration = durationMs;
    if (durationMs > this.maxDuration) this.maxDuration = durationMs;

    if (cacheHit) {
      this.cacheHits++;
    } else {
      this.cacheMisses++;
    }

    // Keep only recent samples for percentile calculations
    if (this.durations.length < this.maxSamples) {
      this.durations.push(durationMs);
    } else {
      // Replace oldest sample (ring buffer style)
      this.durations[this.queryCount % this.maxSamples] = durationMs;
    }
  }

  getMetrics(): QueryMetrics {
    const sorted = [...this.durations].sort((a, b) => a - b);
    const len = sorted.length;

    return {
      queryCount: this.queryCount,
      totalDurationMs: this.totalDuration,
      minDurationMs: this.minDuration === Infinity ? 0 : this.minDuration,
      maxDurationMs: this.maxDuration === -Infinity ? 0 : this.maxDuration,
      avgDurationMs: this.queryCount > 0 ? this.totalDuration / this.queryCount : 0,
      p50DurationMs: len > 0 ? sorted[Math.floor(len * 0.5)] ?? 0 : 0,
      p95DurationMs: len > 0 ? sorted[Math.floor(len * 0.95)] ?? 0 : 0,
      p99DurationMs: len > 0 ? sorted[Math.floor(len * 0.99)] ?? 0 : 0,
      cacheHits: this.cacheHits,
      cacheMisses: this.cacheMisses,
      cacheHitRate: this.queryCount > 0 ? this.cacheHits / this.queryCount : 0,
    };
  }

  reset(): void {
    this.durations = [];
    this.cacheHits = 0;
    this.cacheMisses = 0;
    this.queryCount = 0;
    this.totalDuration = 0;
    this.minDuration = Infinity;
    this.maxDuration = -Infinity;
  }
}

/**
 * Track memory usage over time.
 */
export function captureMemorySnapshot(): MemoryMetrics {
  const mem = process.memoryUsage();
  return {
    heapUsedBytes: mem.heapUsed,
    heapTotalBytes: mem.heapTotal,
    externalBytes: mem.external,
    rssBytes: mem.rss,
    arrayBuffersBytes: mem.arrayBuffers,
    peakHeapBytes: mem.heapUsed, // heapUsed tracks current; peak needs manual tracking
  };
}

/**
 * Measure the duration of an async operation.
 */
export async function measureAsync<T>(
  fn: () => Promise<T>,
): Promise<{ result: T; durationMs: number }> {
  const start = performance.now();
  const result = await fn();
  const durationMs = performance.now() - start;
  return { result, durationMs };
}

/**
 * Measure the duration of a synchronous operation.
 */
export function measureSync<T>(fn: () => T): { result: T; durationMs: number } {
  const start = performance.now();
  const result = fn();
  const durationMs = performance.now() - start;
  return { result, durationMs };
}
