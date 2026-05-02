import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  QueryPerformanceTracker,
  captureMemorySnapshot,
  measureAsync,
  measureSync,
} from "../../src/utils/performance";

describe("QueryPerformanceTracker", () => {
  it("starts with zero metrics", () => {
    const tracker = new QueryPerformanceTracker();
    const metrics = tracker.getMetrics();

    assert.equal(metrics.queryCount, 0);
    assert.equal(metrics.totalDurationMs, 0);
    assert.equal(metrics.minDurationMs, 0);
    assert.equal(metrics.maxDurationMs, 0);
    assert.equal(metrics.avgDurationMs, 0);
    assert.equal(metrics.cacheHits, 0);
    assert.equal(metrics.cacheMisses, 0);
    assert.equal(metrics.cacheHitRate, 0);
  });

  it("records queries correctly", () => {
    const tracker = new QueryPerformanceTracker();
    tracker.recordQuery(10, false);
    tracker.recordQuery(20, true);
    tracker.recordQuery(30, false);

    const metrics = tracker.getMetrics();
    assert.equal(metrics.queryCount, 3);
    assert.equal(metrics.totalDurationMs, 60);
    assert.equal(metrics.minDurationMs, 10);
    assert.equal(metrics.maxDurationMs, 30);
    assert.equal(metrics.avgDurationMs, 20);
    assert.equal(metrics.cacheHits, 1);
    assert.equal(metrics.cacheMisses, 2);
    assert.equal(metrics.cacheHitRate, 1 / 3);
  });

  it("computes percentiles", () => {
    const tracker = new QueryPerformanceTracker(100);
    // Record 100 queries with durations 1..100
    for (let i = 1; i <= 100; i++) {
      tracker.recordQuery(i, false);
    }

    const metrics = tracker.getMetrics();
    assert.equal(metrics.queryCount, 100);
    // p50 should be ~50, p95 should be ~95, p99 should be ~99
    assert.ok(metrics.p50DurationMs >= 49 && metrics.p50DurationMs <= 51);
    assert.ok(metrics.p95DurationMs >= 94 && metrics.p95DurationMs <= 96);
    assert.ok(metrics.p99DurationMs >= 98 && metrics.p99DurationMs <= 100);
  });

  it("resets metrics", () => {
    const tracker = new QueryPerformanceTracker();
    tracker.recordQuery(10, true);
    tracker.recordQuery(20, false);

    tracker.reset();
    const metrics = tracker.getMetrics();
    assert.equal(metrics.queryCount, 0);
    assert.equal(metrics.cacheHits, 0);
    assert.equal(metrics.cacheMisses, 0);
  });

  it("respects maxSamples limit", () => {
    const tracker = new QueryPerformanceTracker(5);
    for (let i = 0; i < 10; i++) {
      tracker.recordQuery(i * 10, false);
    }

    const metrics = tracker.getMetrics();
    assert.equal(metrics.queryCount, 10);
    // min/max should still reflect all recorded queries
    assert.equal(metrics.minDurationMs, 0);
    assert.equal(metrics.maxDurationMs, 90);
  });
});

describe("captureMemorySnapshot", () => {
  it("returns memory metrics", () => {
    const snapshot = captureMemorySnapshot();
    assert.ok(typeof snapshot.heapUsedBytes === "number");
    assert.ok(typeof snapshot.heapTotalBytes === "number");
    assert.ok(typeof snapshot.rssBytes === "number");
    assert.ok(typeof snapshot.externalBytes === "number");
    assert.ok(snapshot.heapUsedBytes > 0);
    assert.ok(snapshot.heapTotalBytes > 0);
    assert.ok(snapshot.rssBytes > 0);
  });
});

describe("measureAsync", () => {
  it("measures async operation duration", async () => {
    const { result, durationMs } = await measureAsync(async () => {
      await new Promise((r) => setTimeout(r, 10));
      return 42;
    });

    assert.equal(result, 42);
    assert.ok(durationMs >= 8, `Expected >=8ms, got ${durationMs}`);
  });
});

describe("measureSync", () => {
  it("measures sync operation duration", () => {
    const { result, durationMs } = measureSync(() => {
      let sum = 0;
      for (let i = 0; i < 1000; i++) sum += i;
      return sum;
    });

    assert.equal(result, 499500);
    assert.ok(durationMs >= 0);
  });
});
