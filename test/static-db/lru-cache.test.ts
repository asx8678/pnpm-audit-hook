import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { LruCache } from "../../src/static-db/reader";

describe("LruCache", () => {
  it("stores and retrieves values", () => {
    const cache = new LruCache<string, number>(3);
    cache.set("a", 1);
    cache.set("b", 2);

    assert.equal(cache.get("a"), 1);
    assert.equal(cache.get("b"), 2);
    assert.equal(cache.size, 2);
  });

  it("returns undefined for missing keys", () => {
    const cache = new LruCache<string, number>(3);
    assert.equal(cache.get("missing"), undefined);
  });

  it("evicts oldest entry when full", () => {
    const cache = new LruCache<string, number>(2);
    cache.set("a", 1);
    cache.set("b", 2);
    cache.set("c", 3); // should evict "a"

    assert.equal(cache.get("a"), undefined);
    assert.equal(cache.get("b"), 2);
    assert.equal(cache.get("c"), 3);
    assert.equal(cache.size, 2);
  });

  it("moves accessed entries to end (LRU behavior)", () => {
    const cache = new LruCache<string, number>(2);
    cache.set("a", 1);
    cache.set("b", 2);

    // Access "a" to move it to end
    cache.get("a");

    // Now "b" is oldest, should be evicted
    cache.set("c", 3);
    assert.equal(cache.get("a"), 1);
    assert.equal(cache.get("b"), undefined);
    assert.equal(cache.get("c"), 3);
  });

  it("handles updating existing keys", () => {
    const cache = new LruCache<string, number>(2);
    cache.set("a", 1);
    cache.set("a", 10);

    assert.equal(cache.get("a"), 10);
    assert.equal(cache.size, 1);
  });

  it("supports has and delete", () => {
    const cache = new LruCache<string, number>(3);
    cache.set("a", 1);
    cache.set("b", 2);

    assert.equal(cache.has("a"), true);
    assert.equal(cache.has("c"), false);
    assert.equal(cache.delete("a"), true);
    assert.equal(cache.delete("c"), false);
    assert.equal(cache.has("a"), false);
    assert.equal(cache.size, 1);
  });

  it("supports clear", () => {
    const cache = new LruCache<string, number>(3);
    cache.set("a", 1);
    cache.set("b", 2);
    cache.clear();
    assert.equal(cache.size, 0);
  });

  it("returns correct stats", () => {
    const cache = new LruCache<string, number>(10);
    cache.set("a", 1);
    cache.set("b", 2);

    const stats = cache.getStats();
    assert.equal(stats.size, 2);
    assert.equal(stats.maxSize, 10);
    assert.equal(stats.utilization, 0.2);
  });

  it("handles zero max size (unlimited)", () => {
    const cache = new LruCache<string, number>(0);
    for (let i = 0; i < 100; i++) {
      cache.set(`key${i}`, i);
    }
    assert.equal(cache.size, 100);
  });

  it("handles capacity of 1", () => {
    const cache = new LruCache<string, number>(1);
    cache.set("a", 1);
    assert.equal(cache.get("a"), 1);

    cache.set("b", 2);
    assert.equal(cache.get("a"), undefined);
    assert.equal(cache.get("b"), 2);
  });

  it("LRU eviction order is correct for sequence of operations", () => {
    const cache = new LruCache<string, number>(3);
    cache.set("a", 1);
    cache.set("b", 2);
    cache.set("c", 3);

    // Access "a" to make "b" the oldest
    cache.get("a");

    // Add "d" -> evicts "b"
    cache.set("d", 4);
    assert.equal(cache.has("a"), true);
    assert.equal(cache.has("b"), false);
    assert.equal(cache.has("c"), true);
    assert.equal(cache.has("d"), true);
  });
});
