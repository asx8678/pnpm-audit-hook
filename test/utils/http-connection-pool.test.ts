import { describe, it, mock, afterEach } from "node:test";
import assert from "node:assert/strict";
import { HttpClient, HttpError, retry, ConnectionPool, destroyAllPools } from "../../src/utils/http";

describe("ConnectionPool", () => {
  afterEach(async () => {
    await destroyAllPools();
  });

  it("creates pool with default options", async () => {
    const pool = new ConnectionPool();
    const metrics = pool.getMetrics();
    assert.equal(metrics.totalRequests, 0);
    assert.equal(metrics.successfulRequests, 0);
    assert.equal(metrics.failedRequests, 0);
    assert.equal(metrics.connectionErrors, 0);
    assert.equal(metrics.averageLatencyMs, 0);
    await pool.destroy();
  });

  it("creates pool with custom options", async () => {
    const pool = new ConnectionPool({
      maxSockets: 5,
      maxFreeSockets: 2,
      timeout: 10000,
      keepAliveMsecs: 15000,
    });
    const metrics = pool.getMetrics();
    assert.equal(metrics.totalRequests, 0);
    await pool.destroy();
  });

  it("tracks request metrics", async () => {
    const pool = new ConnectionPool();
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => new Response('{}', { status: 200 });

    try {
      await pool.request({
        method: "GET",
        url: "https://api.example.com/test",
        headers: { accept: "application/json" },
        timeoutMs: 5000,
      });

      const metrics = pool.getMetrics();
      assert.equal(metrics.totalRequests, 1);
      assert.equal(metrics.successfulRequests, 1);
      assert.equal(metrics.failedRequests, 0);
      assert.ok(metrics.averageLatencyMs >= 0);
    } finally {
      globalThis.fetch = originalFetch;
      await pool.destroy();
    }
  });

  it("tracks failed request metrics", async () => {
    const pool = new ConnectionPool();
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => { throw new Error("connection refused"); };

    try {
      try {
        await pool.request({
          method: "GET",
          url: "https://api.example.com/test",
          headers: { accept: "application/json" },
          timeoutMs: 5000,
        });
        assert.fail("Should have thrown");
      } catch {
        // Expected
      }

      const metrics = pool.getMetrics();
      assert.equal(metrics.totalRequests, 1);
      assert.equal(metrics.successfulRequests, 0);
      assert.equal(metrics.failedRequests, 1);
    } finally {
      globalThis.fetch = originalFetch;
      await pool.destroy();
    }
  });

  it("throws when destroyed pool is used", async () => {
    const pool = new ConnectionPool();
    await pool.destroy();

    try {
      await pool.request({
        method: "GET",
        url: "https://api.example.com/test",
        headers: {},
        timeoutMs: 5000,
      });
      assert.fail("Should have thrown");
    } catch (err) {
      assert.ok(err instanceof Error);
      assert.ok(err.message.includes("destroyed"));
    }
  });

  it("getAgent returns correct agent for protocol", async () => {
    const pool = new ConnectionPool();
    const httpsAgent = pool.getAgent("https://api.example.com/test");
    const httpAgent = pool.getAgent("http://api.example.com/test");
    assert.ok(httpsAgent);
    assert.ok(httpAgent);
    assert.notEqual(httpsAgent, httpAgent);
    await pool.destroy();
  });

  it("destroy is idempotent", async () => {
    const pool = new ConnectionPool();
    await pool.destroy();
    await pool.destroy(); // Should not throw
  });
});

describe("HttpClient connection pooling", () => {
  afterEach(async () => {
    await destroyAllPools();
  });

  it("uses connection pool by default", async () => {
    let capturedAgent: unknown;
    const mockFetch = mock.fn(async (_url: string, init?: RequestInit) => {
      capturedAgent = (init as Record<string, unknown>)?.["agent"];
      return new Response('{"data": "ok"}', { status: 200 });
    });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mockFetch as typeof fetch;

    const client = new HttpClient({
      timeoutMs: 5000,
      userAgent: "test-agent",
      retries: 0,
    });

    try {
      const result = await client.getJson<{ data: string }>("https://api.example.com/test");
      assert.deepEqual(result, { data: "ok" });
      // When pool is enabled, an agent should be passed to fetch
      assert.ok(capturedAgent, "Expected agent to be passed to fetch");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("skips connection pool when pool is false", async () => {
    let capturedAgent: unknown;
    const mockFetch = mock.fn(async (_url: string, init?: RequestInit) => {
      capturedAgent = (init as Record<string, unknown>)?.["agent"];
      return new Response('{"data": "ok"}', { status: 200 });
    });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mockFetch as typeof fetch;

    const client = new HttpClient({
      timeoutMs: 5000,
      userAgent: "test-agent",
      retries: 0,
      pool: false,
    });

    try {
      const result = await client.getJson<{ data: string }>("https://api.example.com/test");
      assert.deepEqual(result, { data: "ok" });
      // When pool is disabled, no agent should be passed
      assert.equal(capturedAgent, undefined);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("passes pool configuration to ConnectionPool", async () => {
    const mockFetch = mock.fn(async () => {
      return new Response('{}', { status: 200 });
    });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mockFetch as typeof fetch;

    const client = new HttpClient({
      timeoutMs: 5000,
      userAgent: "test-agent",
      retries: 0,
      pool: {
        maxSockets: 3,
        maxFreeSockets: 1,
        timeout: 10000,
      },
    });

    try {
      await client.getJson("https://api.example.com/test");
      // Should work without errors - pool was created with custom config
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
