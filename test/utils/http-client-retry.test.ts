import { describe, it, mock, afterEach } from "node:test";
import assert from "node:assert/strict";
import { HttpClient, HttpError, retry, ConnectionPool, destroyAllPools } from "../../src/utils/http";

describe("HttpClient", () => {
  describe("retry logic", () => {
    it("retries on 500 status code up to max retries", async () => {
      let fetchCalls = 0;
      const mockFetch = mock.fn(async () => {
        fetchCalls++;
        return new Response('{"error": "Internal Server Error"}', {
          status: 500,
          statusText: "Internal Server Error",
        });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        retries: 2,
      });

      try {
        await client.getJson("https://api.example.com/test");
        assert.fail("Should have thrown");
      } catch (err) {
        assert.ok(err instanceof HttpError);
        assert.equal(err.status, 500);
      } finally {
        globalThis.fetch = originalFetch;
      }

      assert.equal(fetchCalls, 3); // 1 initial + 2 retries
    });

    it("retries on 429 with Retry-After header", async () => {
      let fetchCalls = 0;
      const mockFetch = mock.fn(async () => {
        fetchCalls++;
        const headers = new Headers();
        headers.set("retry-after", "1");
        return new Response('{"error": "Too Many Requests"}', {
          status: 429,
          statusText: "Too Many Requests",
          headers,
        });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        retries: 1,
      });

      const startTime = Date.now();
      try {
        await client.getJson("https://api.example.com/test");
        assert.fail("Should have thrown");
      } catch (err) {
        assert.ok(err instanceof HttpError);
        assert.equal(err.status, 429);
        assert.equal(err.retryAfter, "1");
      } finally {
        globalThis.fetch = originalFetch;
      }

      const elapsed = Date.now() - startTime;
      assert.equal(fetchCalls, 2);
      assert.ok(elapsed >= 900, `Expected delay of ~1000ms, got ${elapsed}ms`);
    });

    it("does NOT retry on 400 Bad Request", async () => {
      let fetchCalls = 0;
      const mockFetch = mock.fn(async () => {
        fetchCalls++;
        return new Response('{"error": "Bad Request"}', {
          status: 400,
          statusText: "Bad Request",
        });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        retries: 3,
      });

      try {
        await client.getJson("https://api.example.com/test");
        assert.fail("Should have thrown");
      } catch (err) {
        assert.ok(err instanceof HttpError);
        assert.equal(err.status, 400);
      } finally {
        globalThis.fetch = originalFetch;
      }

      assert.equal(fetchCalls, 1); // No retries for 4xx (except 429)
    });

    it("does NOT retry on 401 Unauthorized", async () => {
      let fetchCalls = 0;
      const mockFetch = mock.fn(async () => {
        fetchCalls++;
        return new Response('{"error": "Unauthorized"}', {
          status: 401,
          statusText: "Unauthorized",
        });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        retries: 3,
      });

      try {
        await client.getJson("https://api.example.com/test");
        assert.fail("Should have thrown");
      } catch (err) {
        assert.ok(err instanceof HttpError);
        assert.equal(err.status, 401);
      } finally {
        globalThis.fetch = originalFetch;
      }

      assert.equal(fetchCalls, 1);
    });

    it("does NOT retry on 403 Forbidden", async () => {
      let fetchCalls = 0;
      const mockFetch = mock.fn(async () => {
        fetchCalls++;
        return new Response('{"error": "Forbidden"}', {
          status: 403,
          statusText: "Forbidden",
        });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        retries: 3,
      });

      try {
        await client.getJson("https://api.example.com/test");
        assert.fail("Should have thrown");
      } catch (err) {
        assert.ok(err instanceof HttpError);
        assert.equal(err.status, 403);
      } finally {
        globalThis.fetch = originalFetch;
      }

      assert.equal(fetchCalls, 1);
    });

    it("does NOT retry on 404 Not Found", async () => {
      let fetchCalls = 0;
      const mockFetch = mock.fn(async () => {
        fetchCalls++;
        return new Response('{"error": "Not Found"}', {
          status: 404,
          statusText: "Not Found",
        });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        retries: 3,
      });

      try {
        await client.getJson("https://api.example.com/test");
        assert.fail("Should have thrown");
      } catch (err) {
        assert.ok(err instanceof HttpError);
        assert.equal(err.status, 404);
      } finally {
        globalThis.fetch = originalFetch;
      }

      assert.equal(fetchCalls, 1);
    });

    it("retries on 502 Bad Gateway", async () => {
      let fetchCalls = 0;
      const mockFetch = mock.fn(async () => {
        fetchCalls++;
        return new Response('{"error": "Bad Gateway"}', {
          status: 502,
          statusText: "Bad Gateway",
        });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        retries: 1,
      });

      try {
        await client.getJson("https://api.example.com/test");
        assert.fail("Should have thrown");
      } catch (err) {
        assert.ok(err instanceof HttpError);
        assert.equal(err.status, 502);
      } finally {
        globalThis.fetch = originalFetch;
      }

      assert.equal(fetchCalls, 2); // Retries on 5xx
    });

    it("retries on 503 Service Unavailable", async () => {
      let fetchCalls = 0;
      const mockFetch = mock.fn(async () => {
        fetchCalls++;
        return new Response('{"error": "Service Unavailable"}', {
          status: 503,
          statusText: "Service Unavailable",
        });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        retries: 1,
      });

      try {
        await client.getJson("https://api.example.com/test");
        assert.fail("Should have thrown");
      } catch (err) {
        assert.ok(err instanceof HttpError);
        assert.equal(err.status, 503);
      } finally {
        globalThis.fetch = originalFetch;
      }

      assert.equal(fetchCalls, 2);
    });

    it("recovers after transient failure", async () => {
      let fetchCalls = 0;
      const mockFetch = mock.fn(async () => {
        fetchCalls++;
        if (fetchCalls === 1) {
          return new Response('{"error": "Service Unavailable"}', {
            status: 503,
            statusText: "Service Unavailable",
          });
        }
        return new Response('{"data": "success"}', {
          status: 200,
          statusText: "OK",
        });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        retries: 2,
      });

      try {
        const result = await client.getJson<{ data: string }>("https://api.example.com/test");
        assert.deepEqual(result, { data: "success" });
      } finally {
        globalThis.fetch = originalFetch;
      }

      assert.equal(fetchCalls, 2);
    });
  });

  describe("timeout handling", () => {
    it("aborts request after timeoutMs", async () => {
      const mockFetch = mock.fn(async (_url: string, init?: RequestInit) => {
        // Simulate a slow request that will be aborted
        return new Promise<Response>((resolve, reject) => {
          const timeout = setTimeout(() => {
            resolve(new Response('{"data": "success"}', { status: 200 }));
          }, 5000);

          // Listen for abort signal
          if (init?.signal) {
            init.signal.addEventListener("abort", () => {
              clearTimeout(timeout);
              reject(new DOMException("The operation was aborted", "AbortError"));
            });
          }
        });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 100, // Very short timeout
        userAgent: "test-agent",
        retries: 0,
      });

      const startTime = Date.now();
      try {
        await client.getJson("https://api.example.com/test");
        assert.fail("Should have thrown");
      } catch (err) {
        assert.ok(err instanceof Error);
        assert.ok(err.name === "AbortError" || err.message.includes("abort"));
      } finally {
        globalThis.fetch = originalFetch;
      }

      const elapsed = Date.now() - startTime;
      assert.ok(elapsed < 1000, `Should abort quickly, took ${elapsed}ms`);
    });
  });

});
