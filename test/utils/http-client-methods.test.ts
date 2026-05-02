import { describe, it, mock, afterEach } from "node:test";
import assert from "node:assert/strict";
import { HttpClient, HttpError, retry, ConnectionPool, destroyAllPools } from "../../src/utils/http";

describe("HttpClient", () => {
  describe("requestJson", () => {
    it("throws HttpError for invalid JSON response", async () => {
      const mockFetch = mock.fn(async () => {
        return new Response("Not valid JSON { broken", {
          status: 200,
          statusText: "OK",
        });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        retries: 0,
      });

      try {
        await client.getJson("https://api.example.com/test");
        assert.fail("Should have thrown");
      } catch (err) {
        assert.ok(err instanceof HttpError);
        // Error message now includes the JSON parse error details for better debugging
        assert.ok(err.message.includes("Invalid JSON response"), `Expected message to include "Invalid JSON response", got: ${err.message}`);
        assert.equal(err.url, "https://api.example.com/test");
        assert.equal(err.status, 200);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it("includes responseText in error for debugging", async () => {
      const invalidJson = "This is not JSON at all!";
      const mockFetch = mock.fn(async () => {
        return new Response(invalidJson, {
          status: 200,
          statusText: "OK",
        });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        retries: 0,
      });

      try {
        await client.getJson("https://api.example.com/test");
        assert.fail("Should have thrown");
      } catch (err) {
        assert.ok(err instanceof HttpError);
        assert.equal(err.responseText, invalidJson);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it("parses valid JSON response", async () => {
      const mockFetch = mock.fn(async () => {
        return new Response('{"items": [1, 2, 3], "count": 3}', {
          status: 200,
          statusText: "OK",
        });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        retries: 0,
      });

      try {
        const result = await client.getJson<{ items: number[]; count: number }>(
          "https://api.example.com/test"
        );
        assert.deepEqual(result, { items: [1, 2, 3], count: 3 });
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it("includes responseText in error on HTTP error", async () => {
      const errorBody = '{"error": "Rate limit exceeded", "retry_after": 60}';
      const mockFetch = mock.fn(async () => {
        return new Response(errorBody, {
          status: 429,
          statusText: "Too Many Requests",
        });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        retries: 0,
      });

      try {
        await client.getJson("https://api.example.com/test");
        assert.fail("Should have thrown");
      } catch (err) {
        assert.ok(err instanceof HttpError);
        assert.equal(err.responseText, errorBody);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });

  describe("request headers", () => {
    it("sets user-agent header", async () => {
      let capturedHeaders: Headers | undefined;
      const mockFetch = mock.fn(async (_url: string, init?: RequestInit) => {
        capturedHeaders = new Headers(init?.headers);
        return new Response('{}', { status: 200 });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "my-custom-agent/1.0",
        retries: 0,
      });

      try {
        await client.getJson("https://api.example.com/test");
        assert.equal(capturedHeaders?.get("user-agent"), "my-custom-agent/1.0");
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it("sets accept header to application/json", async () => {
      let capturedHeaders: Headers | undefined;
      const mockFetch = mock.fn(async (_url: string, init?: RequestInit) => {
        capturedHeaders = new Headers(init?.headers);
        return new Response('{}', { status: 200 });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        retries: 0,
      });

      try {
        await client.getJson("https://api.example.com/test");
        assert.equal(capturedHeaders?.get("accept"), "application/json");
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it("sets content-type for POST requests", async () => {
      let capturedHeaders: Headers | undefined;
      const mockFetch = mock.fn(async (_url: string, init?: RequestInit) => {
        capturedHeaders = new Headers(init?.headers);
        return new Response('{}', { status: 200 });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        retries: 0,
      });

      try {
        await client.postJson("https://api.example.com/test", { data: "value" });
        assert.equal(capturedHeaders?.get("content-type"), "application/json");
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it("includes custom headers from constructor", async () => {
      let capturedHeaders: Headers | undefined;
      const mockFetch = mock.fn(async (_url: string, init?: RequestInit) => {
        capturedHeaders = new Headers(init?.headers);
        return new Response('{}', { status: 200 });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        headers: { Authorization: "Bearer token123", "X-Custom": "value" },
        retries: 0,
      });

      try {
        await client.getJson("https://api.example.com/test");
        assert.equal(capturedHeaders?.get("Authorization"), "Bearer token123");
        assert.equal(capturedHeaders?.get("X-Custom"), "value");
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it("allows extra headers per request", async () => {
      let capturedHeaders: Headers | undefined;
      const mockFetch = mock.fn(async (_url: string, init?: RequestInit) => {
        capturedHeaders = new Headers(init?.headers);
        return new Response('{}', { status: 200 });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        retries: 0,
      });

      try {
        await client.getJson("https://api.example.com/test", {
          "X-Request-ID": "req-123",
        });
        assert.equal(capturedHeaders?.get("X-Request-ID"), "req-123");
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });

  describe("postJson", () => {
    it("sends JSON body", async () => {
      let capturedBody: string | undefined;
      const mockFetch = mock.fn(async (_url: string, init?: RequestInit) => {
        capturedBody = init?.body as string;
        return new Response('{"result": "ok"}', { status: 200 });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        retries: 0,
      });

      try {
        await client.postJson("https://api.example.com/test", {
          name: "test",
          values: [1, 2, 3],
        });
        assert.equal(capturedBody, '{"name":"test","values":[1,2,3]}');
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it("uses POST method", async () => {
      let capturedMethod: string | undefined;
      const mockFetch = mock.fn(async (_url: string, init?: RequestInit) => {
        capturedMethod = init?.method;
        return new Response('{}', { status: 200 });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        retries: 0,
      });

      try {
        await client.postJson("https://api.example.com/test", {});
        assert.equal(capturedMethod, "POST");
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });

  describe("getRaw", () => {
    it("returns Response object", async () => {
      const mockFetch = mock.fn(async () => {
        return new Response('{"data": "raw"}', { status: 200 });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        retries: 0,
      });

      try {
        const response = await client.getRaw("https://api.example.com/test");
        assert.ok(response instanceof Response);
        const json = await response.json();
        assert.deepEqual(json, { data: "raw" });
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it("throws HttpError on failure", async () => {
      const mockFetch = mock.fn(async () => {
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
        retries: 0,
      });

      try {
        await client.getRaw("https://api.example.com/test");
        assert.fail("Should have thrown");
      } catch (err) {
        assert.ok(err instanceof HttpError);
        assert.equal(err.status, 404);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });

  describe("default options", () => {
    it("uses 3 retries by default", async () => {
      let fetchCalls = 0;
      const mockFetch = mock.fn(async () => {
        fetchCalls++;
        return new Response('{"error": "Server Error"}', {
          status: 500,
          statusText: "Internal Server Error",
        });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        // retries not specified, should default to 3
      });

      try {
        await client.getJson("https://api.example.com/test");
        assert.fail("Should have thrown");
      } catch {
        // Expected
      } finally {
        globalThis.fetch = originalFetch;
      }

      assert.equal(fetchCalls, 4); // 1 initial + 3 default retries
    });

    it("uses empty headers by default", async () => {
      let capturedHeaders: Headers | undefined;
      const mockFetch = mock.fn(async (_url: string, init?: RequestInit) => {
        capturedHeaders = new Headers(init?.headers);
        return new Response('{}', { status: 200 });
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as typeof fetch;

      const client = new HttpClient({
        timeoutMs: 5000,
        userAgent: "test-agent",
        // headers not specified
      });

      try {
        await client.getJson("https://api.example.com/test");
        // Should have user-agent and accept, but no custom headers
        assert.equal(capturedHeaders?.get("user-agent"), "test-agent");
        assert.equal(capturedHeaders?.get("accept"), "application/json");
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });
});
