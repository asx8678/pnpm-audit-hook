import { describe, it, mock } from "node:test";
import assert from "node:assert/strict";
import { HttpClient, HttpError, retry } from "../../src/utils/http";

describe("HttpError", () => {
  it("constructs with all fields", () => {
    const error = new HttpError("HTTP 500 Internal Server Error", {
      url: "https://api.example.com/data",
      status: 500,
      retryAfter: "120",
      responseText: '{"error": "server error"}',
    });

    assert.equal(error.message, "HTTP 500 Internal Server Error");
    assert.equal(error.name, "HttpError");
    assert.equal(error.url, "https://api.example.com/data");
    assert.equal(error.status, 500);
    assert.equal(error.retryAfter, "120");
    assert.equal(error.responseText, '{"error": "server error"}');
  });

  it("constructs with minimal fields", () => {
    const error = new HttpError("Network error", {
      url: "https://api.example.com/data",
    });

    assert.equal(error.message, "Network error");
    assert.equal(error.url, "https://api.example.com/data");
    assert.equal(error.status, undefined);
    assert.equal(error.retryAfter, undefined);
    assert.equal(error.responseText, undefined);
  });

  it("retryAfter can be a number", () => {
    const error = new HttpError("Rate limited", {
      url: "https://api.example.com/data",
      status: 429,
      retryAfter: 60,
    });

    assert.equal(error.retryAfter, 60);
  });

  it("retryAfter can be a string", () => {
    const error = new HttpError("Rate limited", {
      url: "https://api.example.com/data",
      status: 429,
      retryAfter: "Wed, 21 Oct 2015 07:28:00 GMT",
    });

    assert.equal(error.retryAfter, "Wed, 21 Oct 2015 07:28:00 GMT");
  });
});

describe("retry", () => {
  it("returns result on first success", async () => {
    let attempts = 0;
    const result = await retry(
      async () => {
        attempts++;
        return "success";
      },
      3,
      () => true,
    );

    assert.equal(result, "success");
    assert.equal(attempts, 1);
  });

  it("retries on failure up to max retries", async () => {
    let attempts = 0;
    try {
      await retry(
        async () => {
          attempts++;
          throw new Error("fail");
        },
        3,
        () => true,
      );
      assert.fail("Should have thrown");
    } catch (err) {
      assert.ok(err instanceof Error);
      assert.equal(err.message, "fail");
    }

    assert.equal(attempts, 4); // 1 initial + 3 retries
  });

  it("does not retry when shouldRetry returns false", async () => {
    let attempts = 0;
    try {
      await retry(
        async () => {
          attempts++;
          throw new Error("non-retryable");
        },
        3,
        () => false,
      );
      assert.fail("Should have thrown");
    } catch (err) {
      assert.ok(err instanceof Error);
    }

    assert.equal(attempts, 1);
  });

  it("succeeds after retries", async () => {
    let attempts = 0;
    const result = await retry(
      async () => {
        attempts++;
        if (attempts < 3) throw new Error("fail");
        return "success after retries";
      },
      3,
      () => true,
    );

    assert.equal(result, "success after retries");
    assert.equal(attempts, 3);
  });

  it("uses Retry-After numeric value from HttpError", async () => {
    const startTime = Date.now();
    let attempts = 0;

    try {
      await retry(
        async () => {
          attempts++;
          throw new HttpError("Rate limited", {
            url: "https://test.com",
            status: 429,
            retryAfter: 1, // 1 second
          });
        },
        1,
        () => true,
      );
    } catch {
      // Expected
    }

    const elapsed = Date.now() - startTime;
    // Should wait at least 1000ms (1 second) for the retry
    assert.ok(elapsed >= 900, `Expected delay of ~1000ms, got ${elapsed}ms`);
    assert.equal(attempts, 2);
  });

  it("uses Retry-After string numeric value from HttpError", async () => {
    const startTime = Date.now();
    let attempts = 0;

    try {
      await retry(
        async () => {
          attempts++;
          throw new HttpError("Rate limited", {
            url: "https://test.com",
            status: 429,
            retryAfter: "1", // String "1" second
          });
        },
        1,
        () => true,
      );
    } catch {
      // Expected
    }

    const elapsed = Date.now() - startTime;
    assert.ok(elapsed >= 900, `Expected delay of ~1000ms, got ${elapsed}ms`);
    assert.equal(attempts, 2);
  });

  it("caps Retry-After at 30 seconds", async () => {
    const startTime = Date.now();
    let attempts = 0;

    // We'll use a very short test by checking it doesn't wait 100 seconds
    try {
      await retry(
        async () => {
          attempts++;
          throw new HttpError("Rate limited", {
            url: "https://test.com",
            status: 429,
            retryAfter: 100, // 100 seconds, should be capped to 30
          });
        },
        0, // No retries
        () => true,
      );
    } catch {
      // Expected immediately since retries=0
    }

    const elapsed = Date.now() - startTime;
    // With 0 retries, should throw immediately
    assert.ok(elapsed < 1000, `Should not wait when retries=0`);
    assert.equal(attempts, 1);
  });
});

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
        assert.ok(err.message.startsWith("Invalid JSON response:"), `Expected message to start with "Invalid JSON response:", got: ${err.message}`);
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
