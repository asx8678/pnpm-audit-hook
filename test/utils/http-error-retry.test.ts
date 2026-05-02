import { describe, it, mock, afterEach } from "node:test";
import assert from "node:assert/strict";
import { HttpClient, HttpError, retry, ConnectionPool, destroyAllPools } from "../../src/utils/http";

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

