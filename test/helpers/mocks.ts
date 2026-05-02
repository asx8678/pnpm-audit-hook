/**
 * Mock factories for testing.
 *
 * Provides reusable mock implementations for common dependencies
 * like Cache, HttpClient, and process.env.
 */
import type { AuditConfig, VulnerabilityFinding } from "../../src/types";
import type { Cache, CacheEntry } from "../../src/cache/types";
import type { HttpClient, HttpRequestOptions, HttpResponse } from "../../src/utils/http";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface MockCache extends Cache {
  store: Map<string, CacheEntry<unknown>>;
  /** Reset all statistics */
  resetStats(): void;
}

export interface MockHttpClient extends HttpClient {
  /** All recorded requests */
  requests: HttpRequestOptions[];
  /** Set response for a URL pattern */
  mockResponse(pattern: string | RegExp, response: HttpResponse<unknown>): void;
  /** Set error for a URL pattern */
  mockError(pattern: string | RegExp, error: Error): void;
  /** Reset all mocks and recorded requests */
  reset(): void;
}

// ─── Cache Mock ──────────────────────────────────────────────────────────────

/**
 * Create a mock Cache for testing.
 *
 * Supports automatic TTL expiry and exposes the internal store for assertions.
 *
 * @example
 * ```ts
 * const cache = createMockCache();
 * await cache.set("key", { data: "value" }, 3600);
 * const entry = await cache.get("key");
 * assert.deepEqual(entry?.value, { data: "value" });
 * ```
 */
export function createMockCache(): MockCache {
  const store = new Map<string, CacheEntry<unknown>>();
  let hitCount = 0;
  let missCount = 0;

  return {
    store,

    async get(key: string): Promise<CacheEntry<unknown> | null> {
      const entry = store.get(key);
      if (!entry) {
        missCount++;
        return null;
      }
      if (entry.expiresAt < Date.now()) {
        store.delete(key);
        missCount++;
        return null;
      }
      hitCount++;
      return entry;
    },

    async set(
      key: string,
      value: unknown,
      ttlSeconds: number,
      options?: { version?: string; dependencies?: string[] }
    ): Promise<void> {
      const now = Date.now();
      store.set(key, {
        value,
        storedAt: now,
        expiresAt: now + ttlSeconds * 1000,
        version: options?.version,
        dependencies: options?.dependencies,
      });
    },

    async delete(key: string): Promise<boolean> {
      return store.delete(key);
    },

    async has(key: string): Promise<boolean> {
      return store.has(key);
    },

    async clear(): Promise<void> {
      store.clear();
    },

    getStatistics() {
      return {
        hits: hitCount,
        misses: missCount,
        sets: 0,
        deletes: 0,
        evictions: 0,
        totalEntries: store.size,
        totalSizeBytes: 0,
        averageReadTimeMs: 0,
        averageWriteTimeMs: 0,
        prunedEntries: 0,
      };
    },

    async prune() {
      return { pruned: 0, failed: 0 };
    },

    getHealth() {
      return {
        status: "healthy" as const,
        hitRate: hitCount + missCount > 0 ? hitCount / (hitCount + missCount) : 0,
        sizeBytes: 0,
        entryCount: store.size,
        recommendations: [] as string[],
      };
    },

    resetStats() {
      hitCount = 0;
      missCount = 0;
    },
  };
}

// ─── HTTP Client Mock ────────────────────────────────────────────────────────

/**
 * Create a mock HttpClient for testing.
 *
 * Records all requests and allows setting canned responses.
 *
 * @example
 * ```ts
 * const http = createMockHttpClient();
 * http.mockResponse("https://api.example.com/data", {
 *   status: 200,
 *   data: { results: [] },
 *   headers: {},
 * });
 *
 * const response = await http.get("https://api.example.com/data");
 * assert.equal(response.status, 200);
 * assert.equal(http.requests.length, 1);
 * ```
 */
export function createMockHttpClient(): MockHttpClient {
  const requests: HttpRequestOptions[] = [];
  const responses: Array<{ pattern: string | RegExp; response?: HttpResponse<unknown>; error?: Error }> = [];

  function findMatchingResponse(url: string) {
    return responses.find((r) => {
      if (typeof r.pattern === "string") {
        return url.includes(r.pattern);
      }
      return r.pattern.test(url);
    });
  }

  const client: MockHttpClient = {
    requests,
    mockResponse(pattern, response) {
      responses.push({ pattern, response });
    },
    mockError(pattern, error) {
      responses.push({ pattern, error });
    },
    reset() {
      requests.length = 0;
      responses.length = 0;
    },

    async get<T>(url: string, options?: HttpRequestOptions): Promise<HttpResponse<T>> {
      requests.push({ url, method: "GET", ...options });
      const match = findMatchingResponse(url);

      if (!match) {
        throw new Error(`No mock response configured for URL: ${url}`);
      }
      if (match.error) {
        throw match.error;
      }
      return match.response as HttpResponse<T>;
    },

    async post<T>(url: string, body?: unknown, options?: HttpRequestOptions): Promise<HttpResponse<T>> {
      requests.push({ url, method: "POST", body, ...options });
      const match = findMatchingResponse(url);

      if (!match) {
        throw new Error(`No mock response configured for URL: ${url}`);
      }
      if (match.error) {
        throw match.error;
      }
      return match.response as HttpResponse<T>;
    },
  };

  return client;
}

// ─── Finding Builder ─────────────────────────────────────────────────────────

/**
 * Create a VulnerabilityFinding with sensible defaults.
 *
 * All fields can be overridden via the overrides parameter.
 *
 * @example
 * ```ts
 * const vuln = createMockFinding({ packageName: "lodash", severity: "critical" });
 * ```
 */
export function createMockFinding(
  overrides: Partial<VulnerabilityFinding> = {}
): VulnerabilityFinding {
  return {
    id: "GHSA-test-0001",
    source: "github",
    packageName: "test-package",
    packageVersion: "1.0.0",
    severity: "high",
    ...overrides,
  };
}

/**
 * Create multiple mock findings with unique IDs.
 */
export function createMockFindings(
  count: number,
  baseOverrides: Partial<VulnerabilityFinding> = {}
): VulnerabilityFinding[] {
  return Array.from({ length: count }, (_, i) =>
    createMockFinding({
      ...baseOverrides,
      id: `GHSA-test-${String(i + 1).padStart(4, "0")}`,
      packageName: baseOverrides.packageName ?? `package-${i + 1}`,
    })
  );
}

// ─── Config Builder ──────────────────────────────────────────────────────────

/**
 * Create an AuditConfig with sensible defaults.
 */
export function createMockConfig(overrides: Partial<AuditConfig> = {}): AuditConfig {
  return {
    policy: {
      block: ["critical", "high"],
      warn: ["medium", "low", "unknown"],
      allowlist: [],
    },
    sources: {
      github: { enabled: true },
      nvd: { enabled: true },
      osv: { enabled: true },
    },
    performance: { timeoutMs: 15000 },
    cache: { ttlSeconds: 3600 },
    failOnNoSources: true,
    failOnSourceError: true,
    ...overrides,
  };
}

// ─── Environment Mock ────────────────────────────────────────────────────────

/**
 * Create a temporary environment variable override that is automatically
 * cleaned up after the test.
 *
 * @example
 * ```ts
 * using env = mockEnv({ GITHUB_TOKEN: "test-token" });
 * // ... test code that reads process.env.GITHUB_TOKEN ...
 * // env is automatically restored when the block exits
 * ```
 */
export function mockEnv(
  vars: Record<string, string | undefined>
): { [Symbol.dispose](): void } {
  const original: Record<string, string | undefined> = {};

  for (const [key, value] of Object.entries(vars)) {
    original[key] = process.env[key];
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }

  return {
    [Symbol.dispose]() {
      for (const [key, originalValue] of Object.entries(original)) {
        if (originalValue === undefined) {
          delete process.env[key];
        } else {
          process.env[key] = originalValue;
        }
      }
    },
  };
}

// ─── Sleep Helper ────────────────────────────────────────────────────────────

/**
 * Sleep for a given number of milliseconds. Useful for testing timeouts.
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
