// GitHub Advisory Cache & Auth Tests — cache behavior, cache key versioning, authorization.
import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { GitHubAdvisorySource } from "../../src/databases/github-advisory";
import type { SourceContext } from "../../src/databases/connector";
import type { AuditConfig, VulnerabilityFinding } from "../../src/types";

import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { GitHubAdvisorySource } from "../../src/databases/github-advisory";
import type { SourceContext } from "../../src/databases/connector";
import type { AuditConfig, VulnerabilityFinding } from "../../src/types";
import type { Cache, CacheEntry } from "../../src/cache/types";
import type { HttpClient } from "../../src/utils/http";

const REGISTRY_URL = "https://registry.npmjs.org";
const githubCacheKey = (name: string, version: string) =>
  `github:${REGISTRY_URL}:${name}@${version}`;

function baseConfig(): AuditConfig {
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
  };
}

function createMockCache(): Cache & { store: Map<string, CacheEntry<unknown>> } {
  const store = new Map<string, CacheEntry<unknown>>();
  return {
    store,
    async get(key: string): Promise<CacheEntry<unknown> | null> {
      const entry = store.get(key);
      if (!entry) return null;
      if (entry.expiresAt < Date.now()) {
        store.delete(key);
        return null;
      }
      return entry;
    },
    async set(key: string, value: unknown, ttlSeconds: number, options?: { version?: string; dependencies?: string[] }): Promise<void> {
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
        hits: 0,
        misses: 0,
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
        status: 'healthy',
        hitRate: 0,
        sizeBytes: 0,
        entryCount: store.size,
        recommendations: [],
      };
    },
  };
}

function createMockHttpClient(responses: Array<{ data: unknown; status?: number }>): HttpClient & { calls: string[] } {
  let callIndex = 0;
  const calls: string[] = [];
  return {
    calls,
    getJson: async () => { throw new Error("Not implemented"); },
    postJson: async () => { throw new Error("Not implemented"); },
    getRaw: async (url: string) => {
      calls.push(url);
      const response = responses[callIndex++];
      if (!response) {
        throw new Error(`No mock response for call ${callIndex}`);
      }
      if (response.status && response.status >= 400) {
        throw new Error(`HTTP ${response.status}`);
      }
      return {
        json: async () => response.data,
        ok: true,
        status: response.status ?? 200,
      } as Response;
    },
  } as HttpClient & { calls: string[] };
}

function finding(overrides: Partial<VulnerabilityFinding> = {}): VulnerabilityFinding {
  return {
    id: "CVE-2025-0001",
    source: "github",
    packageName: "test-pkg",
    packageVersion: "1.0.0",
    severity: "high",
    ...overrides,
  };
}

function createContext(
  cache: Cache,
  http: HttpClient,
  cfgOverrides: Partial<AuditConfig> = {},
  env: Record<string, string | undefined> = {},
): SourceContext {
  return {
    cfg: { ...baseConfig(), ...cfgOverrides },
    env,
    cache,
    http,
    registryUrl: REGISTRY_URL,
  };
}


describe("GitHubAdvisorySource", () => {
  let source: GitHubAdvisorySource;

  beforeEach(() => {
    source = new GitHubAdvisorySource();
  });

  describe("cache behavior", () => {
    it("returns cached findings without API call", async () => {
      const cache = createMockCache();
      const cachedFindings = [finding({ id: "CACHED-001", packageName: "cached-pkg", packageVersion: "1.0.0" })];
      await cache.set(githubCacheKey("cached-pkg", "1.0.0"), cachedFindings, 3600);

      const http = createMockHttpClient([]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "cached-pkg", version: "1.0.0" }], ctx);

      assert.equal(http.calls.length, 0, "Should not make API calls for cached packages");
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0]!.id, "CACHED-001");
    });

    it("queries API for uncached packages only", async () => {
      const cache = createMockCache();
      await cache.set(githubCacheKey("cached", "1.0.0"), [finding({ packageName: "cached", packageVersion: "1.0.0" })], 3600);

      const http = createMockHttpClient([{ data: [] }]);
      const ctx = createContext(cache, http);

      await source.query(
        [
          { name: "cached", version: "1.0.0" },
          { name: "uncached", version: "2.0.0" },
        ],
        ctx,
      );

      assert.equal(http.calls.length, 1);
      assert.ok(http.calls[0]!.includes("affects=uncached%402.0.0"));
      assert.ok(!http.calls[0]!.includes("affects=cached%401.0.0"));
    });

    it("caches findings after successful query", async () => {
      const cache = createMockCache();
      const advisory = createGitHubAdvisory("new-pkg", "1.0.0");
      const http = createMockHttpClient([{ data: [advisory] }]);
      const ctx = createContext(cache, http);

      await source.query([{ name: "new-pkg", version: "1.0.0" }], ctx);

      const cached = await cache.get(githubCacheKey("new-pkg", "1.0.0"));
      assert.ok(cached, "Findings should be cached");
      assert.ok(Array.isArray(cached.value));
    });

    it("returns early when all packages are cached", async () => {
      const cache = createMockCache();
      await cache.set(githubCacheKey("pkg1", "1.0.0"), [finding({ packageName: "pkg1" })], 3600);
      await cache.set(githubCacheKey("pkg2", "2.0.0"), [finding({ packageName: "pkg2" })], 3600);

      const http = createMockHttpClient([]);
      const ctx = createContext(cache, http);

      const result = await source.query(
        [
          { name: "pkg1", version: "1.0.0" },
          { name: "pkg2", version: "2.0.0" },
        ],
        ctx,
      );

      assert.equal(http.calls.length, 0);
      assert.equal(result.findings.length, 2);
      assert.equal(result.ok, true);
    });
  });

  describe("cache key with DB version", () => {
    it("includes dbVersion in cache key when provided", async () => {
      const sourceWithDb = new GitHubAdvisorySource({
        dbVersion: "2025-01-15T00:00:00Z",
      });

      const cache = createMockCache();
      const http = createMockHttpClient([{ data: [] }]);
      const ctx = createContext(cache, http);

      await sourceWithDb.query([{ name: "pkg", version: "1.0.0" }], ctx);

      // Check the cache was stored with dbVersion in the key
      const keys = [...cache.store.keys()];
      assert.equal(keys.length, 1);
      assert.ok(keys[0]!.includes("dbVersion=2025-01-15T00:00:00Z"),
        `Expected cache key to include dbVersion, got: ${keys[0]}`);
      assert.ok(keys[0]!.startsWith(`github:${REGISTRY_URL}:pkg@1.0.0`));
    });

    it("includes dbVersion before API call to bust stale cache on read", async () => {
      // Set cache with an OLD dbVersion (simulating stale cache from previous DB)
      const cache = createMockCache();
      const oldDbVersion = "2024-06-01T00:00:00Z";
      const newDbVersion = "2025-01-15T00:00:00Z";

      // Pre-populate cache with the OLD dbVersion in the key
      const oldKey = `github:${REGISTRY_URL}:pkg@1.0.0:dbVersion=${oldDbVersion}`;
      await cache.set(oldKey, [finding({ id: "STALE-FROM-OLD-DB" })], 3600);

      const sourceWithNewDb = new GitHubAdvisorySource({
        dbVersion: newDbVersion,
      });

      const http = createMockHttpClient([{ data: [] }]);
      const ctx = createContext(cache, http);

      const result = await sourceWithNewDb.query([{ name: "pkg", version: "1.0.0" }], ctx);

      // The old cache entry with old dbVersion should NOT be found;
      // the source should query the API instead
      assert.equal(http.calls.length, 1,
        "Should make API call because old cache has different dbVersion");

      // The new cache entry should have the new dbVersion
      const newKey = `github:${REGISTRY_URL}:pkg@1.0.0:dbVersion=${newDbVersion}`;
      const newCached = await cache.get(newKey);
      assert.ok(newCached, "New cache entry should exist with updated dbVersion");
    });

    it("derives dbVersion from staticDb when not explicitly provided", async () => {
      const mockStaticDb = {
        isReady: () => true,
        getCutoffDate: () => "2025-01-01T00:00:00Z",
        getDbVersion: () => "2025-01-15T00:00:00Z",
        getIndex: () => null,
        hasVulnerabilities: async () => false,
        queryPackage: async () => [],
        queryPackageWithOptions: async () => [],
      };

      const source = new GitHubAdvisorySource({
        staticDb: mockStaticDb,
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      const cache = createMockCache();
      const http = createMockHttpClient([{ data: [] }]);
      const ctx = createContext(cache, http);

      // Trigger a query — the cache key should include the dbVersion derived from staticDb
      await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      const keys = [...cache.store.keys()];
      assert.equal(keys.length, 1);
      assert.ok(keys[0]!.includes("dbVersion=2025-01-15T00:00:00Z"),
        `Expected cache key to include dbVersion derived from staticDb, got: ${keys[0]}`);
    });

    it("does not include dbVersion when not available", async () => {
      const sourceNoDb = new GitHubAdvisorySource();

      const cache = createMockCache();
      const http = createMockHttpClient([{ data: [] }]);
      const ctx = createContext(cache, http);

      // Trigger query — the cache key should NOT include dbVersion
      await sourceNoDb.query([{ name: "pkg", version: "1.0.0" }], ctx);

      const keys = [...cache.store.keys()];
      assert.equal(keys.length, 1);
      assert.ok(!keys[0]!.includes("dbVersion="),
        `Expected cache key to NOT include dbVersion, got: ${keys[0]}`);
    });
  });

  describe("authorization", () => {
    it("includes GITHUB_TOKEN in authorization header", async () => {
      const cache = createMockCache();
      let capturedHeaders: Record<string, string> = {};
      const http = {
        calls: [] as string[],
        getJson: async () => { throw new Error("Not implemented"); },
        postJson: async () => { throw new Error("Not implemented"); },
        getRaw: async (url: string, headers?: Record<string, string>) => {
          capturedHeaders = headers ?? {};
          return { json: async () => [], ok: true, status: 200 } as Response;
        },
      } as HttpClient & { calls: string[] };

      const ctx = createContext(cache, http, {}, { GITHUB_TOKEN: "ghp_test123" });

      await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(capturedHeaders.Authorization, "Bearer ghp_test123");
    });

    it("uses GH_TOKEN as fallback", async () => {
      const cache = createMockCache();
      let capturedHeaders: Record<string, string> = {};
      const http = {
        calls: [] as string[],
        getJson: async () => { throw new Error("Not implemented"); },
        postJson: async () => { throw new Error("Not implemented"); },
        getRaw: async (url: string, headers?: Record<string, string>) => {
          capturedHeaders = headers ?? {};
          return { json: async () => [], ok: true, status: 200 } as Response;
        },
      } as HttpClient & { calls: string[] };

      const ctx = createContext(cache, http, {}, { GH_TOKEN: "ghp_fallback" });

      await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(capturedHeaders.Authorization, "Bearer ghp_fallback");
    });
  });
});

function createGitHubAdvisory(
  packageName: string,
  packageVersion: string,
  overrides: {
    cve_id?: string | null;
    ghsa_id?: string;
    vulnerable_version_range?: string;
    first_patched_version?: { identifier: string } | string;
  } = {},
) {
  const hasCveOverride = "cve_id" in overrides;
  const cveId = hasCveOverride ? overrides.cve_id : "CVE-2025-0001";
  const ghsaId = overrides.ghsa_id ?? "GHSA-xxxx-xxxx-xxxx";

  const identifiers: Array<{ type: string; value: string }> = [];
  if (cveId) identifiers.push({ type: "CVE", value: cveId });
  identifiers.push({ type: "GHSA", value: ghsaId });

  return {
    id: "ADV-001",
    ghsa_id: ghsaId,
    cve_id: cveId ?? undefined,
    html_url: "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx",
    summary: "Test vulnerability",
    description: "A test vulnerability for unit testing",
    severity: "high",
    identifiers,
    vulnerabilities: [
      {
        package: { name: packageName, ecosystem: "npm" },
        vulnerable_version_range: overrides.vulnerable_version_range ?? `<=${packageVersion}`,
        first_patched_version: overrides.first_patched_version ?? { identifier: "999.0.0" },
      },
    ],
    published_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-01T00:00:00Z",
  };
}