// OSV Cache & Error Tests — cache behavior, error handling, response parsing, edge cases.
// Cross-source deduplication (OSV + GitHub) is tested in aggregator.test.ts.
// isVersionAffectedByOsvSemverRange() is tested in semver.test.ts.
// Rate limiting / retry behavior lives in HttpClient (http.test.ts).
import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { OsvSource } from "../../src/databases/osv";
import type { SourceContext } from "../../src/databases/connector";
import type { AuditConfig, VulnerabilityFinding } from "../../src/types";
import type { Cache, CacheEntry } from "../../src/cache/types";
import type { HttpClient } from "../../src/utils/http";

const REGISTRY_URL = "https://registry.npmjs.org";
const osvCacheKey = (name: string, version: string) =>
  `osv:${REGISTRY_URL}:${name}@${version}`;

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
    async set(key: string, value: unknown, ttlSeconds: number): Promise<void> {
      const now = Date.now();
      store.set(key, {
        value,
        storedAt: now,
        expiresAt: now + ttlSeconds * 1000,
      });
    },
  };
}

interface MockCall {
  url: string;
  body?: unknown;
}

/**
 * Mock HTTP client that responds to POST requests to the OSV API.
 * Captures request bodies for assertion.
 */
function createMockHttpClient(
  responses: Array<{ data: unknown; status?: number }>,
): HttpClient & { calls: MockCall[] } {
  let callIndex = 0;
  const calls: MockCall[] = [];
  return {
    calls,
    getJson: async () => { throw new Error("Not implemented"); },
    postJson: async <T>(url: string, body: unknown): Promise<T> => {
      calls.push({ url, body });
      const response = responses[callIndex++];
      if (!response) {
        throw new Error(`No mock response for call ${callIndex}`);
      }
      if (response.status && response.status >= 400) {
        throw new Error(`HTTP ${response.status}`);
      }
      return response.data as T;
    },
    getRaw: async () => { throw new Error("Not implemented"); },
  } as HttpClient & { calls: MockCall[] };
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

/** Create a mock OSV vulnerability response object. */
function createOsvVuln(overrides: {
  id?: string;
  summary?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
    }>;
    versions?: string[];
  }>;
  references?: Array<{ type: string; url: string }>;
  published?: string;
  modified?: string;
} = {}): Record<string, unknown> {
  return {
    id: overrides.id ?? "OSV-2025-0001",
    summary: overrides.summary ?? "Test OSV vulnerability",
    severity: overrides.severity ?? [{ type: "CVSS_V3", score: "7.5/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" }],
    affected: overrides.affected ?? [
      {
        package: { name: "test-pkg", ecosystem: "npm" },
        ranges: [
          {
            type: "SEMVER",
            events: [
              { introduced: "0" },
              { fixed: "2.0.0" },
            ],
          },
        ],
      },
    ],
    references: overrides.references ?? [
      { type: "ADVISORY", url: "https://osv.dev/vulnerability/OSV-2025-0001" },
    ],
    published: overrides.published ?? "2025-01-15T00:00:00Z",
    modified: overrides.modified ?? "2025-01-20T00:00:00Z",
  };
}

describe("OsvSource", () => {
  let source: OsvSource;

  beforeEach(() => {
    source = new OsvSource();
  });

  describe("cache behavior", () => {
    it("returns cached findings without API call", async () => {
      const cache = createMockCache();
      const cachedFindings: VulnerabilityFinding[] = [{
        id: "CACHED-OSV-001",
        source: "osv",
        packageName: "cached-pkg",
        packageVersion: "1.0.0",
        severity: "high",
      }];
      await cache.set(osvCacheKey("cached-pkg", "1.0.0"), cachedFindings, 3600);

      const http = createMockHttpClient([]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "cached-pkg", version: "1.0.0" }], ctx);

      assert.equal(http.calls.length, 0);
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0]!.id, "CACHED-OSV-001");
    });

    it("caches findings after successful query", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            affected: [{
              package: { name: "new-pkg", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      await source.query([{ name: "new-pkg", version: "1.0.0" }], ctx);

      const cached = await cache.get(osvCacheKey("new-pkg", "1.0.0"));
      assert.ok(cached, "Findings should be cached");
      assert.ok(Array.isArray(cached.value));
    });

    it("returns early when all packages are cached", async () => {
      const cache = createMockCache();
      await cache.set(osvCacheKey("pkg1", "1.0.0"), [{
        id: "OSV-001", source: "osv", packageName: "pkg1",
        packageVersion: "1.0.0", severity: "low",
      }], 3600);
      await cache.set(osvCacheKey("pkg2", "2.0.0"), [{
        id: "OSV-002", source: "osv", packageName: "pkg2",
        packageVersion: "2.0.0", severity: "medium",
      }], 3600);

      const http = createMockHttpClient([]);
      const ctx = createContext(cache, http);

      const result = await source.query(
        [{ name: "pkg1", version: "1.0.0" }, { name: "pkg2", version: "2.0.0" }],
        ctx,
      );

      assert.equal(http.calls.length, 0);
      assert.equal(result.findings.length, 2);
      assert.equal(result.ok, true);
    });
  });

  describe("error handling", () => {
    it("captures fetch errors and reports failure", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{ data: null, status: 500 }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.ok, false);
      assert.ok(result.error);
    });

    it("reports partial failure when some queries fail", async () => {
      const cache = createMockCache();
      let callCount = 0;
      const http = {
        calls: [] as MockCall[],
        getJson: async () => { throw new Error("Not implemented"); },
        postJson: async (url: string, body: unknown) => {
          http.calls.push({ url, body });
          callCount++;
          if (callCount === 1) return { vulns: [] };
          throw new Error("Network error");
        },
        getRaw: async () => { throw new Error("Not implemented"); },
      } as HttpClient & { calls: MockCall[] };

      const ctx = createContext(cache, http);

      const result = await source.query(
        [{ name: "pkg-a", version: "1.0.0" }, { name: "pkg-b", version: "2.0.0" }],
        ctx,
      );

      assert.equal(result.ok, false);
      assert.ok(result.error?.includes("Partial failure"));
    });

    it("handles malformed response gracefully", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{ data: "not an object" }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.ok, false);
      assert.ok(result.error);
    });

    it("skips OSV API in offline mode", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([]);
      const ctx = createContext(cache, http);

      const result = await source.query(
        [{ name: "pkg", version: "1.0.0" }],
        ctx,
        { offline: true },
      );

      assert.equal(http.calls.length, 0);
      assert.equal(result.ok, true);
      assert.equal(result.findings.length, 0);
    });
  });

  describe("response parsing", () => {
    it("extracts URL from ADVISORY reference", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            references: [
              { type: "PACKAGE", url: "https://npmjs.com/package/pkg" },
              { type: "ADVISORY", url: "https://osv.dev/vulnerability/OSV-2025-0001" },
            ],
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings[0]!.url, "https://osv.dev/vulnerability/OSV-2025-0001");
    });

    it("falls back to first reference when no ADVISORY type", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            references: [
              { type: "REPORT", url: "https://github.com/issue/123" },
            ],
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings[0]!.url, "https://github.com/issue/123");
    });

    it("extracts fixed version from range events", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [{
                type: "SEMVER",
                events: [
                  { introduced: "1.0.0" },
                  { fixed: "1.2.5" },
                ],
              }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.1.0" }], ctx);

      assert.equal(result.findings[0]!.fixedVersion, "1.2.5");
    });

    it("deduplicates findings within same batch", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [
            createOsvVuln({
              id: "GHSA-xxxx-xxxx-xxxx",
              affected: [{
                package: { name: "pkg", ecosystem: "npm" },
                ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
              }],
            }),
            // Same vuln appearing twice (same canonical id)
            createOsvVuln({
              id: "GHSA-xxxx-xxxx-xxxx",
              affected: [{
                package: { name: "pkg", ecosystem: "npm" },
                ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
              }],
            }),
          ],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings.length, 1);
    });

    it("filters out non-npm ecosystem affected entries", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            affected: [
              {
                package: { name: "pkg", ecosystem: "PyPI" },
                ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
              },
              {
                package: { name: "pkg", ecosystem: "npm" },
                ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
              },
            ],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0]!.source, "osv");
    });

    it("skips vulns with no id", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [{
            // no id field
            summary: "Vuln with no id",
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
            }],
          }],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings.length, 0);
    });
  });

  describe("edge cases", () => {
    it("returns empty findings when OSV returns empty vulns array", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{ data: { vulns: [] } }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "safe-pkg", version: "1.0.0" }], ctx);

      assert.equal(result.ok, true);
      assert.equal(result.findings.length, 0);
    });

    it("matches version across multiple SEMVER ranges in one affected entry", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            id: "OSV-2025-MULTI",
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [
                    { introduced: "1.0.0" },
                    { fixed: "1.5.0" },
                  ],
                },
                {
                  type: "SEMVER",
                  events: [
                    { introduced: "2.0.0" },
                    { fixed: "2.3.0" },
                  ],
                },
              ],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      // Version in first range
      const r1 = await source.query([{ name: "pkg", version: "1.2.0" }], ctx);
      assert.equal(r1.findings.length, 1);

      // Version between ranges (not affected)
      // Need fresh cache/http for each query since dedup set is per-query
      const cache2 = createMockCache();
      const http2 = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            id: "OSV-2025-MULTI",
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [
                    { introduced: "1.0.0" },
                    { fixed: "1.5.0" },
                  ],
                },
                {
                  type: "SEMVER",
                  events: [
                    { introduced: "2.0.0" },
                    { fixed: "2.3.0" },
                  ],
                },
              ],
            }],
          })],
        },
      }]);
      const ctx2 = createContext(cache2, http2);
      const r2 = await source.query([{ name: "pkg", version: "1.7.0" }], ctx2);
      assert.equal(r2.findings.length, 0);

      // Version in second range
      const cache3 = createMockCache();
      const http3 = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            id: "OSV-2025-MULTI",
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [
                    { introduced: "1.0.0" },
                    { fixed: "1.5.0" },
                  ],
                },
                {
                  type: "SEMVER",
                  events: [
                    { introduced: "2.0.0" },
                    { fixed: "2.3.0" },
                  ],
                },
              ],
            }],
          })],
        },
      }]);
      const ctx3 = createContext(cache3, http3);
      const r3 = await source.query([{ name: "pkg", version: "2.1.0" }], ctx3);
      assert.equal(r3.findings.length, 1);
    });

    it("matches package names case-insensitively", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            id: "OSV-2025-CASE",
            affected: [{
              // OSV response uses different casing than queried package
              package: { name: "MyAwesomePackage", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      // Query with lowercase name, OSV responds with PascalCase
      const result = await source.query([{ name: "myawesomepackage", version: "1.0.0" }], ctx);

      assert.equal(result.findings.length, 1);
      // The finding should use the queried package name
      assert.equal(result.findings[0]!.packageName, "myawesomepackage");
    });
  });
});
