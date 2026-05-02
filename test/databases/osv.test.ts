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

  describe("isEnabled", () => {
    it("returns true when enabled in config", () => {
      const cfg = baseConfig();
      assert.equal(source.isEnabled(cfg, {}), true);
    });

    it("returns false when disabled in config", () => {
      const cfg = baseConfig();
      cfg.sources.osv.enabled = false;
      assert.equal(source.isEnabled(cfg, {}), false);
    });

    it("returns false when PNPM_AUDIT_DISABLE_OSV env is true", () => {
      const cfg = baseConfig();
      assert.equal(source.isEnabled(cfg, { PNPM_AUDIT_DISABLE_OSV: "true" }), false);
    });

    it("returns true when PNPM_AUDIT_DISABLE_OSV env is not true", () => {
      const cfg = baseConfig();
      assert.equal(source.isEnabled(cfg, { PNPM_AUDIT_DISABLE_OSV: "false" }), true);
    });
  });

  describe("id", () => {
    it("has id 'osv'", () => {
      assert.equal(source.id, "osv");
    });
  });

  describe("query - basic", () => {
    it("returns empty findings when OSV returns no vulnerabilities", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{ data: {} }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "safe-pkg", version: "1.0.0" }], ctx);

      assert.equal(result.ok, true);
      assert.equal(result.findings.length, 0);
    });

    it("returns findings when OSV returns vulnerabilities", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            id: "GHSA-xxxx-xxxx-xxxx",
            affected: [{
              package: { name: "test-pkg", ecosystem: "npm" },
              ranges: [{
                type: "SEMVER",
                events: [
                  { introduced: "0" },
                  { fixed: "2.0.0" },
                ],
              }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "test-pkg", version: "1.0.0" }], ctx);

      assert.equal(result.ok, true);
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0]!.source, "osv");
      assert.equal(result.findings[0]!.packageName, "test-pkg");
      assert.equal(result.findings[0]!.packageVersion, "1.0.0");
    });
  });

  describe("query - POST body", () => {
    it("sends correct POST body to OSV API", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{ data: {} }]);
      const ctx = createContext(cache, http);

      await source.query([{ name: "lodash", version: "4.17.0" }], ctx);

      assert.equal(http.calls.length, 1);
      assert.equal(http.calls[0]!.url, "https://api.osv.dev/v1/query");
      assert.deepEqual(http.calls[0]!.body, {
        package: { name: "lodash", ecosystem: "npm" },
        version: "4.17.0",
      });
    });
  });

  describe("version range filtering", () => {
    it("includes packages within SEMVER introduced/fixed range", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            affected: [{
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [{
                type: "SEMVER",
                events: [
                  { introduced: "4.0.0" },
                  { fixed: "4.17.21" },
                ],
              }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "lodash", version: "4.17.0" }], ctx);

      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0]!.affectedRange, ">=4.0.0 <4.17.21");
    });

    it("excludes packages outside SEMVER range", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            affected: [{
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [{
                type: "SEMVER",
                events: [
                  { introduced: "4.0.0" },
                  { fixed: "4.17.21" },
                ],
              }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "lodash", version: "4.17.21" }], ctx);

      assert.equal(result.findings.length, 0);
    });

    it("includes packages within last_affected range", async () => {
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
                  { last_affected: "1.5.0" },
                ],
              }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.5.0" }], ctx);

      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0]!.affectedRange, ">=1.0.0 <=1.5.0");
    });

    it("includes packages in explicit version list", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [],
              versions: ["1.0.0", "1.1.0", "1.2.0"],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.1.0" }], ctx);

      assert.equal(result.findings.length, 1);
    });

    it("excludes packages not in explicit version list", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [],
              versions: ["1.0.0", "1.1.0"],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "2.0.0" }], ctx);

      assert.equal(result.findings.length, 0);
    });

    it("includes vulnerability when no ranges or versions (fail-closed)", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [],
              versions: [],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "9.9.9" }], ctx);

      assert.equal(result.findings.length, 1);
    });
  });

  describe("identifier extraction", () => {
    it("uses CVE id as canonical when OSV id starts with CVE-", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            id: "CVE-2025-12345",
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings[0]!.id, "CVE-2025-12345");
      assert.ok(result.findings[0]!.identifiers!.some(i => i.type === "CVE" && i.value === "CVE-2025-12345"));
      assert.ok(result.findings[0]!.identifiers!.some(i => i.type === "OSV"));
    });

    it("uses GHSA id as canonical when OSV id starts with GHSA-", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            id: "GHSA-xxxx-xxxx-xxxx",
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings[0]!.id, "GHSA-XXXX-XXXX-XXXX");
    });

    it("uses OSV id as canonical for generic OSV IDs", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            id: "OSV-2025-54321",
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings[0]!.id, "OSV-2025-54321");
    });
  });

  describe("severity mapping", () => {
    it("maps CVSS 9.0+ to critical", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            severity: [{ type: "CVSS_V3", score: "9.8/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings[0]!.severity, "critical");
    });

    it("maps CVSS 7.0-8.9 to high", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            severity: [{ type: "CVSS_V3", score: "7.5/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" }],
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings[0]!.severity, "high");
    });

    it("maps CVSS 4.0-6.9 to medium", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            severity: [{ type: "CVSS_V3", score: "5.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" }],
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings[0]!.severity, "medium");
    });

    it("defaults to unknown when no severity info", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            severity: [],
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings[0]!.severity, "unknown");
    });
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

  describe("multiple packages", () => {
    it("queries each package individually via POST", async () => {
      const cache = createMockCache();
      const packages = [
        { name: "pkg-a", version: "1.0.0" },
        { name: "pkg-b", version: "2.0.0" },
        { name: "pkg-c", version: "3.0.0" },
      ];

      const http = createMockHttpClient([
        { data: {} },
        { data: {} },
        { data: {} },
      ]);
      const ctx = createContext(cache, http);

      await source.query(packages, ctx);

      assert.equal(http.calls.length, 3);
      assert.deepEqual(http.calls[0]!.body, {
        package: { name: "pkg-a", ecosystem: "npm" },
        version: "1.0.0",
      });
      assert.deepEqual(http.calls[1]!.body, {
        package: { name: "pkg-b", ecosystem: "npm" },
        version: "2.0.0",
      });
      assert.deepEqual(http.calls[2]!.body, {
        package: { name: "pkg-c", ecosystem: "npm" },
        version: "3.0.0",
      });
    });
  });
});
