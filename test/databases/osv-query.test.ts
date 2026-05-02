// OSV Query Tests — isEnabled, id, query basics, version range filtering, multiple packages.
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
