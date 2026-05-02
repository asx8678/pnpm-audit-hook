// OSV Identifier & Severity Tests — identifier extraction, severity mapping, finding normalization.
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
    it("maps CVSS 9.0+ to critical with correct score", async () => {
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
      assert.equal(result.findings[0]!.cvssScore, 9.8);
    });

    it("maps CVSS 7.0-8.9 to high with correct score", async () => {
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
      assert.equal(result.findings[0]!.cvssScore, 7.5);
    });

    it("maps CVSS 4.0-6.9 to medium with correct score", async () => {
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
      assert.equal(result.findings[0]!.cvssScore, 5.0);
    });

    it("maps CVSS 0.1-3.9 to low with correct score", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            severity: [{ type: "CVSS_V3", score: "2.5/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N" }],
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings[0]!.severity, "low");
      assert.equal(result.findings[0]!.cvssScore, 2.5);
    });

    it("maps CVSS 0.0 to unknown severity with score 0", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            severity: [{ type: "CVSS_V3", score: "0.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N" }],
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
      assert.equal(result.findings[0]!.cvssScore, 0);
    });

    it("defaults to unknown severity and undefined cvssScore when no severity info", async () => {
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
      assert.equal(result.findings[0]!.cvssScore, undefined);
    });

    it("defaults to unknown severity and undefined cvssScore when severity has non-CVSS_V3 types", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            severity: [{ type: "OTHER", score: "HIGH" }],
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
      assert.equal(result.findings[0]!.cvssScore, undefined);
    });
  });

  describe("finding normalization", () => {
    it("maps vuln.summary to finding.title", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            id: "OSV-2025-001",
            summary: "Prototype pollution in deep merge",
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings[0]!.title, "Prototype pollution in deep merge");
    });

    it("maps vuln.details to finding.description", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [{
            ...createOsvVuln({
              id: "OSV-2025-002",
              affected: [{
                package: { name: "pkg", ecosystem: "npm" },
                ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
              }],
            }),
            details: "A detailed description of the vulnerability.",
          }],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings[0]!.description, "A detailed description of the vulnerability.");
    });

    it("maps vuln.published to finding.publishedAt", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            id: "OSV-2025-003",
            published: "2024-06-15T10:30:00Z",
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings[0]!.publishedAt, "2024-06-15T10:30:00Z");
    });

    it("maps vuln.modified to finding.modifiedAt", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            id: "OSV-2025-004",
            modified: "2024-08-20T14:00:00Z",
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings[0]!.modifiedAt, "2024-08-20T14:00:00Z");
    });

    it("builds complete identifiers array for CVE-prefixed OSV id", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            id: "CVE-2025-99999",
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      const ids = result.findings[0]!.identifiers!;
      // CVE entry should come first (canonical), then OSV entry
      assert.equal(ids.length, 2);
      assert.equal(ids[0]!.type, "CVE");
      assert.equal(ids[0]!.value, "CVE-2025-99999");
      assert.equal(ids[1]!.type, "OSV");
      assert.equal(ids[1]!.value, "CVE-2025-99999");
      // Canonical id should be the CVE
      assert.equal(result.findings[0]!.id, "CVE-2025-99999");
    });

    it("builds complete identifiers array for GHSA-prefixed OSV id", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            id: "GHSA-aa11-bb22-cc33",
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      const ids = result.findings[0]!.identifiers!;
      // GHSA entry should come first (canonical), then OSV entry
      assert.equal(ids.length, 2);
      assert.equal(ids[0]!.type, "GHSA");
      assert.equal(ids[0]!.value, "GHSA-AA11-BB22-CC33");
      assert.equal(ids[1]!.type, "OSV");
      assert.equal(ids[1]!.value, "GHSA-AA11-BB22-CC33");
      // Canonical id should be the GHSA (uppercased)
      assert.equal(result.findings[0]!.id, "GHSA-AA11-BB22-CC33");
    });

    it("normalizes OSV id to uppercase for canonical and identifiers", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{
        data: {
          vulns: [createOsvVuln({
            id: "ghsa-xx11-yy22-zz33",
            affected: [{
              package: { name: "pkg", ecosystem: "npm" },
              ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
            }],
          })],
        },
      }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      // Canonical id should be uppercased
      assert.equal(result.findings[0]!.id, "GHSA-XX11-YY22-ZZ33");
      // Identifier values should also be uppercased
      assert.ok(result.findings[0]!.identifiers!.every(i => i.value === i.value.toUpperCase()));
    });
  });

});
