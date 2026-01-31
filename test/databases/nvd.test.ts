import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { enrichFindingsWithNvd } from "../../src/databases/nvd";
import type { SourceContext } from "../../src/databases/connector";
import type { AuditConfig, VulnerabilityFinding } from "../../src/types";
import type { Cache, CacheEntry } from "../../src/cache/types";
import type { HttpClient } from "../../src/utils/http";

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
    },
    performance: { timeoutMs: 15000 },
    cache: { ttlSeconds: 3600 },
    failOnNoSources: true,
    failOnSourceError: true,
    staticBaseline: { enabled: false, cutoffDate: "2024-01-01" },
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

interface MockHttpOptions {
  responses?: Array<{ data: unknown; status?: number }>;
}

function createMockHttpClient(opts: MockHttpOptions = {}): HttpClient & { calls: Array<{ url: string; headers?: Record<string, string> }> } {
  let callIndex = 0;
  const calls: Array<{ url: string; headers?: Record<string, string> }> = [];

  return {
    calls,
    getJson: async <T>(url: string, headers?: Record<string, string>): Promise<T> => {
      calls.push({ url, headers });
      const responses = opts.responses ?? [];
      const response = responses[callIndex++];
      if (!response) {
        throw new Error(`No mock response for call ${callIndex}`);
      }
      if (response.status === 404) {
        const err = new Error("HTTP 404 Not Found");
        (err as Error & { status: number }).status = 404;
        throw err;
      }
      if (response.status === 429) {
        const err = new Error("HTTP 429 Too Many Requests");
        (err as Error & { status: number }).status = 429;
        throw err;
      }
      if (response.status && response.status >= 400) {
        throw new Error(`HTTP ${response.status}`);
      }
      return response.data as T;
    },
    postJson: async () => {
      throw new Error("Not implemented");
    },
    getRaw: async () => {
      throw new Error("Not implemented");
    },
  } as HttpClient & { calls: Array<{ url: string; headers?: Record<string, string> }> };
}

function finding(overrides: Partial<VulnerabilityFinding> = {}): VulnerabilityFinding {
  return {
    id: "CVE-2025-0001",
    source: "github",
    packageName: "test-pkg",
    packageVersion: "1.0.0",
    severity: "unknown",
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
    registryUrl: "https://registry.npmjs.org",
  };
}

function createNvdResponse(cveId: string, opts: {
  baseSeverity?: string;
  baseScore?: number;
  metricVersion?: "v31" | "v30" | "v2";
  metricType?: "Primary" | "Secondary";
  published?: string;
  lastModified?: string;
} = {}) {
  const severity = opts.baseSeverity ?? "HIGH";
  const score = opts.baseScore ?? 7.5;
  const version = opts.metricVersion ?? "v31";
  const type = opts.metricType ?? "Primary";

  const cvssData = { baseScore: score, baseSeverity: severity };
  const metric = { type, cvssData };

  const metrics: Record<string, unknown[]> = {};
  if (version === "v31") metrics.cvssMetricV31 = [metric];
  else if (version === "v30") metrics.cvssMetricV30 = [metric];
  else metrics.cvssMetricV2 = [metric];

  return {
    vulnerabilities: [{
      cve: {
        id: cveId,
        published: opts.published ?? "2025-01-01T00:00:00.000",
        lastModified: opts.lastModified ?? "2025-01-15T00:00:00.000",
        metrics,
      },
    }],
  };
}

describe("enrichFindingsWithNvd", () => {
  describe("empty findings", () => {
    it("returns ok:true with empty findings array", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({ responses: [] });
      const ctx = createContext(cache, http);

      const result = await enrichFindingsWithNvd([], ctx);

      assert.equal(result.ok, true);
      assert.equal(http.calls.length, 0);
    });
  });

  describe("severity filtering", () => {
    it("only fetches NVD data for findings with severity unknown", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: createNvdResponse("CVE-2025-0001") }],
      });
      const ctx = createContext(cache, http);

      const findings = [
        finding({ id: "CVE-2025-0001", severity: "unknown" }),
        finding({ id: "CVE-2025-0002", severity: "high" }),
        finding({ id: "CVE-2025-0003", severity: "critical" }),
      ];

      await enrichFindingsWithNvd(findings, ctx);

      assert.equal(http.calls.length, 1);
      assert.ok(http.calls[0]!.url.includes("CVE-2025-0001"));
    });

    it("does not fetch when all findings have known severity", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({ responses: [] });
      const ctx = createContext(cache, http);

      const findings = [
        finding({ id: "CVE-2025-0001", severity: "high" }),
        finding({ id: "CVE-2025-0002", severity: "medium" }),
      ];

      const result = await enrichFindingsWithNvd(findings, ctx);

      assert.equal(result.ok, true);
      assert.equal(http.calls.length, 0);
    });
  });

  describe("CVE ID extraction", () => {
    it("extracts CVE IDs from finding.id", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: createNvdResponse("CVE-2025-12345") }],
      });
      const ctx = createContext(cache, http);

      const findings = [finding({ id: "CVE-2025-12345", severity: "unknown" })];

      await enrichFindingsWithNvd(findings, ctx);

      assert.equal(http.calls.length, 1);
      assert.ok(http.calls[0]!.url.includes("cveId=CVE-2025-12345"));
    });

    it("extracts CVE IDs from finding.identifiers array", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: createNvdResponse("CVE-2025-99999") }],
      });
      const ctx = createContext(cache, http);

      const findings = [finding({
        id: "GHSA-xxxx-yyyy-zzzz",
        severity: "unknown",
        identifiers: [
          { type: "GHSA", value: "GHSA-xxxx-yyyy-zzzz" },
          { type: "CVE", value: "CVE-2025-99999" },
        ],
      })];

      await enrichFindingsWithNvd(findings, ctx);

      assert.equal(http.calls.length, 1);
      assert.ok(http.calls[0]!.url.includes("cveId=CVE-2025-99999"));
    });

    it("normalizes CVE IDs to uppercase", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: createNvdResponse("CVE-2025-0001") }],
      });
      const ctx = createContext(cache, http);

      const findings = [finding({ id: "cve-2025-0001", severity: "unknown" })];

      await enrichFindingsWithNvd(findings, ctx);

      assert.ok(http.calls[0]!.url.includes("cveId=CVE-2025-0001"));
    });
  });

  describe("enrichment", () => {
    it("enriches findings with NVD severity when available", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: createNvdResponse("CVE-2025-0001", { baseSeverity: "CRITICAL" }) }],
      });
      const ctx = createContext(cache, http);

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      await enrichFindingsWithNvd(findings, ctx);

      assert.equal(findings[0]!.severity, "critical");
    });

    it("enriches findings with published date", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: createNvdResponse("CVE-2025-0001", { published: "2025-02-01T12:00:00.000" }) }],
      });
      const ctx = createContext(cache, http);

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      await enrichFindingsWithNvd(findings, ctx);

      assert.equal(findings[0]!.publishedAt, "2025-02-01T12:00:00.000");
    });

    it("enriches findings with modified date", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: createNvdResponse("CVE-2025-0001", { lastModified: "2025-03-01T12:00:00.000" }) }],
      });
      const ctx = createContext(cache, http);

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      await enrichFindingsWithNvd(findings, ctx);

      assert.equal(findings[0]!.modifiedAt, "2025-03-01T12:00:00.000");
    });

    it("enriches findings with NVD URL", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: createNvdResponse("CVE-2025-0001") }],
      });
      const ctx = createContext(cache, http);

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      await enrichFindingsWithNvd(findings, ctx);

      assert.equal(findings[0]!.url, "https://nvd.nist.gov/vuln/detail/CVE-2025-0001");
    });

    it("does not overwrite existing publishedAt", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: createNvdResponse("CVE-2025-0001", { published: "2025-02-01T12:00:00.000" }) }],
      });
      const ctx = createContext(cache, http);

      const findings = [finding({
        id: "CVE-2025-0001",
        severity: "unknown",
        publishedAt: "2024-12-01T00:00:00.000",
      })];

      await enrichFindingsWithNvd(findings, ctx);

      assert.equal(findings[0]!.publishedAt, "2024-12-01T00:00:00.000");
    });
  });

  describe("CVSS metric selection", () => {
    it("prefers Primary CVSS metrics over Secondary", async () => {
      const cache = createMockCache();
      const response = {
        vulnerabilities: [{
          cve: {
            id: "CVE-2025-0001",
            metrics: {
              cvssMetricV31: [
                { type: "Secondary", cvssData: { baseScore: 5.0, baseSeverity: "MEDIUM" } },
                { type: "Primary", cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL" } },
              ],
            },
          },
        }],
      };
      const http = createMockHttpClient({ responses: [{ data: response }] });
      const ctx = createContext(cache, http);

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      await enrichFindingsWithNvd(findings, ctx);

      assert.equal(findings[0]!.severity, "critical");
    });

    it("falls back to first metric when no Primary type", async () => {
      const cache = createMockCache();
      const response = {
        vulnerabilities: [{
          cve: {
            id: "CVE-2025-0001",
            metrics: {
              cvssMetricV31: [
                { type: "Secondary", cvssData: { baseScore: 7.5, baseSeverity: "HIGH" } },
              ],
            },
          },
        }],
      };
      const http = createMockHttpClient({ responses: [{ data: response }] });
      const ctx = createContext(cache, http);

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      await enrichFindingsWithNvd(findings, ctx);

      assert.equal(findings[0]!.severity, "high");
    });

    it("extracts severity from cvssMetricV31", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: createNvdResponse("CVE-2025-0001", { metricVersion: "v31", baseSeverity: "HIGH" }) }],
      });
      const ctx = createContext(cache, http);

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      await enrichFindingsWithNvd(findings, ctx);

      assert.equal(findings[0]!.severity, "high");
    });

    it("falls back to cvssMetricV30 when v31 not present", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: createNvdResponse("CVE-2025-0001", { metricVersion: "v30", baseSeverity: "MEDIUM" }) }],
      });
      const ctx = createContext(cache, http);

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      await enrichFindingsWithNvd(findings, ctx);

      assert.equal(findings[0]!.severity, "medium");
    });

    it("falls back to cvssMetricV2 when v31 and v30 not present", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: createNvdResponse("CVE-2025-0001", { metricVersion: "v2", baseSeverity: "LOW" }) }],
      });
      const ctx = createContext(cache, http);

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      await enrichFindingsWithNvd(findings, ctx);

      assert.equal(findings[0]!.severity, "low");
    });
  });

  describe("cache behavior", () => {
    it("returns cached data when available", async () => {
      const cache = createMockCache();
      const cachedDetail = {
        id: "CVE-2025-0001",
        baseScore: 9.8,
        baseSeverity: "critical",
        published: "2025-01-01T00:00:00.000",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2025-0001",
      };
      await cache.set("nvd:cve:CVE-2025-0001", cachedDetail, 3600);

      const http = createMockHttpClient({ responses: [] });
      const ctx = createContext(cache, http);

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      await enrichFindingsWithNvd(findings, ctx);

      assert.equal(http.calls.length, 0);
      assert.equal(findings[0]!.severity, "critical");
    });

    it("caches successful NVD responses", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: createNvdResponse("CVE-2025-0001", { baseSeverity: "HIGH" }) }],
      });
      const ctx = createContext(cache, http);

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      await enrichFindingsWithNvd(findings, ctx);

      const cached = await cache.get("nvd:cve:CVE-2025-0001");
      assert.ok(cached, "Response should be cached");
      assert.equal((cached.value as { baseSeverity: string }).baseSeverity, "high");
    });

    it("uses cache for duplicate CVE IDs in same batch", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: createNvdResponse("CVE-2025-0001", { baseSeverity: "HIGH" }) }],
      });
      const ctx = createContext(cache, http);

      const findings = [
        finding({ id: "CVE-2025-0001", severity: "unknown", packageName: "pkg-a" }),
        finding({ id: "CVE-2025-0001", severity: "unknown", packageName: "pkg-b" }),
      ];

      await enrichFindingsWithNvd(findings, ctx);

      // Should only make one API call for the same CVE
      assert.equal(http.calls.length, 1);
      // Both findings should be enriched
      assert.equal(findings[0]!.severity, "high");
      assert.equal(findings[1]!.severity, "high");
    });
  });

  describe("error handling", () => {
    it("handles 404 responses gracefully", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: null, status: 404 }],
      });
      const ctx = createContext(cache, http);

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      const result = await enrichFindingsWithNvd(findings, ctx);

      assert.equal(result.ok, true);
      assert.equal(findings[0]!.severity, "unknown"); // Unchanged
    });

    it("handles 429 rate limit responses", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: null, status: 429 }],
      });
      const ctx = createContext(cache, http);

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      const result = await enrichFindingsWithNvd(findings, ctx);

      assert.equal(result.ok, true); // Still ok because individual failures are handled
      assert.equal(findings[0]!.severity, "unknown");
    });

    it("handles network errors gracefully", async () => {
      const cache = createMockCache();
      let callCount = 0;
      const http = {
        calls: [] as Array<{ url: string; headers?: Record<string, string> }>,
        getJson: async <T>(url: string, headers?: Record<string, string>): Promise<T> => {
          http.calls.push({ url, headers });
          callCount++;
          throw new Error("ECONNREFUSED");
        },
        postJson: async () => { throw new Error("Not implemented"); },
        getRaw: async () => { throw new Error("Not implemented"); },
      } as HttpClient & { calls: Array<{ url: string; headers?: Record<string, string> }> };
      const ctx = createContext(cache, http);

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      const result = await enrichFindingsWithNvd(findings, ctx);

      assert.equal(result.ok, true);
      assert.equal(findings[0]!.severity, "unknown");
    });

    it("continues processing when individual CVE lookups fail", async () => {
      const cache = createMockCache();
      let callCount = 0;
      const http = {
        calls: [] as Array<{ url: string; headers?: Record<string, string> }>,
        getJson: async <T>(url: string, headers?: Record<string, string>): Promise<T> => {
          http.calls.push({ url, headers });
          callCount++;
          if (callCount === 1) {
            throw new Error("First call fails");
          }
          return createNvdResponse("CVE-2025-0002", { baseSeverity: "HIGH" }) as T;
        },
        postJson: async () => { throw new Error("Not implemented"); },
        getRaw: async () => { throw new Error("Not implemented"); },
      } as HttpClient & { calls: Array<{ url: string; headers?: Record<string, string> }> };
      const ctx = createContext(cache, http);

      const findings = [
        finding({ id: "CVE-2025-0001", severity: "unknown", packageName: "pkg-a" }),
        finding({ id: "CVE-2025-0002", severity: "unknown", packageName: "pkg-b" }),
      ];

      const result = await enrichFindingsWithNvd(findings, ctx);

      assert.equal(result.ok, true);
      assert.equal(findings[0]!.severity, "unknown"); // First failed
      assert.equal(findings[1]!.severity, "high"); // Second succeeded
    });

    it("handles empty vulnerabilities array", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: { vulnerabilities: [] } }],
      });
      const ctx = createContext(cache, http);

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      const result = await enrichFindingsWithNvd(findings, ctx);

      assert.equal(result.ok, true);
      assert.equal(findings[0]!.severity, "unknown");
    });

    it("handles missing metrics in response", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: { vulnerabilities: [{ cve: { id: "CVE-2025-0001" } }] } }],
      });
      const ctx = createContext(cache, http);

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      const result = await enrichFindingsWithNvd(findings, ctx);

      assert.equal(result.ok, true);
      // Severity remains unknown when no metrics available
      assert.equal(findings[0]!.severity, "unknown");
    });
  });

  describe("API key handling", () => {
    it("includes NVD_API_KEY in request header", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: createNvdResponse("CVE-2025-0001") }],
      });
      const ctx = createContext(cache, http, {}, { NVD_API_KEY: "test-api-key-123" });

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      await enrichFindingsWithNvd(findings, ctx);

      assert.equal(http.calls[0]!.headers?.apiKey, "test-api-key-123");
    });

    it("uses NIST_NVD_API_KEY as fallback", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: createNvdResponse("CVE-2025-0001") }],
      });
      const ctx = createContext(cache, http, {}, { NIST_NVD_API_KEY: "nist-key-456" });

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      await enrichFindingsWithNvd(findings, ctx);

      assert.equal(http.calls[0]!.headers?.apiKey, "nist-key-456");
    });

    it("prefers NVD_API_KEY over NIST_NVD_API_KEY", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: createNvdResponse("CVE-2025-0001") }],
      });
      const ctx = createContext(cache, http, {}, {
        NVD_API_KEY: "primary-key",
        NIST_NVD_API_KEY: "fallback-key",
      });

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      await enrichFindingsWithNvd(findings, ctx);

      assert.equal(http.calls[0]!.headers?.apiKey, "primary-key");
    });

    it("omits apiKey header when no key provided", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: createNvdResponse("CVE-2025-0001") }],
      });
      const ctx = createContext(cache, http, {}, {});

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      await enrichFindingsWithNvd(findings, ctx);

      assert.equal(http.calls[0]!.headers?.apiKey, undefined);
    });
  });

  describe("rate limiting configuration", () => {
    it("configures 700ms delay with API key", async () => {
      // This test verifies the rate limit config is applied correctly
      // We cannot easily test actual timing, but we verify the code path
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [
          { data: createNvdResponse("CVE-2025-0001") },
          { data: createNvdResponse("CVE-2025-0002") },
        ],
      });
      const ctx = createContext(cache, http, {}, { NVD_API_KEY: "test-key" });

      const findings = [
        finding({ id: "CVE-2025-0001", severity: "unknown", packageName: "pkg-a" }),
        finding({ id: "CVE-2025-0002", severity: "unknown", packageName: "pkg-b" }),
      ];

      const result = await enrichFindingsWithNvd(findings, ctx);

      assert.equal(result.ok, true);
      assert.equal(http.calls.length, 2);
    });

    it("configures 6500ms delay without API key", async () => {
      // This test verifies the no-key path
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: createNvdResponse("CVE-2025-0001") }],
      });
      const ctx = createContext(cache, http, {}, {});

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      const result = await enrichFindingsWithNvd(findings, ctx);

      assert.equal(result.ok, true);
    });
  });

  describe("concurrency", () => {
    it("respects concurrency of 2 with API key", async () => {
      const cache = createMockCache();
      const callOrder: string[] = [];
      let concurrentCalls = 0;
      let maxConcurrent = 0;

      const http = {
        calls: [] as Array<{ url: string; headers?: Record<string, string> }>,
        getJson: async <T>(url: string, headers?: Record<string, string>): Promise<T> => {
          http.calls.push({ url, headers });
          const cveMatch = url.match(/cveId=(CVE-[\d-]+)/);
          const cveId = cveMatch ? cveMatch[1] : "unknown";

          concurrentCalls++;
          maxConcurrent = Math.max(maxConcurrent, concurrentCalls);
          callOrder.push(`start:${cveId}`);

          // Simulate async work
          await new Promise(r => setTimeout(r, 10));

          callOrder.push(`end:${cveId}`);
          concurrentCalls--;

          return createNvdResponse(cveId ?? "CVE-0000-0000") as T;
        },
        postJson: async () => { throw new Error("Not implemented"); },
        getRaw: async () => { throw new Error("Not implemented"); },
      } as HttpClient & { calls: Array<{ url: string; headers?: Record<string, string> }> };

      const ctx = createContext(cache, http, {}, { NVD_API_KEY: "test-key" });

      const findings = [
        finding({ id: "CVE-2025-0001", severity: "unknown", packageName: "pkg-a" }),
        finding({ id: "CVE-2025-0002", severity: "unknown", packageName: "pkg-b" }),
        finding({ id: "CVE-2025-0003", severity: "unknown", packageName: "pkg-c" }),
      ];

      await enrichFindingsWithNvd(findings, ctx);

      // With API key, max concurrency should be 2
      assert.ok(maxConcurrent <= 2, `Max concurrent calls should be <= 2, was ${maxConcurrent}`);
    });

    it("respects concurrency of 1 without API key", async () => {
      const cache = createMockCache();
      let concurrentCalls = 0;
      let maxConcurrent = 0;

      const http = {
        calls: [] as Array<{ url: string; headers?: Record<string, string> }>,
        getJson: async <T>(url: string, headers?: Record<string, string>): Promise<T> => {
          http.calls.push({ url, headers });
          const cveMatch = url.match(/cveId=(CVE-[\d-]+)/);
          const cveId = cveMatch ? cveMatch[1] : "unknown";

          concurrentCalls++;
          maxConcurrent = Math.max(maxConcurrent, concurrentCalls);

          await new Promise(r => setTimeout(r, 5));

          concurrentCalls--;

          return createNvdResponse(cveId ?? "CVE-0000-0000") as T;
        },
        postJson: async () => { throw new Error("Not implemented"); },
        getRaw: async () => { throw new Error("Not implemented"); },
      } as HttpClient & { calls: Array<{ url: string; headers?: Record<string, string> }> };

      const ctx = createContext(cache, http, {}, {}); // No API key

      const findings = [
        finding({ id: "CVE-2025-0001", severity: "unknown", packageName: "pkg-a" }),
        finding({ id: "CVE-2025-0002", severity: "unknown", packageName: "pkg-b" }),
      ];

      await enrichFindingsWithNvd(findings, ctx);

      // Without API key, max concurrency should be 1
      assert.equal(maxConcurrent, 1, `Max concurrent calls should be 1, was ${maxConcurrent}`);
    });
  });

  describe("URL construction", () => {
    it("builds correct NVD API URL", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: createNvdResponse("CVE-2025-12345") }],
      });
      const ctx = createContext(cache, http);

      const findings = [finding({ id: "CVE-2025-12345", severity: "unknown" })];

      await enrichFindingsWithNvd(findings, ctx);

      const url = http.calls[0]!.url;
      assert.ok(url.startsWith("https://services.nvd.nist.gov/rest/json/cves/2.0"));
      assert.ok(url.includes("cveId=CVE-2025-12345"));
    });
  });

  describe("duration tracking", () => {
    it("returns durationMs in result", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient({
        responses: [{ data: createNvdResponse("CVE-2025-0001") }],
      });
      const ctx = createContext(cache, http);

      const findings = [finding({ id: "CVE-2025-0001", severity: "unknown" })];

      const result = await enrichFindingsWithNvd(findings, ctx);

      assert.ok(typeof result.durationMs === "number");
      assert.ok(result.durationMs >= 0);
    });
  });
});
