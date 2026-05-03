/**
 * Tests for the EPSS (Exploit Prediction Scoring System) fetcher.
 *
 * @module utils/epss-fetcher.test
 */

import { describe, it, beforeEach, afterEach, mock } from "node:test";
import assert from "node:assert/strict";
import {
  EpssFetcher,
  enrichFindingsWithEpss,
  createEpssFetcher,
} from "../../src/utils/epss-fetcher";
import type { EpssData, VulnerabilityFinding } from "../../src/types";

/**
 * Helper: create a mock fetch that returns the given EPSS API response body.
 */
function mockEpssApi(body: unknown): ReturnType<typeof mock.fn> {
  return mock.fn(async () => {
    return {
      ok: true,
      status: 200,
      json: async () => body,
    } as Response;
  });
}

/**
 * Helper: create a mock fetch that fails with the given error.
 */
function mockFailingFetch(errorMsg: string): ReturnType<typeof mock.fn> {
  return mock.fn(async () => {
    throw new Error(errorMsg);
  });
}

/**
 * Helper: create a mock fetch that returns a non-OK status.
 */
function mockNonOkFetch(status: number, statusText: string): ReturnType<typeof mock.fn> {
  return mock.fn(async () => {
    return {
      ok: false,
      status,
      statusText,
    } as Response;
  });
}

const sampleEpssResponse = {
  data: [
    {
      cve: "CVE-2023-26159",
      epss: "0.1234",
      percentile: "0.8567",
      date: "2024-01-15",
    },
  ],
  meta: {
    apiVersion: "v2",
    timestamp: "2024-01-15T00:00:00.000Z",
  },
};

describe("EpssFetcher", () => {
  let fetcher: EpssFetcher;
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    fetcher = new EpssFetcher({ enableCache: true });
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe("constructor", () => {
    it("should create a fetcher with default options", () => {
      const defaultFetcher = new EpssFetcher();
      assert.ok(defaultFetcher instanceof EpssFetcher);
    });

    it("should create a fetcher with custom options", () => {
      const customFetcher = new EpssFetcher({
        apiUrl: "https://custom-api.example.com/epss",
        cacheTtlMs: 30 * 60 * 1000,
        timeoutMs: 5000,
      });
      assert.ok(customFetcher instanceof EpssFetcher);
    });

    it("should create a disabled fetcher", () => {
      const disabledFetcher = new EpssFetcher({ disabled: true });
      assert.ok(disabledFetcher instanceof EpssFetcher);
    });
  });

  describe("getEpss", () => {
    it("should return null when fetcher is disabled", async () => {
      const disabledFetcher = new EpssFetcher({ disabled: true });
      const result = await disabledFetcher.getEpss("CVE-2023-26159");
      assert.equal(result, null);
    });

    it("should return EPSS data when API responds successfully", async () => {
      const mockFetchFn = mockEpssApi(sampleEpssResponse);
      globalThis.fetch = mockFetchFn as typeof fetch;

      const result = await fetcher.getEpss("CVE-2023-26159");

      assert.deepEqual(result, {
        cveId: "CVE-2023-26159",
        epssScore: 0.1234,
        epssPercentile: 0.8567,
        date: "2024-01-15",
        modelVersion: "v2023.03.01",
      });

      // Verify fetch was called with correct URL
      assert.equal(mockFetchFn.mock.callCount(), 1);
      const fetchUrl = String(mockFetchFn.mock.calls[0]!.arguments[0]);
      assert.ok(fetchUrl.includes("cve=CVE-2023-26159"));
    });

    it("should return null when CVE is not found in EPSS database", async () => {
      const emptyResponse = { data: [], meta: { apiVersion: "v2", timestamp: "2024-01-15T00:00:00.000Z" } };
      globalThis.fetch = mockEpssApi(emptyResponse) as typeof fetch;

      const result = await fetcher.getEpss("CVE-9999-99999");
      assert.equal(result, null);
    });

    it("should return null when API request fails", async () => {
      globalThis.fetch = mockFailingFetch("Network error") as typeof fetch;

      const result = await fetcher.getEpss("CVE-2023-26159");
      assert.equal(result, null);
    });

    it("should return null when API returns non-OK status", async () => {
      globalThis.fetch = mockNonOkFetch(429, "Too Many Requests") as typeof fetch;

      const result = await fetcher.getEpss("CVE-2023-26159");
      assert.equal(result, null);
    });

    it("should cache results and return cached data on subsequent calls", async () => {
      const mockFetchFn = mockEpssApi(sampleEpssResponse);
      globalThis.fetch = mockFetchFn as typeof fetch;

      // First call - hits API
      const result1 = await fetcher.getEpss("CVE-2023-26159");
      assert.ok(result1);
      assert.equal(mockFetchFn.mock.callCount(), 1);

      // Second call - should use cache
      const result2 = await fetcher.getEpss("CVE-2023-26159");
      assert.deepEqual(result2, result1);
      // Should NOT have called fetch again
      assert.equal(mockFetchFn.mock.callCount(), 1);
    });

    it("should normalize EPSS scores to 0-1 range", async () => {
      const clampedResponse = {
        data: [
          {
            cve: "CVE-2023-26159",
            epss: "1.5", // Invalid - should be clamped to 1
            percentile: "-0.2", // Invalid - should be clamped to 0
            date: "2024-01-15",
          },
        ],
        meta: { apiVersion: "v2", timestamp: "2024-01-15T00:00:00.000Z" },
      };
      globalThis.fetch = mockEpssApi(clampedResponse) as typeof fetch;

      const result = await fetcher.getEpss("CVE-2023-26159");

      assert.ok(result);
      assert.equal(result.epssScore, 1.0); // Clamped to max
      assert.equal(result.epssPercentile, 0.0); // Clamped to min
    });
  });

  describe("getEpssBatch", () => {
    it("should return empty map when disabled", async () => {
      const disabledFetcher = new EpssFetcher({ disabled: true });
      const result = await disabledFetcher.getEpssBatch([
        "CVE-2023-26159",
        "CVE-2024-1234",
      ]);
      assert.equal(result.size, 0);
    });

    it("should return empty map for empty input", async () => {
      const result = await fetcher.getEpssBatch([]);
      assert.equal(result.size, 0);
    });

    it("should batch multiple CVEs in a single request", async () => {
      const batchResponse = {
        data: [
          {
            cve: "CVE-2023-26159",
            epss: "0.1234",
            percentile: "0.8567",
            date: "2024-01-15",
          },
          {
            cve: "CVE-2024-1234",
            epss: "0.5678",
            percentile: "0.9876",
            date: "2024-01-15",
          },
        ],
        meta: { apiVersion: "v2", timestamp: "2024-01-15T00:00:00.000Z" },
      };
      const mockFetchFn = mockEpssApi(batchResponse);
      globalThis.fetch = mockFetchFn as typeof fetch;

      const result = await fetcher.getEpssBatch([
        "CVE-2023-26159",
        "CVE-2024-1234",
      ]);

      assert.equal(result.size, 2);
      assert.deepEqual(result.get("CVE-2023-26159"), {
        cveId: "CVE-2023-26159",
        epssScore: 0.1234,
        epssPercentile: 0.8567,
        date: "2024-01-15",
        modelVersion: "v2023.03.01",
      });
      assert.deepEqual(result.get("CVE-2024-1234"), {
        cveId: "CVE-2024-1234",
        epssScore: 0.5678,
        epssPercentile: 0.9876,
        date: "2024-01-15",
        modelVersion: "v2023.03.01",
      });

      // Should batch into single request
      assert.equal(mockFetchFn.mock.callCount(), 1);
    });

    it("should use cached data for known CVEs", async () => {
      const mockFetchFn = mockEpssApi(sampleEpssResponse);
      globalThis.fetch = mockFetchFn as typeof fetch;

      // First, cache one CVE
      await fetcher.getEpss("CVE-2023-26159");
      assert.equal(mockFetchFn.mock.callCount(), 1);

      // Create a mock that responds to both CVEs for the batch call
      const batchResponse = {
        data: [
          { cve: "CVE-2023-26159", epss: "0.1234", percentile: "0.8567", date: "2024-01-15" },
          { cve: "CVE-2024-1234", epss: "0.5678", percentile: "0.9876", date: "2024-01-15" },
        ],
        meta: { apiVersion: "v2", timestamp: "2024-01-15T00:00:00.000Z" },
      };
      const batchMockFetchFn = mockEpssApi(batchResponse);
      globalThis.fetch = batchMockFetchFn as typeof fetch;

      // Now batch fetch both
      const batchResult = await fetcher.getEpssBatch(["CVE-2023-26159", "CVE-2024-1234"]);

      // Should only have made 1 request (for CVE-2024-1234, CVE-2023-26159 is cached)
      assert.equal(batchMockFetchFn.mock.callCount(), 1);
      // Both should be in result
      assert.ok(batchResult.has("CVE-2023-26159"));
      assert.ok(batchResult.has("CVE-2024-1234"));
    });
  });

  describe("cache management", () => {
    it("should track cache size", async () => {
      globalThis.fetch = mockEpssApi(sampleEpssResponse) as typeof fetch;

      assert.equal(fetcher.cacheSize, 0);

      await fetcher.getEpss("CVE-2023-26159");
      assert.equal(fetcher.cacheSize, 1);

      // Fetch another CVE
      const secondResponse = {
        data: [{ cve: "CVE-2024-1234", epss: "0.5", percentile: "0.9", date: "2024-01-15" }],
        meta: { apiVersion: "v2", timestamp: "2024-01-15T00:00:00.000Z" },
      };
      globalThis.fetch = mockEpssApi(secondResponse) as typeof fetch;
      await fetcher.getEpss("CVE-2024-1234");
      assert.equal(fetcher.cacheSize, 2);
    });

    it("should clear cache", async () => {
      globalThis.fetch = mockEpssApi(sampleEpssResponse) as typeof fetch;

      await fetcher.getEpss("CVE-2023-26159");
      assert.equal(fetcher.cacheSize, 1);

      fetcher.clearCache();
      assert.equal(fetcher.cacheSize, 0);
    });

    it("should return cached CVE IDs", async () => {
      globalThis.fetch = mockEpssApi(sampleEpssResponse) as typeof fetch;

      await fetcher.getEpss("CVE-2023-26159");

      const secondResponse = {
        data: [{ cve: "CVE-2024-1234", epss: "0.5", percentile: "0.9", date: "2024-01-15" }],
        meta: { apiVersion: "v2", timestamp: "2024-01-15T00:00:00.000Z" },
      };
      globalThis.fetch = mockEpssApi(secondResponse) as typeof fetch;
      await fetcher.getEpss("CVE-2024-1234");

      const cachedIds = fetcher.getCachedCveIds();
      assert.ok(cachedIds.includes("CVE-2023-26159"));
      assert.ok(cachedIds.includes("CVE-2024-1234"));
    });
  });

  describe("error handling", () => {
    it("should handle network timeout gracefully", async () => {
      globalThis.fetch = mock.fn(async () => {
        const abortError: any = new Error("The operation was aborted");
        abortError.name = "AbortError";
        throw abortError;
      }) as typeof fetch;

      const result = await fetcher.getEpss("CVE-2023-26159");
      assert.equal(result, null);
    });

    it("should handle invalid JSON response gracefully", async () => {
      globalThis.fetch = mock.fn(async () => {
        return {
          ok: true,
          status: 200,
          json: async () => { throw new Error("Invalid JSON"); },
        } as Response;
      }) as typeof fetch;

      const result = await fetcher.getEpss("CVE-2023-26159");
      assert.equal(result, null);
    });

    it("should handle malformed EPSS data gracefully", async () => {
      const malformedResponse = {
        data: [
          {
            cve: "CVE-2023-26159",
            epss: "not-a-number",
            percentile: "also-not-a-number",
            date: "2024-01-15",
          },
        ],
        meta: { apiVersion: "v2", timestamp: "2024-01-15T00:00:00.000Z" },
      };
      globalThis.fetch = mockEpssApi(malformedResponse) as typeof fetch;

      const result = await fetcher.getEpss("CVE-2023-26159");
      assert.equal(result, null);
    });
  });
});

describe("enrichFindingsWithEpss", () => {
  let fetcher: EpssFetcher;
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    fetcher = new EpssFetcher({ enableCache: true });
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("should return findings unchanged when no CVE IDs found", async () => {
    const findings: VulnerabilityFinding[] = [
      {
        id: "GHSA-1234-5678",
        source: "github",
        packageName: "test-package",
        packageVersion: "1.0.0",
        severity: "medium",
        identifiers: [{ type: "GHSA", value: "GHSA-1234-5678" }],
      },
    ];

    const result = await enrichFindingsWithEpss(findings, fetcher);
    assert.deepEqual(result, findings);
  });

  it("should enrich findings with EPSS data", async () => {
    const findings: VulnerabilityFinding[] = [
      {
        id: "GHSA-1234-5678",
        source: "github",
        packageName: "test-package",
        packageVersion: "1.0.0",
        severity: "medium",
        identifiers: [{ type: "CVE", value: "CVE-2023-26159" }],
      },
    ];

    const mockResponse = {
      data: [
        {
          cve: "CVE-2023-26159",
          epss: "0.4567",
          percentile: "0.9876",
          date: "2024-01-15",
        },
      ],
      meta: { apiVersion: "v2", timestamp: "2024-01-15T00:00:00.000Z" },
    };

    globalThis.fetch = mockEpssApi(mockResponse) as typeof fetch;

    const result = await enrichFindingsWithEpss(findings, fetcher);

    assert.deepEqual(result[0]!.epss, {
      cveId: "CVE-2023-26159",
      epssScore: 0.4567,
      epssPercentile: 0.9876,
      date: "2024-01-15",
      modelVersion: "v2023.03.01",
    });
  });

  it("should handle findings with CVE IDs in the finding.id field", async () => {
    const findings: VulnerabilityFinding[] = [
      {
        id: "CVE-2023-26159",
        source: "nvd",
        packageName: "test-package",
        packageVersion: "1.0.0",
        severity: "high",
      },
    ];

    const mockResponse = {
      data: [
        {
          cve: "CVE-2023-26159",
          epss: "0.7890",
          percentile: "0.9999",
          date: "2024-01-15",
        },
      ],
      meta: { apiVersion: "v2", timestamp: "2024-01-15T00:00:00.000Z" },
    };

    globalThis.fetch = mockEpssApi(mockResponse) as typeof fetch;

    const result = await enrichFindingsWithEpss(findings, fetcher);

    assert.ok(result[0]!.epss);
    assert.equal(result[0]!.epss!.cveId, "CVE-2023-26159");
  });

  it("should not modify findings without EPSS data available", async () => {
    const findings: VulnerabilityFinding[] = [
      {
        id: "GHSA-1234-5678",
        source: "github",
        packageName: "test-package",
        packageVersion: "1.0.0",
        severity: "medium",
        identifiers: [{ type: "CVE", value: "CVE-9999-99999" }],
      },
    ];

    const emptyResponse = { data: [], meta: { apiVersion: "v2", timestamp: "2024-01-15T00:00:00.000Z" } };
    globalThis.fetch = mockEpssApi(emptyResponse) as typeof fetch;

    const result = await enrichFindingsWithEpss(findings, fetcher);
    assert.equal(result[0]!.epss, undefined);
  });

  it("should handle multiple findings with mixed CVE availability", async () => {
    const findings: VulnerabilityFinding[] = [
      {
        id: "GHSA-0001",
        source: "github",
        packageName: "pkg-a",
        packageVersion: "1.0.0",
        severity: "high",
        identifiers: [{ type: "CVE", value: "CVE-2023-26159" }],
      },
      {
        id: "GHSA-0002",
        source: "github",
        packageName: "pkg-b",
        packageVersion: "2.0.0",
        severity: "low",
        identifiers: [{ type: "CVE", value: "CVE-9999-0000" }],
      },
    ];

    const partialResponse = {
      data: [
        {
          cve: "CVE-2023-26159",
          epss: "0.75",
          percentile: "0.95",
          date: "2024-01-15",
        },
        // CVE-9999-0000 not in response
      ],
      meta: { apiVersion: "v2", timestamp: "2024-01-15T00:00:00.000Z" },
    };

    globalThis.fetch = mockEpssApi(partialResponse) as typeof fetch;

    const result = await enrichFindingsWithEpss(findings, fetcher);

    // First finding should have EPSS data
    assert.ok(result[0]!.epss);
    assert.equal(result[0]!.epss!.cveId, "CVE-2023-26159");

    // Second finding should NOT have EPSS data
    assert.equal(result[1]!.epss, undefined);
  });
});

describe("createEpssFetcher", () => {
  it("should create an EPSS fetcher instance", () => {
    const fetcher = createEpssFetcher();
    assert.ok(fetcher instanceof EpssFetcher);
  });

  it("should create an EPSS fetcher with custom options", () => {
    const fetcher = createEpssFetcher({
      disabled: true,
      cacheTtlMs: 60000,
    });
    assert.ok(fetcher instanceof EpssFetcher);
  });
});
