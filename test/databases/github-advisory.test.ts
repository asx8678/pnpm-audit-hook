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

  describe("isEnabled", () => {
    it("returns true when enabled in config", () => {
      const cfg = baseConfig();
      assert.equal(source.isEnabled(cfg, {}), true);
    });

    it("returns false when disabled in config", () => {
      const cfg = baseConfig();
      cfg.sources.github.enabled = false;
      assert.equal(source.isEnabled(cfg, {}), false);
    });

    it("returns false when PNPM_AUDIT_DISABLE_GITHUB env is true", () => {
      const cfg = baseConfig();
      assert.equal(source.isEnabled(cfg, { PNPM_AUDIT_DISABLE_GITHUB: "true" }), false);
    });
  });

  describe("pagination", () => {
    it("stops pagination when data.length < 100", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([
        { data: Array(50).fill(createGitHubAdvisory("pkg", "1.0.0")) },
      ]);
      const ctx = createContext(cache, http);

      await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(http.calls.length, 1, "Should only make one API call when results < 100");
    });

    it("continues pagination when data.length === 100", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([
        { data: Array(100).fill(createGitHubAdvisory("pkg", "1.0.0")) },
        { data: Array(50).fill(createGitHubAdvisory("pkg", "1.0.0")) },
      ]);
      const ctx = createContext(cache, http);

      await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(http.calls.length, 2, "Should make two API calls when first response has 100 items");
      assert.ok(http.calls[0]!.includes("page=1"));
      assert.ok(http.calls[1]!.includes("page=2"));
    });

    it("stops pagination when data is empty", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([
        { data: [] },
      ]);
      const ctx = createContext(cache, http);

      await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(http.calls.length, 1);
    });
  });

  describe("version range filtering", () => {
    it("includes packages within vulnerable range", async () => {
      const cache = createMockCache();
      const advisory = createGitHubAdvisory("lodash", "4.17.0", {
        vulnerable_version_range: "<4.17.21",
      });
      const http = createMockHttpClient([{ data: [advisory] }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "lodash", version: "4.17.0" }], ctx);

      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0]!.packageName, "lodash");
    });

    it("excludes packages outside vulnerable range", async () => {
      const cache = createMockCache();
      const advisory = createGitHubAdvisory("lodash", "4.17.0", {
        vulnerable_version_range: "<4.17.0",
      });
      const http = createMockHttpClient([{ data: [advisory] }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "lodash", version: "4.17.21" }], ctx);

      assert.equal(result.findings.length, 0);
    });

    it("includes packages when no range specified", async () => {
      const cache = createMockCache();
      const advisory = createGitHubAdvisory("lodash", "4.17.0", {
        vulnerable_version_range: undefined,
      });
      const http = createMockHttpClient([{ data: [advisory] }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "lodash", version: "4.17.0" }], ctx);

      assert.equal(result.findings.length, 1);
    });
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

  describe("per-package querying", () => {
    it("queries each package individually", async () => {
      const cache = createMockCache();
      const packages = Array.from({ length: 15 }, (_, i) => ({
        name: `pkg-${i}`,
        version: "1.0.0",
      }));

      const http = createMockHttpClient(
        packages.map(() => ({ data: [] }))
      );
      const ctx = createContext(cache, http);

      await source.query(packages, ctx);

      assert.equal(http.calls.length, 15, "Should query each package individually");
    });

    it("each request has single affects param", async () => {
      const cache = createMockCache();
      const packages = [
        { name: "pkg-a", version: "1.0.0" },
        { name: "pkg-b", version: "2.0.0" },
        { name: "pkg-c", version: "3.0.0" },
      ];

      const http = createMockHttpClient([{ data: [] }, { data: [] }, { data: [] }]);
      const ctx = createContext(cache, http);

      await source.query(packages, ctx);

      // Each call should have exactly one affects param
      assert.ok(http.calls[0]!.includes("affects=pkg-a%401.0.0"));
      assert.ok(http.calls[1]!.includes("affects=pkg-b%402.0.0"));
      assert.ok(http.calls[2]!.includes("affects=pkg-c%403.0.0"));
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
      const packages = [
        { name: "pkg-a", version: "1.0.0" },
        { name: "pkg-b", version: "2.0.0" },
      ];

      let callCount = 0;
      const http = {
        calls: [] as string[],
        getJson: async () => { throw new Error("Not implemented"); },
        postJson: async () => { throw new Error("Not implemented"); },
        getRaw: async (url: string) => {
          http.calls.push(url);
          callCount++;
          if (callCount === 1) {
            return { json: async () => [], ok: true, status: 200 } as Response;
          }
          throw new Error("Network error");
        },
      } as HttpClient & { calls: string[] };

      const ctx = createContext(cache, http);

      const result = await source.query(packages, ctx);

      assert.equal(result.ok, false);
      assert.ok(result.error?.includes("Partial failure"));
    });

    it("handles invalid JSON response", async () => {
      const cache = createMockCache();
      const http = {
        calls: [] as string[],
        getJson: async () => { throw new Error("Not implemented"); },
        postJson: async () => { throw new Error("Not implemented"); },
        getRaw: async (url: string) => {
          http.calls.push(url);
          return {
            json: async () => { throw new SyntaxError("Unexpected token"); },
            ok: true,
            status: 200,
          } as unknown as Response;
        },
      } as HttpClient & { calls: string[] };

      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.ok, false);
      assert.ok(result.error?.includes("invalid JSON"));
    });

    it("handles non-array response", async () => {
      const cache = createMockCache();
      const http = createMockHttpClient([{ data: { message: "API rate limit exceeded" } }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.ok, false);
      assert.ok(result.error?.includes("rate limit"));
    });
  });

  describe("response parsing", () => {
    it("extracts CVE id from advisory", async () => {
      const cache = createMockCache();
      const advisory = createGitHubAdvisory("pkg", "1.0.0", {
        cve_id: "CVE-2025-12345",
        ghsa_id: "GHSA-xxxx-xxxx-xxxx",
      });
      const http = createMockHttpClient([{ data: [advisory] }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings[0]!.id, "CVE-2025-12345");
    });

    it("falls back to GHSA id when no CVE", async () => {
      const cache = createMockCache();
      const advisory = createGitHubAdvisory("pkg", "1.0.0", {
        cve_id: null,
        ghsa_id: "GHSA-abcd-efgh-ijkl",
      });
      const http = createMockHttpClient([{ data: [advisory] }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings[0]!.id, "GHSA-ABCD-EFGH-IJKL");
    });

    it("extracts fixed version from first_patched_version object", async () => {
      const cache = createMockCache();
      const advisory = createGitHubAdvisory("pkg", "1.0.0", {
        first_patched_version: { identifier: "2.0.0" },
      });
      const http = createMockHttpClient([{ data: [advisory] }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings[0]!.fixedVersion, "2.0.0");
    });

    it("extracts fixed version from first_patched_version string", async () => {
      const cache = createMockCache();
      const advisory = createGitHubAdvisory("pkg", "1.0.0", {
        first_patched_version: "3.0.0",
      });
      const http = createMockHttpClient([{ data: [advisory] }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings[0]!.fixedVersion, "3.0.0");
    });

    it("deduplicates findings within same batch", async () => {
      const cache = createMockCache();
      const advisory1 = createGitHubAdvisory("pkg", "1.0.0", { cve_id: "CVE-2025-0001" });
      const advisory2 = createGitHubAdvisory("pkg", "1.0.0", { cve_id: "CVE-2025-0001" });
      const http = createMockHttpClient([{ data: [advisory1, advisory2] }]);
      const ctx = createContext(cache, http);

      const result = await source.query([{ name: "pkg", version: "1.0.0" }], ctx);

      assert.equal(result.findings.length, 1);
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
