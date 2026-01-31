import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import type { VulnerabilityFinding, PackageRef, AuditConfig } from "../../src/types";
import type {
  StaticVulnerability,
  StaticDbQueryResult,
} from "../../src/static-db/types";
import { satisfies } from "../../src/utils/semver";

/**
 * Mock StaticDbReader for testing hybrid lookup.
 */
interface MockStaticDbReader {
  isReady(): boolean;
  getCutoffDate(): string;
  findVulnerabilities(
    packageName: string,
    version: string
  ): Promise<StaticDbQueryResult>;
}

/**
 * Mock API source for testing hybrid lookup.
 */
interface MockApiSource {
  query(
    packages: PackageRef[],
    publishedAfter?: string
  ): Promise<{ findings: VulnerabilityFinding[]; ok: boolean }>;
}

/**
 * Hybrid lookup that combines static DB and live API results.
 * This is a test implementation showing the expected behavior.
 */
class HybridLookup {
  constructor(
    private staticDb: MockStaticDbReader | null,
    private apiSource: MockApiSource
  ) {}

  /**
   * Query vulnerabilities for packages using hybrid approach:
   * 1. If static DB available: get historical vulns from static DB
   * 2. Query API for vulns published after cutoff date
   * 3. Deduplicate overlapping results
   */
  async query(packages: PackageRef[]): Promise<{
    findings: VulnerabilityFinding[];
    sources: { staticDb: boolean; api: boolean };
  }> {
    const allFindings: VulnerabilityFinding[] = [];
    let usedStaticDb = false;
    let usedApi = false;

    // Get static DB results if available
    if (this.staticDb?.isReady()) {
      usedStaticDb = true;
      const cutoffDate = this.staticDb.getCutoffDate();

      for (const pkg of packages) {
        const result = await this.staticDb.findVulnerabilities(pkg.name, pkg.version);
        if (result.found) {
          // Convert StaticVulnerability to VulnerabilityFinding
          for (const vuln of result.vulnerabilities) {
            allFindings.push(this.staticVulnToFinding(vuln, pkg.version));
          }
        }
      }

      // Query API only for vulns after cutoff
      const apiResult = await this.apiSource.query(packages, cutoffDate);
      if (apiResult.ok) {
        usedApi = true;
        allFindings.push(...apiResult.findings);
      }
    } else {
      // No static DB - query API for all vulns
      const apiResult = await this.apiSource.query(packages);
      if (apiResult.ok) {
        usedApi = true;
        allFindings.push(...apiResult.findings);
      }
    }

    // Deduplicate
    const deduped = this.deduplicateFindings(allFindings);

    return {
      findings: deduped,
      sources: { staticDb: usedStaticDb, api: usedApi },
    };
  }

  private staticVulnToFinding(
    vuln: StaticVulnerability,
    version: string
  ): VulnerabilityFinding {
    return {
      id: vuln.id,
      source: vuln.source,
      packageName: vuln.packageName,
      packageVersion: version,
      severity: vuln.severity,
      title: vuln.title,
      url: vuln.url,
      publishedAt: vuln.publishedAt,
      modifiedAt: vuln.modifiedAt,
      identifiers: vuln.identifiers,
      affectedRange: vuln.affectedVersions.map((av) => av.range).join(" || "),
      fixedVersion: vuln.affectedVersions[0]?.fixed,
    };
  }

  /**
   * Deduplicate findings by (packageName, packageVersion, id).
   * Prefers findings with more data (e.g., from API over static).
   */
  private deduplicateFindings(findings: VulnerabilityFinding[]): VulnerabilityFinding[] {
    const seen = new Map<string, VulnerabilityFinding>();

    for (const finding of findings) {
      const key = `${finding.packageName}@${finding.packageVersion}:${finding.id}`;
      const existing = seen.get(key);

      if (!existing) {
        seen.set(key, finding);
      } else {
        // Prefer finding with more data
        if (this.hasMoreData(finding, existing)) {
          seen.set(key, finding);
        }
      }
    }

    return [...seen.values()];
  }

  private hasMoreData(a: VulnerabilityFinding, b: VulnerabilityFinding): boolean {
    // Count non-null fields
    const countFields = (f: VulnerabilityFinding) =>
      [f.title, f.url, f.description, f.publishedAt, f.fixedVersion, f.identifiers].filter(
        Boolean
      ).length;
    return countFields(a) > countFields(b);
  }
}

// ============================================================================
// Test Fixtures
// ============================================================================

function createStaticVuln(overrides: Partial<StaticVulnerability> = {}): StaticVulnerability {
  return {
    id: "CVE-2024-0001",
    packageName: "test-pkg",
    severity: "high",
    publishedAt: "2024-06-01T00:00:00Z",
    affectedVersions: [{ range: ">=1.0.0 <2.0.0", fixed: "2.0.0" }],
    source: "github",
    title: "Test vulnerability",
    ...overrides,
  };
}

function createFinding(overrides: Partial<VulnerabilityFinding> = {}): VulnerabilityFinding {
  return {
    id: "CVE-2025-0001",
    source: "github",
    packageName: "test-pkg",
    packageVersion: "1.0.0",
    severity: "high",
    ...overrides,
  };
}

// ============================================================================
// Tests
// ============================================================================

describe("HybridLookup", () => {
  describe("hybrid query flow", () => {
    it("uses static DB for historical vulns and API for recent vulns", async () => {
      const staticVuln = createStaticVuln({
        id: "CVE-2024-STATIC",
        packageName: "lodash",
        publishedAt: "2024-06-01T00:00:00Z",
      });

      const apiVuln = createFinding({
        id: "CVE-2025-API",
        packageName: "lodash",
        packageVersion: "4.17.0",
        publishedAt: "2025-01-15T00:00:00Z",
      });

      const mockStaticDb: MockStaticDbReader = {
        isReady: () => true,
        getCutoffDate: () => "2025-01-01T00:00:00Z",
        findVulnerabilities: async (name, version) => {
          if (name === "lodash" && satisfies(version, ">=1.0.0 <2.0.0")) {
            return { vulnerabilities: [staticVuln], found: true, durationMs: 1 };
          }
          return { vulnerabilities: [], found: true, durationMs: 1 };
        },
      };

      const mockApi: MockApiSource = {
        query: async (packages, publishedAfter) => {
          // API should only be queried for vulns after cutoff
          assert.equal(publishedAfter, "2025-01-01T00:00:00Z");
          return { findings: [apiVuln], ok: true };
        },
      };

      const hybrid = new HybridLookup(mockStaticDb, mockApi);
      const result = await hybrid.query([{ name: "lodash", version: "1.5.0" }]);

      assert.equal(result.sources.staticDb, true);
      assert.equal(result.sources.api, true);
      assert.equal(result.findings.length, 2);
      assert.ok(result.findings.some((f) => f.id === "CVE-2024-STATIC"));
      assert.ok(result.findings.some((f) => f.id === "CVE-2025-API"));
    });

    it("only uses API when static DB unavailable", async () => {
      const apiVuln = createFinding({ id: "CVE-2025-API" });

      let apiCalledWithDate: string | undefined;
      const mockApi: MockApiSource = {
        query: async (packages, publishedAfter) => {
          apiCalledWithDate = publishedAfter;
          return { findings: [apiVuln], ok: true };
        },
      };

      const hybrid = new HybridLookup(null, mockApi);
      const result = await hybrid.query([{ name: "test-pkg", version: "1.0.0" }]);

      assert.equal(result.sources.staticDb, false);
      assert.equal(result.sources.api, true);
      assert.equal(apiCalledWithDate, undefined); // No date filter when no static DB
      assert.equal(result.findings.length, 1);
    });

    it("only uses API when static DB not ready", async () => {
      const mockStaticDb: MockStaticDbReader = {
        isReady: () => false,
        getCutoffDate: () => "2025-01-01T00:00:00Z",
        findVulnerabilities: async () => {
          throw new Error("Should not be called");
        },
      };

      const mockApi: MockApiSource = {
        query: async () => ({ findings: [createFinding()], ok: true }),
      };

      const hybrid = new HybridLookup(mockStaticDb, mockApi);
      const result = await hybrid.query([{ name: "test-pkg", version: "1.0.0" }]);

      assert.equal(result.sources.staticDb, false);
      assert.equal(result.sources.api, true);
    });
  });

  describe("deduplication of overlapping results", () => {
    it("deduplicates identical vulns from static and API", async () => {
      // Create a minimal static vuln (no title)
      const staticVuln: StaticVulnerability = {
        id: "CVE-2024-OVERLAP",
        packageName: "lodash",
        severity: "high",
        publishedAt: "2024-06-01T00:00:00Z",
        affectedVersions: [{ range: ">=1.0.0 <2.0.0" }], // No fixed version
        source: "github",
        // No title, no url
      };

      // API vuln has more data: title, description, url, publishedAt, fixedVersion
      const apiVuln = createFinding({
        id: "CVE-2024-OVERLAP",
        packageName: "lodash",
        packageVersion: "1.5.0",
        title: "API title",
        description: "More detailed description",
        url: "https://example.com",
        publishedAt: "2024-06-01T00:00:00Z",
        fixedVersion: "2.0.0",
      });

      const mockStaticDb: MockStaticDbReader = {
        isReady: () => true,
        getCutoffDate: () => "2025-01-01T00:00:00Z",
        findVulnerabilities: async () => ({
          vulnerabilities: [staticVuln],
          found: true,
          durationMs: 1,
        }),
      };

      const mockApi: MockApiSource = {
        query: async () => ({ findings: [apiVuln], ok: true }),
      };

      const hybrid = new HybridLookup(mockStaticDb, mockApi);
      const result = await hybrid.query([{ name: "lodash", version: "1.5.0" }]);

      // Should have only one finding after deduplication
      assert.equal(result.findings.length, 1);
      // Should prefer the one with more data (API version has more non-null fields)
      assert.equal(result.findings[0]!.title, "API title");
    });

    it("keeps distinct vulns from both sources", async () => {
      const staticVuln1 = createStaticVuln({ id: "CVE-2024-STATIC-1" });
      const staticVuln2 = createStaticVuln({ id: "CVE-2024-STATIC-2" });

      const apiVuln = createFinding({ id: "CVE-2025-API-1" });

      const mockStaticDb: MockStaticDbReader = {
        isReady: () => true,
        getCutoffDate: () => "2025-01-01T00:00:00Z",
        findVulnerabilities: async () => ({
          vulnerabilities: [staticVuln1, staticVuln2],
          found: true,
          durationMs: 1,
        }),
      };

      const mockApi: MockApiSource = {
        query: async () => ({ findings: [apiVuln], ok: true }),
      };

      const hybrid = new HybridLookup(mockStaticDb, mockApi);
      const result = await hybrid.query([{ name: "test-pkg", version: "1.5.0" }]);

      assert.equal(result.findings.length, 3);
    });

    it("deduplicates by package+version+id combination", async () => {
      // Same CVE affecting different versions should NOT be deduplicated
      const staticVuln = createStaticVuln({
        id: "CVE-2024-SAME",
        packageName: "lodash",
      });

      const mockStaticDb: MockStaticDbReader = {
        isReady: () => true,
        getCutoffDate: () => "2025-01-01T00:00:00Z",
        findVulnerabilities: async (name, version) => ({
          vulnerabilities: [staticVuln],
          found: true,
          durationMs: 1,
        }),
      };

      const mockApi: MockApiSource = {
        query: async () => ({ findings: [], ok: true }),
      };

      const hybrid = new HybridLookup(mockStaticDb, mockApi);
      const result = await hybrid.query([
        { name: "lodash", version: "1.0.0" },
        { name: "lodash", version: "1.5.0" },
      ]);

      // Each version should have its own finding
      assert.equal(result.findings.length, 2);
      assert.ok(result.findings.some((f) => f.packageVersion === "1.0.0"));
      assert.ok(result.findings.some((f) => f.packageVersion === "1.5.0"));
    });
  });

  describe("fallback when static DB unavailable", () => {
    it("returns API results when static DB fails to load", async () => {
      const mockStaticDb: MockStaticDbReader = {
        isReady: () => false,
        getCutoffDate: () => "",
        findVulnerabilities: async () => {
          throw new Error("DB not loaded");
        },
      };

      const apiVuln = createFinding({ id: "CVE-2025-FALLBACK" });
      const mockApi: MockApiSource = {
        query: async () => ({ findings: [apiVuln], ok: true }),
      };

      const hybrid = new HybridLookup(mockStaticDb, mockApi);
      const result = await hybrid.query([{ name: "test-pkg", version: "1.0.0" }]);

      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0]!.id, "CVE-2025-FALLBACK");
    });

    it("queries full API range when static DB unavailable", async () => {
      let apiReceivedPublishedAfter: string | undefined;

      const mockApi: MockApiSource = {
        query: async (packages, publishedAfter) => {
          apiReceivedPublishedAfter = publishedAfter;
          return { findings: [], ok: true };
        },
      };

      const hybrid = new HybridLookup(null, mockApi);
      await hybrid.query([{ name: "test-pkg", version: "1.0.0" }]);

      // Should query without date filter
      assert.equal(apiReceivedPublishedAfter, undefined);
    });
  });

  describe("date filtering (only fetch after cutoff)", () => {
    it("passes cutoff date to API query", async () => {
      let apiReceivedPublishedAfter: string | undefined;

      const mockStaticDb: MockStaticDbReader = {
        isReady: () => true,
        getCutoffDate: () => "2025-01-15T00:00:00Z",
        findVulnerabilities: async () => ({
          vulnerabilities: [],
          found: true,
          durationMs: 1,
        }),
      };

      const mockApi: MockApiSource = {
        query: async (packages, publishedAfter) => {
          apiReceivedPublishedAfter = publishedAfter;
          return { findings: [], ok: true };
        },
      };

      const hybrid = new HybridLookup(mockStaticDb, mockApi);
      await hybrid.query([{ name: "test-pkg", version: "1.0.0" }]);

      assert.equal(apiReceivedPublishedAfter, "2025-01-15T00:00:00Z");
    });

    it("static DB filters out vulns after cutoff automatically", async () => {
      const oldVuln = createStaticVuln({
        id: "CVE-2024-OLD",
        publishedAt: "2024-06-01T00:00:00Z",
      });

      // This shouldn't be in static DB, but if it were...
      const newVuln = createStaticVuln({
        id: "CVE-2025-NEW",
        publishedAt: "2025-02-01T00:00:00Z",
      });

      const mockStaticDb: MockStaticDbReader = {
        isReady: () => true,
        getCutoffDate: () => "2025-01-01T00:00:00Z",
        findVulnerabilities: async () => ({
          // Static DB should only contain vulns before cutoff
          vulnerabilities: [oldVuln],
          found: true,
          durationMs: 1,
        }),
      };

      const mockApi: MockApiSource = {
        query: async () => ({ findings: [], ok: true }),
      };

      const hybrid = new HybridLookup(mockStaticDb, mockApi);
      const result = await hybrid.query([{ name: "test-pkg", version: "1.5.0" }]);

      // Should only have old vuln from static DB
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0]!.id, "CVE-2024-OLD");
    });
  });

  describe("package scenarios", () => {
    it("handles package in static DB only", async () => {
      const staticVuln = createStaticVuln({ id: "CVE-2024-STATIC-ONLY" });

      const mockStaticDb: MockStaticDbReader = {
        isReady: () => true,
        getCutoffDate: () => "2025-01-01T00:00:00Z",
        findVulnerabilities: async () => ({
          vulnerabilities: [staticVuln],
          found: true,
          durationMs: 1,
        }),
      };

      const mockApi: MockApiSource = {
        query: async () => ({ findings: [], ok: true }),
      };

      const hybrid = new HybridLookup(mockStaticDb, mockApi);
      const result = await hybrid.query([{ name: "legacy-pkg", version: "1.0.0" }]);

      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0]!.id, "CVE-2024-STATIC-ONLY");
    });

    it("handles package in API only", async () => {
      const mockStaticDb: MockStaticDbReader = {
        isReady: () => true,
        getCutoffDate: () => "2025-01-01T00:00:00Z",
        findVulnerabilities: async () => ({
          vulnerabilities: [],
          found: false, // Not in static DB
          durationMs: 1,
        }),
      };

      const apiVuln = createFinding({ id: "CVE-2025-API-ONLY" });
      const mockApi: MockApiSource = {
        query: async () => ({ findings: [apiVuln], ok: true }),
      };

      const hybrid = new HybridLookup(mockStaticDb, mockApi);
      const result = await hybrid.query([{ name: "new-pkg", version: "1.0.0" }]);

      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0]!.id, "CVE-2025-API-ONLY");
    });

    it("handles package in both sources", async () => {
      const staticVuln = createStaticVuln({
        id: "CVE-2024-BOTH-STATIC",
        packageName: "popular-pkg",
      });

      const apiVuln = createFinding({
        id: "CVE-2025-BOTH-API",
        packageName: "popular-pkg",
      });

      const mockStaticDb: MockStaticDbReader = {
        isReady: () => true,
        getCutoffDate: () => "2025-01-01T00:00:00Z",
        findVulnerabilities: async () => ({
          vulnerabilities: [staticVuln],
          found: true,
          durationMs: 1,
        }),
      };

      const mockApi: MockApiSource = {
        query: async () => ({ findings: [apiVuln], ok: true }),
      };

      const hybrid = new HybridLookup(mockStaticDb, mockApi);
      const result = await hybrid.query([{ name: "popular-pkg", version: "1.5.0" }]);

      assert.equal(result.findings.length, 2);
      assert.ok(result.findings.some((f) => f.id === "CVE-2024-BOTH-STATIC"));
      assert.ok(result.findings.some((f) => f.id === "CVE-2025-BOTH-API"));
    });

    it("handles package with no vulnerabilities", async () => {
      const mockStaticDb: MockStaticDbReader = {
        isReady: () => true,
        getCutoffDate: () => "2025-01-01T00:00:00Z",
        findVulnerabilities: async () => ({
          vulnerabilities: [],
          found: false,
          durationMs: 1,
        }),
      };

      const mockApi: MockApiSource = {
        query: async () => ({ findings: [], ok: true }),
      };

      const hybrid = new HybridLookup(mockStaticDb, mockApi);
      const result = await hybrid.query([{ name: "safe-pkg", version: "1.0.0" }]);

      assert.equal(result.findings.length, 0);
      assert.equal(result.sources.staticDb, true);
      assert.equal(result.sources.api, true);
    });
  });

  describe("version matching edge cases", () => {
    it("handles prerelease versions", async () => {
      const staticVuln = createStaticVuln({
        id: "CVE-2024-PRERELEASE",
        affectedVersions: [{ range: ">=1.0.0-alpha <1.0.0", fixed: "1.0.0" }],
      });

      const mockStaticDb: MockStaticDbReader = {
        isReady: () => true,
        getCutoffDate: () => "2025-01-01T00:00:00Z",
        findVulnerabilities: async (name, version) => {
          if (satisfies(version, ">=1.0.0-alpha <1.0.0")) {
            return { vulnerabilities: [staticVuln], found: true, durationMs: 1 };
          }
          return { vulnerabilities: [], found: true, durationMs: 1 };
        },
      };

      const mockApi: MockApiSource = {
        query: async () => ({ findings: [], ok: true }),
      };

      const hybrid = new HybridLookup(mockStaticDb, mockApi);
      const result = await hybrid.query([{ name: "test-pkg", version: "1.0.0-beta.1" }]);

      assert.equal(result.findings.length, 1);
    });

    it("handles versions with build metadata", async () => {
      const staticVuln = createStaticVuln({
        id: "CVE-2024-BUILD",
        affectedVersions: [{ range: ">=1.0.0 <2.0.0" }],
      });

      const mockStaticDb: MockStaticDbReader = {
        isReady: () => true,
        getCutoffDate: () => "2025-01-01T00:00:00Z",
        findVulnerabilities: async (name, version) => {
          // Semver ignores build metadata for comparison
          const cleanVersion = version.split("+")[0]!;
          if (satisfies(cleanVersion, ">=1.0.0 <2.0.0")) {
            return { vulnerabilities: [staticVuln], found: true, durationMs: 1 };
          }
          return { vulnerabilities: [], found: true, durationMs: 1 };
        },
      };

      const mockApi: MockApiSource = {
        query: async () => ({ findings: [], ok: true }),
      };

      const hybrid = new HybridLookup(mockStaticDb, mockApi);
      const result = await hybrid.query([{ name: "test-pkg", version: "1.5.0+build.123" }]);

      assert.equal(result.findings.length, 1);
    });

    it("handles wildcard version ranges", async () => {
      const staticVuln = createStaticVuln({
        id: "CVE-2024-WILDCARD",
        affectedVersions: [{ range: "1.x" }],
      });

      const mockStaticDb: MockStaticDbReader = {
        isReady: () => true,
        getCutoffDate: () => "2025-01-01T00:00:00Z",
        findVulnerabilities: async (name, version) => {
          if (satisfies(version, "1.x")) {
            return { vulnerabilities: [staticVuln], found: true, durationMs: 1 };
          }
          return { vulnerabilities: [], found: true, durationMs: 1 };
        },
      };

      const mockApi: MockApiSource = {
        query: async () => ({ findings: [], ok: true }),
      };

      const hybrid = new HybridLookup(mockStaticDb, mockApi);

      const result1 = await hybrid.query([{ name: "test-pkg", version: "1.9.9" }]);
      assert.equal(result1.findings.length, 1);

      const result2 = await hybrid.query([{ name: "test-pkg", version: "2.0.0" }]);
      assert.equal(result2.findings.length, 0);
    });
  });
});
