import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import type { VulnerabilityFinding, Severity, FindingSource } from "../../src/types";
import type {
  StaticDbIndex,
  PackageShard,
  StaticVulnerability,
  StaticDbQueryOptions,
  StaticDbQueryResult,
} from "../../src/static-db/types";
import { severityLevel } from "../../src/static-db/types";
import { satisfies } from "../../src/utils/semver";

/**
 * Mock implementation of StaticDbReader for testing.
 * This mirrors what the real implementation should do.
 */
class MockStaticDbReader {
  private index: StaticDbIndex | null = null;
  private packageCache = new Map<string, PackageShard>();
  private dataPath: string;
  private cutoffDate: string;
  private ready = false;

  constructor(config: { dataPath: string; cutoffDate: string }) {
    this.dataPath = config.dataPath;
    this.cutoffDate = config.cutoffDate;
  }

  async initialize(): Promise<void> {
    try {
      const indexPath = path.join(this.dataPath, "index.json");
      const indexContent = await fs.readFile(indexPath, "utf-8");
      this.index = JSON.parse(indexContent) as StaticDbIndex;
      this.ready = true;
    } catch {
      this.ready = false;
      this.index = null;
    }
  }

  isReady(): boolean {
    return this.ready;
  }

  getCutoffDate(): string {
    return this.cutoffDate;
  }

  getIndex(): StaticDbIndex | null {
    return this.index;
  }

  hasVulnerabilities(packageName: string): boolean {
    if (!this.index) return false;
    return packageName in this.index.packages;
  }

  async loadPackageShard(packageName: string): Promise<PackageShard | null> {
    if (this.packageCache.has(packageName)) {
      return this.packageCache.get(packageName)!;
    }

    try {
      // Handle scoped packages (@scope/name -> @scope/name.json)
      const shardPath = path.join(this.dataPath, `${packageName}.json`);
      const content = await fs.readFile(shardPath, "utf-8");
      const shard = JSON.parse(content) as PackageShard;
      this.packageCache.set(packageName, shard);
      return shard;
    } catch {
      return null;
    }
  }

  /**
   * Find vulnerabilities for a package/version with optional filtering.
   */
  async findVulnerabilities(
    packageName: string,
    version: string,
    options?: StaticDbQueryOptions
  ): Promise<StaticDbQueryResult> {
    const startTime = Date.now();

    if (!this.index || !this.hasVulnerabilities(packageName)) {
      return {
        vulnerabilities: [],
        found: false,
        durationMs: Date.now() - startTime,
      };
    }

    const shard = await this.loadPackageShard(packageName);
    if (!shard) {
      return {
        vulnerabilities: [],
        found: false,
        durationMs: Date.now() - startTime,
      };
    }

    let vulns = shard.vulnerabilities.filter((v) => {
      // Check version against affected ranges
      const isAffected = v.affectedVersions.some((av) => satisfies(version, av.range));
      if (!isAffected) return false;

      // Apply date filters
      if (options?.publishedAfter && v.publishedAt < options.publishedAfter) {
        return false;
      }
      if (options?.publishedBefore && v.publishedAt >= options.publishedBefore) {
        return false;
      }

      // Apply severity filter
      if (options?.minSeverity) {
        const minLevel = severityLevel(options.minSeverity);
        const vulnLevel = severityLevel(v.severity);
        if (vulnLevel < minLevel) return false;
      }

      return true;
    });

    return {
      vulnerabilities: vulns,
      found: true,
      durationMs: Date.now() - startTime,
    };
  }

  /**
   * Query for a package (returns all vulns for any version).
   */
  async queryPackage(packageName: string): Promise<VulnerabilityFinding[]> {
    if (!this.index || !this.hasVulnerabilities(packageName)) {
      return [];
    }

    const shard = await this.loadPackageShard(packageName);
    if (!shard) {
      return [];
    }

    // Convert StaticVulnerability to VulnerabilityFinding
    return shard.vulnerabilities.map((v) => ({
      id: v.id,
      source: v.source,
      packageName: v.packageName,
      packageVersion: "*", // All versions; caller must filter
      severity: v.severity,
      title: v.title,
      url: v.url,
      publishedAt: v.publishedAt,
      modifiedAt: v.modifiedAt,
      identifiers: v.identifiers,
      affectedRange: v.affectedVersions.map((av) => av.range).join(" || "),
      fixedVersion: v.affectedVersions[0]?.fixed,
    }));
  }
}

// ============================================================================
// Tests
// ============================================================================

describe("StaticDbReader", () => {
  const fixturesPath = path.join(__dirname, "../fixtures/static-db");

  describe("initialization", () => {
    it("initializes successfully with valid data path", async () => {
      const reader = new MockStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      await reader.initialize();

      assert.equal(reader.isReady(), true);
    });

    it("fails gracefully with invalid data path", async () => {
      const reader = new MockStaticDbReader({
        dataPath: "/nonexistent/path",
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      await reader.initialize();

      assert.equal(reader.isReady(), false);
    });

    it("returns correct cutoff date", async () => {
      const reader = new MockStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      await reader.initialize();

      assert.equal(reader.getCutoffDate(), "2025-01-01T00:00:00Z");
    });

    it("loads index metadata correctly", async () => {
      const reader = new MockStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });

      await reader.initialize();
      const index = reader.getIndex();

      assert.ok(index);
      assert.equal(index.schemaVersion, 1);
      assert.equal(index.totalPackages, 3);
      assert.equal(index.totalVulnerabilities, 8);
    });
  });

  describe("hasVulnerabilities", () => {
    let reader: MockStaticDbReader;

    beforeEach(async () => {
      reader = new MockStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });
      await reader.initialize();
    });

    it("returns true for packages in index", () => {
      assert.equal(reader.hasVulnerabilities("lodash"), true);
      assert.equal(reader.hasVulnerabilities("react"), true);
      assert.equal(reader.hasVulnerabilities("@angular/core"), true);
    });

    it("returns false for packages not in index", () => {
      assert.equal(reader.hasVulnerabilities("express"), false);
      assert.equal(reader.hasVulnerabilities("unknown-package"), false);
    });

    it("returns false when reader is not ready", async () => {
      const badReader = new MockStaticDbReader({
        dataPath: "/nonexistent",
        cutoffDate: "2025-01-01T00:00:00Z",
      });
      await badReader.initialize();

      assert.equal(badReader.hasVulnerabilities("lodash"), false);
    });
  });

  describe("findVulnerabilities", () => {
    let reader: MockStaticDbReader;

    beforeEach(async () => {
      reader = new MockStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });
      await reader.initialize();
    });

    describe("version matching", () => {
      it("finds vulnerabilities for affected version", async () => {
        const result = await reader.findVulnerabilities("lodash", "4.17.0");

        assert.equal(result.found, true);
        assert.ok(result.vulnerabilities.length > 0);
        assert.ok(result.vulnerabilities.some((v) => v.id === "CVE-2024-12345"));
      });

      it("finds multiple vulnerabilities for affected version", async () => {
        const result = await reader.findVulnerabilities("lodash", "4.0.0");

        assert.equal(result.found, true);
        // Should match both CVE-2024-12345 (>=4.0.0 <4.17.21) and CVE-2024-11111 (>=3.0.0 <4.17.15)
        assert.ok(result.vulnerabilities.length >= 2);
      });

      it("returns empty for unaffected version", async () => {
        const result = await reader.findVulnerabilities("lodash", "4.17.21");

        assert.equal(result.found, true);
        // 4.17.21 is the fixed version for CVE-2024-12345 and CVE-2024-11111
        assert.equal(result.vulnerabilities.filter((v) => v.id === "CVE-2024-12345").length, 0);
      });

      it("handles version ranges with multiple entries", async () => {
        // React has multiple affected ranges for CVE-2024-22222
        const result17 = await reader.findVulnerabilities("react", "17.0.1");
        const result18 = await reader.findVulnerabilities("react", "18.0.0");

        assert.ok(result17.vulnerabilities.some((v) => v.id === "CVE-2024-22222"));
        assert.ok(result18.vulnerabilities.some((v) => v.id === "CVE-2024-22222"));
      });

      it("returns empty for version before all affected ranges", async () => {
        const result = await reader.findVulnerabilities("lodash", "2.0.0");

        // 2.0.0 is before >=3.0.0 (CVE-2024-11111) and >=4.0.0 (CVE-2024-12345)
        // but might match <3.10.0 (CVE-2023-99999)
        const hasOnlyOldVulns = result.vulnerabilities.every((v) => v.id === "CVE-2023-99999");
        assert.ok(hasOnlyOldVulns || result.vulnerabilities.length === 0);
      });

      it("handles unbounded ranges (no fixed version)", async () => {
        const result = await reader.findVulnerabilities("lodash", "3.5.0");

        assert.equal(result.found, true);
        // Should match CVE-2023-99999 which has range <3.10.0 with no fix
        assert.ok(result.vulnerabilities.some((v) => v.id === "CVE-2023-99999"));
      });
    });

    describe("scoped packages", () => {
      it("finds vulnerabilities for scoped packages", async () => {
        const result = await reader.findVulnerabilities("@angular/core", "14.0.0");

        assert.equal(result.found, true);
        assert.ok(result.vulnerabilities.some((v) => v.id === "CVE-2024-33333"));
      });

      it("handles multiple version ranges for scoped packages", async () => {
        const result14 = await reader.findVulnerabilities("@angular/core", "14.2.0");
        const result15 = await reader.findVulnerabilities("@angular/core", "15.0.0");

        assert.ok(result14.vulnerabilities.some((v) => v.id === "CVE-2024-33333"));
        assert.ok(result15.vulnerabilities.some((v) => v.id === "CVE-2024-33333"));
      });
    });

    describe("missing packages", () => {
      it("returns found: false for unknown packages", async () => {
        const result = await reader.findVulnerabilities("unknown-package", "1.0.0");

        assert.equal(result.found, false);
        assert.deepEqual(result.vulnerabilities, []);
      });

      it("includes duration even for unknown packages", async () => {
        const result = await reader.findVulnerabilities("unknown-package", "1.0.0");

        assert.ok(typeof result.durationMs === "number");
        assert.ok(result.durationMs >= 0);
      });
    });

    describe("date filtering", () => {
      it("filters vulnerabilities published after date", async () => {
        const result = await reader.findVulnerabilities("lodash", "4.0.0", {
          publishedAfter: "2024-07-01T00:00:00Z",
        });

        // Should only include CVE-2024-12345 (Dec 2024), not CVE-2024-11111 (Jun 2024)
        const ids = result.vulnerabilities.map((v) => v.id);
        assert.ok(ids.includes("CVE-2024-12345"));
        assert.ok(!ids.includes("CVE-2024-11111"));
      });

      it("filters vulnerabilities published before date", async () => {
        const result = await reader.findVulnerabilities("lodash", "4.0.0", {
          publishedBefore: "2024-07-01T00:00:00Z",
        });

        // Should only include CVE-2024-11111 (Jun 2024), not CVE-2024-12345 (Dec 2024)
        const ids = result.vulnerabilities.map((v) => v.id);
        assert.ok(!ids.includes("CVE-2024-12345"));
        assert.ok(ids.includes("CVE-2024-11111"));
      });

      it("applies both date filters together", async () => {
        const result = await reader.findVulnerabilities("lodash", "4.0.0", {
          publishedAfter: "2024-05-01T00:00:00Z",
          publishedBefore: "2024-07-01T00:00:00Z",
        });

        // Should only include CVE-2024-11111 (Jun 2024)
        assert.equal(result.vulnerabilities.length, 1);
        assert.equal(result.vulnerabilities[0]!.id, "CVE-2024-11111");
      });
    });

    describe("severity filtering", () => {
      it("filters by minimum severity", async () => {
        const result = await reader.findVulnerabilities("lodash", "3.0.0", {
          minSeverity: "high",
        });

        // Should include high and critical, not medium or low
        for (const v of result.vulnerabilities) {
          assert.ok(["critical", "high"].includes(v.severity));
        }
      });

      it("includes all severities when filter is low", async () => {
        const result = await reader.findVulnerabilities("@angular/core", "12.0.0", {
          minSeverity: "low",
        });

        // Should include low severity vulnerability
        assert.ok(result.vulnerabilities.some((v) => v.severity === "low"));
      });

      it("returns empty when no vulns meet severity threshold", async () => {
        const result = await reader.findVulnerabilities("@angular/core", "14.0.0", {
          minSeverity: "critical",
        });

        // Angular vulns are medium and low, none critical
        assert.equal(result.vulnerabilities.length, 0);
      });
    });
  });

  describe("queryPackage", () => {
    let reader: MockStaticDbReader;

    beforeEach(async () => {
      reader = new MockStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });
      await reader.initialize();
    });

    it("returns all vulnerabilities for a package", async () => {
      const findings = await reader.queryPackage("lodash");

      assert.equal(findings.length, 3);
      assert.ok(findings.some((f) => f.id === "CVE-2024-12345"));
      assert.ok(findings.some((f) => f.id === "CVE-2024-11111"));
      assert.ok(findings.some((f) => f.id === "CVE-2023-99999"));
    });

    it("returns empty array for unknown package", async () => {
      const findings = await reader.queryPackage("unknown-package");

      assert.deepEqual(findings, []);
    });

    it("converts to VulnerabilityFinding format", async () => {
      const findings = await reader.queryPackage("react");

      const finding = findings.find((f) => f.id === "CVE-2024-22222");
      assert.ok(finding);
      assert.equal(finding.source, "github");
      assert.equal(finding.packageName, "react");
      assert.equal(finding.severity, "high");
      assert.equal(finding.title, "XSS vulnerability in React DOM");
      assert.ok(finding.url);
    });
  });

  describe("metadata retrieval", () => {
    let reader: MockStaticDbReader;

    beforeEach(async () => {
      reader = new MockStaticDbReader({
        dataPath: fixturesPath,
        cutoffDate: "2025-01-01T00:00:00Z",
      });
      await reader.initialize();
    });

    it("returns package index entry", () => {
      const index = reader.getIndex();
      assert.ok(index);

      const lodashEntry = index.packages["lodash"];
      assert.ok(lodashEntry);
      assert.equal(lodashEntry.count, 3);
      assert.equal(lodashEntry.maxSeverity, "critical");
    });

    it("returns build info", () => {
      const index = reader.getIndex();
      assert.ok(index);
      assert.ok(index.buildInfo);
      assert.equal(index.buildInfo.generator, "test-fixture");
      assert.deepEqual(index.buildInfo.sources, ["github-advisory"]);
    });
  });
});

describe("severityLevel", () => {
  it("returns correct levels for all severities", () => {
    assert.equal(severityLevel("critical"), 4);
    assert.equal(severityLevel("high"), 3);
    assert.equal(severityLevel("medium"), 2);
    assert.equal(severityLevel("low"), 1);
    assert.equal(severityLevel("unknown"), 0);
  });

  it("returns 0 for invalid severity", () => {
    assert.equal(severityLevel("invalid" as Severity), 0);
  });
});
