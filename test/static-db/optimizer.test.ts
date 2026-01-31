import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import type { StaticVulnerability, PackageShard, StaticDbIndex, PackageIndexEntry } from "../../src/static-db/types";
import {
  compressDate,
  expandDate,
  mergeAffectedRanges,
  getFirstFixedVersion,
  optimizeVulnerability,
  expandVulnerability,
  optimizePackageData,
  expandPackageData,
  optimizeIndex,
  expandIndex,
  optimizeIndexEntry,
  expandIndexEntry,
  compressDatabase,
  getStorageStats,
  readMaybeCompressed,
  writeMaybeCompressed,
  PackageBloomFilter,
  createPackageFilter,
  binarySearchPackage,
  type OptimizedVulnerability,
  type OptimizedPackageData,
  type OptimizedIndex,
} from "../../src/static-db/optimizer";

describe("Date Compression", () => {
  describe("compressDate", () => {
    it("should compress ISO 8601 timestamp to YYYY-MM-DD", () => {
      assert.equal(compressDate("2024-01-15T12:30:45.000Z"), "2024-01-15");
      assert.equal(compressDate("2024-06-20T00:00:00Z"), "2024-06-20");
    });

    it("should pass through already compressed dates", () => {
      assert.equal(compressDate("2024-01-15"), "2024-01-15");
    });

    it("should handle undefined", () => {
      assert.equal(compressDate(undefined), undefined);
    });

    it("should handle various ISO formats", () => {
      assert.equal(compressDate("2024-01-15T12:30:45"), "2024-01-15");
      assert.equal(compressDate("2024-01-15T12:30:45+00:00"), "2024-01-15");
    });
  });

  describe("expandDate", () => {
    it("should expand YYYY-MM-DD to ISO 8601", () => {
      assert.equal(expandDate("2024-01-15"), "2024-01-15T00:00:00.000Z");
    });

    it("should pass through already expanded dates", () => {
      assert.equal(expandDate("2024-01-15T12:30:45.000Z"), "2024-01-15T12:30:45.000Z");
    });

    it("should handle undefined", () => {
      assert.equal(expandDate(undefined), undefined);
    });
  });
});

describe("Version Range Operations", () => {
  describe("mergeAffectedRanges", () => {
    it("should return single range unchanged", () => {
      assert.equal(mergeAffectedRanges([{ range: ">=1.0.0 <2.0.0" }]), ">=1.0.0 <2.0.0");
    });

    it("should merge multiple ranges with ||", () => {
      const result = mergeAffectedRanges([
        { range: ">=1.0.0 <1.5.0" },
        { range: ">=2.0.0 <2.5.0" },
      ]);
      assert.equal(result, ">=1.0.0 <1.5.0 || >=2.0.0 <2.5.0");
    });

    it("should deduplicate identical ranges", () => {
      const result = mergeAffectedRanges([
        { range: "<1.0.0" },
        { range: "<1.0.0" },
        { range: ">=2.0.0" },
      ]);
      assert.equal(result, "<1.0.0 || >=2.0.0");
    });

    it("should return * for empty ranges", () => {
      assert.equal(mergeAffectedRanges([]), "*");
    });
  });

  describe("getFirstFixedVersion", () => {
    it("should return first fixed version", () => {
      const ranges = [{ range: "<1.0.0" }, { range: "<2.0.0", fixed: "2.0.0" }];
      assert.equal(getFirstFixedVersion(ranges), "2.0.0");
    });

    it("should return undefined if no fixed version", () => {
      const ranges = [{ range: "<1.0.0" }];
      assert.equal(getFirstFixedVersion(ranges), undefined);
    });
  });
});

describe("Vulnerability Optimization", () => {
  const sampleVuln: StaticVulnerability = {
    id: "CVE-2024-1234",
    packageName: "lodash",
    severity: "high",
    publishedAt: "2024-01-15T12:30:45.000Z",
    modifiedAt: "2024-01-20T10:00:00.000Z",
    affectedVersions: [{ range: ">=1.0.0 <4.17.21", fixed: "4.17.21" }],
    source: "github",
    title: "Prototype Pollution",
    url: "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx",
  };

  describe("optimizeVulnerability", () => {
    it("should optimize vulnerability with short keys", () => {
      const optimized = optimizeVulnerability(sampleVuln);

      assert.equal(optimized.id, "CVE-2024-1234");
      assert.equal(optimized.sev, 3); // high = 3
      assert.equal(optimized.pub, "2024-01-15");
      assert.equal(optimized.aff, ">=1.0.0 <4.17.21");
      assert.equal(optimized.fix, "4.17.21");
      assert.equal(optimized.src, 0); // github = 0
      assert.equal(optimized.ttl, "Prototype Pollution");
      assert.equal(optimized.url, "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx");
    });

    it("should omit optional fields when empty", () => {
      const minimalVuln: StaticVulnerability = {
        id: "CVE-2024-5678",
        packageName: "test-pkg",
        severity: "low",
        publishedAt: "2024-01-01",
        affectedVersions: [{ range: "<1.0.0" }],
        source: "nvd",
      };

      const optimized = optimizeVulnerability(minimalVuln);

      assert.equal(optimized.fix, undefined);
      assert.equal(optimized.ttl, undefined);
      assert.equal(optimized.url, undefined);
    });
  });

  describe("expandVulnerability", () => {
    it("should expand back to full format", () => {
      const optimized = optimizeVulnerability(sampleVuln);
      const expanded = expandVulnerability(optimized, "lodash");

      assert.equal(expanded.id, sampleVuln.id);
      assert.equal(expanded.packageName, "lodash");
      assert.equal(expanded.severity, "high");
      assert.equal(expanded.publishedAt, "2024-01-15T00:00:00.000Z");
      assert.equal(expanded.affectedVersions[0]!.range, ">=1.0.0 <4.17.21");
      assert.equal(expanded.affectedVersions[0]!.fixed, "4.17.21");
      assert.equal(expanded.source, "github");
      assert.equal(expanded.title, "Prototype Pollution");
    });
  });
});

describe("Package Data Optimization", () => {
  const sampleVulns: StaticVulnerability[] = [
    {
      id: "CVE-2024-1111",
      packageName: "express",
      severity: "critical",
      publishedAt: "2024-03-01T00:00:00Z",
      affectedVersions: [{ range: "<4.18.0", fixed: "4.18.0" }],
      source: "github",
    },
    {
      id: "CVE-2024-2222",
      packageName: "express",
      severity: "medium",
      publishedAt: "2024-01-01T00:00:00Z",
      affectedVersions: [{ range: "<4.17.0", fixed: "4.17.0" }],
      source: "nvd",
    },
  ];

  describe("optimizePackageData", () => {
    it("should optimize package with vulnerabilities", () => {
      const optimized = optimizePackageData(sampleVulns);

      assert.equal(optimized.pkg, "express");
      assert.equal(optimized.v.length, 2);
      // Should be sorted by date descending
      assert.equal(optimized.v[0]!.id, "CVE-2024-1111");
      assert.equal(optimized.v[1]!.id, "CVE-2024-2222");
    });

    it("should handle empty vulnerability list", () => {
      const optimized = optimizePackageData([]);

      assert.equal(optimized.pkg, "");
      assert.equal(optimized.v.length, 0);
    });
  });

  describe("expandPackageData", () => {
    it("should expand back to full format", () => {
      const optimized = optimizePackageData(sampleVulns);
      const expanded = expandPackageData(optimized);

      assert.equal(expanded.packageName, "express");
      assert.equal(expanded.vulnerabilities.length, 2);
      assert.equal(expanded.vulnerabilities[0]!.id, "CVE-2024-1111");
    });
  });
});

describe("Index Optimization", () => {
  const sampleIndex: StaticDbIndex = {
    schemaVersion: 1,
    lastUpdated: "2024-06-01T12:00:00.000Z",
    cutoffDate: "2024-05-01T00:00:00.000Z",
    totalVulnerabilities: 100,
    totalPackages: 50,
    packages: {
      lodash: { count: 5, maxSeverity: "critical", latestVuln: "2024-04-15T00:00:00Z" },
      express: { count: 3, maxSeverity: "high" },
    },
  };

  describe("optimizeIndex", () => {
    it("should optimize index with short keys", () => {
      const optimized = optimizeIndex(sampleIndex);

      assert.equal(optimized.ver, 1);
      assert.equal(optimized.upd, "2024-06-01");
      assert.equal(optimized.cut, "2024-05-01");
      assert.equal(optimized.tv, 100);
      assert.equal(optimized.tp, 50);
      assert.equal(optimized.p.lodash!.c, 5);
      assert.equal(optimized.p.lodash!.s, 4); // critical = 4
      assert.equal(optimized.p.lodash!.l, "2024-04-15");
    });

    it("should create sorted package list", () => {
      const optimized = optimizeIndex(sampleIndex);

      assert.ok(optimized.pkgList !== undefined);
      assert.deepEqual(optimized.pkgList, ["express", "lodash"]);
    });
  });

  describe("expandIndex", () => {
    it("should expand back to full format", () => {
      const optimized = optimizeIndex(sampleIndex);
      const expanded = expandIndex(optimized);

      assert.equal(expanded.schemaVersion, 1);
      assert.equal(expanded.lastUpdated, "2024-06-01T00:00:00.000Z");
      assert.equal(expanded.totalVulnerabilities, 100);
      assert.equal(expanded.packages.lodash!.count, 5);
      assert.equal(expanded.packages.lodash!.maxSeverity, "critical");
    });
  });
});

describe("Bloom Filter", () => {
  describe("PackageBloomFilter", () => {
    it("should correctly identify added packages", () => {
      const filter = new PackageBloomFilter(100, 0.01);

      filter.add("lodash");
      filter.add("express");
      filter.add("react");

      assert.equal(filter.mightContain("lodash"), true);
      assert.equal(filter.mightContain("express"), true);
      assert.equal(filter.mightContain("react"), true);
    });

    it("should return false for definitely absent packages", () => {
      const filter = new PackageBloomFilter(100, 0.01);

      filter.add("lodash");
      filter.add("express");

      // Bloom filters should have no false negatives
      assert.equal(filter.mightContain("definitely-not-added-package-xyz"), false);
    });

    it("should serialize and deserialize correctly", () => {
      const filter = new PackageBloomFilter(100, 0.01);

      filter.add("lodash");
      filter.add("express");
      filter.add("react");

      const serialized = filter.serialize();
      const restored = PackageBloomFilter.deserialize(serialized);

      assert.equal(restored.mightContain("lodash"), true);
      assert.equal(restored.mightContain("express"), true);
      assert.equal(restored.mightContain("react"), true);
    });
  });

  describe("createPackageFilter", () => {
    it("should create filter with all packages", () => {
      const packages = ["lodash", "express", "react", "vue", "angular"];
      const filter = createPackageFilter(packages);

      for (const pkg of packages) {
        assert.equal(filter.mightContain(pkg), true);
      }
    });
  });
});

describe("Binary Search", () => {
  describe("binarySearchPackage", () => {
    const sortedPackages = ["angular", "express", "lodash", "react", "vue"];

    it("should find existing packages", () => {
      assert.equal(binarySearchPackage(sortedPackages, "lodash"), true);
      assert.equal(binarySearchPackage(sortedPackages, "angular"), true);
      assert.equal(binarySearchPackage(sortedPackages, "vue"), true);
    });

    it("should return false for non-existent packages", () => {
      assert.equal(binarySearchPackage(sortedPackages, "svelte"), false);
      assert.equal(binarySearchPackage(sortedPackages, "preact"), false);
      assert.equal(binarySearchPackage(sortedPackages, "aaa"), false);
      assert.equal(binarySearchPackage(sortedPackages, "zzz"), false);
    });

    it("should handle empty list", () => {
      assert.equal(binarySearchPackage([], "lodash"), false);
    });

    it("should handle single element list", () => {
      assert.equal(binarySearchPackage(["lodash"], "lodash"), true);
      assert.equal(binarySearchPackage(["lodash"], "express"), false);
    });
  });
});

describe("File Operations", () => {
  let testDir: string;

  beforeEach(async () => {
    testDir = await fs.mkdtemp(path.join(os.tmpdir(), "static-db-test-"));
  });

  afterEach(async () => {
    await fs.rm(testDir, { recursive: true, force: true });
  });

  describe("writeMaybeCompressed / readMaybeCompressed", () => {
    it("should write and read uncompressed files below threshold", async () => {
      const data = { small: "data" };
      const filePath = path.join(testDir, "small.json");

      const result = await writeMaybeCompressed(filePath, data, { threshold: 1000 });

      assert.equal(result.compressed, false);

      const read = await readMaybeCompressed<typeof data>(filePath);
      assert.deepEqual(read, data);
    });

    it("should compress files above threshold", async () => {
      const data = { large: "x".repeat(20000) };
      const filePath = path.join(testDir, "large.json");

      const result = await writeMaybeCompressed(filePath, data, { threshold: 100 });

      assert.equal(result.compressed, true);

      const read = await readMaybeCompressed<typeof data>(filePath);
      assert.deepEqual(read, data);
    });

    it("should return null for non-existent files", async () => {
      const result = await readMaybeCompressed(path.join(testDir, "nonexistent.json"));
      assert.equal(result, null);
    });
  });

  describe("compressDatabase", () => {
    it("should compress large files in database", async () => {
      // Create test database structure
      const indexData = {
        schemaVersion: 1,
        lastUpdated: "2024-01-01",
        cutoffDate: "2024-01-01",
        totalVulnerabilities: 1,
        totalPackages: 1,
        packages: { lodash: { count: 1, maxSeverity: "high" } },
      };

      // Create a large file that should be compressed
      const largeShard = {
        packageName: "lodash",
        lastUpdated: "2024-01-01",
        vulnerabilities: Array(100)
          .fill(null)
          .map((_, i) => ({
            id: `CVE-2024-${String(i).padStart(4, "0")}`,
            packageName: "lodash",
            severity: "high",
            publishedAt: "2024-01-01",
            affectedVersions: [{ range: "<1.0.0" }],
            source: "github",
            title: "Test vulnerability with a somewhat long title",
            description: "A".repeat(200),
          })),
      };

      await fs.writeFile(path.join(testDir, "index.json"), JSON.stringify(indexData));
      await fs.writeFile(path.join(testDir, "lodash.json"), JSON.stringify(largeShard));

      const result = await compressDatabase(testDir);

      assert.ok(result.filesProcessed > 0);
      assert.ok(result.compressionRatio < 1);
    });
  });

  describe("getStorageStats", () => {
    it("should calculate storage statistics", async () => {
      const indexData = { schemaVersion: 1, packages: {} };
      const shardData = { packageName: "test", vulnerabilities: [] };

      await fs.writeFile(path.join(testDir, "index.json"), JSON.stringify(indexData));
      await fs.writeFile(path.join(testDir, "test.json"), JSON.stringify(shardData));

      const stats = await getStorageStats(testDir);

      assert.ok(stats.totalBytes > 0);
      assert.equal(stats.shardCount, 1);
      // uncompressedCount includes both index and shard files
      assert.ok(stats.uncompressedCount >= 1);
    });

    it("should handle scoped packages", async () => {
      const scopeDir = path.join(testDir, "@types");
      await fs.mkdir(scopeDir, { recursive: true });

      await fs.writeFile(path.join(testDir, "index.json"), JSON.stringify({}));
      await fs.writeFile(path.join(scopeDir, "node.json"), JSON.stringify({}));

      const stats = await getStorageStats(testDir);

      assert.equal(stats.shardCount, 1);
    });
  });
});

describe("Round-trip Integrity", () => {
  it("should preserve data through optimize/expand cycle", () => {
    const originalVuln: StaticVulnerability = {
      id: "CVE-2024-9999",
      packageName: "test-package",
      severity: "critical",
      publishedAt: "2024-06-15T10:30:00.000Z",
      modifiedAt: "2024-06-20T15:45:00.000Z",
      affectedVersions: [
        { range: ">=1.0.0 <1.5.0", fixed: "1.5.0" },
        { range: ">=2.0.0 <2.3.0", fixed: "2.3.0" },
      ],
      source: "nvd",
      title: "Test Vulnerability",
      url: "https://example.com/vuln",
    };

    const optimized = optimizeVulnerability(originalVuln);
    const expanded = expandVulnerability(optimized, originalVuln.packageName);

    // Core fields should match
    assert.equal(expanded.id, originalVuln.id);
    assert.equal(expanded.packageName, originalVuln.packageName);
    assert.equal(expanded.severity, originalVuln.severity);
    assert.equal(expanded.source, originalVuln.source);
    assert.equal(expanded.title, originalVuln.title);
    assert.equal(expanded.url, originalVuln.url);

    // Date is compressed to YYYY-MM-DD and expanded to midnight UTC
    assert.equal(expanded.publishedAt?.slice(0, 10), originalVuln.publishedAt?.slice(0, 10));

    // Affected ranges are merged in optimized format
    assert.ok(expanded.affectedVersions[0]!.range.includes(">=1.0.0 <1.5.0"));
    assert.ok(expanded.affectedVersions[0]!.range.includes(">=2.0.0 <2.3.0"));
  });
});
