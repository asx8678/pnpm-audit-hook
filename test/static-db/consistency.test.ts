/**
 * Tests for Static DB Consistency Analyzer.
 *
 * Builds a temporary data directory with known consistent,
 * orphan, missing, count-mismatch, and metadata-mismatch scenarios.
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

import {
  analyzeStaticDbConsistency,
  decodeShardPath,
  type StaticDbConsistencyReport,
} from "../../src/static-db/consistency";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function makeTempDb(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "consistency-test-"));
  return dir;
}

async function writeJson(filePath: string, data: unknown): Promise<void> {
  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(data));
}

async function writeIndex(
  dir: string,
  packages: Record<string, { count: number; maxSeverity: string }>,
  meta?: Partial<{
    totalVulnerabilities: number;
    totalPackages: number;
    lastUpdated: string;
    cutoffDate: string;
    schemaVersion: number;
  }>,
): Promise<void> {
  const pkgs = packages || {};
  const realTotalVulns = Object.values(pkgs).reduce((s, e) => s + e.count, 0);
  const index = {
    schemaVersion: meta?.schemaVersion ?? 1,
    lastUpdated: meta?.lastUpdated ?? "2025-01-01T00:00:00Z",
    cutoffDate: meta?.cutoffDate ?? "2025-12-31T23:59:59Z",
    totalVulnerabilities:
      meta?.totalVulnerabilities ?? realTotalVulns,
    totalPackages: meta?.totalPackages ?? Object.keys(pkgs).length,
    packages: pkgs,
  };
  await writeJson(path.join(dir, "index.json"), index);
}

async function writeShard(dir: string, packageName: string, vulnCount: number): Promise<void> {
  const vulns: Array<{ id: string; severity: string }> = [];
  for (let i = 0; i < vulnCount; i++) {
    vulns.push({ id: `CVE-2025-${String(i).padStart(5, "0")}`, severity: "medium" });
  }

  const data = { packageName, lastUpdated: "2025-01-01T00:00:00Z", vulnerabilities: vulns };

  if (packageName.startsWith("@")) {
    const slashIdx = packageName.indexOf("/");
    const scope = packageName.slice(0, slashIdx);
    const name = packageName.slice(slashIdx + 1);
    await writeJson(path.join(dir, scope, `${name}.json`), data);
  } else {
    await writeJson(path.join(dir, `${packageName}.json`), data);
  }
}

// ---------------------------------------------------------------------------
// decodeShardPath
// ---------------------------------------------------------------------------

describe("decodeShardPath", () => {
  it("decodes unscoped package", () => {
    assert.equal(decodeShardPath("lodash.json"), "lodash");
    assert.equal(decodeShardPath("lodash.json.gz"), "lodash");
  });

  it("decodes scoped package", () => {
    assert.equal(decodeShardPath("@angular/core.json"), "@angular/core");
    assert.equal(decodeShardPath("@angular/core.json.gz"), "@angular/core");
  });

  it("decodes numeric name", () => {
    assert.equal(decodeShardPath("101.json"), "101");
  });

  it("handles path with directory components", () => {
    assert.equal(decodeShardPath("@scope/name.json"), "@scope/name");
  });

  it("normalizes backslashes", () => {
    assert.equal(decodeShardPath("@scope\\name.json"), "@scope/name");
    assert.equal(decodeShardPath("lodash.json"), "lodash");
  });
});

// ---------------------------------------------------------------------------
// analyzeStaticDbConsistency
// ---------------------------------------------------------------------------

describe("analyzeStaticDbConsistency", () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await makeTempDb();
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("reports consistent when index matches shards", async () => {
    await writeIndex(tmpDir, {
      lodash: { count: 2, maxSeverity: "high" },
      express: { count: 1, maxSeverity: "medium" },
    });
    await writeShard(tmpDir, "lodash", 2);
    await writeShard(tmpDir, "express", 1);

    const report = await analyzeStaticDbConsistency(tmpDir);
    assert.equal(report.indexLoaded, true);
    assert.equal(report.isConsistent, true);
    assert.equal(report.indexedPackageCount, 2);
    assert.equal(report.indexTotalPackages, 2);
    assert.equal(report.shardFileCount, 2);
    assert.equal(report.orphanShards.length, 0);
    assert.equal(report.missingShards.length, 0);
    assert.equal(report.countMismatches.length, 0);
    assert.equal(report.packageNameMismatches.length, 0);
    assert.equal(report.metadataMismatches.length, 0);
    assert.equal(report.errors.length, 0);
  });

  it("detects orphan shards", async () => {
    await writeIndex(tmpDir, {
      lodash: { count: 1, maxSeverity: "high" },
    });
    await writeShard(tmpDir, "lodash", 1);
    await writeShard(tmpDir, "express", 2); // orphan

    const report = await analyzeStaticDbConsistency(tmpDir);
    assert.equal(report.isConsistent, false);
    assert.equal(report.orphanShards.length, 1);
    assert.ok(report.orphanShards[0]!.includes("express.json"));
  });

  it("detects missing shards", async () => {
    await writeIndex(tmpDir, {
      lodash: { count: 1, maxSeverity: "high" },
      express: { count: 1, maxSeverity: "medium" }, // missing shard
    });
    await writeShard(tmpDir, "lodash", 1);

    const report = await analyzeStaticDbConsistency(tmpDir);
    assert.equal(report.isConsistent, false);
    assert.equal(report.missingShards.length, 1);
    assert.equal(report.missingShards[0], "express");
  });

  it("detects count mismatches", async () => {
    await writeIndex(tmpDir, {
      lodash: { count: 5, maxSeverity: "high" }, // index says 5
    });
    await writeShard(tmpDir, "lodash", 2); // shard has 2

    const report = await analyzeStaticDbConsistency(tmpDir);
    assert.equal(report.isConsistent, false);
    assert.equal(report.countMismatches.length, 1);
    assert.equal(report.countMismatches[0]!.packageName, "lodash");
    assert.equal(report.countMismatches[0]!.indexCount, 5);
    assert.equal(report.countMismatches[0]!.shardCount, 2);
  });

  it("detects package name mismatches", async () => {
    await writeIndex(tmpDir, {
      lodash: { count: 1, maxSeverity: "medium" },
    });

    // Write a shard with mismatched internal name
    const data = {
      packageName: "lodash-fork",
      lastUpdated: "2025-01-01T00:00:00Z",
      vulnerabilities: [{ id: "CVE-2025-00001", severity: "medium" }],
    };
    await writeJson(path.join(tmpDir, "lodash.json"), data);

    const report = await analyzeStaticDbConsistency(tmpDir);
    assert.equal(report.packageNameMismatches.length, 1);
    assert.equal(report.packageNameMismatches[0]!.decodedName, "lodash");
    assert.equal(report.packageNameMismatches[0]!.actualName, "lodash-fork");
  });

  it("handles scoped packages correctly", async () => {
    await writeIndex(tmpDir, {
      "@angular/core": { count: 3, maxSeverity: "critical" },
      "@angular/common": { count: 1, maxSeverity: "high" },
    });
    await writeShard(tmpDir, "@angular/core", 3);
    await writeShard(tmpDir, "@angular/common", 1);

    const report = await analyzeStaticDbConsistency(tmpDir);
    assert.equal(report.isConsistent, true);
    assert.equal(report.indexedPackageCount, 2);
    assert.equal(report.shardFileCount, 2);
  });

  it("handles mixed inconsistencies", async () => {
    await writeIndex(tmpDir, {
      a: { count: 1, maxSeverity: "low" },
      b: { count: 2, maxSeverity: "medium" },
      c: { count: 3, maxSeverity: "high" }, // missing shard
    });
    await writeShard(tmpDir, "a", 1);
    await writeShard(tmpDir, "b", 99); // count mismatch
    await writeShard(tmpDir, "d", 1); // orphan

    const report = await analyzeStaticDbConsistency(tmpDir);
    assert.equal(report.isConsistent, false);
    assert.equal(report.orphanShards.length, 1);
    assert.equal(report.missingShards.length, 1);
    assert.equal(report.missingShards[0], "c");
    assert.equal(report.countMismatches.length, 1);
    assert.equal(report.countMismatches[0]!.packageName, "b");
  });

  it("reports missing index as inconsistent", async () => {
    // No index.json written — only shard files
    await writeShard(tmpDir, "lodash", 1);
    await writeShard(tmpDir, "express", 2);

    const report = await analyzeStaticDbConsistency(tmpDir);
    assert.equal(report.indexLoaded, false);
    assert.equal(report.indexedPackageCount, 0);
    assert.equal(report.isConsistent, false);
    assert.ok(report.errors.length > 0);
  });

  it("reports missing index + no shards as inconsistent", async () => {
    // Neither index nor shards — empty directory
    const emptyDir = path.join(tmpDir, "empty");
    await fs.mkdir(emptyDir, { recursive: true });

    const report = await analyzeStaticDbConsistency(emptyDir);
    assert.equal(report.indexLoaded, false);
    assert.equal(report.shardFileCount, 0);
    assert.equal(report.isConsistent, false);
    assert.ok(report.errors.length > 0);
  });

  it("detects metadata mismatch: totalPackages", async () => {
    // Write index with wrong totalPackages
    const packages = {
      lodash: { count: 1, maxSeverity: "high" },
      express: { count: 1, maxSeverity: "medium" },
    };
    await writeIndex(tmpDir, packages, { totalPackages: 99 });
    await writeShard(tmpDir, "lodash", 1);
    await writeShard(tmpDir, "express", 1);

    const report = await analyzeStaticDbConsistency(tmpDir);
    assert.equal(report.isConsistent, false);
    assert.equal(report.metadataMismatches.length, 1);
    assert.equal(report.metadataMismatches[0]!.field, "totalPackages");
    assert.equal(report.metadataMismatches[0]!.expected, 99);
    assert.equal(report.metadataMismatches[0]!.actual, 2);
  });

  it("detects metadata mismatch: totalVulnerabilities", async () => {
    // Write index with wrong totalVulnerabilities
    const packages = {
      lodash: { count: 1, maxSeverity: "high" },
      express: { count: 2, maxSeverity: "medium" },
    };
    // Real sum is 3, but metadata says 99
    await writeIndex(tmpDir, packages, { totalVulnerabilities: 99 });
    await writeShard(tmpDir, "lodash", 1);
    await writeShard(tmpDir, "express", 2);

    const report = await analyzeStaticDbConsistency(tmpDir);
    assert.equal(report.isConsistent, false);
    // May also have totalPackages mismatch if we didn't set it
    const vMismatch = report.metadataMismatches.find(
      (m) => m.field === "totalVulnerabilities",
    );
    assert.ok(vMismatch, "should have totalVulnerabilities mismatch");
    assert.equal(vMismatch!.expected, 99);
    assert.equal(vMismatch!.actual, 3);
  });

  it("reports correct sumIndexCounts and indexTotalVulnerabilities", async () => {
    await writeIndex(tmpDir, {
      a: { count: 5, maxSeverity: "low" },
      b: { count: 10, maxSeverity: "medium" },
    });
    await writeShard(tmpDir, "a", 5);
    await writeShard(tmpDir, "b", 10);

    const report = await analyzeStaticDbConsistency(tmpDir);
    assert.equal(report.sumIndexCounts, 15);
    assert.equal(report.indexTotalVulnerabilities, 15);
    assert.equal(report.metadataMismatches.length, 0);
    assert.equal(report.isConsistent, true);
  });

  it("returns empty report for missing data directory", async () => {
    const missingDir = path.join(tmpDir, "nonexistent");
    const report = await analyzeStaticDbConsistency(missingDir);
    assert.equal(report.indexLoaded, false);
    assert.equal(report.indexedPackageCount, 0);
    assert.equal(report.shardFileCount, 0);
    assert.equal(report.isConsistent, false);
    assert.ok(report.errors.length > 0);
  });

  it("reports inconsistent with only README.md and no index", async () => {
    await fs.writeFile(path.join(tmpDir, "README.md"), "test readme");
    const report = await analyzeStaticDbConsistency(tmpDir);
    assert.equal(report.indexLoaded, false);
    assert.equal(report.indexedPackageCount, 0);
    assert.equal(report.shardFileCount, 0);
    assert.equal(report.isConsistent, false); // no index loaded
    assert.ok(report.errors.length > 0);
  });
});
