import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { createStaticDbReader } from "../../src/static-db/reader";
import { computeShardHash } from "../../src/static-db/optimizer";

/**
 * Helper: compute a sha256-<hex> hash of a Buffer, matching the
 * `computeShardHash` format used in production code.
 */
function sha256Hex(buf: Buffer): string {
  return `sha256-${crypto.createHash("sha256").update(buf).digest("hex")}`;
}

/**
 * Helper: create a minimal static DB in tempDir with one package.
 * Returns the shard file path so callers can tamper with it.
 */
async function setupMinimalDb(
  tempDir: string,
  options?: { tamperShard?: boolean; omitIntegrity?: boolean },
): Promise<{ shardPath: string; originalHash: string }> {
  // Write a shard file for "lodash"
  const shardPath = path.join(tempDir, "lodash.json");
  const shardData = {
    packageName: "lodash",
    lastUpdated: "2025-01-01T00:00:00Z",
    vulnerabilities: [
      {
        id: "CVE-2024-0001",
        packageName: "lodash",
        severity: "high",
        publishedAt: "2024-01-01T00:00:00Z",
        affectedVersions: [{ range: "<4.17.21", fixed: "4.17.21" }],
        source: "github",
        title: "Prototype Pollution in lodash",
      },
    ],
  };

  const shardBuf = Buffer.from(JSON.stringify(shardData), "utf-8");
  await fs.writeFile(shardPath, shardBuf);

  const originalHash = sha256Hex(shardBuf);

  // Tamper with the shard file if requested (write different content)
  if (options?.tamperShard) {
    const tamperedData = { ...shardData, vulnerabilities: [] };
    await fs.writeFile(shardPath, Buffer.from(JSON.stringify(tamperedData), "utf-8"));
  }

  // Build integrity map
  const integrity: Record<string, string> = {};
  if (!options?.omitIntegrity) {
    // Read the ACTUAL file bytes (may have been tampered above, that's the point
    // of the tamper test — the hash is from the ORIGINAL file, but the file was
    // overwritten after we computed the hash).
    // For valid test: hash matches file on disk.
    // For tamper test: we use the ORIGINAL hash but the file was changed.
    integrity["lodash.json"] = originalHash;
  }

  // Write the index
  const index = {
    schemaVersion: 1,
    lastUpdated: "2025-01-01T00:00:00Z",
    cutoffDate: "2025-12-31",
    totalVulnerabilities: 1,
    totalPackages: 1,
    packages: {
      lodash: { count: 1, latestVuln: "2025-01-01T00:00:00Z", maxSeverity: "high" },
    },
    ...(options?.omitIntegrity ? {} : { integrity }),
  };

  await fs.writeFile(path.join(tempDir, "index.json"), JSON.stringify(index));

  return { shardPath, originalHash };
}

describe("Shard integrity verification", () => {
  let tempDir: string;
  let warnMessages: string[];
  const originalWarn = console.warn;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pnpm-audit-integrity-"));
    warnMessages = [];
    // Capture logger warnings
    console.warn = (...args: unknown[]) => {
      warnMessages.push(args.map(String).join(" "));
      originalWarn.apply(console, args);
    };
  });

  afterEach(async () => {
    console.warn = originalWarn;
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it("loads a shard when integrity hash matches", async () => {
    await setupMinimalDb(tempDir);

    const reader = await createStaticDbReader({
      dataPath: tempDir,
      cutoffDate: "2025-12-31",
    });
    assert.ok(reader, "Reader should initialize successfully");

    const findings = await reader!.queryPackage("lodash");
    assert.equal(findings.length, 1, "Should return the vulnerability from the untampered shard");
    assert.equal(findings[0]?.id, "CVE-2024-0001");

    // No integrity warning should have been emitted
    const integrityWarnings = warnMessages.filter((m) =>
      m.includes("Shard integrity check failed"),
    );
    assert.equal(integrityWarnings.length, 0, "No integrity warnings for valid shard");
  });

  it("skips a shard and warns when integrity hash does not match", async () => {
    await setupMinimalDb(tempDir, { tamperShard: true });

    const reader = await createStaticDbReader({
      dataPath: tempDir,
      cutoffDate: "2025-12-31",
    });
    assert.ok(reader, "Reader should still initialize (index itself is not integrity-checked)");

    const findings = await reader!.queryPackage("lodash");
    assert.equal(findings.length, 0, "Should return empty findings for tampered shard");

    // An integrity warning should have been emitted
    const integrityWarnings = warnMessages.filter((m) =>
      m.includes("Shard integrity check failed"),
    );
    assert.equal(
      integrityWarnings.length,
      1,
      "Exactly one integrity warning for tampered shard",
    );
    assert.ok(
      integrityWarnings[0]!.includes("lodash"),
      "Warning should mention the package name",
    );
  });

  it("loads shard without integrity map when integrity field is absent", async () => {
    await setupMinimalDb(tempDir, { omitIntegrity: true });

    const reader = await createStaticDbReader({
      dataPath: tempDir,
      cutoffDate: "2025-12-31",
    });
    assert.ok(reader, "Reader should initialize without integrity map");

    const findings = await reader!.queryPackage("lodash");
    assert.equal(
      findings.length,
      1,
      "Should return vulnerabilities when no integrity map is present",
    );
  });

  it("loads a scoped package shard and verifies integrity", async () => {
    // Create a scoped package shard with proper @scope/name directory structure
    const scopeDir = path.join(tempDir, "@angular");
    await fs.mkdir(scopeDir, { recursive: true });

    const shardPath = path.join(scopeDir, "core.json");
    const shardData = {
      packageName: "@angular/core",
      lastUpdated: "2025-01-01T00:00:00Z",
      vulnerabilities: [
        {
          id: "GHSA-2024-0001",
          packageName: "@angular/core",
          severity: "medium",
          publishedAt: "2024-06-01T00:00:00Z",
          affectedVersions: [{ range: "<17.0.0", fixed: "17.0.0" }],
          source: "osv",
          title: "XSS in @angular/core",
        },
      ],
    };

    const shardBuf = Buffer.from(JSON.stringify(shardData), "utf-8");
    await fs.writeFile(shardPath, shardBuf);

    const originalHash = sha256Hex(shardBuf);

    // Integrity key uses forward-slash path: "@angular/core.json"
    const integrity: Record<string, string> = {
      "@angular/core.json": originalHash,
    };

    const index = {
      schemaVersion: 1,
      lastUpdated: "2025-01-01T00:00:00Z",
      cutoffDate: "2025-12-31",
      totalVulnerabilities: 1,
      totalPackages: 1,
      packages: {
        "@angular/core": { count: 1, latestVuln: "2025-01-01T00:00:00Z", maxSeverity: "medium" },
      },
      integrity,
    };

    await fs.writeFile(path.join(tempDir, "index.json"), JSON.stringify(index));

    const reader = await createStaticDbReader({
      dataPath: tempDir,
      cutoffDate: "2025-12-31",
    });
    assert.ok(reader, "Reader should initialize with scoped package");

    const findings = await reader!.queryPackage("@angular/core");
    assert.equal(findings.length, 1, "Should return the vulnerability from the scoped shard");
    assert.equal(findings[0]?.id, "GHSA-2024-0001");
    assert.equal(findings[0]?.source, "osv", "Source should be preserved as osv");

    // No integrity warning should have been emitted
    const integrityWarnings = warnMessages.filter((m) =>
      m.includes("Shard integrity check failed"),
    );
    assert.equal(integrityWarnings.length, 0, "No integrity warnings for valid scoped shard");
  });

  it("computeShardHash returns sha256- prefixed hex string", () => {
    const buf = Buffer.from("test content", "utf-8");
    const hash = computeShardHash(buf);

    assert.ok(hash.startsWith("sha256-"), "Hash should start with sha256- prefix");
    // SHA-256 hex digest is 64 characters, plus "sha256-" prefix = 71
    assert.equal(hash.length, 71, "Hash should be sha256- + 64 hex chars");

    // Same input → same hash
    const hash2 = computeShardHash(buf);
    assert.equal(hash, hash2, "Deterministic hash for same input");

    // Different input → different hash
    const hash3 = computeShardHash(Buffer.from("different content", "utf-8"));
    assert.notEqual(hash, hash3, "Different input produces different hash");
  });
});
