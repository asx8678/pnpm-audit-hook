import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { createStaticDbReader } from "../../src/static-db/reader";

describe("StaticDbReader compatibility", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pnpm-audit-static-db-"));
    await fs.mkdir(path.join(tempDir, "packages"), { recursive: true });
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it("loads legacy packages/ shards and filters by version", async () => {
    const index = {
      schemaVersion: 1,
      lastUpdated: "2025-01-01T00:00:00Z",
      cutoffDate: "2025-12-31",
      totalVulnerabilities: 1,
      totalPackages: 1,
      packages: {
        lodash: { vulnCount: 1, lastModified: "2025-01-01T00:00:00Z" },
      },
    };
    await fs.writeFile(
      path.join(tempDir, "index.json"),
      JSON.stringify(index),
    );

    const shard = {
      name: "lodash",
      lastUpdated: "2025-01-01T00:00:00Z",
      vulnerabilities: [
        {
          id: "CVE-2024-0001",
          severity: "high",
          publishedAt: "2024-01-01T00:00:00Z",
          affectedRange: "<4.17.21",
          fixedVersion: "4.17.21",
        },
      ],
    };
    await fs.writeFile(
      path.join(tempDir, "packages", "lodash.json"),
      JSON.stringify(shard),
    );

    const reader = await createStaticDbReader({
      dataPath: tempDir,
      cutoffDate: "2025-12-31",
    });
    assert.ok(reader);

    const findings = await reader!.queryPackageWithOptions("lodash", {
      version: "4.17.0",
    });
    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.packageName, "lodash");

    const none = await reader!.queryPackageWithOptions("lodash", {
      version: "5.0.0",
    });
    assert.equal(none.length, 0);
  });
});
