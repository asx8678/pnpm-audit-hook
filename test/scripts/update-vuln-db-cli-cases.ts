import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import assert from "node:assert/strict";

interface ScriptSandbox {
  rootDir: string;
  dataDir: string;
  scriptPath: string;
}

interface MockAdvisory {
  ghsaId: string;
  packageName: string;
  publishedAt: string;
  updatedAt: string;
  severity?: string;
}

function createScriptSandbox(): ScriptSandbox {
  const rootDir = mkdtempSync(join(tmpdir(), "pnpm-audit-hook-update-db-"));
  cpSync(join(process.cwd(), "scripts"), join(rootDir, "scripts"), { recursive: true });

  const dataDir = join(rootDir, "src", "static-db", "data");
  mkdirSync(dataDir, { recursive: true });

  return {
    rootDir,
    dataDir,
    scriptPath: join(rootDir, "scripts", "update-vuln-db.ts"),
  };
}

function seedStaleStaticDb(dataDir: string): void {
  mkdirSync(join(dataDir, "packages"), { recursive: true });
  mkdirSync(join(dataDir, "@stale-scope"), { recursive: true });
  writeFileSync(join(dataDir, "README.md"), "# Static DB docs\n");
  writeFileSync(join(dataDir, "index.json"), "{\"oldIndex\":true}\n");
  writeFileSync(join(dataDir, "old-root.json"), "{\"oldRoot\":true}\n");
  writeFileSync(join(dataDir, "packages", "leftover.json"), "{\"leftover\":true}\n");
  writeFileSync(join(dataDir, "@stale-scope", "leftover.json"), "{\"leftover\":true}\n");
}

function runUpdateScript(
  sandbox: ScriptSandbox,
  args: string[],
  preloadPath?: string,
): ReturnType<typeof spawnSync> {
  return spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      ...(preloadPath ? ["--import", preloadPath] : []),
      sandbox.scriptPath,
      ...args,
    ],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: { ...process.env, GITHUB_TOKEN: "" },
    },
  );
}

function writeMockFetchModule(sandbox: ScriptSandbox, advisories: MockAdvisory[]): string {
  const nodes = advisories.map((advisory) => ({
    ghsaId: advisory.ghsaId,
    summary: `${advisory.packageName} advisory`,
    description: "Mock advisory description",
    severity: advisory.severity ?? "high",
    publishedAt: advisory.publishedAt,
    updatedAt: advisory.updatedAt,
    permalink: `https://github.com/advisories/${advisory.ghsaId}`,
    identifiers: [{ type: "GHSA", value: advisory.ghsaId }],
    vulnerabilities: {
      nodes: [
        {
          package: { name: advisory.packageName, ecosystem: "NPM" },
          vulnerableVersionRange: "<1.0.0",
          firstPatchedVersion: { identifier: "1.0.0" },
        },
      ],
    },
  }));

  const mockFetchPath = join(sandbox.rootDir, "mock-fetch.mjs");
  writeFileSync(
    mockFetchPath,
    `const response = ${JSON.stringify({
      data: {
        securityAdvisories: {
          pageInfo: { hasNextPage: false, endCursor: null },
          nodes,
        },
      },
    })};\n` +
      `globalThis.fetch = async () => ({\n` +
      `  status: 200,\n` +
      `  ok: true,\n` +
      `  headers: { get: () => null },\n` +
      `  json: async () => response,\n` +
      `});\n`,
  );
  return mockFetchPath;
}

function readIndex(dataDir: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(dataDir, "index.json"), "utf8")) as Record<string, unknown>;
}

function withSandbox(testFn: (sandbox: ScriptSandbox) => void): void {
  const sandbox = createScriptSandbox();
  try {
    testFn(sandbox);
  } finally {
    rmSync(sandbox.rootDir, { recursive: true, force: true });
  }
}

describe("update-vuln-db CLI rebuild safety and coverage modes", () => {
  it("does not clear existing data when a full rebuild receives GraphQL errors", () => {
    withSandbox((sandbox) => {
      seedStaleStaticDb(sandbox.dataDir);
      const mockFetchPath = join(sandbox.rootDir, "mock-fetch.mjs");
      writeFileSync(
        mockFetchPath,
        `globalThis.fetch = async () => ({\n` +
          `  status: 200, ok: true, headers: { get: () => null },\n` +
          `  json: async () => ({ errors: [{ message: "mock GraphQL failure" }] }),\n` +
          `});\n`,
      );

      const result = runUpdateScript(sandbox, [], mockFetchPath);
      const output = `${result.stdout}\n${result.stderr}`;

      assert.equal(result.status, 1, output);
      assert.match(output, /GitHub GraphQL errors/);
      assert.equal(readFileSync(join(sandbox.dataDir, "index.json"), "utf8"), "{\"oldIndex\":true}\n");
      assert.ok(existsSync(join(sandbox.dataDir, "old-root.json")));
      assert.ok(existsSync(join(sandbox.dataDir, "packages", "leftover.json")));
      assert.ok(existsSync(join(sandbox.dataDir, "@stale-scope", "leftover.json")));
    });
  });

  it("clears stale shards during sample rebuild only after sample data is ready", () => {
    withSandbox((sandbox) => {
      seedStaleStaticDb(sandbox.dataDir);

      const result = runUpdateScript(sandbox, ["--sample"]);
      const output = `${result.stdout}\n${result.stderr}`;

      assert.equal(result.status, 0, output);
      assert.match(output, /Non-incremental rebuild data collected; clearing existing shard files/);
      assert.ok(existsSync(join(sandbox.dataDir, "README.md")));
      assert.ok(existsSync(join(sandbox.dataDir, "index.json")));
      assert.ok(existsSync(join(sandbox.dataDir, "lodash.json")));
      assert.ok(!existsSync(join(sandbox.dataDir, "old-root.json")));
      assert.ok(!existsSync(join(sandbox.dataDir, "packages")));
      assert.ok(!existsSync(join(sandbox.dataDir, "@stale-scope")));
    });
  });

  it("writes sample coverage metadata", () => {
    withSandbox((sandbox) => {
      const result = runUpdateScript(sandbox, ["--sample"]);
      assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);

      assert.deepEqual(readIndex(sandbox.dataDir).coverage, {
        mode: "sample",
        ecosystem: "NPM",
        cutoffDate: "2025-12-31T23:59:59Z",
      });
    });
  });

  it("writes full coverage metadata for default full mode", () => {
    withSandbox((sandbox) => {
      const mockFetchPath = writeMockFetchModule(sandbox, [
        {
          ghsaId: "GHSA-full-0001",
          packageName: "full-package",
          publishedAt: "2019-01-01T00:00:00Z",
          updatedAt: "2019-01-02T00:00:00Z",
        },
      ]);

      const result = runUpdateScript(sandbox, [], mockFetchPath);
      assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);

      const index = readIndex(sandbox.dataDir);
      assert.deepEqual(index.coverage, {
        mode: "full",
        ecosystem: "NPM",
        cutoffDate: "2025-12-31T23:59:59Z",
      });
      assert.ok(existsSync(join(sandbox.dataDir, "full-package.json")));
    });
  });

  it("--years filters by publishedAt OR updatedAt and writes recent coverage", () => {
    withSandbox((sandbox) => {
      const mockFetchPath = writeMockFetchModule(sandbox, [
        {
          ghsaId: "GHSA-old-stale",
          packageName: "old-stale-package",
          publishedAt: "2019-01-01T00:00:00Z",
          updatedAt: "2020-01-01T00:00:00Z",
        },
        {
          ghsaId: "GHSA-old-updated",
          packageName: "old-updated-package",
          publishedAt: "2019-01-01T00:00:00Z",
          updatedAt: "2024-01-01T00:00:00Z",
        },
        {
          ghsaId: "GHSA-new-published",
          packageName: "new-published-package",
          publishedAt: "2024-06-01T00:00:00Z",
          updatedAt: "2024-06-02T00:00:00Z",
        },
      ]);

      const result = runUpdateScript(sandbox, ["--years", "5"], mockFetchPath);
      assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);

      const index = readIndex(sandbox.dataDir);
      assert.equal(index.totalPackages, 2);
      assert.equal(index.totalVulnerabilities, 2);
      assert.deepEqual(Object.keys(index.packages as Record<string, unknown>).sort(), [
        "new-published-package",
        "old-updated-package",
      ]);
      assert.deepEqual(index.coverage, {
        mode: "recent",
        ecosystem: "NPM",
        cutoffDate: "2025-12-31T23:59:59Z",
        sinceDate: "2020-12-31T23:59:59.000Z",
        retentionYears: 5,
      });
      assert.ok(!existsSync(join(sandbox.dataDir, "old-stale-package.json")));
    });
  });

  it("invalid --years fails before cleanup and preserves stale DB", () => {
    withSandbox((sandbox) => {
      seedStaleStaticDb(sandbox.dataDir);

      const result = runUpdateScript(sandbox, ["--years", "nope"]);
      const output = `${result.stdout}\n${result.stderr}`;

      assert.equal(result.status, 1, output);
      assert.match(output, /Invalid --years value/);
      assert.equal(readFileSync(join(sandbox.dataDir, "index.json"), "utf8"), "{\"oldIndex\":true}\n");
      assert.ok(existsSync(join(sandbox.dataDir, "packages", "leftover.json")));
    });
  });

  it("rejects ambiguous --since plus --years before cleanup", () => {
    withSandbox((sandbox) => {
      seedStaleStaticDb(sandbox.dataDir);

      const result = runUpdateScript(sandbox, ["--since=2024-01-01T00:00:00Z", "--years", "1"]);
      const output = `${result.stdout}\n${result.stderr}`;

      assert.equal(result.status, 1, output);
      assert.match(output, /Use either --since or --years/);
      assert.equal(readFileSync(join(sandbox.dataDir, "index.json"), "utf8"), "{\"oldIndex\":true}\n");
    });
  });
});
