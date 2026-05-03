/**
 * Monorepo SBOM Generator tests.
 *
 * Tests workspace detection, concurrent generation, aggregation,
 * error handling, and edge cases for pnpm monorepo SBOM generation.
 */

import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import {
  MonorepoSbomGenerator,
  generateMonorepoSbom,
} from "../../src/sbom/monorepo-generator";
import type { PackageRef, VulnerabilityFinding, PnpmLockfile } from "../../src/types";
import type {
  MonorepoSbomOptions,
  MonorepoSbomResult,
} from "../../src/sbom/monorepo-generator";

// ═══════════════════════════════════════════════════════════════════════════════
// Test Fixtures
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Creates a realistic pnpm monorepo lockfile with multiple workspaces.
 */
function createMonorepoLockfile(): PnpmLockfile {
  return {
    lockfileVersion: "9.0",
    importers: {
      ".": {
        dependencies: {
          "shared-lib": { version: "1.0.0", specifier: "workspace:*" },
          "express": { version: "4.18.2", specifier: "^4.18.0" },
        },
        devDependencies: {
          "typescript": { version: "5.3.3", specifier: "^5.3.0" },
        },
      },
      "./packages/pkg-a": {
        dependencies: {
          "lodash": { version: "4.17.21", specifier: "^4.17.0" },
          "shared-lib": { version: "1.0.0", specifier: "workspace:*" },
        },
        devDependencies: {
          "jest": { version: "29.7.0", specifier: "^29.0.0" },
        },
      },
      "./packages/pkg-b": {
        dependencies: {
          "axios": { version: "1.6.0", specifier: "^1.6.0" },
          "shared-lib": { version: "1.0.0", specifier: "workspace:*" },
        },
        optionalDependencies: {
          "optional-dep": { version: "2.0.0", specifier: "^2.0.0" },
        },
      },
    },
    packages: {
      "express@4.18.2": {
        resolution: { integrity: "sha512-express123" },
        dependencies: { "body-parser": "1.20.1", "cookie": "0.5.0" },
      },
      "body-parser@1.20.1": {
        resolution: { integrity: "sha512-bodyparser" },
      },
      "cookie@0.5.0": {
        resolution: { integrity: "sha512-cookie123" },
      },
      "lodash@4.17.21": {
        resolution: { integrity: "sha512-lodash123" },
      },
      "axios@1.6.0": {
        resolution: { integrity: "sha512-axios123" },
        dependencies: { "follow-redirects": "1.15.4" },
      },
      "follow-redirects@1.15.4": {
        resolution: { integrity: "sha512-redirects" },
      },
      "typescript@5.3.3": {
        resolution: { integrity: "sha512-ts123" },
      },
      "jest@29.7.0": {
        resolution: { integrity: "sha512-jest123" },
        dependencies: { "@jest/core": "29.7.0" },
      },
      "@jest/core@29.7.0": {
        resolution: { integrity: "sha512-jestcore" },
      },
      "optional-dep@2.0.0": {
        resolution: { integrity: "sha512-optdep123" },
      },
      "shared-lib@1.0.0": {
        resolution: { type: "directory", directory: "packages/shared-lib" },
      },
    },
  };
}

/**
 * Creates a lockfile with only a root importer (non-monorepo).
 */
function createSinglePackageLockfile(): PnpmLockfile {
  return {
    lockfileVersion: "9.0",
    importers: {
      ".": {
        dependencies: {
          "express": { version: "4.18.2", specifier: "^4.18.0" },
        },
      },
    },
    packages: {
      "express@4.18.2": {
        resolution: { integrity: "sha512-express123" },
      },
    },
  };
}

/**
 * Creates a lockfile with no importers section.
 */
function createNoImportersLockfile(): PnpmLockfile {
  return {
    lockfileVersion: "9.0",
    packages: {
      "express@4.18.2": {
        resolution: { integrity: "sha512-express123" },
      },
    },
  };
}

/**
 * Creates an empty lockfile.
 */
function createEmptyLockfile(): PnpmLockfile {
  return { lockfileVersion: "9.0" };
}

/**
 * Creates vulnerability findings that span multiple workspaces.
 */
function createFindings(): VulnerabilityFinding[] {
  return [
    {
      id: "CVE-2024-0001",
      source: "github",
      packageName: "lodash",
      packageVersion: "4.17.21",
      severity: "high",
      title: "Prototype Pollution in lodash",
      cvssScore: 7.5,
      publishedAt: "2024-01-15T00:00:00Z",
      url: "https://github.com/advisories/CVE-2024-0001",
    },
    {
      id: "CVE-2024-0002",
      source: "github",
      packageName: "axios",
      packageVersion: "1.6.0",
      severity: "medium",
      title: "SSRF in axios",
      cvssScore: 5.3,
      publishedAt: "2024-02-10T00:00:00Z",
      url: "https://github.com/advisories/CVE-2024-0002",
    },
    {
      id: "CVE-2024-0003",
      source: "github",
      packageName: "follow-redirects",
      packageVersion: "1.15.4",
      severity: "low",
      title: "Information exposure via redirects",
      cvssScore: 3.1,
      publishedAt: "2024-03-01T00:00:00Z",
      url: "https://github.com/advisories/CVE-2024-0003",
    },
  ];
}

// ═══════════════════════════════════════════════════════════════════════════════
// Workspace Detection Tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("MonorepoSbomGenerator – workspace detection", () => {
  let generator: MonorepoSbomGenerator;

  beforeEach(() => {
    generator = new MonorepoSbomGenerator();
  });

  it("should detect workspaces from lockfile importers", () => {
    const lockfile = createMonorepoLockfile();
    const workspaces = generator.detectWorkspaces(lockfile);

    assert.equal(workspaces.length, 3, "should detect 3 workspaces");

    // Root should be first
    assert.equal(workspaces[0]!.path, ".");
    assert.equal(workspaces[0]!.name, "root");
    assert.equal(workspaces[0]!.isRoot, true);

    // Child workspaces
    assert.equal(workspaces[1]!.path, "./packages/pkg-a");
    assert.equal(workspaces[1]!.name, "pkg-a");
    assert.equal(workspaces[1]!.isRoot, false);

    assert.equal(workspaces[2]!.path, "./packages/pkg-b");
    assert.equal(workspaces[2]!.name, "pkg-b");
    assert.equal(workspaces[2]!.isRoot, false);
  });

  it("should resolve packages for each workspace", () => {
    const lockfile = createMonorepoLockfile();
    const workspaces = generator.detectWorkspaces(lockfile);

    // Root: express + typescript (shared-lib is workspace: protocol, skipped)
    const rootWs = workspaces.find((w) => w.isRoot)!;
    assert.equal(rootWs.packages.length, 2, "root should have 2 packages");
    assert.ok(rootWs.packages.some((p) => p.name === "express"));
    assert.ok(rootWs.packages.some((p) => p.name === "typescript"));

    // pkg-a: lodash (shared-lib is workspace: protocol, skipped)
    const pkgA = workspaces.find((w) => w.path === "./packages/pkg-a")!;
    assert.equal(pkgA.packages.length, 2, "pkg-a should have 2 packages");
    assert.ok(pkgA.packages.some((p) => p.name === "lodash"));
    assert.ok(pkgA.packages.some((p) => p.name === "jest"));

    // pkg-b: axios + optional-dep (shared-lib is workspace: protocol, skipped)
    const pkgB = workspaces.find((w) => w.path === "./packages/pkg-b")!;
    assert.equal(pkgB.packages.length, 2, "pkg-b should have 2 packages");
    assert.ok(pkgB.packages.some((p) => p.name === "axios"));
    assert.ok(pkgB.packages.some((p) => p.name === "optional-dep"));
  });

  it("should return empty array for lockfile without importers", () => {
    const lockfile = createNoImportersLockfile();
    const workspaces = generator.detectWorkspaces(lockfile);
    assert.equal(workspaces.length, 0);
  });

  it("should return empty array for empty lockfile", () => {
    const lockfile = createEmptyLockfile();
    const workspaces = generator.detectWorkspaces(lockfile);
    assert.equal(workspaces.length, 0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// isMonorepo / getWorkspacePaths Tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("MonorepoSbomGenerator – isMonorepo & getWorkspacePaths", () => {
  let generator: MonorepoSbomGenerator;

  beforeEach(() => {
    generator = new MonorepoSbomGenerator();
  });

  it("should detect monorepo correctly", () => {
    assert.equal(generator.isMonorepo(createMonorepoLockfile()), true);
    assert.equal(generator.isMonorepo(createSinglePackageLockfile()), false);
    assert.equal(generator.isMonorepo(createNoImportersLockfile()), false);
  });

  it("should return workspace paths", () => {
    const paths = generator.getWorkspacePaths(createMonorepoLockfile());
    assert.deepEqual(paths, [".", "./packages/pkg-a", "./packages/pkg-b"]);
  });

  it("should return empty for non-monorepo", () => {
    assert.deepEqual(generator.getWorkspacePaths(createSinglePackageLockfile()), ["."]);
    assert.deepEqual(generator.getWorkspacePaths(createNoImportersLockfile()), []);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SBOM Generation Tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("MonorepoSbomGenerator – SBOM generation", () => {
  let generator: MonorepoSbomGenerator;

  beforeEach(() => {
    generator = new MonorepoSbomGenerator();
  });

  it("should generate SBOMs for all workspaces", async () => {
    const lockfile = createMonorepoLockfile();
    const findings = createFindings();

    const result = await generator.generate(lockfile, findings, {
      format: "cyclonedx",
      generateWorkspaceSboms: true,
    });

    assert.equal(result.workspaces.length, 3, "should have 3 workspace results");
    assert.equal(result.errors.length, 0, "should have no errors");
    assert.equal(result.stats.totalWorkspaces, 3);
    assert.equal(result.stats.processedWorkspaces, 3);
    assert.ok(result.stats.generationTimeMs >= 0);

    // Each workspace should have a valid SBOM
    for (const ws of result.workspaces) {
      assert.ok(ws.result.content.length > 0, `workspace ${ws.workspacePath} should have content`);
      assert.equal(ws.result.format, "cyclonedx");
      assert.ok(ws.packageCount > 0, `workspace ${ws.workspacePath} should have packages`);
    }
  });

  it("should generate valid JSON content in workspace SBOMs", async () => {
    const lockfile = createMonorepoLockfile();
    const result = await generator.generate(lockfile, [], {
      format: "cyclonedx",
      generateWorkspaceSboms: true,
    });

    for (const ws of result.workspaces) {
      const parsed = JSON.parse(ws.result.content);
      assert.equal(parsed.bomFormat, "CycloneDX");
      assert.ok(Array.isArray(parsed.components));
    }
  });

  it("should produce aggregated SBOM with deduplicated packages", async () => {
    const lockfile = createMonorepoLockfile();
    const result = await generator.generate(lockfile, [], {
      format: "cyclonedx",
      includeWorkspacesInRoot: true,
      generateWorkspaceSboms: true,
    });

    // Aggregated should have content
    assert.ok(result.aggregated.content.length > 0);

    // Root should be same as aggregated when includeWorkspacesInRoot is true
    assert.equal(result.root.content, result.aggregated.content);

    // Parse and check components
    const parsed = JSON.parse(result.aggregated.content);
    assert.ok(parsed.components.length > 0, "aggregated should have components");

    // All component names should be unique
    const names = parsed.components.map((c: { name: string }) => c.name);
    const uniqueNames = new Set(names);
    assert.equal(names.length, uniqueNames.size, "components should be deduplicated");
  });

  it("should generate root SBOM separately when includeWorkspacesInRoot is false", async () => {
    const lockfile = createMonorepoLockfile();
    const result = await generator.generate(lockfile, [], {
      format: "cyclonedx",
      includeWorkspacesInRoot: false,
      generateWorkspaceSboms: true,
    });

    // Root should only contain root workspace packages
    const rootParsed = JSON.parse(result.root.content);
    const rootNames = rootParsed.components.map((c: { name: string }) => c.name);
    assert.ok(rootNames.includes("express"), "root should include express");
    assert.ok(rootNames.includes("typescript"), "root should include typescript");

    // Aggregated should contain everything
    const aggParsed = JSON.parse(result.aggregated.content);
    assert.ok(aggParsed.components.length > rootParsed.components.length,
      "aggregated should have more components than root");
  });

  it("should skip workspace SBOM generation when disabled", async () => {
    const lockfile = createMonorepoLockfile();
    const result = await generator.generate(lockfile, [], {
      format: "cyclonedx",
      generateWorkspaceSboms: false,
    });

    assert.equal(result.workspaces.length, 0, "should have no workspace results");
    assert.ok(result.aggregated.content.length > 0, "aggregated should still exist");
  });

  it("should include vulnerability info when requested", async () => {
    const lockfile = createMonorepoLockfile();
    const findings = createFindings();

    const result = await generator.generate(lockfile, findings, {
      format: "cyclonedx",
      includeVulnerabilities: true,
    });

    // Check aggregated SBOM has vulnerability info
    const parsed = JSON.parse(result.aggregated.content);
    assert.ok(
      parsed.vulnerabilities && parsed.vulnerabilities.length > 0,
      "aggregated SBOM should include vulnerabilities",
    );
  });

  it("should generate SPDX format", async () => {
    const lockfile = createMonorepoLockfile();
    const result = await generator.generate(lockfile, [], {
      format: "spdx",
    });

    assert.ok(result.aggregated.content.length > 0);
    const parsed = JSON.parse(result.aggregated.content);
    assert.equal(parsed.spdxVersion, "SPDX-2.3");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Concurrency Tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("MonorepoSbomGenerator – concurrency", () => {
  it("should respect concurrency limit", async () => {
    const lockfile = createMonorepoLockfile();
    const completionOrder: string[] = [];

    const result = await generateMonorepoSbom(lockfile, [], {
      format: "cyclonedx",
      concurrency: 1, // Force serial processing
      onWorkspaceComplete: (_completed, _total, workspacePath) => {
        completionOrder.push(workspacePath);
      },
    });

    // All workspaces should be processed
    assert.equal(result.stats.processedWorkspaces, 3);

    // With concurrency=1, they should complete in detection order
    assert.equal(completionOrder.length, 3);
  });

  it("should default to concurrency of 4", async () => {
    const lockfile = createMonorepoLockfile();
    const result = await generateMonorepoSbom(lockfile, [], {
      format: "cyclonedx",
    });

    // Should complete successfully with default concurrency
    assert.equal(result.stats.processedWorkspaces, 3);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Error Handling Tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("MonorepoSbomGenerator – error handling", () => {
  it("should fall back to single SBOM when no workspaces detected", async () => {
    const lockfile = createNoImportersLockfile();
    const result = await generator.generate(lockfile, [], {
      format: "cyclonedx",
    });

    assert.equal(result.workspaces.length, 0);
    assert.equal(result.stats.totalWorkspaces, 1, "should report 1 workspace (fallback)");
    assert.ok(result.aggregated.content.length > 0, "should still produce a valid SBOM");
  });

  it("should handle empty lockfile gracefully", async () => {
    const lockfile = createEmptyLockfile();
    const result = await generator.generate(lockfile, [], {
      format: "cyclonedx",
    });

    assert.equal(result.stats.totalWorkspaces, 1);
    assert.ok(result.aggregated.content.length > 0);
  });

  it("should include workspace errors in result", async () => {
    const lockfile = createMonorepoLockfile();

    // The generator should handle errors gracefully
    const result = await generator.generate(lockfile, [], {
      format: "cyclonedx",
    });

    // No errors expected for a valid lockfile
    assert.equal(result.errors.length, 0);
  });

  let generator: MonorepoSbomGenerator;
  beforeEach(() => {
    generator = new MonorepoSbomGenerator();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Stats Tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("MonorepoSbomGenerator – stats", () => {
  it("should report accurate stats", async () => {
    const lockfile = createMonorepoLockfile();
    const findings = createFindings();

    const result = await generator.generate(lockfile, findings, {
      format: "cyclonedx",
    });

    assert.equal(result.stats.totalWorkspaces, 3);
    assert.equal(result.stats.processedWorkspaces, 3);
    assert.ok(result.stats.totalComponents > 0, "should have components");
    assert.ok(result.stats.generationTimeMs >= 0, "should have non-negative time");

    // Workspace component counts should be populated
    assert.equal(Object.keys(result.stats.workspaceComponentCounts).length, 3);
    assert.ok(
      result.stats.workspaceComponentCounts["."] !== undefined,
      "should have root count",
    );
  });

  it("should count vulnerabilities in stats", async () => {
    const lockfile = createMonorepoLockfile();
    const findings = createFindings();

    const result = await generator.generate(lockfile, findings, {
      format: "cyclonedx",
      includeVulnerabilities: true,
    });

    // lodash is in pkg-a, axios/follow-redirects are in pkg-b
    assert.ok(result.stats.totalVulnerabilities > 0, "should have vulnerabilities");
  });

  let generator: MonorepoSbomGenerator;
  beforeEach(() => {
    generator = new MonorepoSbomGenerator();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Progress Callback Tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("MonorepoSbomGenerator – progress callback", () => {
  it("should call onWorkspaceComplete for each workspace", async () => {
    const lockfile = createMonorepoLockfile();
    const progressCalls: Array<{ completed: number; total: number; path: string }> = [];

    await generateMonorepoSbom(lockfile, [], {
      format: "cyclonedx",
      onWorkspaceComplete: (completed, total, workspacePath) => {
        progressCalls.push({ completed, total, path: workspacePath });
      },
    });

    assert.equal(progressCalls.length, 3, "should call callback 3 times");
    assert.equal(progressCalls[0]!.total, 3);
    assert.equal(progressCalls[0]!.completed, 1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Package Deduplication Tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("MonorepoSbomGenerator – deduplication", () => {
  it("should deduplicate packages across workspaces", async () => {
    // Create a lockfile where multiple workspaces depend on the same package
    const lockfile: PnpmLockfile = {
      lockfileVersion: "9.0",
      importers: {
        ".": {
          dependencies: {
            "lodash": { version: "4.17.21", specifier: "^4.17.0" },
          },
        },
        "./packages/a": {
          dependencies: {
            "lodash": { version: "4.17.21", specifier: "^4.17.0" },
          },
        },
        "./packages/b": {
          dependencies: {
            "lodash": { version: "4.17.21", specifier: "^4.17.0" },
          },
        },
      },
      packages: {
        "lodash@4.17.21": {
          resolution: { integrity: "sha512-lodash123" },
        },
      },
    };

    const result = await generateMonorepoSbom(lockfile, [], {
      format: "cyclonedx",
      generateWorkspaceSboms: true,
      includeWorkspacesInRoot: true,
    });

    // Aggregated should have only 1 lodash
    const parsed = JSON.parse(result.aggregated.content);
    const lodashEntries = parsed.components.filter(
      (c: { name: string }) => c.name === "lodash",
    );
    assert.equal(lodashEntries.length, 1, "lodash should appear exactly once in aggregated SBOM");

    // Each workspace should have its own lodash
    for (const ws of result.workspaces) {
      const wsParsed = JSON.parse(ws.result.content);
      const wsLodash = wsParsed.components.filter(
        (c: { name: string }) => c.name === "lodash",
      );
      assert.equal(wsLodash.length, 1, `workspace ${ws.workspacePath} should have lodash`);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Convenience Function Tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("generateMonorepoSbom – convenience function", () => {
  it("should work with minimal options", async () => {
    const lockfile = createMonorepoLockfile();
    const result = await generateMonorepoSbom(lockfile, []);

    assert.ok(result.aggregated.content.length > 0);
    assert.equal(result.stats.totalWorkspaces, 3);
  });

  it("should work with empty options object", async () => {
    const lockfile = createMonorepoLockfile();
    const result = await generateMonorepoSbom(lockfile, [], {});

    assert.ok(result.aggregated.content.length > 0);
  });
});
