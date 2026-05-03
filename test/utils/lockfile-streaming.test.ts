import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import {
  StreamingLockfileParser,
  parseLockfileStreaming,
} from "../../src/utils/lockfile/streaming-parser.js";
import {
  extractPackagesFromLockfile,
  extractPackagesFromLockfileStreaming,
} from "../../src/utils/lockfile/package-extractor.js";
import type { PnpmLockfile } from "../../src/types.js";

// =============================================================================
// Test Helpers
// =============================================================================

/**
 * Generate a synthetic pnpm lockfile for testing.
 */
function generateLockfile(
  packageCount: number,
  options: {
    registryRatio?: number; // Ratio of registry packages (0-1)
    scopedRatio?: number;   // Ratio of scoped packages (0-1)
    withDeps?: boolean;     // Include dependency entries
  } = {},
): PnpmLockfile {
  const {
    registryRatio = 0.9,
    scopedRatio = 0.2,
    withDeps = true,
  } = options;

  const packages: Record<string, any> = {};
  const registryPackages: string[] = [];

  for (let i = 0; i < packageCount; i++) {
    const isScoped = i % Math.round(1 / scopedRatio) === 0;
    const name = isScoped ? `@scope/pkg${i}` : `pkg${i}`;
    const version = `${1 + (i % 10)}.0.${i}`;
    const key = `${name}@${version}`;

    const isRegistry = i / packageCount < registryRatio;

    if (isRegistry) {
      // Registry package with integrity
      packages[key] = {
        resolution: { integrity: `sha512-${i.toString().padStart(3, "0")}` },
        dependencies: withDeps && i % 3 === 0 ? { [`${name}-dep`]: `${version}` } : undefined,
      };
      registryPackages.push(key);
    } else {
      // Non-registry package (directory, link, or git)
      const type = i % 3;
      if (type === 0) {
        packages[key] = {
          resolution: { directory: `../local-${i}`, type: "directory" },
        };
      } else if (type === 1) {
        packages[key] = {
          resolution: { path: `../link-${i}` },
        };
      } else {
        packages[key] = {
          resolution: {}, // Git or other non-registry
        };
      }
    }
  }

  return {
    lockfileVersion: "9.0",
    packages,
    importers: {
      ".": {
        dependencies: registryPackages.slice(0, 10).reduce((acc, key) => {
          const name = key.split("@")[0]!;
          acc[name] = key.split("@").slice(1).join("@");
          return acc;
        }, {} as Record<string, string>),
      },
    },
  };
}

/**
 * Generate lockfile with specific patterns for edge case testing.
 */
function generateEdgeCaseLockfile(): PnpmLockfile {
  return {
    lockfileVersion: "9.0",
    packages: {
      // Valid registry packages
      "lodash@4.17.21": {
        resolution: { integrity: "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1k0XDi77M75Wl10gRnT9tW9G6p4N25A79JL3bQ1zC0R5n6Q==" },
      },
      "@types/node@20.10.0": {
        resolution: { integrity: "sha512-abc123" },
      },
      // Package with peer suffix
      "react-dom@18.2.0(react@18.2.0)": {
        resolution: { integrity: "sha512-def456" },
      },
      // Non-registry packages
      "file:../local-pkg": {
        resolution: { directory: "../local-pkg", type: "directory" },
      },
      "link:../sibling": {
        resolution: { path: "../sibling" },
      },
      // HTTP tarball (registry-like)
      "custom-pkg@1.0.0": {
        resolution: { tarball: "https://example.com/pkg.tgz" },
      },
      // File tarball (non-registry)
      "local-tarball@1.0.0": {
        resolution: { tarball: "file:./local.tgz" },
      },
    },
  };
}

// =============================================================================
// Tests
// =============================================================================

describe("StreamingLockfileParser", () => {
  describe("constructor", () => {
    it("creates parser with default options", () => {
      const parser = new StreamingLockfileParser();
      assert.ok(parser instanceof StreamingLockfileParser);
    });

    it("creates parser with custom options", () => {
      const parser = new StreamingLockfileParser({
        batchSize: 50,
        maxMemoryMB: 200,
        onProgress: () => {},
      });
      assert.ok(parser instanceof StreamingLockfileParser);
    });

    it("throws on invalid batchSize", () => {
      assert.throws(
        () => new StreamingLockfileParser({ batchSize: 0 }),
        /batchSize must be positive/,
      );
    });

    it("throws on invalid maxMemoryMB", () => {
      assert.throws(
        () => new StreamingLockfileParser({ maxMemoryMB: -1 }),
        /maxMemoryMB must be positive/,
      );
    });
  });

  describe("parse - small lockfiles", () => {
    it("handles null lockfile", () => {
      const parser = new StreamingLockfileParser();
      const result = parser.parse(null);

      assert.equal(result.packages.length, 0);
      assert.equal(result.stats.totalProcessed, 0);
      assert.equal(result.stats.registryPackages, 0);
      assert.equal(result.stats.skippedPackages, 0);
      assert.ok(result.stats.durationMs >= 0);
      assert.ok(result.stats.peakMemoryMB > 0);
    });

    it("handles undefined lockfile", () => {
      const parser = new StreamingLockfileParser();
      const result = parser.parse(undefined);

      assert.equal(result.packages.length, 0);
      assert.equal(result.stats.totalProcessed, 0);
    });

    it("handles empty lockfile", () => {
      const parser = new StreamingLockfileParser();
      const result = parser.parse({});

      assert.equal(result.packages.length, 0);
      assert.equal(result.stats.totalProcessed, 0);
    });

    it("handles lockfile with empty packages", () => {
      const parser = new StreamingLockfileParser();
      const result = parser.parse({
        packages: {},
        importers: { ".": { dependencies: {} } },
      });

      assert.equal(result.packages.length, 0);
      assert.equal(result.stats.totalProcessed, 0);
    });

    it("extracts packages from small lockfile", () => {
      const lockfile = generateEdgeCaseLockfile();
      const parser = new StreamingLockfileParser();
      const result = parser.parse(lockfile);

      // Should extract: lodash, @types/node, react-dom, custom-pkg (HTTP tarball)
      assert.equal(result.packages.length, 4);
      assert.equal(result.stats.registryPackages, 4);
      assert.equal(result.stats.skippedPackages, 3); // file, link, local-tarball
      assert.equal(result.stats.totalProcessed, 7);
    });

    it("extracts scoped packages correctly", () => {
      const lockfile: PnpmLockfile = {
        packages: {
          "@types/node@20.10.0": {
            resolution: { integrity: "sha512-abc" },
          },
          "@babel/core@7.23.0": {
            resolution: { integrity: "sha512-def" },
          },
        },
      };

      const parser = new StreamingLockfileParser();
      const result = parser.parse(lockfile);

      assert.equal(result.packages.length, 2);
      const names = result.packages.map((p) => p.name).sort();
      assert.deepEqual(names, ["@babel/core", "@types/node"]);
    });

    it("handles old format package keys", () => {
      const lockfile: PnpmLockfile = {
        packages: {
          "/lodash/4.17.21": {
            resolution: { integrity: "sha512-abc" },
          },
          "/@types/node/20.10.0": {
            resolution: { integrity: "sha512-def" },
          },
        },
      };

      const parser = new StreamingLockfileParser();
      const result = parser.parse(lockfile);

      assert.equal(result.packages.length, 2);
      const names = result.packages.map((p) => p.name).sort();
      assert.deepEqual(names, ["@types/node", "lodash"]);
    });
  });

  describe("parse - large lockfiles (batch processing)", () => {
    it("processes large lockfile in batches", () => {
      const lockfile = generateLockfile(500);
      const parser = new StreamingLockfileParser({ batchSize: 100 });
      const result = parser.parse(lockfile);

      // Should extract most packages as registry packages
      assert.ok(result.packages.length > 400);
      assert.equal(result.stats.totalProcessed, 500);
      assert.ok(result.stats.durationMs >= 0);
    });

    it("reports progress during batch processing", () => {
      const lockfile = generateLockfile(250);
      const progressUpdates: Array<{ processed: number; total: number }> = [];

      const parser = new StreamingLockfileParser({
        batchSize: 50,
        onProgress: (processed, total) => {
          progressUpdates.push({ processed, total });
        },
      });

      parser.parse(lockfile);

      // Should have progress updates
      assert.ok(progressUpdates.length > 0);

      // Progress should be monotonically increasing
      for (let i = 1; i < progressUpdates.length; i++) {
        assert.ok(
          progressUpdates[i]!.processed >= progressUpdates[i - 1]!.processed,
          "Progress should be monotonically increasing",
        );
      }

      // Final progress should equal total
      const lastUpdate = progressUpdates[progressUpdates.length - 1]!;
      assert.equal(lastUpdate.processed, lastUpdate.total);
    });

    it("handles different batch sizes", () => {
      const lockfile = generateLockfile(100);

      const parser1 = new StreamingLockfileParser({ batchSize: 10 });
      const result1 = parser1.parse(lockfile);

      const parser2 = new StreamingLockfileParser({ batchSize: 100 });
      const result2 = parser2.parse(lockfile);

      // Both should produce same results
      assert.equal(result1.packages.length, result2.packages.length);
      assert.equal(result1.stats.registryPackages, result2.stats.registryPackages);
    });

    it("tracks peak memory usage", () => {
      const lockfile = generateLockfile(1000);
      const parser = new StreamingLockfileParser({ batchSize: 100 });
      const result = parser.parse(lockfile);

      assert.ok(result.stats.peakMemoryMB > 0, "Peak memory should be positive");
    });
  });

  describe("parse - edge cases", () => {
    it("handles mix of valid and invalid package keys", () => {
      const lockfile: PnpmLockfile = {
        packages: {
          "lodash@4.17.21": {
            resolution: { integrity: "sha512-abc" },
          },
          "": {
            resolution: { integrity: "sha512-def" },
          },
          "invalid": {
            resolution: { integrity: "sha512-ghi" },
          },
          "@types/node@20.10.0": {
            resolution: { integrity: "sha512-jkl" },
          },
        },
      };

      const parser = new StreamingLockfileParser();
      const result = parser.parse(lockfile);

      // Should only extract valid packages
      assert.equal(result.packages.length, 2);
      const names = result.packages.map((p) => p.name).sort();
      assert.deepEqual(names, ["@types/node", "lodash"]);
    });

    it("handles packages without resolution", () => {
      const lockfile: PnpmLockfile = {
        packages: {
          "lodash@4.17.21": {
            resolution: { integrity: "sha512-abc" },
          },
          "no-resolution@1.0.0": {},
          "empty-resolution@1.0.0": {
            resolution: {},
          },
        },
      };

      const parser = new StreamingLockfileParser();
      const result = parser.parse(lockfile);

      assert.equal(result.packages.length, 1);
      assert.equal(result.packages[0]!.name, "lodash");
    });

    it("maintains consistency with standard extraction", () => {
      const lockfile = generateEdgeCaseLockfile();

      const standardResult = extractPackagesFromLockfile(lockfile);
      const streamingParser = new StreamingLockfileParser();
      const streamingResult = streamingParser.parse(lockfile);

      // Should produce same packages (order may differ)
      const standardNames = standardResult.packages.map((p) => `${p.name}@${p.version}`).sort();
      const streamingNames = streamingResult.packages.map((p) => `${p.name}@${p.version}`).sort();

      assert.deepEqual(standardNames, streamingNames);
    });
  });

  describe("performance", () => {
    it("processes 1000 packages efficiently", () => {
      const lockfile = generateLockfile(1000);
      const parser = new StreamingLockfileParser({ batchSize: 100 });

      const startTime = performance.now();
      const result = parser.parse(lockfile);
      const elapsed = performance.now() - startTime;

      assert.ok(elapsed < 1000, `Should process 1000 packages in under 1s, took ${elapsed.toFixed(2)}ms`);
      assert.ok(result.packages.length > 800, "Should extract most packages");
    });
  });
});

describe("parseLockfileStreaming", () => {
  it("parses lockfile with default options", () => {
    const lockfile = generateEdgeCaseLockfile();
    const result = parseLockfileStreaming(lockfile);

    assert.equal(result.packages.length, 4);
    assert.ok(result.stats.durationMs >= 0);
  });

  it("parses lockfile with custom options", () => {
    const lockfile = generateLockfile(200);
    const progressCalls: number[] = [];

    const result = parseLockfileStreaming(lockfile, {
      batchSize: 50,
      onProgress: (processed) => {
        progressCalls.push(processed);
      },
    });

    assert.ok(result.packages.length > 0);
    assert.ok(progressCalls.length > 0);
  });

  it("handles null lockfile", () => {
    const result = parseLockfileStreaming(null);
    assert.equal(result.packages.length, 0);
  });
});

describe("extractPackagesFromLockfileStreaming", () => {
  describe("small lockfile (below threshold)", () => {
    it("uses standard extraction for small lockfiles", () => {
      const lockfile = generateEdgeCaseLockfile();
      const result = extractPackagesFromLockfileStreaming(lockfile, {}, 100);

      // Should work like standard extraction
      assert.equal(result.packages.length, 4);
      assert.equal(result.stats.totalProcessed, 7);
    });

    it("returns statistics for small lockfiles", () => {
      const lockfile = generateEdgeCaseLockfile();
      const result = extractPackagesFromLockfileStreaming(lockfile, {}, 100);

      assert.ok(result.stats.durationMs >= 0);
      assert.ok(result.stats.peakMemoryMB > 0);
      assert.equal(result.stats.registryPackages, 4);
      assert.equal(result.stats.skippedPackages, 3);
    });
  });

  describe("large lockfile (above threshold)", () => {
    it("uses streaming parser for large lockfiles", () => {
      const lockfile = generateLockfile(1500);
      const progressUpdates: Array<{ processed: number; total: number }> = [];

      const result = extractPackagesFromLockfileStreaming(
        lockfile,
        {
          batchSize: 200,
          onProgress: (processed, total) => {
            progressUpdates.push({ processed, total });
          },
        },
        1000, // threshold
      );

      assert.ok(result.packages.length > 1000);
      assert.equal(result.stats.totalProcessed, 1500);
      assert.ok(progressUpdates.length > 0);
    });

    it("respects custom threshold", () => {
      const lockfile = generateLockfile(100);

      // With high threshold, should use standard extraction
      const result1 = extractPackagesFromLockfileStreaming(lockfile, {}, 1000);
      assert.ok(result1.stats.durationMs >= 0);

      // With low threshold, should use streaming
      const result2 = extractPackagesFromLockfileStreaming(lockfile, {}, 50);
      assert.ok(result2.stats.durationMs >= 0);

      // Both should produce same results
      assert.equal(result1.packages.length, result2.packages.length);
    });
  });

  describe("edge cases", () => {
    it("handles null lockfile", () => {
      const result = extractPackagesFromLockfileStreaming(null);
      assert.equal(result.packages.length, 0);
      assert.equal(result.stats.totalProcessed, 0);
    });

    it("handles empty lockfile", () => {
      const result = extractPackagesFromLockfileStreaming({});
      assert.equal(result.packages.length, 0);
    });

    it("handles lockfile with only non-registry packages", () => {
      const lockfile: PnpmLockfile = {
        packages: {
          "file:../local-pkg": {
            resolution: { directory: "../local-pkg", type: "directory" },
          },
          "link:../sibling": {
            resolution: { path: "../sibling" },
          },
        },
      };

      const result = extractPackagesFromLockfileStreaming(lockfile);
      assert.equal(result.packages.length, 0);
      assert.equal(result.stats.registryPackages, 0);
      assert.equal(result.stats.skippedPackages, 2);
    });
  });
});

describe("integration with existing codebase", () => {
  it("produces compatible output with extractPackagesFromLockfile", () => {
    const testCases = [
      generateEdgeCaseLockfile(),
      generateLockfile(100),
      generateLockfile(500, { registryRatio: 0.8 }),
      generateLockfile(1000, { withDeps: false }),
    ];

    for (const lockfile of testCases) {
      const standardResult = extractPackagesFromLockfile(lockfile);
      const streamingResult = extractPackagesFromLockfileStreaming(lockfile);

      // Sort both for comparison
      const standardSorted = standardResult.packages
        .map((p) => `${p.name}@${p.version}`)
        .sort();
      const streamingSorted = streamingResult.packages
        .map((p) => `${p.name}@${p.version}`)
        .sort();

      assert.deepEqual(
        standardSorted,
        streamingSorted,
        "Streaming and standard extraction should produce identical results",
      );
    }
  });

  it("handles real-world lockfile format", () => {
    const lockfile: PnpmLockfile = {
      lockfileVersion: "9.0",
      settings: {
        autoInstallPeers: true,
        excludeLinksFromLockfile: false,
      },
      importers: {
        ".": {
          dependencies: {
            lodash: { specifier: "^4.17.21", version: "4.17.21" },
            react: { specifier: "^18.2.0", version: "18.2.0" },
          },
        },
      },
      packages: {
        "/lodash@4.17.21": {
          resolution: {
            integrity: "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1k0XDi77M75Wl10gRnT9tW9G6p4N25A79JL3bQ1zC0R5n6Q==",
          },
          engines: { node: ">=0.8.0" },
        },
        "/react@18.2.0": {
          resolution: {
            integrity: "sha512-/3JO8ttlaqxg8m6haddm3PSgGRpmPKaW+4Le3znLM5zu67UkZ+HyGytBAwCldB69Wq8qGKpW6ac9YMA==",
          },
          engines: { node: ">=0.10.0" },
          dependencies: {
            "loose-envify": "1.4.0",
            scheduler: "0.23.0",
          },
        },
        "/loose-envify@1.4.0": {
          resolution: {
            integrity: "sha512-lyuxPGr/WFHvR7HYM9J3uHqd9js5XwpDcNp1QdBwfYZ0QvsHZ0jkBEXz4sAaUk5dri6F99We===",
          },
          engines: { node: ">=0.10.0" },
          dependencies: {
            "js-tokens": "4.0.0",
          },
        },
      },
    };

    const standardResult = extractPackagesFromLockfile(lockfile);
    const streamingResult = extractPackagesFromLockfileStreaming(lockfile);

    assert.deepEqual(
      standardResult.packages.map((p) => p.name).sort(),
      streamingResult.packages.map((p) => p.name).sort(),
    );
  });
});