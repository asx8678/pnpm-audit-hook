/**
 * SBOM diff CLI integration tests.
 *
 * Tests the --sbom-diff and --diff-output flags via the CLI.
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const CLI = path.join(__dirname, "..", "..", "..", "bin", "cli.js");

// ============================================================================
// Test Fixtures
// ============================================================================

const cycloneDXOld = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  serialNumber: "urn:uuid:old-serial",
  version: 1,
  metadata: {
    timestamp: "2025-01-01T00:00:00.000Z",
    tools: [{ vendor: "test", name: "test", version: "1.0.0" }],
  },
  components: [
    {
      type: "library",
      "bom-ref": "pkg:npm/lodash@4.17.20",
      name: "lodash",
      version: "4.17.20",
      purl: "pkg:npm/lodash@4.17.20",
    },
    {
      type: "library",
      "bom-ref": "pkg:npm/express@4.18.0",
      name: "express",
      version: "4.18.0",
      purl: "pkg:npm/express@4.18.0",
    },
    {
      type: "library",
      "bom-ref": "pkg:npm/body-parser@1.20.0",
      name: "body-parser",
      version: "1.20.0",
      purl: "pkg:npm/body-parser@1.20.0",
    },
  ],
};

const cycloneDXNew = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  serialNumber: "urn:uuid:new-serial",
  version: 1,
  metadata: {
    timestamp: "2025-06-01T00:00:00.000Z",
    tools: [{ vendor: "test", name: "test", version: "1.0.0" }],
  },
  components: [
    {
      type: "library",
      "bom-ref": "pkg:npm/lodash@4.17.21",
      name: "lodash",
      version: "4.17.21",
      purl: "pkg:npm/lodash@4.17.21",
    },
    {
      type: "library",
      "bom-ref": "pkg:npm/express@4.19.0",
      name: "express",
      version: "4.19.0",
      purl: "pkg:npm/express@4.19.0",
    },
    {
      type: "library",
      "bom-ref": "pkg:npm/minimist@1.2.6",
      name: "minimist",
      version: "1.2.6",
      purl: "pkg:npm/minimist@1.2.6",
    },
  ],
};

const spdxOld = {
  spdxVersion: "SPDX-2.3",
  dataLicense: "CC0-1.0",
  SPDXID: "SPDXRef-DOCUMENT",
  name: "old-project",
  documentNamespace: "https://spdx.org/spdxdocs/old",
  creationInfo: {
    created: "2025-01-01T00:00:00Z",
    creators: ["Tool: test-1.0.0"],
  },
  documentDescribes: ["SPDXRef-DOCUMENT"],
  packages: [
    {
      SPDXID: "SPDXRef-DOCUMENT",
      name: "old-project",
      versionInfo: "NOASSERTION",
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      licenseConcluded: "NOASSERTION",
      licenseDeclared: "NOASSERTION",
      copyrightText: "NOASSERTION",
    },
    {
      SPDXID: "SPDXRef-Package-lodash",
      name: "lodash",
      versionInfo: "4.17.20",
      downloadLocation: "https://registry.npmjs.org/lodash",
      filesAnalyzed: false,
      licenseConcluded: "MIT",
      licenseDeclared: "MIT",
      copyrightText: "NOASSERTION",
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: "pkg:npm/lodash@4.17.20",
        },
      ],
    },
  ],
  relationships: [],
};

const spdxNew = {
  spdxVersion: "SPDX-2.3",
  dataLicense: "CC0-1.0",
  SPDXID: "SPDXRef-DOCUMENT",
  name: "new-project",
  documentNamespace: "https://spdx.org/spdxdocs/new",
  creationInfo: {
    created: "2025-06-01T00:00:00Z",
    creators: ["Tool: test-1.0.0"],
  },
  documentDescribes: ["SPDXRef-DOCUMENT"],
  packages: [
    {
      SPDXID: "SPDXRef-DOCUMENT",
      name: "new-project",
      versionInfo: "NOASSERTION",
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      licenseConcluded: "NOASSERTION",
      licenseDeclared: "NOASSERTION",
      copyrightText: "NOASSERTION",
    },
    {
      SPDXID: "SPDXRef-Package-lodash",
      name: "lodash",
      versionInfo: "4.17.21",
      downloadLocation: "https://registry.npmjs.org/lodash",
      filesAnalyzed: false,
      licenseConcluded: "MIT",
      licenseDeclared: "MIT",
      copyrightText: "NOASSERTION",
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: "pkg:npm/lodash@4.17.21",
        },
      ],
    },
  ],
  relationships: [],
};

// ============================================================================
// Tests
// ============================================================================

describe("CLI SBOM Diff Integration", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "cli-sbom-diff-test-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  describe("--sbom-diff flag in help", () => {
    it("shows --sbom-diff in help output", () => {
      const result = spawnSync("node", [CLI, "--help"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      assert.ok(
        result.stdout.includes("--sbom-diff"),
        "Help should include --sbom-diff"
      );
      assert.ok(
        result.stdout.includes("--diff-output"),
        "Help should include --diff-output"
      );
    });

    it("includes diff examples in help output", () => {
      const result = spawnSync("node", [CLI, "--help"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      assert.ok(
        result.stdout.includes("--sbom-diff old-sbom.json new-sbom.json"),
        "Help should include diff examples"
      );
    });
  });

  describe("--sbom-diff with CycloneDX files", () => {
    it("outputs human-readable diff to stdout", async () => {
      const oldPath = path.join(tempDir, "old-sbom.json");
      const newPath = path.join(tempDir, "new-sbom.json");
      await fs.writeFile(oldPath, JSON.stringify(cycloneDXOld));
      await fs.writeFile(newPath, JSON.stringify(cycloneDXNew));

      const result = spawnSync(
        "node",
        [CLI, "--sbom-diff", oldPath, newPath],
        { encoding: "utf8", cwd: tempDir }
      );

      assert.ok(result.stdout.includes("SBOM Diff Report"), "Should output diff report header");
      assert.ok(result.stdout.includes("Summary"), "Should include summary");
      assert.ok(result.stdout.includes("Updated Dependencies"), "Should show updated");
      assert.ok(result.stdout.includes("Removed Dependencies"), "Should show removed");
      assert.ok(result.stdout.includes("Added Dependencies"), "Should show added");
      // Exit code 1 because there are changes
      assert.equal(result.status, 1);
    });

    it("writes JSON diff to file with --diff-output", async () => {
      const oldPath = path.join(tempDir, "old-sbom.json");
      const newPath = path.join(tempDir, "new-sbom.json");
      const outputPath = path.join(tempDir, "diff-report.json");
      await fs.writeFile(oldPath, JSON.stringify(cycloneDXOld));
      await fs.writeFile(newPath, JSON.stringify(cycloneDXNew));

      const result = spawnSync(
        "node",
        [CLI, "--sbom-diff", oldPath, newPath, "--diff-output", outputPath],
        { encoding: "utf8", cwd: tempDir }
      );

      // Should write file
      const content = await fs.readFile(outputPath, "utf-8");
      const diff = JSON.parse(content);

      assert.ok(diff.added, "Should have added array");
      assert.ok(diff.removed, "Should have removed array");
      assert.ok(diff.updated, "Should have updated array");
      assert.ok(diff.unchanged, "Should have unchanged array");
      assert.ok(diff.summary, "Should have summary");
      assert.ok(diff.metadata, "Should have metadata");

      assert.equal(diff.summary.totalAdded, 1);   // minimist
      assert.equal(diff.summary.totalRemoved, 1);  // body-parser
      assert.equal(diff.summary.totalUpdated, 2);  // lodash, express
      assert.equal(diff.summary.totalUnchanged, 0);

      assert.equal(diff.metadata.oldFormat, "cyclonedx");
      assert.equal(diff.metadata.newFormat, "cyclonedx");

      // Should report file written to stderr
      assert.ok(
        result.stderr.includes("Diff report written to"),
        "Should report file written"
      );
    });
  });

  describe("--sbom-diff with SPDX files", () => {
    it("handles SPDX format correctly", async () => {
      const oldPath = path.join(tempDir, "old-sbom.json");
      const newPath = path.join(tempDir, "new-sbom.json");
      await fs.writeFile(oldPath, JSON.stringify(spdxOld));
      await fs.writeFile(newPath, JSON.stringify(spdxNew));

      const result = spawnSync(
        "node",
        [CLI, "--sbom-diff", oldPath, newPath],
        { encoding: "utf8", cwd: tempDir }
      );

      assert.ok(result.stdout.includes("SBOM Diff Report"));
      assert.ok(result.stdout.includes("lodash@4.17.20 -> 4.17.21"), "Should show lodash update");
      // Exit 1 because there are changes
      assert.equal(result.status, 1);
    });
  });

  describe("--sbom-diff with identical files", () => {
    it("reports no changes and exits 0", async () => {
      const oldPath = path.join(tempDir, "sbom.json");
      await fs.writeFile(oldPath, JSON.stringify(cycloneDXOld));

      const result = spawnSync(
        "node",
        [CLI, "--sbom-diff", oldPath, oldPath],
        { encoding: "utf8", cwd: tempDir }
      );

      assert.ok(result.stdout.includes("Added:     0"));
      assert.ok(result.stdout.includes("Removed:   0"));
      assert.ok(result.stdout.includes("Updated:   0"));
      assert.equal(result.status, 0, "Should exit 0 for no changes");
    });
  });

  describe("error handling", () => {
    it("errors when --sbom-diff has no file arguments", () => {
      const result = spawnSync(
        "node",
        [CLI, "--sbom-diff"],
        { encoding: "utf8", cwd: tempDir }
      );

      assert.ok(result.stderr.includes("--sbom-diff requires two file arguments"));
      assert.notEqual(result.status, 0);
    });

    it("errors when only one file argument is provided", () => {
      const oldPath = path.join(tempDir, "old-sbom.json");

      const result = spawnSync(
        "node",
        [CLI, "--sbom-diff", oldPath],
        { encoding: "utf8", cwd: tempDir }
      );

      assert.ok(
        result.stderr.includes("--sbom-diff requires two file arguments") ||
        result.stderr.includes("ENOENT") ||
        result.stderr.includes("not found"),
        "Should show error about missing files"
      );
      assert.notEqual(result.status, 0);
    });

    it("errors when old SBOM file does not exist", async () => {
      const newPath = path.join(tempDir, "new-sbom.json");
      await fs.writeFile(newPath, JSON.stringify(cycloneDXNew));

      const result = spawnSync(
        "node",
        [CLI, "--sbom-diff", "/nonexistent/old.json", newPath],
        { encoding: "utf8", cwd: tempDir }
      );

      assert.ok(
        result.stderr.includes("not found") || result.stderr.includes("ENOENT"),
        "Should report file not found"
      );
      assert.notEqual(result.status, 0);
    });

    it("errors when new SBOM file does not exist", async () => {
      const oldPath = path.join(tempDir, "old-sbom.json");
      await fs.writeFile(oldPath, JSON.stringify(cycloneDXOld));

      const result = spawnSync(
        "node",
        [CLI, "--sbom-diff", oldPath, "/nonexistent/new.json"],
        { encoding: "utf8", cwd: tempDir }
      );

      assert.ok(
        result.stderr.includes("not found") || result.stderr.includes("ENOENT"),
        "Should report file not found"
      );
      assert.notEqual(result.status, 0);
    });

    it("errors when SBOM file contains invalid JSON", async () => {
      const oldPath = path.join(tempDir, "bad-old.json");
      const newPath = path.join(tempDir, "bad-new.json");
      await fs.writeFile(oldPath, "not json {{{");
      await fs.writeFile(newPath, JSON.stringify(cycloneDXNew));

      const result = spawnSync(
        "node",
        [CLI, "--sbom-diff", oldPath, newPath],
        { encoding: "utf8", cwd: tempDir }
      );

      assert.ok(
        result.stderr.includes("Invalid JSON"),
        "Should report invalid JSON"
      );
      assert.notEqual(result.status, 0);
    });

    it("errors when SBOM has unrecognized format", async () => {
      const oldPath = path.join(tempDir, "old.json");
      const newPath = path.join(tempDir, "new.json");
      await fs.writeFile(oldPath, JSON.stringify({ notAnSbom: true }));
      await fs.writeFile(newPath, JSON.stringify(cycloneDXNew));

      const result = spawnSync(
        "node",
        [CLI, "--sbom-diff", oldPath, newPath],
        { encoding: "utf8", cwd: tempDir }
      );

      assert.ok(
        result.stderr.includes("Unrecognized") || result.stderr.includes("Diff error"),
        "Should report unrecognized format"
      );
      assert.notEqual(result.status, 0);
    });
  });
});
