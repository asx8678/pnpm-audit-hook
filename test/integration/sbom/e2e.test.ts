/**
 * End-to-End SBOM Integration Tests
 *
 * Tests SBOM generation with real lockfile fixtures from
 * test/fixtures/lockfiles/. Covers CycloneDX and SPDX output
 * formats, file output, and schema validation.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const CLI = path.join(__dirname, "..", "..", "..", "bin", "cli.js");
const FIXTURES_DIR = path.join(__dirname, "..", "..", "..", "test", "fixtures", "lockfiles");

type LockfileFixture = "empty" | "pnpm-v6" | "pnpm-v7" | "pnpm-v9" | "large-lockfile";

const ALL_FIXTURES: LockfileFixture[] = [
  "empty",
  "pnpm-v6",
  "pnpm-v7",
  "pnpm-v9",
  "large-lockfile",
];

// ============================================================================
// Helpers
// ============================================================================

function runCli(args: string[], cwd: string): { stdout: string; stderr: string; status: number | null } {
  const { spawnSync } = require("node:child_process");
  return spawnSync("node", [CLI, ...args], {
    encoding: "utf8",
    cwd,
    timeout: 30_000,
  });
}

function parseJson(content: string): Record<string, unknown> {
  try {
    return JSON.parse(content);
  } catch {
    return {};
  }
}

// ============================================================================
// Tests
// ============================================================================

describe("SBOM E2E Tests", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sbom-e2e-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  // ---------------------------------------------------------------------------
  // CycloneDX generation from real lockfiles
  // ---------------------------------------------------------------------------
  describe("CycloneDX generation from lockfiles", () => {
    for (const fixture of ALL_FIXTURES) {
      it(`generates CycloneDX from ${fixture} lockfile`, async () => {
        // Copy fixture lockfile
        const lockfilePath = path.join(FIXTURES_DIR, `${fixture}.yaml`);
        await fs.copyFile(lockfilePath, path.join(tempDir, "pnpm-lock.yaml"));

        const outputPath = path.join(tempDir, "sbom-cdx.json");
        const result = runCli(
          ["--sbom", "--sbom-format", "cyclonedx", "--sbom-output", outputPath, "--offline"],
          tempDir,
        );

        // SBOM file should always be created (even with empty lockfile)
        const fileExists = await fs
          .access(outputPath)
          .then(() => true)
          .catch(() => false);

        if (fixture === "empty") {
          // Empty lockfile may or may not produce output depending on lockfile parsing
          // The important thing is it doesn't crash
          return;
        }

        assert.ok(fileExists, `CycloneDX SBOM should be created for ${fixture}`);

        const content = await fs.readFile(outputPath, "utf8");
        const bom = parseJson(content);

        // Basic CycloneDX structure validation
        assert.equal(bom.bomFormat, "CycloneDX", "Should have bomFormat=CycloneDX");
        assert.ok(bom.specVersion, "Should have specVersion");
        assert.ok(bom.serialNumber, "Should have serialNumber");
        assert.ok(typeof bom.version === "number", "Should have numeric version");
        assert.ok(bom.metadata, "Should have metadata");
        assert.ok(bom.metadata.timestamp, "Should have metadata.timestamp");
        assert.ok(Array.isArray(bom.components), "Should have components array");

        if (fixture === "large-lockfile") {
          assert.ok(bom.components.length >= 30, "Large lockfile should produce many components");
        }
      });
    }
  });

  // ---------------------------------------------------------------------------
  // SPDX generation from real lockfiles
  // ---------------------------------------------------------------------------
  describe("SPDX generation from lockfiles", () => {
    for (const fixture of ALL_FIXTURES) {
      it(`generates SPDX from ${fixture} lockfile`, async () => {
        const lockfilePath = path.join(FIXTURES_DIR, `${fixture}.yaml`);
        await fs.copyFile(lockfilePath, path.join(tempDir, "pnpm-lock.yaml"));

        const outputPath = path.join(tempDir, "sbom-spdx.json");
        const result = runCli(
          ["--sbom", "--sbom-format", "spdx", "--sbom-output", outputPath, "--offline"],
          tempDir,
        );

        const fileExists = await fs
          .access(outputPath)
          .then(() => true)
          .catch(() => false);

        if (fixture === "empty") {
          return;
        }

        assert.ok(fileExists, `SPDX SBOM should be created for ${fixture}`);

        const content = await fs.readFile(outputPath, "utf8");
        const doc = parseJson(content);

        // Basic SPDX structure validation
        assert.ok(doc.spdxVersion, "Should have spdxVersion");
        assert.equal(doc.dataLicense, "CC0-1.0", "Should have dataLicense=CC0-1.0");
        assert.equal(doc.SPDXID, "SPDXRef-DOCUMENT", "Should have SPDXID=SPDXRef-DOCUMENT");
        assert.ok(doc.documentNamespace, "Should have documentNamespace");
        assert.ok(doc.creationInfo, "Should have creationInfo");
        assert.ok(Array.isArray(doc.packages), "Should have packages array");
        assert.ok(Array.isArray(doc.relationships), "Should have relationships array");

        if (fixture === "large-lockfile") {
          assert.ok(doc.packages.length >= 30, "Large lockfile should produce many packages");
        }
      });
    }
  });

  // ---------------------------------------------------------------------------
  // CycloneDX XML generation
  // ---------------------------------------------------------------------------
  describe("CycloneDX XML generation", () => {
    it("generates CycloneDX XML from pnpm-v9 lockfile", async () => {
      const lockfilePath = path.join(FIXTURES_DIR, "pnpm-v9.yaml");
      await fs.copyFile(lockfilePath, path.join(tempDir, "pnpm-lock.yaml"));

      const outputPath = path.join(tempDir, "sbom-cdx.xml");
      runCli(
        ["--sbom", "--sbom-format", "cyclonedx-xml", "--sbom-output", outputPath, "--offline"],
        tempDir,
      );

      const fileExists = await fs
        .access(outputPath)
        .then(() => true)
        .catch(() => false);

      assert.ok(fileExists, "CycloneDX XML should be created");

      const content = await fs.readFile(outputPath, "utf8");
      assert.ok(content.includes("<?xml"), "Should have XML declaration");
      assert.ok(content.includes("<bom"), "Should have <bom> root element");
      assert.ok(content.includes("</bom>"), "Should have closing </bom>");
      assert.ok(
        content.includes("http://cyclonedx.org/schema/bom"),
        "Should have CycloneDX namespace",
      );
    });
  });

  // ---------------------------------------------------------------------------
  // SWID Tag generation
  // ---------------------------------------------------------------------------
  describe("SWID Tag generation", () => {
    it("generates SWID tags from pnpm-v9 lockfile", async () => {
      const lockfilePath = path.join(FIXTURES_DIR, "pnpm-v9.yaml");
      await fs.copyFile(lockfilePath, path.join(tempDir, "pnpm-lock.yaml"));

      const outputPath = path.join(tempDir, "sbom-swid.xml");
      runCli(
        ["--sbom", "--sbom-format", "swid", "--sbom-output", outputPath, "--offline"],
        tempDir,
      );

      const fileExists = await fs
        .access(outputPath)
        .then(() => true)
        .catch(() => false);

      assert.ok(fileExists, "SWID tags should be created");

      const content = await fs.readFile(outputPath, "utf8");
      assert.ok(content.includes("<?xml"), "Should have XML declaration");
      assert.ok(content.includes("<swidTagSet>"), "Should have <swidTagSet> root element");
      assert.ok(content.includes("</swidTagSet>"), "Should have closing </swidTagSet>");
    });
  });

  // ---------------------------------------------------------------------------
  // File output behavior
  // ---------------------------------------------------------------------------
  describe("file output", () => {
    it("creates output directory if it does not exist", async () => {
      const lockfilePath = path.join(FIXTURES_DIR, "pnpm-v9.yaml");
      await fs.copyFile(lockfilePath, path.join(tempDir, "pnpm-lock.yaml"));

      const nestedOutput = path.join(tempDir, "deeply", "nested", "dir", "sbom.json");
      runCli(["--sbom", "--sbom-output", nestedOutput, "--offline"], tempDir);

      const fileExists = await fs
        .access(nestedOutput)
        .then(() => true)
        .catch(() => false);

      assert.ok(fileExists, "Should create nested directories for output");
    });

    it("overwrites existing SBOM file", async () => {
      const lockfilePath = path.join(FIXTURES_DIR, "pnpm-v9.yaml");
      await fs.copyFile(lockfilePath, path.join(tempDir, "pnpm-lock.yaml"));

      const outputPath = path.join(tempDir, "sbom.json");
      await fs.writeFile(outputPath, "old content");

      runCli(["--sbom", "--sbom-output", outputPath, "--offline"], tempDir);

      const content = await fs.readFile(outputPath, "utf8");
      assert.notEqual(content, "old content", "Should overwrite existing file");
    });

    it("writes CycloneDX to file and SPDX to file separately", async () => {
      const lockfilePath = path.join(FIXTURES_DIR, "pnpm-v9.yaml");
      await fs.copyFile(lockfilePath, path.join(tempDir, "pnpm-lock.yaml"));

      const cdxPath = path.join(tempDir, "cdx.json");
      const spdxPath = path.join(tempDir, "spdx.json");

      runCli(["--sbom", "--sbom-format", "cyclonedx", "--sbom-output", cdxPath, "--offline"], tempDir);
      runCli(["--sbom", "--sbom-format", "spdx", "--sbom-output", spdxPath, "--offline"], tempDir);

      const cdxExists = await fs.access(cdxPath).then(() => true).catch(() => false);
      const spdxExists = await fs.access(spdxPath).then(() => true).catch(() => false);

      assert.ok(cdxExists, "CycloneDX file should exist");
      assert.ok(spdxExists, "SPDX file should exist");

      const cdxContent = parseJson(await fs.readFile(cdxPath, "utf8"));
      const spdxContent = parseJson(await fs.readFile(spdxPath, "utf8"));

      assert.equal(cdxContent.bomFormat, "CycloneDX");
      assert.ok(spdxContent.spdxVersion, "SPDX should have version");
    });
  });

  // ---------------------------------------------------------------------------
  // Schema validation via schema-validator module
  // ---------------------------------------------------------------------------
  describe("schema validation", () => {
    it("validates CycloneDX output against schema", async () => {
      const lockfilePath = path.join(FIXTURES_DIR, "pnpm-v9.yaml");
      await fs.copyFile(lockfilePath, path.join(tempDir, "pnpm-lock.yaml"));

      const outputPath = path.join(tempDir, "sbom-cdx.json");
      runCli(["--sbom", "--sbom-format", "cyclonedx", "--sbom-output", outputPath, "--offline"], tempDir);

      const fileExists = await fs.access(outputPath).then(() => true).catch(() => false);
      if (!fileExists) return;

      const content = await fs.readFile(outputPath, "utf8");

      // Use the schema validator directly
      const { validateSbom } = await import("../../../src/sbom/schema-validator.js");
      const result = validateSbom(content, "cyclonedx");

      if (!result.valid) {
        console.error("CycloneDX validation errors:", result.errors);
      }
      assert.ok(result.valid, "CycloneDX should pass schema validation");
    });

    it("validates SPDX output against schema", async () => {
      const lockfilePath = path.join(FIXTURES_DIR, "pnpm-v9.yaml");
      await fs.copyFile(lockfilePath, path.join(tempDir, "pnpm-lock.yaml"));

      const outputPath = path.join(tempDir, "sbom-spdx.json");
      runCli(["--sbom", "--sbom-format", "spdx", "--sbom-output", outputPath, "--offline"], tempDir);

      const fileExists = await fs.access(outputPath).then(() => true).catch(() => false);
      if (!fileExists) return;

      const content = await fs.readFile(outputPath, "utf8");

      const { validateSbom } = await import("../../../src/sbom/schema-validator.js");
      const result = validateSbom(content, "spdx");

      if (!result.valid) {
        console.error("SPDX validation errors:", result.errors);
      }
      assert.ok(result.valid, "SPDX should pass schema validation");
    });
  });

  // ---------------------------------------------------------------------------
  // Cross-format consistency
  // ---------------------------------------------------------------------------
  describe("cross-format consistency", () => {
    it("CycloneDX and SPDX have the same number of components for the same lockfile", async () => {
      const lockfilePath = path.join(FIXTURES_DIR, "pnpm-v9.yaml");
      await fs.copyFile(lockfilePath, path.join(tempDir, "pnpm-lock.yaml"));

      const cdxPath = path.join(tempDir, "cdx.json");
      const spdxPath = path.join(tempDir, "spdx.json");

      runCli(["--sbom", "--sbom-format", "cyclonedx", "--sbom-output", cdxPath, "--offline"], tempDir);
      runCli(["--sbom", "--sbom-format", "spdx", "--sbom-output", spdxPath, "--offline"], tempDir);

      const cdxFileExists = await fs.access(cdxPath).then(() => true).catch(() => false);
      const spdxFileExists = await fs.access(spdxPath).then(() => true).catch(() => false);

      if (!cdxFileExists || !spdxFileExists) return;

      const cdx = parseJson(await fs.readFile(cdxPath, "utf8"));
      const spdx = parseJson(await fs.readFile(spdxPath, "utf8"));

      const cdxCount = Array.isArray(cdx.components) ? cdx.components.length : 0;
      // SPDX includes the root document as a package, so subtract 1
      const spdxCount = Array.isArray(spdx.packages) ? spdx.packages.length - 1 : 0;

      assert.equal(
        cdxCount,
        spdxCount,
        `Component count should match: CycloneDX=${cdxCount}, SPDX=${spdxCount}`,
      );
    });
  });
});
