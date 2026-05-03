import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const CLI = path.join(__dirname, "..", "..", "..", "bin", "cli.js");

describe("CLI SBOM Integration", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "cli-sbom-test-"));
    // Copy pnpm-lock.yaml to temp dir for testing
    const lockfilePath = path.join(__dirname, "..", "..", "..", "pnpm-lock.yaml");
    try {
      await fs.access(lockfilePath);
      await fs.copyFile(lockfilePath, path.join(tempDir, "pnpm-lock.yaml"));
    } catch {
      // If no lockfile, we'll test help and parsing only
    }
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  describe("--sbom flag", () => {
    it("shows --sbom in help output", () => {
      const result = spawnSync("node", [CLI, "--help"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      assert.ok(result.stdout.includes("--sbom"), "Help should include --sbom");
      assert.ok(
        result.stdout.includes("--sbom-format"),
        "Help should include --sbom-format"
      );
      assert.ok(
        result.stdout.includes("--sbom-output"),
        "Help should include --sbom-output"
      );
    });

    it("includes SBOM examples in help output", () => {
      const result = spawnSync("node", [CLI, "--help"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      assert.ok(
        result.stdout.includes("pnpm-audit-scan --sbom"),
        "Help should include SBOM examples"
      );
    });

    it("generates SBOM to stdout when --sbom is used", () => {
      const result = spawnSync("node", [CLI, "--sbom", "--offline"], {
        encoding: "utf8",
        cwd: tempDir,
      });
      // Output should be JSON (even if exit code is non-zero due to vulnerabilities)
      assert.ok(result.stdout.length > 0, "Should produce output");
      assert.ok(
        result.stdout.includes("bomFormat"),
        "Should contain CycloneDX format indicator"
      );
    });

    it("generates SBOM to file when --sbom-output is specified", async () => {
      const outputPath = path.join(tempDir, "test-sbom.json");
      const result = spawnSync(
        "node",
        [CLI, "--sbom", "--offline", "--sbom-output", outputPath],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      
      // Check that the file was created
      const fileExists = await fs
        .access(outputPath)
        .then(() => true)
        .catch(() => false);
      assert.ok(fileExists, "SBOM output file should be created");
      
      // Check file content
      const content = await fs.readFile(outputPath, "utf8");
      assert.ok(content.includes("bomFormat"), "File should contain CycloneDX format");
      assert.ok(
        content.includes("components"),
        "File should contain components array"
      );
    });

    it("generates SPDX format when --sbom-format spdx is used", async () => {
      const outputPath = path.join(tempDir, "test-spdx.json");
      const result = spawnSync(
        "node",
        [
          CLI,
          "--sbom",
          "--sbom-format",
          "spdx",
          "--offline",
          "--sbom-output",
          outputPath,
        ],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      
      // Check that the file was created
      const fileExists = await fs
        .access(outputPath)
        .then(() => true)
        .catch(() => false);
      assert.ok(fileExists, "SPDX SBOM output file should be created");
      
      // Check file content for SPDX indicators
      const content = await fs.readFile(outputPath, "utf8");
      assert.ok(
        content.includes("spdxVersion"),
        "File should contain SPDX version indicator"
      );
    });

    it("parses --sbom-format argument correctly", () => {
      const result = spawnSync(
        "node",
        [CLI, "--sbom", "--sbom-format", "cyclonedx", "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      // Should not error about invalid format
      assert.ok(!result.stderr.includes("Unknown SBOM format"));
    });

    it("parses --sbom-output argument correctly", async () => {
      const outputPath = path.join(tempDir, "custom-sbom.json");
      const result = spawnSync(
        "node",
        [CLI, "--sbom", "--sbom-output", outputPath, "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      
      // Check that the file was created at the specified path
      const fileExists = await fs
        .access(outputPath)
        .then(() => true)
        .catch(() => false);
      assert.ok(fileExists, "SBOM should be written to specified output path");
    });
  });

  describe("--help includes all SBOM options", () => {
    it("has SBOM options documented", () => {
      const result = spawnSync("node", [CLI, "--help"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      
      // Check for SBOM option descriptions
      assert.ok(
        result.stdout.includes("Generate SBOM"),
        "Help should describe SBOM generation"
      );
      assert.ok(
        result.stdout.includes("cyclonedx"),
        "Help should mention CycloneDX format"
      );
      assert.ok(
        result.stdout.includes("spdx"),
        "Help should mention SPDX format"
      );
    });
  });
});