import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { parseArgs, HELP } from "../../../bin/parse-args.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const CLI = path.join(__dirname, "..", "..", "..", "bin", "cli.js");
const FIXTURES_DIR = path.join(__dirname, "..", "..", "fixtures", "sbom");

describe("--validate-sbom", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "validate-sbom-test-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  // ---------------------------------------------------------------------------
  // parseArgs tests
  // ---------------------------------------------------------------------------
  describe("parseArgs", () => {
    it('sets validateSbom when --validate-sbom <file> is passed', () => {
      const args = parseArgs(["--validate-sbom", "sbom.json"]);
      assert.equal(args.validateSbom, "sbom.json");
    });

    it("sets validationOutput when --validation-output <path> is passed", () => {
      const args = parseArgs(["--validation-output", "report.json"]);
      assert.equal(args.validationOutput, "report.json");
    });

    it("does not interfere with --format flag", () => {
      const args = parseArgs(["--validate-sbom", "sbom.json", "--format", "cyclonedx"]);
      assert.equal(args.validateSbom, "sbom.json");
      assert.equal(args.format, "cyclonedx");
    });

    it("does not interfere with --offline flag", () => {
      const args = parseArgs(["--validate-sbom", "sbom.json", "--offline"]);
      assert.equal(args.validateSbom, "sbom.json");
      assert.equal(args.offline, true);
    });

    it("does not interfere with --help flag", () => {
      const args = parseArgs(["--validate-sbom", "sbom.json", "--help"]);
      assert.equal(args.validateSbom, "sbom.json");
      assert.equal(args.help, true);
    });
  });

  // ---------------------------------------------------------------------------
  // Help text
  // ---------------------------------------------------------------------------
  describe("help output", () => {
    it("--validate-sbom appears in help output", () => {
      assert.ok(
        HELP.includes("--validate-sbom"),
        "HELP text should mention --validate-sbom",
      );
    });

    it("--validation-output appears in help output", () => {
      assert.ok(
        HELP.includes("--validation-output"),
        "HELP text should mention --validation-output",
      );
    });

    it("includes example usage for --validate-sbom", () => {
      assert.ok(
        HELP.includes("pnpm-audit-scan --validate-sbom sbom.json"),
        "HELP text should include validate-sbom example",
      );
    });

    it("CLI --help includes --validate-sbom", () => {
      const result = spawnSync("node", [CLI, "--help"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      assert.ok(
        result.stdout.includes("--validate-sbom"),
        "CLI --help should include --validate-sbom",
      );
      assert.ok(
        result.stdout.includes("--validation-output"),
        "CLI --help should include --validation-output",
      );
    });
  });

  // ---------------------------------------------------------------------------
  // Valid SBOM validation
  // ---------------------------------------------------------------------------
  describe("valid SBOM validation", () => {
    it("validates a valid CycloneDX SBOM (auto-detect)", async () => {
      const sbomPath = path.join(FIXTURES_DIR, "sample-cyclonedx.json");
      const result = spawnSync("node", [CLI, "--validate-sbom", sbomPath], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      assert.ok(result.stdout.includes("PASS"), "Should show PASS");
      assert.ok(result.stdout.includes("cyclonedx"), "Should show cyclonedx format");
    });

    it("validates a valid CycloneDX SBOM (explicit format)", async () => {
      const sbomPath = path.join(FIXTURES_DIR, "sample-cyclonedx.json");
      const result = spawnSync(
        "node",
        [CLI, "--validate-sbom", sbomPath, "--format", "cyclonedx"],
        { encoding: "utf8" },
      );
      assert.equal(result.status, 0);
      assert.ok(result.stdout.includes("PASS"), "Should show PASS");
    });

    it("validates a valid SPDX SBOM (auto-detect)", async () => {
      const sbomPath = path.join(FIXTURES_DIR, "sample-spdx.json");
      const result = spawnSync("node", [CLI, "--validate-sbom", sbomPath], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      assert.ok(result.stdout.includes("PASS"), "Should show PASS");
      assert.ok(result.stdout.includes("spdx"), "Should show spdx format");
    });

    it("validates a valid SPDX SBOM (explicit format)", async () => {
      const sbomPath = path.join(FIXTURES_DIR, "sample-spdx.json");
      const result = spawnSync(
        "node",
        [CLI, "--validate-sbom", sbomPath, "--format", "spdx"],
        { encoding: "utf8" },
      );
      assert.equal(result.status, 0);
      assert.ok(result.stdout.includes("PASS"), "Should show PASS");
    });
  });

  // ---------------------------------------------------------------------------
  // Auto-detection
  // ---------------------------------------------------------------------------
  describe("auto-detection", () => {
    it("auto-detects CycloneDX format from bomFormat field", async () => {
      const sbomPath = path.join(FIXTURES_DIR, "sample-cyclonedx.json");
      const result = spawnSync(
        "node",
        [CLI, "--validate-sbom", sbomPath, "--format", "auto"],
        { encoding: "utf8" },
      );
      assert.equal(result.status, 0);
      assert.ok(result.stdout.includes("cyclonedx"));
    });

    it("auto-detects SPDX format from spdxVersion field", async () => {
      const sbomPath = path.join(FIXTURES_DIR, "sample-spdx.json");
      const result = spawnSync(
        "node",
        [CLI, "--validate-sbom", sbomPath, "--format", "auto"],
        { encoding: "utf8" },
      );
      assert.equal(result.status, 0);
      assert.ok(result.stdout.includes("spdx"));
    });

    it("auto-detects format when no --format flag is given", async () => {
      const sbomPath = path.join(FIXTURES_DIR, "sample-cyclonedx.json");
      const result = spawnSync("node", [CLI, "--validate-sbom", sbomPath], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      assert.ok(result.stdout.includes("cyclonedx"));
    });
  });

  // ---------------------------------------------------------------------------
  // Invalid SBOM validation
  // ---------------------------------------------------------------------------
  describe("invalid SBOM", () => {
    it("reports errors for an incomplete CycloneDX SBOM", async () => {
      const incompleteSbom = path.join(tempDir, "incomplete-cdx.json");
      await fs.writeFile(
        incompleteSbom,
        JSON.stringify({ bomFormat: "CycloneDX" }),
      );

      const result = spawnSync("node", [CLI, "--validate-sbom", incompleteSbom], {
        encoding: "utf8",
      });
      assert.equal(result.status, 1, "Should exit with code 1 for invalid SBOM");
      assert.ok(result.stdout.includes("FAIL"), "Should show FAIL");
      assert.ok(result.stdout.includes("Errors"), "Should show errors section");
      assert.ok(result.stdout.includes("specVersion"), "Should mention missing specVersion");
    });

    it("reports errors for an incomplete SPDX SBOM", async () => {
      const incompleteSbom = path.join(tempDir, "incomplete-spdx.json");
      await fs.writeFile(
        incompleteSbom,
        JSON.stringify({ spdxVersion: "SPDX-2.3" }),
      );

      const result = spawnSync("node", [CLI, "--validate-sbom", incompleteSbom, "--format", "spdx"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 1, "Should exit with code 1 for invalid SBOM");
      assert.ok(result.stdout.includes("FAIL"), "Should show FAIL");
      assert.ok(result.stdout.includes("Errors"), "Should show errors section");
    });
  });

  // ---------------------------------------------------------------------------
  // Error handling
  // ---------------------------------------------------------------------------
  describe("error handling", () => {
    it("exits with code 1 and error message when file is missing", () => {
      const result = spawnSync(
        "node",
        [CLI, "--validate-sbom", "nonexistent.json"],
        { encoding: "utf8" },
      );
      assert.equal(result.status, 1);
      assert.ok(
        result.stderr.includes("not found") || result.stdout.includes("not found"),
        "Should indicate file not found",
      );
    });

    it("exits with code 1 for invalid JSON content", async () => {
      const invalidFile = path.join(tempDir, "not-json.txt");
      await fs.writeFile(invalidFile, "this is not json");

      const result = spawnSync("node", [CLI, "--validate-sbom", invalidFile], {
        encoding: "utf8",
      });
      assert.equal(result.status, 1);
      // Auto-detect can't parse invalid JSON
      assert.ok(
        result.stderr.includes("Could not auto-detect") ||
          result.stdout.includes("Could not auto-detect") ||
          result.stdout.includes("FAIL"),
        "Should indicate detection failure or validation failure",
      );
    });

    it("exits with code 1 for invalid format hint", async () => {
      const sbomPath = path.join(FIXTURES_DIR, "sample-cyclonedx.json");
      const result = spawnSync(
        "node",
        [CLI, "--validate-sbom", sbomPath, "--format", "invalid-format"],
        { encoding: "utf8" },
      );
      // The validateSbom function returns errors for unsupported format
      assert.equal(result.status, 1);
    });
  });

  // ---------------------------------------------------------------------------
  // --validation-output
  // ---------------------------------------------------------------------------
  describe("--validation-output", () => {
    it("writes JSON validation report to file", async () => {
      const sbomPath = path.join(FIXTURES_DIR, "sample-cyclonedx.json");
      const outputPath = path.join(tempDir, "report.json");

      const result = spawnSync(
        "node",
        [CLI, "--validate-sbom", sbomPath, "--validation-output", outputPath],
        { encoding: "utf8" },
      );
      assert.equal(result.status, 0);

      // Check file was written
      const content = await fs.readFile(outputPath, "utf8");
      const report = JSON.parse(content);
      assert.equal(report.valid, true);
      assert.equal(report.format, "cyclonedx");
      assert.ok(Array.isArray(report.errors));
      assert.ok(Array.isArray(report.warnings));
      assert.equal(report.file, sbomPath);
    });

    it("writes validation report even when SBOM is invalid", async () => {
      const incompleteSbom = path.join(tempDir, "incomplete.json");
      await fs.writeFile(
        incompleteSbom,
        JSON.stringify({ bomFormat: "CycloneDX" }),
      );
      const outputPath = path.join(tempDir, "fail-report.json");

      const result = spawnSync(
        "node",
        [CLI, "--validate-sbom", incompleteSbom, "--validation-output", outputPath],
        { encoding: "utf8" },
      );
      assert.equal(result.status, 1);

      const content = await fs.readFile(outputPath, "utf8");
      const report = JSON.parse(content);
      assert.equal(report.valid, false);
      assert.ok(report.errors.length > 0, "Should have validation errors");
    });

    it("creates parent directories for --validation-output", async () => {
      const sbomPath = path.join(FIXTURES_DIR, "sample-cyclonedx.json");
      const outputPath = path.join(tempDir, "nested", "dir", "report.json");

      const result = spawnSync(
        "node",
        [CLI, "--validate-sbom", sbomPath, "--validation-output", outputPath],
        { encoding: "utf8" },
      );
      assert.equal(result.status, 0);

      const content = await fs.readFile(outputPath, "utf8");
      const report = JSON.parse(content);
      assert.equal(report.valid, true);
    });

    it("still outputs to stdout when --validation-output is set", async () => {
      const sbomPath = path.join(FIXTURES_DIR, "sample-cyclonedx.json");
      const outputPath = path.join(tempDir, "report.json");

      const result = spawnSync(
        "node",
        [CLI, "--validate-sbom", sbomPath, "--validation-output", outputPath],
        { encoding: "utf8" },
      );
      assert.ok(result.stdout.includes("SBOM Validation"), "Should output to stdout");
      assert.ok(result.stdout.includes("PASS"), "Should show status in stdout");
    });
  });
});
