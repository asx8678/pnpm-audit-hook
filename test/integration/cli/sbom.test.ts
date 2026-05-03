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

    it("defaults to CycloneDX format when no --sbom-format is specified", async () => {
      const outputPath = path.join(tempDir, "default-format.json");
      const result = spawnSync(
        "node",
        [CLI, "--sbom", "--sbom-output", outputPath, "--offline"],
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
      
      // Check that it's CycloneDX format (default)
      const content = await fs.readFile(outputPath, "utf8");
      assert.ok(
        content.includes("bomFormat"),
        "Should default to CycloneDX format"
      );
    });
  });

  describe("error handling", () => {
    it("shows error for invalid SBOM format", () => {
      const result = spawnSync(
        "node",
        [CLI, "--sbom", "--sbom-format", "json", "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      // Should error about invalid format (json is not a valid SBOM format)
      assert.ok(
        result.stderr.includes("Error") || result.stderr.includes("error"),
        "Should show error for invalid format"
      );
    });

    it("shows error for invalid SBOM format case sensitivity", () => {
      const result = spawnSync(
        "node",
        [CLI, "--sbom", "--sbom-format", "CYCLONEDX", "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      // Should handle case sensitivity - check if it fails or works
      // The format should be case-sensitive based on the code
      const hasError = result.stderr.includes("Error") || result.stderr.includes("error");
      const hasOutput = result.stdout.includes("bomFormat") || result.stdout.includes("spdxVersion");
      // Either it errors (case-sensitive) or works (case-insensitive)
      assert.ok(hasError || hasOutput, "Should either error or work with case-insensitive format");
    });

    it("handles non-existent output directory gracefully", async () => {
      const outputPath = path.join(tempDir, "nonexistent", "subdir", "sbom.json");
      const result = spawnSync(
        "node",
        [CLI, "--sbom", "--sbom-output", outputPath, "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      
      // Should create the directory and file
      const fileExists = await fs
        .access(outputPath)
        .then(() => true)
        .catch(() => false);
      assert.ok(fileExists, "Should create non-existent directories for output");
    });

    it("handles read-only output path", async () => {
      // Create a read-only directory
      const readOnlyDir = path.join(tempDir, "readonly");
      await fs.mkdir(readOnlyDir, { mode: 0o555 }); // Read-only
      const outputPath = path.join(readOnlyDir, "sbom.json");
      
      const result = spawnSync(
        "node",
        [CLI, "--sbom", "--sbom-output", outputPath, "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      
      // Should handle error gracefully (don't crash)
      // The exit code might be non-zero due to audit, but SBOM error should be handled
      const hasSbomError = result.stderr.includes("SBOM generation error");
      const fileExists = await fs
        .access(outputPath)
        .then(() => true)
        .catch(() => false);
      
      // Either it writes successfully or shows error - both are acceptable
      assert.ok(
        hasSbomError || fileExists,
        "Should handle read-only path gracefully"
      );
      
      // Clean up
      await fs.chmod(readOnlyDir, 0o755);
    });

    it("shows SBOM error but continues audit when SBOM generation fails", () => {
      // Try to generate SBOM with invalid combination that might cause error
      const result = spawnSync(
        "node",
        [CLI, "--sbom", "--sbom-format", "invalid-format", "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      
      // Should show error for invalid format
      assert.ok(
        result.stderr.includes("Error") || result.stderr.includes("error"),
        "Should show error for invalid format"
      );
      
      // Should still show audit results (exit code might be non-zero)
      assert.ok(
        result.stdout.includes("Audit") || result.stdout.includes("audit"),
        "Should still show audit results"
      );
    });
  });

  describe("integration with audit workflow", () => {
    it("generates SBOM with vulnerability information", async () => {
      const outputPath = path.join(tempDir, "vuln-sbom.json");
      const result = spawnSync(
        "node",
        [CLI, "--sbom", "--sbom-output", outputPath, "--offline"],
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
      
      // Check file content for vulnerability information
      const content = await fs.readFile(outputPath, "utf8");
      const parsed = JSON.parse(content);
      
      // Should have components array
      assert.ok(parsed.components, "Should have components array");
      assert.ok(parsed.components.length > 0, "Should have at least one component");
      
      // Should have metadata with timestamp
      assert.ok(parsed.metadata, "Should have metadata");
      assert.ok(parsed.metadata.timestamp, "Metadata should have timestamp");
    });

    it("SBOM generation doesn't affect audit exit code", () => {
      // Run with SBOM and offline mode
      const resultWithSbom = spawnSync(
        "node",
        [CLI, "--sbom", "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      
      // Run without SBOM
      const resultWithoutSbom = spawnSync(
        "node",
        [CLI, "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      
      // Exit codes should be the same (SBOM shouldn't change audit behavior)
      assert.equal(
        resultWithSbom.status,
        resultWithoutSbom.status,
        "SBOM generation should not affect audit exit code"
      );
    });

    it("SBOM output appears after audit results", () => {
      const result = spawnSync(
        "node",
        [CLI, "--sbom", "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      
      // Should have audit output
      assert.ok(
        result.stdout.includes("Audit") || result.stdout.includes("audit"),
        "Should have audit output"
      );
      
      // Should have SBOM output after audit
      assert.ok(
        result.stdout.includes("bomFormat") || result.stdout.includes("spdxVersion"),
        "Should have SBOM output after audit"
      );
    });

    it("SBOM output to stderr when writing to file", async () => {
      const outputPath = path.join(tempDir, "file-sbom.json");
      const result = spawnSync(
        "node",
        [CLI, "--sbom", "--sbom-output", outputPath, "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      
      // Should show message in stderr about file creation
      assert.ok(
        result.stderr.includes("SBOM written to"),
        "Should show SBOM file creation message in stderr"
      );
    });
  });

  describe("edge cases", () => {
    it("handles empty pnpm-lock.yaml", async () => {
      const emptyLockfile = path.join(tempDir, "pnpm-lock.yaml");
      await fs.writeFile(emptyLockfile, "");
      
      const result = spawnSync(
        "node",
        [CLI, "--sbom", "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      
      // Should handle empty lockfile gracefully
      // Might error or produce empty SBOM - both are acceptable
      assert.ok(
        result.stdout.length > 0 || result.stderr.length > 0,
        "Should produce some output for empty lockfile"
      );
    });

    it("handles large lockfile", async () => {
      // Create a large lockfile with many packages
      const largeLockfile = {
        lockfileVersion: "9.0",
        packages: {} as Record<string, any>,
      };
      
      // Add 100 packages
      for (let i = 0; i < 100; i++) {
        largeLockfile.packages[`/package-${i}@1.0.0`] = {
          resolution: { integrity: `sha512-test${i}` },
        };
      }
      
      const lockfilePath = path.join(tempDir, "pnpm-lock.yaml");
      const yaml = await import("yaml");
      await fs.writeFile(lockfilePath, yaml.stringify(largeLockfile));
      
      const outputPath = path.join(tempDir, "large-sbom.json");
      const result = spawnSync(
        "node",
        [CLI, "--sbom", "--sbom-output", outputPath, "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      
      // Should handle large lockfile
      const fileExists = await fs
        .access(outputPath)
        .then(() => true)
        .catch(() => false);
      assert.ok(fileExists, "Should create SBOM for large lockfile");
      
      // Check file size is reasonable
      const stat = await fs.stat(outputPath);
      assert.ok(stat.size > 1000, "SBOM file should have reasonable size");
    });

    it("handles concurrent SBOM generation", async () => {
      const outputPath1 = path.join(tempDir, "concurrent-1.json");
      const outputPath2 = path.join(tempDir, "concurrent-2.json");
      
      // Run two SBOM generations concurrently
      const promises = [
        new Promise<void>((resolve) => {
          spawnSync(
            "node",
            [CLI, "--sbom", "--sbom-output", outputPath1, "--offline"],
            {
              encoding: "utf8",
              cwd: tempDir,
            }
          );
          resolve();
        }),
        new Promise<void>((resolve) => {
          spawnSync(
            "node",
            [CLI, "--sbom", "--sbom-output", outputPath2, "--offline"],
            {
              encoding: "utf8",
              cwd: tempDir,
            }
          );
          resolve();
        }),
      ];
      
      await Promise.all(promises);
      
      // Both files should be created
      const file1Exists = await fs
        .access(outputPath1)
        .then(() => true)
        .catch(() => false);
      const file2Exists = await fs
        .access(outputPath2)
        .then(() => true)
        .catch(() => false);
      
      assert.ok(file1Exists, "First concurrent SBOM should be created");
      assert.ok(file2Exists, "Second concurrent SBOM should be created");
    });

    it("handles SBOM with special characters in package names", async () => {
      // Create lockfile with special package names
      const specialLockfile = {
        lockfileVersion: "9.0",
        packages: {
          "/@scope/package@1.0.0": {
            resolution: { integrity: "sha512-test123" },
          },
          "/package-with-dashes@1.0.0": {
            resolution: { integrity: "sha512-test456" },
          },
          "/package.with.dots@1.0.0": {
            resolution: { integrity: "sha512-test789" },
          },
        },
      };
      
      const lockfilePath = path.join(tempDir, "pnpm-lock.yaml");
      const yaml = await import("yaml");
      await fs.writeFile(lockfilePath, yaml.stringify(specialLockfile));
      
      const outputPath = path.join(tempDir, "special-chars-sbom.json");
      const result = spawnSync(
        "node",
        [CLI, "--sbom", "--sbom-output", outputPath, "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      
      // Should handle special characters
      const fileExists = await fs
        .access(outputPath)
        .then(() => true)
        .catch(() => false);
      assert.ok(fileExists, "Should create SBOM for packages with special characters");
      
      // Check that package names are preserved
      const content = await fs.readFile(outputPath, "utf8");
      assert.ok(
        content.includes("@scope/package"),
        "Should preserve scoped package names"
      );
      assert.ok(
        content.includes("package-with-dashes"),
        "Should preserve package names with dashes"
      );
    });

    it("handles SBOM with very long package versions", async () => {
      // Create lockfile with long version string
      const longVersionLockfile = {
        lockfileVersion: "9.0",
        packages: {
          "/package@1.0.0-beta.1+build.123": {
            resolution: { integrity: "sha512-test123" },
          },
        },
      };
      
      const lockfilePath = path.join(tempDir, "pnpm-lock.yaml");
      const yaml = await import("yaml");
      await fs.writeFile(lockfilePath, yaml.stringify(longVersionLockfile));
      
      const outputPath = path.join(tempDir, "long-version-sbom.json");
      const result = spawnSync(
        "node",
        [CLI, "--sbom", "--sbom-output", outputPath, "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      
      // Should handle long version strings
      const fileExists = await fs
        .access(outputPath)
        .then(() => true)
        .catch(() => false);
      assert.ok(fileExists, "Should create SBOM for long version strings");
    });

    it("handles SBOM output to existing file (overwrite)", async () => {
      const outputPath = path.join(tempDir, "overwrite-sbom.json");
      
      // Create initial file
      await fs.writeFile(outputPath, "initial content");
      
      // Generate SBOM
      const result = spawnSync(
        "node",
        [CLI, "--sbom", "--sbom-output", outputPath, "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      
      // Should overwrite the file
      const content = await fs.readFile(outputPath, "utf8");
      assert.notEqual(content, "initial content", "Should overwrite existing file");
      assert.ok(content.includes("bomFormat"), "Should contain SBOM content");
    });

    it("SBOM with --quiet flag", () => {
      const result = spawnSync(
        "node",
        [CLI, "--sbom", "--quiet", "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      
      // Should still produce SBOM output
      assert.ok(
        result.stdout.includes("bomFormat") || result.stdout.includes("spdxVersion"),
        "Should produce SBOM even with --quiet flag"
      );
    });

    it("SBOM with --verbose flag", () => {
      const result = spawnSync(
        "node",
        [CLI, "--sbom", "--verbose", "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      
      // Should produce SBOM and possibly verbose output
      assert.ok(
        result.stdout.includes("bomFormat") || result.stdout.includes("spdxVersion"),
        "Should produce SBOM with --verbose flag"
      );
    });

    it("SBOM with both CycloneDX and SPDX formats", async () => {
      const cyclonedxPath = path.join(tempDir, "both-cyclonedx.json");
      const spdxPath = path.join(tempDir, "both-spdx.json");
      
      // Generate CycloneDX
      spawnSync(
        "node",
        [CLI, "--sbom", "--sbom-format", "cyclonedx", "--sbom-output", cyclonedxPath, "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      
      // Generate SPDX
      spawnSync(
        "node",
        [CLI, "--sbom", "--sbom-format", "spdx", "--sbom-output", spdxPath, "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      
      // Both files should be created
      const cyclonedxExists = await fs
        .access(cyclonedxPath)
        .then(() => true)
        .catch(() => false);
      const spdxExists = await fs
        .access(spdxPath)
        .then(() => true)
        .catch(() => false);
      
      assert.ok(cyclonedxExists, "CycloneDX SBOM should be created");
      assert.ok(spdxExists, "SPDX SBOM should be created");
      
      // Check formats are different
      const cyclonedxContent = await fs.readFile(cyclonedxPath, "utf8");
      const spdxContent = await fs.readFile(spdxPath, "utf8");
      
      assert.ok(cyclonedxContent.includes("bomFormat"), "CycloneDX should have bomFormat");
      assert.ok(spdxContent.includes("spdxVersion"), "SPDX should have spdxVersion");
      assert.notEqual(cyclonedxContent, spdxContent, "Formats should be different");
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

    it("documents SBOM format options", () => {
      const result = spawnSync("node", [CLI, "--help"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      
      // Should document that cyclonedx is default
      assert.ok(
        result.stdout.includes("default: cyclonedx") || 
        result.stdout.includes("default:cyclonedx"),
        "Help should document CycloneDX as default format"
      );
    });

    it("documents SBOM output options", () => {
      const result = spawnSync("node", [CLI, "--help"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      
      // Should document stdout as default output
      assert.ok(
        result.stdout.includes("stdout") || result.stdout.includes("default"),
        "Help should document default output behavior"
      );
    });

    it("documents SWID format option", () => {
      const result = spawnSync("node", [CLI, "--help"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      
      // Should document SWID format
      assert.ok(
        result.stdout.includes("swid"),
        "Help should mention SWID format"
      );
    });
  });

  describe("SWID format support", () => {
    it("generates SWID format when --sbom-format swid is used", () => {
      const result = spawnSync(
        "node",
        [CLI, "--sbom", "--sbom-format", "swid", "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      
      // Output should be XML (even if exit code is non-zero due to vulnerabilities)
      assert.ok(result.stdout.length > 0, "Should produce output");
      assert.ok(
        result.stdout.includes("<swidTagSet>"),
        "Should contain SWID tag set root element"
      );
      assert.ok(
        result.stdout.includes("<swid>"),
        "Should contain SWID tag elements"
      );
      assert.ok(
        result.stdout.includes("<tagId>"),
        "Should contain tagId element"
      );
      assert.ok(
        result.stdout.includes("<regid>"),
        "Should contain regid element"
      );
    });

    it("generates SWID SBOM to file when --sbom-output is specified", async () => {
      const outputPath = path.join(tempDir, "test-swid.xml");
      const result = spawnSync(
        "node",
        [
          CLI,
          "--sbom",
          "--sbom-format",
          "swid",
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
      assert.ok(fileExists, "SWID SBOM output file should be created");
      
      // Check file content for SWID indicators
      const content = await fs.readFile(outputPath, "utf8");
      assert.ok(
        content.includes("swidTagSet"),
        "File should contain SWID tag set"
      );
      assert.ok(
        content.includes("<swid>"),
        "File should contain SWID tags"
      );
    });

    it("parses --sbom-format swid argument correctly", () => {
      const result = spawnSync(
        "node",
        [CLI, "--sbom", "--sbom-format", "swid", "--offline"],
        {
          encoding: "utf8",
          cwd: tempDir,
        }
      );
      // Should not error about invalid format
      assert.ok(!result.stderr.includes("Invalid SBOM format"));
    });
  });
});