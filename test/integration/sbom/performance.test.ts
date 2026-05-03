/**
 * SBOM Performance Tests
 *
 * Benchmarks SBOM generation for different lockfile sizes.
 * Performance target: <2s for 1000 dependencies.
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

// ============================================================================
// Helpers
// ============================================================================

function runCli(args: string[], cwd: string): { stdout: string; stderr: string; status: number | null } {
  const { spawnSync } = require("node:child_process");
  return spawnSync("node", [CLI, ...args], {
    encoding: "utf8",
    cwd,
    timeout: 60_000,
  });
}

function parseJson(content: string): Record<string, unknown> {
  try {
    return JSON.parse(content);
  } catch {
    return {};
  }
}

/**
 * Generate a large pnpm lockfile in-memory with the specified number of packages.
 */
function generateLargeLockfile(packageCount: number): Record<string, unknown> {
  const packages: Record<string, Record<string, unknown>> = {};
  const depth = Math.ceil(packageCount / 100);

  for (let i = 0; i < packageCount; i++) {
    const name = `package-${i}`;
    const version = `${Math.floor(i / 10)}.${i % 10}.0`;
    const deps: Record<string, string> = {};

    // Create some dependency chains (up to 3 deps per package)
    for (let d = 0; d < Math.min(3, i); d++) {
      const depIdx = Math.max(0, i - d - 1);
      const depName = `package-${depIdx}`;
      const depVersion = `${Math.floor(depIdx / 10)}.${depIdx % 10}.0`;
      deps[depName] = depVersion;
    }

    packages[`/${name}@${version}`] = {
      resolution: { integrity: `sha512-${Buffer.from(`${name}-${version}`).toString("base64")}` },
      engines: { node: ">=14" },
      dependencies: Object.keys(deps).length > 0 ? deps : undefined,
      dev: i % 5 === 0,
    };
  }

  return {
    lockfileVersion: "9.0",
    packages,
  };
}

// ============================================================================
// Tests
// ============================================================================

describe("SBOM Performance Tests", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sbom-perf-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  // ---------------------------------------------------------------------------
  // Fixture-based benchmarks
  // ---------------------------------------------------------------------------

  describe("fixture-based benchmarks", () => {
    it("CycloneDX generation from pnpm-v9 lockfile completes in <2s", async () => {
      const lockfilePath = path.join(FIXTURES_DIR, "pnpm-v9.yaml");
      await fs.copyFile(lockfilePath, path.join(tempDir, "pnpm-lock.yaml"));

      const outputPath = path.join(tempDir, "sbom.json");
      const start = Date.now();
      runCli(["--sbom", "--sbom-format", "cyclonedx", "--sbom-output", outputPath, "--offline"], tempDir);
      const duration = Date.now() - start;

      assert.ok(duration < 2000, `CycloneDX generation took ${duration}ms, should be <2000ms`);
    });

    it("SPDX generation from pnpm-v9 lockfile completes in <2s", async () => {
      const lockfilePath = path.join(FIXTURES_DIR, "pnpm-v9.yaml");
      await fs.copyFile(lockfilePath, path.join(tempDir, "pnpm-lock.yaml"));

      const outputPath = path.join(tempDir, "sbom.json");
      const start = Date.now();
      runCli(["--sbom", "--sbom-format", "spdx", "--sbom-output", outputPath, "--offline"], tempDir);
      const duration = Date.now() - start;

      assert.ok(duration < 2000, `SPDX generation took ${duration}ms, should be <2000ms`);
    });

    it("CycloneDX generation from large-lockfile fixture completes in <3s", async () => {
      const lockfilePath = path.join(FIXTURES_DIR, "large-lockfile.yaml");
      await fs.copyFile(lockfilePath, path.join(tempDir, "pnpm-lock.yaml"));

      const outputPath = path.join(tempDir, "sbom.json");
      const start = Date.now();
      runCli(["--sbom", "--sbom-format", "cyclonedx", "--sbom-output", outputPath, "--offline"], tempDir);
      const duration = Date.now() - start;

      const fileExists = await fs.access(outputPath).then(() => true).catch(() => false);
      if (fileExists) {
        const content = parseJson(await fs.readFile(outputPath, "utf8"));
        const componentCount = Array.isArray(content.components) ? content.components.length : 0;
        console.log(`  Large lockfile: ${componentCount} components in ${duration}ms`);
      }

      assert.ok(duration < 3000, `Large lockfile generation took ${duration}ms, should be <3000ms`);
    });
  });

  // ---------------------------------------------------------------------------
  // Synthetic load benchmarks
  // ---------------------------------------------------------------------------

  describe("synthetic load benchmarks", () => {
    it("CycloneDX generation with 100 packages completes in <1s", async () => {
      const yaml = await import("yaml");
      const lockfile = generateLargeLockfile(100);
      await fs.writeFile(path.join(tempDir, "pnpm-lock.yaml"), yaml.stringify(lockfile));

      const outputPath = path.join(tempDir, "sbom.json");
      const start = Date.now();
      runCli(["--sbom", "--sbom-format", "cyclonedx", "--sbom-output", outputPath, "--offline"], tempDir);
      const duration = Date.now() - start;

      const fileExists = await fs.access(outputPath).then(() => true).catch(() => false);
      if (fileExists) {
        const content = parseJson(await fs.readFile(outputPath, "utf8"));
        const count = Array.isArray(content.components) ? content.components.length : 0;
        console.log(`  100 packages -> ${count} components in ${duration}ms`);
      }

      assert.ok(duration < 1000, `100 packages took ${duration}ms, should be <1000ms`);
    });

    it("CycloneDX generation with 500 packages completes in <2s", async () => {
      const yaml = await import("yaml");
      const lockfile = generateLargeLockfile(500);
      await fs.writeFile(path.join(tempDir, "pnpm-lock.yaml"), yaml.stringify(lockfile));

      const outputPath = path.join(tempDir, "sbom.json");
      const start = Date.now();
      runCli(["--sbom", "--sbom-format", "cyclonedx", "--sbom-output", outputPath, "--offline"], tempDir);
      const duration = Date.now() - start;

      const fileExists = await fs.access(outputPath).then(() => true).catch(() => false);
      if (fileExists) {
        const content = parseJson(await fs.readFile(outputPath, "utf8"));
        const count = Array.isArray(content.components) ? content.components.length : 0;
        console.log(`  500 packages -> ${count} components in ${duration}ms`);
      }

      assert.ok(duration < 2000, `500 packages took ${duration}ms, should be <2000ms`);
    });

    it("CycloneDX generation with 1000 packages completes in <2s (target)", async () => {
      const yaml = await import("yaml");
      const lockfile = generateLargeLockfile(1000);
      await fs.writeFile(path.join(tempDir, "pnpm-lock.yaml"), yaml.stringify(lockfile));

      const outputPath = path.join(tempDir, "sbom.json");
      const start = Date.now();
      runCli(["--sbom", "--sbom-format", "cyclonedx", "--sbom-output", outputPath, "--offline"], tempDir);
      const duration = Date.now() - start;

      const fileExists = await fs.access(outputPath).then(() => true).catch(() => false);
      if (fileExists) {
        const content = parseJson(await fs.readFile(outputPath, "utf8"));
        const count = Array.isArray(content.components) ? content.components.length : 0;
        console.log(`  1000 packages -> ${count} components in ${duration}ms`);
      }

      assert.ok(duration < 2000, `1000 packages took ${duration}ms, should be <2000ms`);
    });

    it("SPDX generation with 1000 packages completes in <2s (target)", async () => {
      const yaml = await import("yaml");
      const lockfile = generateLargeLockfile(1000);
      await fs.writeFile(path.join(tempDir, "pnpm-lock.yaml"), yaml.stringify(lockfile));

      const outputPath = path.join(tempDir, "sbom.json");
      const start = Date.now();
      runCli(["--sbom", "--sbom-format", "spdx", "--sbom-output", outputPath, "--offline"], tempDir);
      const duration = Date.now() - start;

      const fileExists = await fs.access(outputPath).then(() => true).catch(() => false);
      if (fileExists) {
        const content = parseJson(await fs.readFile(outputPath, "utf8"));
        const count = Array.isArray(content.packages) ? content.packages.length : 0;
        console.log(`  1000 packages -> ${count} packages (SPDX) in ${duration}ms`);
      }

      assert.ok(duration < 2000, `SPDX with 1000 packages took ${duration}ms, should be <2000ms`);
    });
  });

  // ---------------------------------------------------------------------------
  // Output size benchmarks
  // ---------------------------------------------------------------------------

  describe("output size", () => {
    it("CycloneDX output size is reasonable for large lockfile", async () => {
      const yaml = await import("yaml");
      const lockfile = generateLargeLockfile(500);
      await fs.writeFile(path.join(tempDir, "pnpm-lock.yaml"), yaml.stringify(lockfile));

      const outputPath = path.join(tempDir, "sbom.json");
      runCli(["--sbom", "--sbom-format", "cyclonedx", "--sbom-output", outputPath, "--offline"], tempDir);

      const stat = await fs.stat(outputPath);
      const sizeMB = stat.size / (1024 * 1024);

      console.log(`  CycloneDX output: ${(stat.size / 1024).toFixed(1)} KB for 500 packages`);
      assert.ok(sizeMB < 5, `Output size ${sizeMB.toFixed(2)}MB should be <5MB`);
    });

    it("SPDX output size is reasonable for large lockfile", async () => {
      const yaml = await import("yaml");
      const lockfile = generateLargeLockfile(500);
      await fs.writeFile(path.join(tempDir, "pnpm-lock.yaml"), yaml.stringify(lockfile));

      const outputPath = path.join(tempDir, "sbom.json");
      runCli(["--sbom", "--sbom-format", "spdx", "--sbom-output", outputPath, "--offline"], tempDir);

      const stat = await fs.stat(outputPath);
      const sizeMB = stat.size / (1024 * 1024);

      console.log(`  SPDX output: ${(stat.size / 1024).toFixed(1)} KB for 500 packages`);
      assert.ok(sizeMB < 5, `Output size ${sizeMB.toFixed(2)}MB should be <5MB`);
    });
  });
});
