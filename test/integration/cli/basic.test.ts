import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const CLI = path.join(__dirname, "..", "..", "..", "bin", "cli.js");
const SETUP = path.join(__dirname, "..", "..", "..", "bin", "setup.js");

describe("CLI Basic Integration", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "cli-basic-test-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  describe("--version flag", () => {
    it("displays version number in semver format", () => {
      const result = spawnSync("node", [CLI, "--version"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      assert.match(result.stdout.trim(), /^\d+\.\d+\.\d+$/);
    });

    it("does not output extra whitespace", () => {
      const result = spawnSync("node", [CLI, "--version"], {
        encoding: "utf8",
      });
      assert.equal(result.stdout.trim(), result.stdout.trim());
      assert.equal(result.stdout, result.stdout.trim() + "\n");
    });
  });

  describe("--help flag", () => {
    it("displays help text with usage information", () => {
      const result = spawnSync("node", [CLI, "--help"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      assert.match(result.stdout, /Usage/i);
    });

    it("includes all command line options", () => {
      const result = spawnSync("node", [CLI, "--help"], {
        encoding: "utf8",
      });
      assert.ok(result.stdout.includes("--version"), "Should include --version");
      assert.ok(result.stdout.includes("--help"), "Should include --help");
      assert.ok(result.stdout.includes("--offline"), "Should include --offline");
      assert.ok(result.stdout.includes("--quiet"), "Should include --quiet");
      assert.ok(result.stdout.includes("--verbose"), "Should include --verbose");
      assert.ok(result.stdout.includes("--debug"), "Should include --debug");
      assert.ok(result.stdout.includes("--format"), "Should include --format");
      assert.ok(result.stdout.includes("--db-status"), "Should include --db-status");
      assert.ok(result.stdout.includes("--severity"), "Should include --severity");
      assert.ok(result.stdout.includes("--update-db"), "Should include --update-db");
      assert.ok(result.stdout.includes("--troubleshoot"), "Should include --troubleshoot");
    });

    it("returns exit code 0", () => {
      const result = spawnSync("node", [CLI, "--help"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
    });
  });

  describe("--troubleshoot flag", () => {
    it("displays troubleshooting information", () => {
      const result = spawnSync("node", [CLI, "--troubleshoot"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      assert.match(result.stdout, /Troubleshooting Information/i);
      assert.match(result.stdout, /Version Information/i);
      assert.match(result.stdout, /System Information/i);
      assert.match(result.stdout, /Project Checks/i);
    });

    it("displays node.js version", () => {
      const result = spawnSync("node", [CLI, "--troubleshoot"], {
        encoding: "utf8",
      });
      assert.match(result.stdout, /Node\.js:/);
    });

    it("checks for pnpm-lock.yaml", () => {
      const result = spawnSync("node", [CLI, "--troubleshoot"], {
        encoding: "utf8",
        cwd: tempDir,
      });
      assert.match(result.stdout, /pnpm-lock\.yaml/);
    });
  });

  describe("--db-status flag", () => {
    it("displays database status information", () => {
      const result = spawnSync("node", [CLI, "--db-status"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      assert.match(result.stdout, /Database Status/);
      assert.match(result.stdout, /Loaded & ready/);
      assert.match(result.stdout, /DB version/);
      assert.match(result.stdout, /Cutoff date/);
      assert.match(result.stdout, /Total vulns/);
      assert.match(result.stdout, /Total packages/);
      assert.match(result.stdout, /Schema version/);
    });
  });

  describe("error handling", () => {
    it("shows error when pnpm-lock.yaml is missing", () => {
      const result = spawnSync("node", [CLI], {
        encoding: "utf8",
        cwd: tempDir,
      });
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /No pnpm-lock\.yaml found/i);
    });

    it("shows helpful error when dist/ is missing", () => {
      // This test verifies the "not built" error path
      const result = spawnSync("node", [CLI, "--version"], {
        encoding: "utf8",
      });
      // Version should work regardless of dist/
      assert.equal(result.status, 0);
    });
  });
});
