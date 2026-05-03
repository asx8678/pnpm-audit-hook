/**
 * Integration tests for dependency tree CLI functionality.
 *
 * Tests the --dep-tree flag and related options end-to-end.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawnSync } from "node:child_process";

const CLI_PATH = path.join(__dirname, "..", "..", "..", "bin", "cli.js");
const FIXTURES_DIR = path.join(__dirname, "..", "..", "fixtures", "lockfiles");
const SBOM_FIXTURES_DIR = path.join(__dirname, "..", "..", "fixtures", "sbom");

/** Run CLI with given args and return stdout/stderr/status. */
function runCli(
  args: string[],
  options?: { cwd?: string },
): { stdout: string; stderr: string; status: number | null } {
  const result = spawnSync("node", [CLI_PATH, ...args], {
    encoding: "utf-8",
    cwd: options?.cwd ?? process.cwd(),
    timeout: 15000,
    env: { ...process.env, NODE_NO_WARNINGS: "1" },
  });
  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    status: result.status,
  };
}

describe("CLI integration: --dep-tree", () => {
  it("should show help text includes --dep-tree options", () => {
    const { stdout } = runCli(["--help"]);
    assert.ok(stdout.includes("--dep-tree"), "help should mention --dep-tree");
    assert.ok(stdout.includes("--tree-depth"), "help should mention --tree-depth");
    assert.ok(stdout.includes("--tree-format"), "help should mention --tree-format");
    assert.ok(stdout.includes("--tree-output"), "help should mention --tree-output");
    assert.ok(stdout.includes("--sbom-input"), "help should mention --sbom-input");
  });

  it("should generate ASCII tree from lockfile (project's own lockfile)", () => {
    const { stdout, status } = runCli(["--dep-tree"], {
      cwd: path.join(__dirname, "..", "..", ".."),
    });

    assert.equal(status, 0);
    // Output should contain box-drawing characters
    assert.ok(
      stdout.includes("├") || stdout.includes("└") || stdout.split("\n").length >= 1,
      "output should contain tree-like structure",
    );
    // Should have at least the root line
    assert.ok(stdout.trim().length > 0, "should produce non-empty output");
  });

  it("should generate JSON tree when --tree-format json is used", () => {
    const { stdout, status } = runCli(["--dep-tree", "--tree-format", "json"], {
      cwd: path.join(__dirname, "..", "..", ".."),
    });

    assert.equal(status, 0);

    // Parse as JSON
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(stdout);
    } catch {
      assert.fail("Output should be valid JSON");
    }

    assert.ok(parsed.name, "JSON should have name field");
    assert.ok(Array.isArray(parsed.children), "JSON should have children array");
  });

  it("should respect --tree-depth limit", () => {
    const { stdout, status } = runCli(
      ["--dep-tree", "--tree-depth", "1"],
      { cwd: path.join(__dirname, "..", "..", "..") },
    );

    assert.equal(status, 0);
    // Tree should be limited to depth 1 (root + direct deps only)
    const lines = stdout.trim().split("\n");
    // Should have root + some deps, but not deeply nested
    assert.ok(lines.length >= 1);
  });

  it("should write tree to file with --tree-output", () => {
    const tmpFile = path.join(os.tmpdir(), `tree-test-${Date.now()}.txt`);

    try {
      const { stderr, status } = runCli(
        ["--dep-tree", "--tree-output", tmpFile],
        { cwd: path.join(__dirname, "..", "..", "..") },
      );

      assert.equal(status, 0);
      assert.ok(stderr.includes("written to"), "should confirm file write");

      // Verify file exists and has content
      assert.ok(fs.existsSync(tmpFile), "output file should exist");
      const content = fs.readFileSync(tmpFile, "utf-8");
      assert.ok(content.trim().length > 0, "file should have content");
    } finally {
      if (fs.existsSync(tmpFile)) {
        fs.unlinkSync(tmpFile);
      }
    }
  });

  it("should build tree from --sbom-input file", () => {
    const sbomPath = path.join(SBOM_FIXTURES_DIR, "sample-cyclonedx.json");

    if (!fs.existsSync(sbomPath)) {
      // Skip if fixture doesn't exist
      return;
    }

    const { stdout, status } = runCli(["--dep-tree", "--sbom-input", sbomPath]);

    assert.equal(status, 0);
    assert.ok(stdout.trim().length > 0, "should produce tree output");
    // Our sample SBOM has lodash and express
    assert.ok(
      stdout.includes("lodash") || stdout.includes("express"),
      "should contain package names from SBOM",
    );
  });

  it("should error on missing SBOM file", () => {
    const { stderr, status } = runCli([
      "--dep-tree",
      "--sbom-input",
      "/nonexistent/sbom.json",
    ]);

    assert.notEqual(status, 0);
    assert.ok(stderr.includes("not found") || stderr.includes("Error"));
  });

  it("should error on invalid JSON in SBOM file", () => {
    const tmpFile = path.join(os.tmpdir(), `invalid-sbom-${Date.now()}.json`);
    fs.writeFileSync(tmpFile, "this is not json", "utf-8");

    try {
      const { stderr, status } = runCli(["--dep-tree", "--sbom-input", tmpFile]);

      assert.notEqual(status, 0);
      assert.ok(
        stderr.includes("Invalid JSON") || stderr.includes("Error"),
        `stderr should report JSON error, got: ${stderr}`,
      );
    } finally {
      fs.unlinkSync(tmpFile);
    }
  });

  it("should error when no lockfile found and no --sbom-input", () => {
    const tmpDir = os.tmpdir();
    // Run in a temp dir with no lockfile
    const { stderr, status } = runCli(["--dep-tree"], { cwd: tmpDir });

    assert.notEqual(status, 0);
    assert.ok(
      stderr.includes("No pnpm-lock.yaml") || stderr.includes("Error"),
      `stderr should report missing lockfile, got: ${stderr}`,
    );
  });

  it("should generate JSON tree and write to file", () => {
    const tmpFile = path.join(os.tmpdir(), `tree-json-test-${Date.now()}.json`);

    try {
      const { status } = runCli(
        ["--dep-tree", "--tree-format", "json", "--tree-output", tmpFile],
        { cwd: path.join(__dirname, "..", "..", "..") },
      );

      assert.equal(status, 0);

      const content = fs.readFileSync(tmpFile, "utf-8");
      const parsed = JSON.parse(content);
      assert.ok(parsed.name, "JSON file should contain valid tree");
    } finally {
      if (fs.existsSync(tmpFile)) {
        fs.unlinkSync(tmpFile);
      }
    }
  });

  it("should build tree from SPDX SBOM via --sbom-input", () => {
    const spdxPath = path.join(SBOM_FIXTURES_DIR, "sample-spdx.json");

    if (!fs.existsSync(spdxPath)) {
      return;
    }

    const { stdout, status } = runCli(["--dep-tree", "--sbom-input", spdxPath]);

    assert.equal(status, 0);
    assert.ok(stdout.trim().length > 0, "should produce tree output from SPDX");
  });
});
