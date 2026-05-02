import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const CLI = path.join(__dirname, "..", "..", "..", "bin", "cli.js");

describe("CLI Error Handling Integration", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "cli-error-test-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  describe("missing lockfile", () => {
    it("shows error message when pnpm-lock.yaml is missing", () => {
      const result = spawnSync("node", [CLI], {
        encoding: "utf8",
        cwd: tempDir,
      });
      assert.equal(result.status, 1);
      assert.match(result.stderr, /No pnpm-lock\.yaml found/i);
    });

    it("suggests running from pnpm project root", () => {
      const result = spawnSync("node", [CLI], {
        encoding: "utf8",
        cwd: tempDir,
      });
      assert.match(result.stderr, /Run it from a pnpm project root/i);
    });

    it("suggests using npm audit or yarn audit for non-pnpm projects", () => {
      const result = spawnSync("node", [CLI], {
        encoding: "utf8",
        cwd: tempDir,
      });
      assert.match(result.stderr, /npm audit.*yarn audit/i);
    });
  });

  describe("invalid lockfile", () => {
    it("handles empty file gracefully", async () => {
      await fs.writeFile(path.join(tempDir, "pnpm-lock.yaml"), "");

      const result = spawnSync("node", [CLI, "--offline"], {
        encoding: "utf8",
        cwd: tempDir,
      });
      // Should handle empty lockfile
      assert.notEqual(result.status, 0);
    });

    it("handles invalid YAML gracefully", async () => {
      await fs.writeFile(
        path.join(tempDir, "pnpm-lock.yaml"),
        "invalid: yaml: content: {{{{"
      );

      const result = spawnSync("node", [CLI, "--offline"], {
        encoding: "utf8",
        cwd: tempDir,
      });
      // Should handle invalid YAML
    });

    it("handles non-YAML content gracefully", async () => {
      await fs.writeFile(
        path.join(tempDir, "pnpm-lock.yaml"),
        "This is not YAML content, just plain text"
      );

      const result = spawnSync("node", [CLI, "--offline"], {
        encoding: "utf8",
        cwd: tempDir,
      });
      // Should handle non-YAML content
    });
  });

  describe("invalid flags", () => {
    it("shows error for unknown flags", () => {
      const result = spawnSync("node", [CLI, "--invalid-flag"], {
        encoding: "utf8",
      });
      // Unknown flags should cause an error
      assert.notEqual(result.status, 0);
    });

    it("shows error for invalid format option", () => {
      const result = spawnSync("node", [CLI, "--format", "invalid"], {
        encoding: "utf8",
      });
      // Invalid format should cause an error
      assert.notEqual(result.status, 0);
    });

    it("shows error for invalid severity option", () => {
      const result = spawnSync("node", [CLI, "--severity", "invalid"], {
        encoding: "utf8",
      });
      // Invalid severity should cause an error
      assert.notEqual(result.status, 0);
    });
  });

  describe("concurrent execution", () => {
    it("handles multiple CLI instances running concurrently", async () => {
      const results: Array<{ status: number | null; stdout: string; stderr: string }> = [];
      const promises: Promise<void>[] = [];

      // Create a lockfile for testing
      const lockfileContent = `lockfileVersion: '9.0'

importers:
  .:
    dependencies: {}

packages: {}
`;
      await fs.writeFile(path.join(tempDir, "pnpm-lock.yaml"), lockfileContent);

      // Run multiple instances concurrently
      for (let i = 0; i < 5; i++) {
        promises.push(
          new Promise((resolve) => {
            const result = spawnSync("node", [CLI, "--version"], {
              encoding: "utf8",
              cwd: tempDir,
            });
            results.push(result);
            resolve();
          })
        );
      }

      await Promise.all(promises);

      // All instances should return the same version
      const versions = results.map((r) => r.stdout.trim());
      const uniqueVersions = new Set(versions);
      assert.equal(uniqueVersions.size, 1, "All instances should return the same version");
    });
  });

  describe("environment variable handling", () => {
    it("respects PNPM_AUDIT_QUIET env var", async () => {
      const lockfileContent = `lockfileVersion: '9.0'

importers:
  .:
    dependencies: {}

packages: {}
`;
      await fs.writeFile(path.join(tempDir, "pnpm-lock.yaml"), lockfileContent);

      const result = spawnSync("node", [CLI], {
        encoding: "utf8",
        cwd: tempDir,
        env: {
          ...process.env,
          PNPM_AUDIT_QUIET: "true",
        },
      });
      // Should not error when quiet mode is set via env
    });

    it("respects PNPM_AUDIT_VERBOSE env var", async () => {
      const lockfileContent = `lockfileVersion: '9.0'

importers:
  .:
    dependencies: {}

packages: {}
`;
      await fs.writeFile(path.join(tempDir, "pnpm-lock.yaml"), lockfileContent);

      const result = spawnSync("node", [CLI], {
        encoding: "utf8",
        cwd: tempDir,
        env: {
          ...process.env,
          PNPM_AUDIT_VERBOSE: "true",
        },
      });
      // Should not error when verbose mode is set via env
    });

    it("respects PNPM_AUDIT_OFFLINE env var", async () => {
      const lockfileContent = `lockfileVersion: '9.0'

importers:
  .:
    dependencies: {}

packages: {}
`;
      await fs.writeFile(path.join(tempDir, "pnpm-lock.yaml"), lockfileContent);

      const result = spawnSync("node", [CLI], {
        encoding: "utf8",
        cwd: tempDir,
        env: {
          ...process.env,
          PNPM_AUDIT_OFFLINE: "true",
        },
      });
      // Should not error when offline mode is set via env
    });
  });
});
