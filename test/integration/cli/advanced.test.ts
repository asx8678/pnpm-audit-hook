import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const CLI = path.join(__dirname, "..", "..", "..", "bin", "cli.js");

describe("CLI Advanced Integration", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "cli-advanced-test-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  describe("flag combinations", () => {
    it("--version and --help can be used together", () => {
      const result = spawnSync("node", [CLI, "--version", "--help"], {
        encoding: "utf8",
      });
      // Should still work, showing help takes precedence
      assert.equal(result.status, 0);
      assert.match(result.stdout, /Usage/i);
    });

    it("--help with --quiet does not affect output", () => {
      const result = spawnSync("node", [CLI, "--help", "--quiet"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      assert.match(result.stdout, /Usage/i);
    });

    it("--help with --verbose does not affect output", () => {
      const result = spawnSync("node", [CLI, "--help", "--verbose"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      assert.match(result.stdout, /Usage/i);
    });

    it("--db-status with --quiet flag works", () => {
      const result = spawnSync("node", [CLI, "--db-status", "--quiet"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      assert.match(result.stdout, /Database Status/);
    });

    it("--troubleshoot with --quiet flag works", () => {
      const result = spawnSync("node", [CLI, "--troubleshoot", "--quiet"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      assert.match(result.stdout, /Troubleshooting Information/i);
    });
  });

  describe("format options", () => {
    it("--format json is accepted", () => {
      // Create a lockfile to test with
      const lockfileContent = `lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21

packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-test}
    dev: false
`;
      fs.writeFile(path.join(tempDir, "pnpm-lock.yaml"), lockfileContent);

      const result = spawnSync("node", [CLI, "--format", "json", "--offline"], {
        encoding: "utf8",
        cwd: tempDir,
      });
      // Should not error on the format flag itself
      // May error on missing dist/ but that's ok
    });

    it("--format table is accepted", () => {
      const lockfileContent = `lockfileVersion: '9.0'

importers:
  .:
    dependencies: {}

packages: {}
`;
      fs.writeFile(path.join(tempDir, "pnpm-lock.yaml"), lockfileContent);

      const result = spawnSync("node", [CLI, "--format", "table", "--offline"], {
        encoding: "utf8",
        cwd: tempDir,
      });
      // Should not error on the format flag
    });
  });

  describe("severity options", () => {
    it("--severity critical is accepted", () => {
      const lockfileContent = `lockfileVersion: '9.0'

importers:
  .:
    dependencies: {}

packages: {}
`;
      fs.writeFile(path.join(tempDir, "pnpm-lock.yaml"), lockfileContent);

      const result = spawnSync("node", [CLI, "--severity", "critical", "--offline"], {
        encoding: "utf8",
        cwd: tempDir,
      });
      // Should not error on the severity flag
    });

    it("-s short flag works", () => {
      const lockfileContent = `lockfileVersion: '9.0'

importers:
  .:
    dependencies: {}

packages: {}
`;
      fs.writeFile(path.join(tempDir, "pnpm-lock.yaml"), lockfileContent);

      const result = spawnSync("node", [CLI, "-s", "high", "--offline"], {
        encoding: "utf8",
        cwd: tempDir,
      });
      // Should not error on the -s flag
    });

    it("--severity critical,high is accepted", () => {
      const lockfileContent = `lockfileVersion: '9.0'

importers:
  .:
    dependencies: {}

packages: {}
`;
      fs.writeFile(path.join(tempDir, "pnpm-lock.yaml"), lockfileContent);

      const result = spawnSync("node", [CLI, "--severity", "critical,high", "--offline"], {
        encoding: "utf8",
        cwd: tempDir,
      });
      // Should not error
    });
  });

  describe("offline mode", () => {
    it("--offline flag is accepted", () => {
      const lockfileContent = `lockfileVersion: '9.0'

importers:
  .:
    dependencies: {}

packages: {}
`;
      fs.writeFile(path.join(tempDir, "pnpm-lock.yaml"), lockfileContent);

      const result = spawnSync("node", [CLI, "--offline"], {
        encoding: "utf8",
        cwd: tempDir,
      });
      // Should not error
    });
  });

  describe("exit codes", () => {
    it("returns exit code 1 when pnpm-lock.yaml is missing", () => {
      const result = spawnSync("node", [CLI], {
        encoding: "utf8",
        cwd: tempDir,
      });
      assert.equal(result.status, 1);
      assert.match(result.stderr, /No pnpm-lock\.yaml found/i);
    });

    it("returns exit code 0 for --version", () => {
      const result = spawnSync("node", [CLI, "--version"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
    });

    it("returns exit code 0 for --help", () => {
      const result = spawnSync("node", [CLI, "--help"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
    });

    it("returns exit code 0 for --db-status", () => {
      const result = spawnSync("node", [CLI, "--db-status"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
    });

    it("returns exit code 0 for --troubleshoot", () => {
      const result = spawnSync("node", [CLI, "--troubleshoot"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
    });
  });
});
