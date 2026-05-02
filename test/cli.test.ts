import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, renameSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const CLI = join(__dirname, "..", "bin", "cli.js");
const DIST_INDEX = join(__dirname, "..", "dist", "index.js");
const DIST_BACKUP = DIST_INDEX + ".bak";

/**
 * Temporarily hide dist/index.js so the CLI hits the "not built" error path.
 * Restores it afterward (even if the test throws).
 */
function withHiddenDist(fn: () => void): void {
  const wasPresent = existsSync(DIST_INDEX);
  if (wasPresent) {
    renameSync(DIST_INDEX, DIST_BACKUP);
  }
  try {
    fn();
  } finally {
    if (wasPresent) {
      renameSync(DIST_BACKUP, DIST_INDEX);
    }
  }
}

describe("CLI error handling", () => {
  it("--version works without dist/", () => {
    withHiddenDist(() => {
      const result = spawnSync("node", [CLI, "--version"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      assert.match(result.stdout, /\d+\.\d+\.\d+/);
    });
  });

  it("--help works without dist/", () => {
    withHiddenDist(() => {
      const result = spawnSync("node", [CLI, "--help"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 0);
      assert.match(result.stdout, /Usage/i);
    });
  });

  it("shows helpful error when dist/ is missing", () => {
    withHiddenDist(() => {
      const result = spawnSync("node", [CLI], { encoding: "utf8" });
      assert.equal(result.status, 1);
      assert.match(result.stderr, /not built/i);
    });
  });
});
