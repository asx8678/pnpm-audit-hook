import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, renameSync } from "node:fs";
import path, { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs, HELP } from "../bin/parse-args.js";

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

describe("parseArgs", () => {
  describe("--update-db flag", () => {
    it('sets updateDb to "incremental" when flag is passed without a value', () => {
      const args = parseArgs(["--update-db"]);
      assert.equal(args.updateDb, "incremental");
    });

    it("sets updateDb to 'full' when --update-db=full is passed", () => {
      const args = parseArgs(["--update-db=full"]);
      assert.equal(args.updateDb, "full");
    });

    it("falls back to 'incremental' for unknown --update-db values", () => {
      const args = parseArgs(["--update-db=unknown"]);
      assert.equal(args.updateDb, "incremental");
    });

    it('falls back to "incremental" for --update-db with empty value', () => {
      const args = parseArgs(["--update-db="]);
      assert.equal(args.updateDb, "incremental");
    });

    it("does not interfere with --offline flag", () => {
      const args = parseArgs(["--update-db", "--offline"]);
      assert.equal(args.updateDb, "incremental");
      assert.equal(args.offline, true);
    });

    it("does not interfere with --format flag", () => {
      const args = parseArgs(["--update-db=full", "--format", "json"]);
      assert.equal(args.updateDb, "full");
      assert.equal(args.format, "json");
    });

    it("does not interfere with --severity flag", () => {
      const args = parseArgs([
        "--update-db",
        "--severity",
        "critical",
        "--offline",
      ]);
      assert.equal(args.updateDb, "incremental");
      assert.equal(args.severity, "critical");
      assert.equal(args.offline, true);
    });

    it("does not interfere with --quiet flag", () => {
      const args = parseArgs(["--quiet", "--update-db"]);
      assert.equal(args.quiet, true);
      assert.equal(args.updateDb, "incremental");
    });

    it("does not interfere with --help flag", () => {
      const args = parseArgs(["--update-db", "--help"]);
      assert.equal(args.updateDb, "incremental");
      assert.equal(args.help, true);
    });
  });
});

describe("HELP text", () => {
  it("includes documentation for --update-db", () => {
    assert.ok(HELP.includes("--update-db"), "HELP text should mention --update-db");
    assert.ok(
      HELP.includes("incremental"),
      "HELP text should mention 'incremental' mode"
    );
    assert.ok(HELP.includes("full"), "HELP text should mention 'full' mode");
  });
});

describe("CLI --help output", () => {
  it("prints help text with --update-db documented", () => {
    const cliPath = path.resolve(__dirname, "..", "bin", "cli.js");
    const result = spawnSync("node", [cliPath, "--help"], {
      encoding: "utf-8",
    });

    assert.equal(result.status, 0);
    assert.ok(
      result.stdout.includes("--update-db"),
      "CLI --help should mention --update-db"
    );
    assert.ok(
      result.stdout.includes("incremental"),
      "CLI --help should mention 'incremental' mode"
    );
    assert.ok(
      result.stdout.includes("full"),
      "CLI --help should mention 'full' mode"
    );
  });
});
