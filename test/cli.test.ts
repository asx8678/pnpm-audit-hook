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
  describe("--db-status flag", () => {
    it('sets dbStatus to true when --db-status flag is passed', () => {
      const args = parseArgs(["--db-status"]);
      assert.equal(args.dbStatus, true);
    });

    it("does not interfere with --offline flag", () => {
      const args = parseArgs(["--db-status", "--offline"]);
      assert.equal(args.dbStatus, true);
      assert.equal(args.offline, true);
    });

    it("does not interfere with --quiet flag", () => {
      const args = parseArgs(["--db-status", "--quiet"]);
      assert.equal(args.dbStatus, true);
      assert.equal(args.quiet, true);
    });

    it("does not interfere with --help flag", () => {
      const args = parseArgs(["--db-status", "--help"]);
      assert.equal(args.dbStatus, true);
      assert.equal(args.help, true);
    });
  });

  describe("--sbom flag", () => {
    it('sets sbom to true when --sbom flag is passed', () => {
      const args = parseArgs(["--sbom"]);
      assert.equal(args.sbom, true);
    });

    it("does not interfere with --offline flag", () => {
      const args = parseArgs(["--sbom", "--offline"]);
      assert.equal(args.sbom, true);
      assert.equal(args.offline, true);
    });

    it("does not interfere with --quiet flag", () => {
      const args = parseArgs(["--sbom", "--quiet"]);
      assert.equal(args.sbom, true);
      assert.equal(args.quiet, true);
    });

    it("does not interfere with --help flag", () => {
      const args = parseArgs(["--sbom", "--help"]);
      assert.equal(args.sbom, true);
      assert.equal(args.help, true);
    });
  });

  describe("--sbom-format flag", () => {
    it('sets sbomFormat when --sbom-format cyclonedx is passed', () => {
      const args = parseArgs(["--sbom-format", "cyclonedx"]);
      assert.equal(args.sbomFormat, "cyclonedx");
    });

    it('sets sbomFormat when --sbom-format spdx is passed', () => {
      const args = parseArgs(["--sbom-format", "spdx"]);
      assert.equal(args.sbomFormat, "spdx");
    });

    it("does not interfere with --sbom flag", () => {
      const args = parseArgs(["--sbom", "--sbom-format", "spdx"]);
      assert.equal(args.sbom, true);
      assert.equal(args.sbomFormat, "spdx");
    });
  });

  describe("--sbom-output flag", () => {
    it('sets sbomOutput when --sbom-output path is passed', () => {
      const args = parseArgs(["--sbom-output", "sbom.json"]);
      assert.equal(args.sbomOutput, "sbom.json");
    });

    it("does not interfere with other flags", () => {
      const args = parseArgs(["--sbom", "--sbom-format", "cyclonedx", "--sbom-output", "output.json"]);
      assert.equal(args.sbom, true);
      assert.equal(args.sbomFormat, "cyclonedx");
      assert.equal(args.sbomOutput, "output.json");
    });
  });

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

describe("--severity flag", () => {
    it('--severity critical sets args.severity to "critical"', () => {
      const args = parseArgs(["--severity", "critical"]);
      assert.equal(args.severity, "critical");
    });

    it('--severity critical,high sets args.severity to "critical,high"', () => {
      const args = parseArgs(["--severity", "critical,high"]);
      assert.equal(args.severity, "critical,high");
    });

    it('-s medium sets args.severity to "medium"', () => {
      const args = parseArgs(["-s", "medium"]);
      assert.equal(args.severity, "medium");
    });

    it("--severity with --quiet does not interfere", () => {
      const args = parseArgs(["--severity", "low", "--quiet"]);
      assert.equal(args.severity, "low");
      assert.equal(args.quiet, true);
    });

    it("--severity does not interfere with --update-db", () => {
      const args = parseArgs(["--severity", "critical", "--update-db"]);
      assert.equal(args.severity, "critical");
      assert.equal(args.updateDb, "incremental");
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

describe("CLI --db-status integration", () => {
  it("exits with code 0 and shows database status", () => {
    const result = spawnSync("node", [CLI, "--db-status"], {
      encoding: "utf8",
    });
    assert.equal(result.status, 0);
    assert.match(result.stdout, /Database Status/);
    assert.match(result.stdout, /Loaded & ready/);
  });

  it("displays expected status fields", () => {
    const result = spawnSync("node", [CLI, "--db-status"], {
      encoding: "utf8",
    });
    assert.equal(result.status, 0);
    assert.match(result.stdout, /DB version/);
    assert.match(result.stdout, /Cutoff date/);
    assert.match(result.stdout, /Total vulns/);
    assert.match(result.stdout, /Total packages/);
    assert.match(result.stdout, /Schema version/);
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
