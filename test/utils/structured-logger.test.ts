import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";

// Test structured logger with child processes to control environment variables

const projectRoot = path.resolve(__dirname, "../..");
const tsxBin = path.join(projectRoot, "node_modules", ".bin", "tsx");

// Build a clean base environment
const getCleanBaseEnv = (): NodeJS.ProcessEnv => {
  const excludeVars = new Set([
    "CI", "TF_BUILD", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL",
    "PNPM_AUDIT_VERBOSE", "PNPM_AUDIT_JSON", "PNPM_AUDIT_FORMAT",
    "PNPM_AUDIT_QUIET", "PNPM_AUDIT_DEBUG",
  ]);
  const clean: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!excludeVars.has(key)) {
      clean[key] = value;
    }
  }
  return clean;
};

const testScript = (code: string, env: Record<string, string> = {}) => {
  const fullCode = `import { structuredLogger, createLogger, getChildLogger } from "./src/utils/logger"; ${code}`;
  
  const baseEnv = getCleanBaseEnv();
  const finalEnv: NodeJS.ProcessEnv = { ...baseEnv };
  for (const [key, value] of Object.entries(env)) {
    if (value === "") {
      delete finalEnv[key];
    } else {
      finalEnv[key] = value;
    }
  }

  const result = spawnSync(tsxBin, ["-e", fullCode], {
    cwd: projectRoot,
    env: finalEnv,
    encoding: "utf-8",
    timeout: 10000,
  });
  return {
    stdout: result.stdout || "",
    stderr: result.stderr || "",
    exitCode: result.status ?? 1,
  };
};

describe("structuredLogger", () => {
  describe("basic logging", () => {
    it("outputs info messages when not quiet", () => {
      const { stdout } = testScript(
        'structuredLogger.info("test message");',
        { PNPM_AUDIT_QUIET: "", PNPM_AUDIT_JSON: "" }
      );

      assert.ok(stdout.includes("[pnpm-audit]"));
      assert.ok(stdout.includes("[info]"));
      assert.ok(stdout.includes("test message"));
    });

    it("does not output when quiet mode", () => {
      const { stdout } = testScript(
        'structuredLogger.info("test message");',
        { PNPM_AUDIT_QUIET: "true", PNPM_AUDIT_JSON: "" }
      );

      assert.equal(stdout, "");
    });

    it("always outputs error messages", () => {
      const { stderr } = testScript(
        'structuredLogger.error("test error");',
        { PNPM_AUDIT_QUIET: "true", PNPM_AUDIT_JSON: "" }
      );

      assert.ok(stderr.includes("[error]"));
      assert.ok(stderr.includes("test error"));
    });
  });

  describe("structured metadata", () => {
    it("includes source in output", () => {
      const { stdout } = testScript(
        'structuredLogger.info("test message", { source: "test-module" });',
        { PNPM_AUDIT_QUIET: "", PNPM_AUDIT_JSON: "" }
      );

      assert.ok(stdout.includes("[test-module]"));
      assert.ok(stdout.includes("test message"));
    });

    it("includes correlation ID in output", () => {
      const { stdout } = testScript(
        'structuredLogger.setCorrelationId("abc-123"); structuredLogger.info("test message");',
        { PNPM_AUDIT_QUIET: "", PNPM_AUDIT_JSON: "" }
      );

      assert.ok(stdout.includes("[abc-123]"));
      assert.ok(stdout.includes("test message"));
    });
  });

  describe("child logger", () => {
    it("creates child logger with source context", () => {
      const { stdout } = testScript(
        'const child = getChildLogger("child-module"); child.info("child message");',
        { PNPM_AUDIT_QUIET: "", PNPM_AUDIT_JSON: "" }
      );

      assert.ok(stdout.includes("[child-module]"));
      assert.ok(stdout.includes("child message"));
    });
  });

  describe("timing", () => {
    it("logs timing information", () => {
      const { stdout } = testScript(
        'structuredLogger.timing("operation", 150);',
        { PNPM_AUDIT_DEBUG: "true", PNPM_AUDIT_JSON: "" }
      );

      assert.ok(stdout.includes("operation: 150ms"));
    });
  });
});

describe("createLogger", () => {
  it("creates logger with source", () => {
    const { stdout } = testScript(
      'const log = createLogger("my-source"); log.info("test");',
      { PNPM_AUDIT_QUIET: "", PNPM_AUDIT_JSON: "" }
    );

    assert.ok(stdout.includes("[my-source]"));
    assert.ok(stdout.includes("test"));
  });

  it("creates logger with correlation ID", () => {
    const { stdout } = testScript(
      'const log = createLogger("source", "corr-123"); log.info("test");',
      { PNPM_AUDIT_QUIET: "", PNPM_AUDIT_JSON: "" }
    );

    assert.ok(stdout.includes("[corr-123]"));
  });
});