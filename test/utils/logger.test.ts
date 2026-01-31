import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";

// The logger module captures env vars at load time as constants.
// To properly test different env configurations, we use child processes
// with different environment variables.

const projectRoot = path.resolve(__dirname, "../..");

// Build a clean base environment that excludes CI/audit-related vars
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
  // Construct inline code to avoid newline escaping issues
  const fullCode = `import { logger, isJsonMode, isVerbose, getOutputFormat } from "./src/utils/logger"; ${code}`;

  // Start with clean base env, then apply test-specific vars
  // Empty string values are filtered out (treated as "unset")
  const baseEnv = getCleanBaseEnv();
  const finalEnv: NodeJS.ProcessEnv = { ...baseEnv };
  for (const [key, value] of Object.entries(env)) {
    if (value === "") {
      delete finalEnv[key]; // Explicitly unset
    } else {
      finalEnv[key] = value;
    }
  }

  const result = spawnSync("npx", ["tsx", "-e", fullCode], {
    cwd: projectRoot,
    env: finalEnv,
    encoding: "utf-8",
  });
  return {
    stdout: result.stdout || "",
    stderr: result.stderr || "",
  };
};

describe("logger", () => {
  describe("debug", () => {
    it("does not output when PNPM_AUDIT_DEBUG is not set", () => {
      const { stdout, stderr } = testScript('logger.debug("test message");', {
        PNPM_AUDIT_DEBUG: "",
        PNPM_AUDIT_JSON: "",
      });

      assert.equal(stdout, "");
      assert.equal(stderr, "");
    });

    it("outputs when PNPM_AUDIT_DEBUG=true", () => {
      const { stdout } = testScript('logger.debug("test message");', {
        PNPM_AUDIT_DEBUG: "true",
        PNPM_AUDIT_JSON: "",
      });

      assert.ok(stdout.includes("[debug]"));
      assert.ok(stdout.includes("test message"));
    });
  });

  describe("info", () => {
    it("does not output when PNPM_AUDIT_QUIET=true", () => {
      const { stdout, stderr } = testScript('logger.info("test message");', {
        PNPM_AUDIT_QUIET: "true",
        PNPM_AUDIT_JSON: "",
      });

      assert.equal(stdout, "");
      assert.equal(stderr, "");
    });

    it("outputs normally when not quiet", () => {
      const { stdout } = testScript('logger.info("test message");', {
        PNPM_AUDIT_QUIET: "",
        PNPM_AUDIT_JSON: "",
      });

      assert.ok(stdout.includes("[pnpm-audit]"));
      assert.ok(stdout.includes("test message"));
    });
  });

  describe("warn", () => {
    it("does not output when PNPM_AUDIT_QUIET=true", () => {
      const { stdout, stderr } = testScript('logger.warn("test warning");', {
        PNPM_AUDIT_QUIET: "true",
        PNPM_AUDIT_JSON: "",
      });

      assert.equal(stdout, "");
      assert.equal(stderr, "");
    });

    it("outputs normally when not quiet", () => {
      const { stderr } = testScript('logger.warn("test warning");', {
        PNPM_AUDIT_QUIET: "",
        PNPM_AUDIT_JSON: "",
      });

      assert.ok(stderr.includes("[warn]"));
      assert.ok(stderr.includes("test warning"));
    });
  });

  describe("error", () => {
    it("always outputs (not suppressed by QUIET)", () => {
      const { stderr } = testScript('logger.error("test error");', {
        PNPM_AUDIT_QUIET: "true",
        PNPM_AUDIT_JSON: "",
      });

      assert.ok(stderr.includes("[error]"));
      assert.ok(stderr.includes("test error"));
    });
  });

  describe("JSON mode", () => {
    it("logger methods do not output when PNPM_AUDIT_JSON=true", () => {
      const code = 'logger.debug("debug msg"); logger.info("info msg"); logger.warn("warn msg"); logger.error("error msg");';
      const { stdout, stderr } = testScript(code, {
        PNPM_AUDIT_JSON: "true",
        PNPM_AUDIT_DEBUG: "true",
        PNPM_AUDIT_QUIET: "",
      });

      assert.equal(stdout, "");
      assert.equal(stderr, "");
    });

    it("logger.json outputs when PNPM_AUDIT_JSON=true", () => {
      const { stdout } = testScript(
        'logger.json({ foo: "bar", count: 42 });',
        { PNPM_AUDIT_JSON: "true" }
      );

      assert.ok(stdout.includes('{"foo":"bar","count":42}'));
    });

    it("logger.json does not output when PNPM_AUDIT_JSON is not set", () => {
      const { stdout, stderr } = testScript(
        'logger.json({ foo: "bar" });',
        { PNPM_AUDIT_JSON: "" }
      );

      assert.equal(stdout, "");
      assert.equal(stderr, "");
    });
  });

  describe("isJsonMode", () => {
    it("returns true when PNPM_AUDIT_JSON=true", () => {
      const { stdout } = testScript('console.log(isJsonMode());', {
        PNPM_AUDIT_JSON: "true",
      });

      assert.equal(stdout.trim(), "true");
    });

    it("returns false when PNPM_AUDIT_JSON is not set", () => {
      const { stdout } = testScript('console.log(isJsonMode());', {
        PNPM_AUDIT_JSON: "",
      });

      assert.equal(stdout.trim(), "false");
    });

    it("returns false when PNPM_AUDIT_JSON is not 'true'", () => {
      const { stdout } = testScript('console.log(isJsonMode());', {
        PNPM_AUDIT_JSON: "false",
      });

      assert.equal(stdout.trim(), "false");
    });
  });

  describe("isVerbose", () => {
    it("returns true when PNPM_AUDIT_VERBOSE=true", () => {
      const { stdout } = testScript("console.log(isVerbose());", {
        PNPM_AUDIT_VERBOSE: "true",
      });
      assert.equal(stdout.trim(), "true");
    });

    it("returns true when CI=true", () => {
      const { stdout } = testScript("console.log(isVerbose());", {
        CI: "true",
      });
      assert.equal(stdout.trim(), "true");
    });

    it("returns true when TF_BUILD=True (Azure DevOps)", () => {
      const { stdout } = testScript("console.log(isVerbose());", {
        TF_BUILD: "True",
      });
      assert.equal(stdout.trim(), "true");
    });

    it("returns true when GITHUB_ACTIONS=true", () => {
      const { stdout } = testScript("console.log(isVerbose());", {
        GITHUB_ACTIONS: "true",
      });
      assert.equal(stdout.trim(), "true");
    });

    it("returns true when GITLAB_CI=true", () => {
      const { stdout } = testScript("console.log(isVerbose());", {
        GITLAB_CI: "true",
      });
      assert.equal(stdout.trim(), "true");
    });

    it("returns true when JENKINS_URL is set", () => {
      const { stdout } = testScript("console.log(isVerbose());", {
        JENKINS_URL: "http://jenkins.example.com",
      });
      assert.equal(stdout.trim(), "true");
    });

    it("returns false when no verbose env vars are set", () => {
      const { stdout } = testScript("console.log(isVerbose());", {});
      assert.equal(stdout.trim(), "false");
    });
  });

  describe("getOutputFormat", () => {
    it("returns 'json' when PNPM_AUDIT_JSON=true", () => {
      const { stdout } = testScript("console.log(getOutputFormat());", {
        PNPM_AUDIT_JSON: "true",
      });
      assert.equal(stdout.trim(), "json");
    });

    it("returns 'azure' when PNPM_AUDIT_FORMAT=azure", () => {
      const { stdout } = testScript("console.log(getOutputFormat());", {
        PNPM_AUDIT_FORMAT: "azure",
      });
      assert.equal(stdout.trim(), "azure");
    });

    it("returns 'azure' when TF_BUILD=True", () => {
      const { stdout } = testScript("console.log(getOutputFormat());", {
        TF_BUILD: "True",
      });
      assert.equal(stdout.trim(), "azure");
    });

    it("returns 'human' by default", () => {
      const { stdout } = testScript("console.log(getOutputFormat());", {});
      assert.equal(stdout.trim(), "human");
    });

    it("returns 'json' over 'azure' when both are set", () => {
      const { stdout } = testScript("console.log(getOutputFormat());", {
        PNPM_AUDIT_JSON: "true",
        PNPM_AUDIT_FORMAT: "azure",
        TF_BUILD: "True",
      });
      assert.equal(stdout.trim(), "json");
    });
  });
});
