import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";

// Test CI integration with child processes

const projectRoot = path.resolve(__dirname, "../..");
const tsxBin = path.join(projectRoot, "node_modules", ".bin", "tsx");

// Build a clean base environment
const getCleanBaseEnv = (): NodeJS.ProcessEnv => {
  const excludeVars = new Set([
    "CI", "TF_BUILD", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL",
    "CODEBUILD_BUILD_ID", "PNPM_AUDIT_VERBOSE", "PNPM_AUDIT_JSON", 
    "PNPM_AUDIT_FORMAT", "PNPM_AUDIT_QUIET", "PNPM_AUDIT_DEBUG",
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
  const fullCode = `import { detectCIPlatform, isCI, getCIPlatformName, emitWarning, emitError, emitNotice } from "./src/utils/ci-integration"; ${code}`;
  
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

describe("CI Integration", () => {
  describe("platform detection", () => {
    it("detects GitHub Actions", () => {
      const { stdout } = testScript(`
        const platform = detectCIPlatform();
        console.log(JSON.stringify({ name: platform.name, isCI: platform.isCI }));
      `, { GITHUB_ACTIONS: "true" });

      const parsed = JSON.parse(stdout.trim());
      assert.equal(parsed.name, "github-actions");
      assert.equal(parsed.isCI, true);
    });

    it("detects Azure DevOps", () => {
      const { stdout } = testScript(`
        const platform = detectCIPlatform();
        console.log(JSON.stringify({ name: platform.name, isCI: platform.isCI }));
      `, { TF_BUILD: "True" });

      const parsed = JSON.parse(stdout.trim());
      assert.equal(parsed.name, "azure-devops");
      assert.equal(parsed.isCI, true);
    });

    it("detects GitLab CI", () => {
      const { stdout } = testScript(`
        const platform = detectCIPlatform();
        console.log(JSON.stringify({ name: platform.name, isCI: platform.isCI }));
      `, { GITLAB_CI: "true" });

      const parsed = JSON.parse(stdout.trim());
      assert.equal(parsed.name, "gitlab-ci");
      assert.equal(parsed.isCI, true);
    });

    it("detects Jenkins", () => {
      const { stdout } = testScript(`
        const platform = detectCIPlatform();
        console.log(JSON.stringify({ name: platform.name, isCI: platform.isCI }));
      `, { JENKINS_URL: "http://jenkins.example.com" });

      const parsed = JSON.parse(stdout.trim());
      assert.equal(parsed.name, "jenkins");
      assert.equal(parsed.isCI, true);
    });

    it("detects AWS CodeBuild", () => {
      const { stdout } = testScript(`
        const platform = detectCIPlatform();
        console.log(JSON.stringify({ name: platform.name, isCI: platform.isCI }));
      `, { CODEBUILD_BUILD_ID: "build-123" });

      const parsed = JSON.parse(stdout.trim());
      assert.equal(parsed.name, "aws-codebuild");
      assert.equal(parsed.isCI, true);
    });

    it("detects local environment", () => {
      const { stdout } = testScript(`
        const platform = detectCIPlatform();
        console.log(JSON.stringify({ name: platform.name, isCI: platform.isCI }));
      `, {});

      const parsed = JSON.parse(stdout.trim());
      assert.equal(parsed.name, "local");
      assert.equal(parsed.isCI, false);
    });
  });

  describe("convenience functions", () => {
    it("isCI returns true in CI environment", () => {
      const { stdout } = testScript(
        "console.log(isCI());",
        { GITHUB_ACTIONS: "true" }
      );

      assert.equal(stdout.trim(), "true");
    });

    it("isCI returns false locally", () => {
      const { stdout } = testScript("console.log(isCI());", {});

      assert.equal(stdout.trim(), "false");
    });

    it("getCIPlatformName returns correct name", () => {
      const { stdout } = testScript(
        "console.log(getCIPlatformName());",
        { GITHUB_ACTIONS: "true" }
      );

      assert.equal(stdout.trim(), "github-actions");
    });
  });

  describe("annotations", () => {
    it("emits warning annotation in GitHub Actions format", () => {
      const { stdout } = testScript(
        'emitWarning("Test warning", "src/file.ts", 42);',
        { GITHUB_ACTIONS: "true" }
      );

      assert.ok(stdout.includes("::warning"));
      assert.ok(stdout.includes("Test warning"));
      assert.ok(stdout.includes("file=src/file.ts"));
      assert.ok(stdout.includes("line=42"));
    });

    it("emits error annotation in Azure DevOps format", () => {
      const { stdout } = testScript(
        'emitError("Test error");',
        { TF_BUILD: "True" }
      );

      assert.ok(stdout.includes("##vso[task.logissue type=error]"));
      assert.ok(stdout.includes("Test error"));
    });
  });
});