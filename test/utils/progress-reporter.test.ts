import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";

// Test progress reporter with child processes

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
  const fullCode = `import { ProgressReporter, formatProgressBar, renderProgressBar } from "./src/utils/progress-reporter"; ${code}`;
  
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

describe("ProgressReporter", () => {
  describe("basic functionality", () => {
    it("creates reporter and manages steps", () => {
      const { stdout } = testScript(`
        const reporter = new ProgressReporter({ showProgressBar: false, showEta: false });
        reporter.start();
        reporter.addStep("step1", "Processing", 10);
        reporter.update("step1", 5);
        const report = reporter.getReport();
        console.log(JSON.stringify({
          percentage: report.percentage,
          currentStep: report.currentStep,
          totalSteps: report.totalSteps
        }));
      `, { PNPM_AUDIT_QUIET: "", PNPM_AUDIT_JSON: "" });

      const parsed = JSON.parse(stdout.trim());
      assert.equal(parsed.percentage, 50);
      assert.equal(parsed.currentStep, 0);
      assert.equal(parsed.totalSteps, 1);
    });

    it("increments progress", () => {
      const { stdout } = testScript(`
        const reporter = new ProgressReporter({ showProgressBar: false, showEta: false });
        reporter.start();
        reporter.addStep("step1", "Processing", 10);
        reporter.increment("step1");
        reporter.increment("step1");
        reporter.increment("step1");
        const report = reporter.getReport();
        console.log(report.steps[0].current);
      `, { PNPM_AUDIT_QUIET: "", PNPM_AUDIT_JSON: "" });

      assert.equal(stdout.trim(), "3");
    });

    it("completes steps and advances", () => {
      const { stdout } = testScript(`
        const reporter = new ProgressReporter({ showProgressBar: false, showEta: false });
        reporter.start();
        reporter.addStep("step1", "Step 1", 10);
        reporter.addStep("step2", "Step 2", 20);
        reporter.completeStep("step1");
        const report = reporter.getReport();
        console.log(JSON.stringify({
          currentStep: report.currentStep,
          step1Complete: report.steps[0].current >= report.steps[0].total
        }));
      `, { PNPM_AUDIT_QUIET: "", PNPM_AUDIT_JSON: "" });

      const parsed = JSON.parse(stdout.trim());
      assert.equal(parsed.currentStep, 1);
      assert.equal(parsed.step1Complete, true);
    });
  });

  describe("report generation", () => {
    it("calculates percentage correctly", () => {
      const { stdout } = testScript(`
        const reporter = new ProgressReporter({ showProgressBar: false, showEta: false });
        reporter.start();
        reporter.addStep("step1", "Step 1", 4);
        reporter.addStep("step2", "Step 2", 6);
        reporter.update("step1", 2);
        reporter.update("step2", 3);
        const report = reporter.getReport();
        console.log(report.percentage);
      `, { PNPM_AUDIT_QUIET: "", PNPM_AUDIT_JSON: "" });

      assert.equal(stdout.trim(), "50");
    });

    it("reports completion", () => {
      const { stdout } = testScript(`
        const reporter = new ProgressReporter({ showProgressBar: false, showEta: false });
        reporter.start();
        reporter.addStep("step1", "Step 1", 10);
        reporter.completeStep("step1");
        const report = reporter.getReport();
        console.log(report.complete);
      `, { PNPM_AUDIT_QUIET: "", PNPM_AUDIT_JSON: "" });

      assert.equal(stdout.trim(), "true");
    });
  });

  describe("sub-progress", () => {
    it("creates sub-progress reporter", () => {
      const { stdout } = testScript(`
        const reporter = new ProgressReporter({ showProgressBar: false, showEta: false });
        reporter.start();
        reporter.addStep("step1", "Processing", 10);
        const sub = reporter.createSubProgress("step1");
        sub.update(5);
        console.log(reporter.getReport().steps[0].current);
      `, { PNPM_AUDIT_QUIET: "", PNPM_AUDIT_JSON: "" });

      assert.equal(stdout.trim(), "5");
    });
  });
});

describe("formatProgressBar", () => {
  it("formats progress bar correctly", () => {
    const { stdout } = testScript(`
      const formatted = formatProgressBar(50, 100, "Test");
      console.log(formatted);
    `, { PNPM_AUDIT_QUIET: "", PNPM_AUDIT_JSON: "", PNPM_AUDIT_VERBOSE: "true" });

    assert.ok(stdout.includes("[pnpm-audit]"));
    assert.ok(stdout.includes("50%"));
    assert.ok(stdout.includes("Test"));
  });

  it("returns empty string when not verbose", () => {
    const { stdout } = testScript(`
      const formatted = formatProgressBar(50, 100, "Test");
      console.log(formatted.length === 0 ? "empty" : "not-empty");
    `, { PNPM_AUDIT_QUIET: "", PNPM_AUDIT_JSON: "" });

    assert.equal(stdout.trim(), "empty");
  });
});