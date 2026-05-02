import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

describe("GitHub Actions CI/CD Integration", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe("CI platform detection", () => {
    it("detects GitHub Actions environment", () => {
      process.env.GITHUB_ACTIONS = "true";
      process.env.GITHUB_WORKFLOW = "CI";
      process.env.GITHUB_RUN_ID = "123456";
      process.env.GITHUB_SHA = "abc123";

      const { detectCIPlatform } = require("../../../src/utils/ci-integration");
      const platform = detectCIPlatform();

      assert.equal(platform.name, "github-actions");
      assert.equal(platform.isCI, true);
      assert.ok(platform.envVars.GITHUB_ACTIONS);
      assert.ok(platform.envVars.GITHUB_WORKFLOW);
    });

    it("does not detect GitHub Actions when env vars missing", () => {
      delete process.env.GITHUB_ACTIONS;
      delete process.env.GITHUB_WORKFLOW;

      const { detectCIPlatform } = require("../../../src/utils/ci-integration");
      const platform = detectCIPlatform();

      assert.notEqual(platform.name, "github-actions");
    });
  });

  describe("CI integration class", () => {
    it("creates GitHub Actions integration", () => {
      process.env.GITHUB_ACTIONS = "true";

      const { GitHubActionsIntegration } = require("../../../src/utils/ci-integration");
      const integration = new GitHubActionsIntegration();

      assert.ok(integration);
      assert.equal(typeof integration.detect, "function");
      assert.equal(typeof integration.emitAnnotation, "function");
      assert.equal(typeof integration.emitLog, "function");
      assert.equal(typeof integration.setOutput, "function");
    });

    it("detect platform returns GitHub Actions", () => {
      process.env.GITHUB_ACTIONS = "true";

      const { GitHubActionsIntegration } = require("../../../src/utils/ci-integration");
      const integration = new GitHubActionsIntegration();
      const platform = integration.detect();

      assert.equal(platform.name, "github-actions");
      assert.equal(platform.isCI, true);
    });
  });

  describe("annotation emission", () => {
    it("emits warning annotation", () => {
      process.env.GITHUB_ACTIONS = "true";

      const { emitWarning } = require("../../../src/utils/ci-integration");

      // Should not throw
      emitWarning("Test warning message", "pnpm-lock.yaml", 1);
      assert.ok(true);
    });

    it("emits error annotation", () => {
      process.env.GITHUB_ACTIONS = "true";

      const { emitError } = require("../../../src/utils/ci-integration");

      // Should not throw
      emitError("Test error message", "pnpm-lock.yaml", 5);
      assert.ok(true);
    });

    it("emits notice annotation", () => {
      process.env.GITHUB_ACTIONS = "true";

      const { emitNotice } = require("../../../src/utils/ci-integration");

      // Should not throw
      emitNotice("Test notice message");
      assert.ok(true);
    });
  });

  describe("output handling", () => {
    it("sets output variable", () => {
      process.env.GITHUB_ACTIONS = "true";
      process.env.GITHUB_OUTPUT = "/tmp/github-output-test";

      const { setCIOutput } = require("../../../src/utils/ci-integration");

      // Should not throw
      setCIOutput("audit-result", "passed");
      assert.ok(true);
    });

    it("handles missing GITHUB_OUTPUT gracefully", () => {
      process.env.GITHUB_ACTIONS = "true";
      delete process.env.GITHUB_OUTPUT;

      const { setCIOutput } = require("../../../src/utils/ci-integration");

      // Should not throw even without GITHUB_OUTPUT
      setCIOutput("audit-result", "passed");
      assert.ok(true);
    });
  });

  describe("utility functions", () => {
    it("isCI detects CI environment", () => {
      process.env.GITHUB_ACTIONS = "true";

      const { isCI } = require("../../../src/utils/ci-integration");

      assert.equal(isCI(), true);
    });

    it("getCIPlatformName returns platform name", () => {
      process.env.GITHUB_ACTIONS = "true";

      const { getCIPlatformName } = require("../../../src/utils/ci-integration");

      assert.equal(getCIPlatformName(), "github-actions");
    });
  });

  describe("factory function", () => {
    it("creates GitHub Actions integration via factory", () => {
      process.env.GITHUB_ACTIONS = "true";

      const { createCIIntegration } = require("../../../src/utils/ci-integration");
      const integration = createCIIntegration();

      assert.ok(integration);
      assert.equal(typeof integration.detect, "function");
      assert.equal(typeof integration.emitAnnotation, "function");
    });

    it("creates integration via singleton", () => {
      process.env.GITHUB_ACTIONS = "true";

      const { getCIIntegration } = require("../../../src/utils/ci-integration");
      const integration1 = getCIIntegration();
      const integration2 = getCIIntegration();

      assert.ok(integration1);
      assert.equal(integration1, integration2); // Same instance
    });
  });
});
