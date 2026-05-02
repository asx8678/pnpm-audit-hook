import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

describe("Azure DevOps CI/CD Integration", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe("CI platform detection", () => {
    it("detects Azure DevOps environment", () => {
      process.env.TF_BUILD = "True";
      process.env.BUILD_BUILDID = "123456";
      process.env.BUILD_BUILDNUMBER = "20240101.1";
      process.env.SYSTEM_TEAMPROJECT = "my-project";

      const { detectCIPlatform } = require("../../../src/utils/ci-integration");
      const platform = detectCIPlatform();

      assert.equal(platform.name, "azure-devops");
      assert.equal(platform.isCI, true);
      assert.ok(platform.envVars.TF_BUILD);
      assert.ok(platform.envVars.BUILD_BUILDID);
    });

    it("does not detect Azure DevOps when env vars missing", () => {
      delete process.env.TF_BUILD;
      delete process.env.BUILD_BUILDID;

      const { detectCIPlatform } = require("../../../src/utils/ci-integration");
      const platform = detectCIPlatform();

      assert.notEqual(platform.name, "azure-devops");
    });
  });

  describe("CI integration class", () => {
    it("creates Azure DevOps integration", () => {
      process.env.TF_BUILD = "True";

      const { AzureDevOpsIntegration } = require("../../../src/utils/ci-integration");
      const integration = new AzureDevOpsIntegration();

      assert.ok(integration);
      assert.equal(typeof integration.detect, "function");
      assert.equal(typeof integration.emitAnnotation, "function");
      assert.equal(typeof integration.emitLog, "function");
      assert.equal(typeof integration.setOutput, "function");
    });

    it("detect platform returns Azure DevOps", () => {
      process.env.TF_BUILD = "True";

      const { AzureDevOpsIntegration } = require("../../../src/utils/ci-integration");
      const integration = new AzureDevOpsIntegration();
      const platform = integration.detect();

      assert.equal(platform.name, "azure-devops");
      assert.equal(platform.isCI, true);
    });
  });

  describe("annotation emission", () => {
    it("emits warning annotation", () => {
      process.env.TF_BUILD = "True";

      const { emitWarning } = require("../../../src/utils/ci-integration");

      // Should not throw
      emitWarning("Test warning message", "pnpm-lock.yaml", 1);
      assert.ok(true);
    });

    it("emits error annotation", () => {
      process.env.TF_BUILD = "True";

      const { emitError } = require("../../../src/utils/ci-integration");

      // Should not throw
      emitError("Test error message", "pnpm-lock.yaml", 5);
      assert.ok(true);
    });

    it("emits notice annotation", () => {
      process.env.TF_BUILD = "True";

      const { emitNotice } = require("../../../src/utils/ci-integration");

      // Should not throw
      emitNotice("Test notice message");
      assert.ok(true);
    });
  });

  describe("output handling", () => {
    it("sets output variable", () => {
      process.env.TF_BUILD = "True";

      const { setCIOutput } = require("../../../src/utils/ci-integration");

      // Should not throw
      setCIOutput("audit-result", "passed");
      assert.ok(true);
    });
  });

  describe("utility functions", () => {
    it("isCI detects CI environment", () => {
      process.env.TF_BUILD = "True";

      const { isCI } = require("../../../src/utils/ci-integration");

      assert.equal(isCI(), true);
    });

    it("getCIPlatformName returns platform name", () => {
      process.env.TF_BUILD = "True";

      const { getCIPlatformName } = require("../../../src/utils/ci-integration");

      assert.equal(getCIPlatformName(), "azure-devops");
    });
  });

  describe("factory function", () => {
    it("creates Azure DevOps integration via factory", () => {
      process.env.TF_BUILD = "True";

      const { createCIIntegration } = require("../../../src/utils/ci-integration");
      const integration = createCIIntegration();

      assert.ok(integration);
      assert.equal(typeof integration.detect, "function");
      assert.equal(typeof integration.emitAnnotation, "function");
    });
  });
});
