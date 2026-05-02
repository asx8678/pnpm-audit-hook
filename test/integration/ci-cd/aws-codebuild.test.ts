import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

describe("AWS CodeBuild CI/CD Integration", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe("CI platform detection", () => {
    it("detects AWS CodeBuild environment", () => {
      process.env.CODEBUILD_BUILD_ID = "my-project:123456";
      process.env.CODEBUILD_BUILD_NUMBER = "123456";
      process.env.CODEBUILD_PROJECT_NAME = "my-project";
      process.env.CODEBUILD_SOURCE_VERSION = "abc123";

      const { detectCIPlatform } = require("../../../src/utils/ci-integration");
      const platform = detectCIPlatform();

      assert.equal(platform.name, "aws-codebuild");
      assert.equal(platform.isCI, true);
      assert.ok(platform.envVars.CODEBUILD_BUILD_ID);
    });

    it("does not detect AWS CodeBuild when env vars missing", () => {
      delete process.env.CODEBUILD_BUILD_ID;
      delete process.env.CODEBUILD_PROJECT_NAME;

      const { detectCIPlatform } = require("../../../src/utils/ci-integration");
      const platform = detectCIPlatform();

      assert.notEqual(platform.name, "aws-codebuild");
    });
  });

  describe("CI integration class", () => {
    it("creates AWS CodeBuild integration", () => {
      process.env.CODEBUILD_BUILD_ID = "my-project:123456";

      const { AWSCodeBuildIntegration } = require("../../../src/utils/ci-integration");
      const integration = new AWSCodeBuildIntegration();

      assert.ok(integration);
      assert.equal(typeof integration.detect, "function");
      assert.equal(typeof integration.emitAnnotation, "function");
      assert.equal(typeof integration.emitLog, "function");
      assert.equal(typeof integration.setOutput, "function");
    });

    it("detect platform returns AWS CodeBuild", () => {
      process.env.CODEBUILD_BUILD_ID = "my-project:123456";

      const { AWSCodeBuildIntegration } = require("../../../src/utils/ci-integration");
      const integration = new AWSCodeBuildIntegration();
      const platform = integration.detect();

      assert.equal(platform.name, "aws-codebuild");
      assert.equal(platform.isCI, true);
    });
  });

  describe("annotation emission", () => {
    it("emits warning annotation", () => {
      process.env.CODEBUILD_BUILD_ID = "my-project:123456";

      const { emitWarning } = require("../../../src/utils/ci-integration");

      // Should not throw
      emitWarning("Test warning message", "pnpm-lock.yaml", 1);
      assert.ok(true);
    });

    it("emits error annotation", () => {
      process.env.CODEBUILD_BUILD_ID = "my-project:123456";

      const { emitError } = require("../../../src/utils/ci-integration");

      // Should not throw
      emitError("Test error message", "pnpm-lock.yaml", 5);
      assert.ok(true);
    });

    it("emits notice annotation", () => {
      process.env.CODEBUILD_BUILD_ID = "my-project:123456";

      const { emitNotice } = require("../../../src/utils/ci-integration");

      // Should not throw
      emitNotice("Test notice message");
      assert.ok(true);
    });
  });

  describe("output handling", () => {
    it("sets output variable", () => {
      process.env.CODEBUILD_BUILD_ID = "my-project:123456";

      const { setCIOutput } = require("../../../src/utils/ci-integration");

      // Should not throw
      setCIOutput("audit-result", "passed");
      assert.ok(true);
    });
  });

  describe("utility functions", () => {
    it("isCI detects CI environment", () => {
      process.env.CODEBUILD_BUILD_ID = "my-project:123456";

      const { isCI } = require("../../../src/utils/ci-integration");

      assert.equal(isCI(), true);
    });

    it("getCIPlatformName returns platform name", () => {
      process.env.CODEBUILD_BUILD_ID = "my-project:123456";

      const { getCIPlatformName } = require("../../../src/utils/ci-integration");

      assert.equal(getCIPlatformName(), "aws-codebuild");
    });
  });

  describe("factory function", () => {
    it("creates AWS CodeBuild integration via factory", () => {
      process.env.CODEBUILD_BUILD_ID = "my-project:123456";

      const { createCIIntegration } = require("../../../src/utils/ci-integration");
      const integration = createCIIntegration();

      assert.ok(integration);
      assert.equal(typeof integration.detect, "function");
      assert.equal(typeof integration.emitAnnotation, "function");
    });
  });
});
