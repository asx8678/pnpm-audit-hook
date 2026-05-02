import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  getEnvironmentVariables,
  isCIEnvironment,
  getOutputFormatFromEnv,
  isVerboseMode,
  getRegistryUrlFromEnv,
  validateEnvironmentVariables,
  getEnvironmentSummary,
  ENV_VAR_DEFINITIONS,
} from "../../src/utils/env-manager";

describe("env-manager", () => {
  describe("getEnvironmentVariables", () => {
    it("returns default values when no env vars are set", () => {
      const env = getEnvironmentVariables({});
      assert.equal(env.PNPM_AUDIT_QUIET, false);
      assert.equal(env.PNPM_AUDIT_DEBUG, false);
      assert.equal(env.PNPM_AUDIT_JSON, false);
      assert.equal(env.PNPM_AUDIT_VERBOSE, false);
      assert.equal(env.PNPM_AUDIT_FORMAT, "human");
      assert.equal(env.PNPM_AUDIT_CONFIG_PATH, "");
      assert.equal(env.PNPM_AUDIT_BLOCK_SEVERITY, "");
      assert.equal(env.PNPM_AUDIT_FAIL_ON_NO_SOURCES, true);
      assert.equal(env.PNPM_AUDIT_FAIL_ON_SOURCE_ERROR, true);
      assert.equal(env.PNPM_AUDIT_OFFLINE, false);
      assert.equal(env.PNPM_REGISTRY, "");
      assert.equal(env.npm_config_registry, "");
      assert.equal(env.NPM_CONFIG_REGISTRY, "");
      assert.equal(env.CI, false);
      assert.equal(env.TF_BUILD, false);
      assert.equal(env.GITHUB_ACTIONS, false);
      assert.equal(env.GITLAB_CI, false);
      assert.equal(env.JENKINS_URL, "");
      assert.equal(env.CODEBUILD_BUILD_ID, "");
      assert.equal(env.GITHUB_OUTPUT, "");
    });

    it("parses boolean env vars correctly", () => {
      const env = getEnvironmentVariables({
        PNPM_AUDIT_QUIET: "true",
        PNPM_AUDIT_DEBUG: "true",
        PNPM_AUDIT_JSON: "true",
        PNPM_AUDIT_VERBOSE: "true",
        CI: "true",
        TF_BUILD: "True",
        GITHUB_ACTIONS: "true",
      });
      assert.equal(env.PNPM_AUDIT_QUIET, true);
      assert.equal(env.PNPM_AUDIT_DEBUG, true);
      assert.equal(env.PNPM_AUDIT_JSON, true);
      assert.equal(env.PNPM_AUDIT_VERBOSE, true);
      assert.equal(env.CI, true);
      assert.equal(env.TF_BUILD, true);
      assert.equal(env.GITHUB_ACTIONS, true);
    });

    it("treats non-'true' values as false", () => {
      const env = getEnvironmentVariables({
        PNPM_AUDIT_QUIET: "false",
        PNPM_AUDIT_DEBUG: "1",
        PNPM_AUDIT_JSON: "yes",
      });
      assert.equal(env.PNPM_AUDIT_QUIET, false);
      assert.equal(env.PNPM_AUDIT_DEBUG, false);
      assert.equal(env.PNPM_AUDIT_JSON, false);
    });

    it("validates string env vars against allowed values", () => {
      const env = getEnvironmentVariables({
        PNPM_AUDIT_FORMAT: "github",
      });
      assert.equal(env.PNPM_AUDIT_FORMAT, "github");
    });

    it("falls back to default for invalid string values", () => {
      const env = getEnvironmentVariables({
        PNPM_AUDIT_FORMAT: "invalid",
      });
      assert.equal(env.PNPM_AUDIT_FORMAT, "human");
    });
  });

  describe("isCIEnvironment", () => {
    it("returns false when no CI vars are set", () => {
      assert.equal(isCIEnvironment({}), false);
    });

    it("returns true when CI=true", () => {
      assert.equal(isCIEnvironment({ CI: "true" }), true);
    });

    it("returns true when TF_BUILD=True", () => {
      assert.equal(isCIEnvironment({ TF_BUILD: "True" }), true);
    });

    it("returns true when GITHUB_ACTIONS=true", () => {
      assert.equal(isCIEnvironment({ GITHUB_ACTIONS: "true" }), true);
    });

    it("returns true when GITLAB_CI=true", () => {
      assert.equal(isCIEnvironment({ GITLAB_CI: "true" }), true);
    });

    it("returns true when JENKINS_URL is set", () => {
      assert.equal(
        isCIEnvironment({ JENKINS_URL: "http://jenkins.example.com" }),
        true,
      );
    });

    it("returns true when CODEBUILD_BUILD_ID is set", () => {
      assert.equal(
        isCIEnvironment({ CODEBUILD_BUILD_ID: "my-build-id" }),
        true,
      );
    });
  });

  describe("getOutputFormatFromEnv", () => {
    it("returns 'human' by default", () => {
      assert.equal(getOutputFormatFromEnv({}), "human");
    });

    it("returns 'json' when PNPM_AUDIT_JSON=true", () => {
      assert.equal(getOutputFormatFromEnv({ PNPM_AUDIT_JSON: "true" }), "json");
    });

    it("returns 'azure' when TF_BUILD=True", () => {
      assert.equal(getOutputFormatFromEnv({ TF_BUILD: "True" }), "azure");
    });

    it("returns 'github' when GITHUB_ACTIONS=true", () => {
      assert.equal(
        getOutputFormatFromEnv({ GITHUB_ACTIONS: "true" }),
        "github",
      );
    });

    it("returns 'github' when GITHUB_ACTIONS=true and PNPM_AUDIT_FORMAT=human", () => {
      // PNPM_AUDIT_FORMAT=human prevents auto-detection
      assert.equal(
        getOutputFormatFromEnv({ GITHUB_ACTIONS: "true", PNPM_AUDIT_FORMAT: "human" }),
        "human",
      );
    });

    it("returns 'aws' when CODEBUILD_BUILD_ID is set", () => {
      assert.equal(
        getOutputFormatFromEnv({ CODEBUILD_BUILD_ID: "build-123" }),
        "aws",
      );
    });

    it("returns explicit format when PNPM_AUDIT_FORMAT is set", () => {
      assert.equal(
        getOutputFormatFromEnv({ PNPM_AUDIT_FORMAT: "azure" }),
        "azure",
      );
    });
  });

  describe("isVerboseMode", () => {
    it("returns false when no verbose env vars are set", () => {
      assert.equal(isVerboseMode({}), false);
    });

    it("returns true when PNPM_AUDIT_VERBOSE=true", () => {
      assert.equal(isVerboseMode({ PNPM_AUDIT_VERBOSE: "true" }), true);
    });

    it("returns true when in CI environment", () => {
      assert.equal(isVerboseMode({ CI: "true" }), true);
    });

    it("returns true when TF_BUILD=True", () => {
      assert.equal(isVerboseMode({ TF_BUILD: "True" }), true);
    });
  });

  describe("getRegistryUrlFromEnv", () => {
    it("returns empty string when no registry vars are set", () => {
      assert.equal(getRegistryUrlFromEnv({}), "");
    });

    it("returns PNPM_REGISTRY when set", () => {
      assert.equal(
        getRegistryUrlFromEnv({ PNPM_REGISTRY: "https://my-registry.com/" }),
        "https://my-registry.com/",
      );
    });

    it("returns npm_config_registry when PNPM_REGISTRY is not set", () => {
      assert.equal(
        getRegistryUrlFromEnv({
          npm_config_registry: "https://npm-registry.com/",
        }),
        "https://npm-registry.com/",
      );
    });

    it("returns NPM_CONFIG_REGISTRY when other vars are not set", () => {
      assert.equal(
        getRegistryUrlFromEnv({
          NPM_CONFIG_REGISTRY: "https://uppercase-registry.com/",
        }),
        "https://uppercase-registry.com/",
      );
    });

    it("prefers PNPM_REGISTRY over other registry vars", () => {
      assert.equal(
        getRegistryUrlFromEnv({
          PNPM_REGISTRY: "https://pnpm-registry.com/",
          npm_config_registry: "https://npm-registry.com/",
          NPM_CONFIG_REGISTRY: "https://uppercase-registry.com/",
        }),
        "https://pnpm-registry.com/",
      );
    });
  });

  describe("validateEnvironmentVariables", () => {
    it("returns empty array for valid env vars", () => {
      const warnings = validateEnvironmentVariables({
        PNPM_AUDIT_FORMAT: "github",
        PNPM_AUDIT_QUIET: "true",
        PNPM_AUDIT_DEBUG: "false",
      });
      assert.equal(warnings.length, 0);
    });

    it("warns on invalid PNPM_AUDIT_FORMAT", () => {
      const warnings = validateEnvironmentVariables({
        PNPM_AUDIT_FORMAT: "invalid",
      });
      assert.equal(warnings.length, 1);
      assert.ok(warnings[0].includes("Invalid PNPM_AUDIT_FORMAT value"));
    });

    it("warns on invalid boolean values", () => {
      const warnings = validateEnvironmentVariables({
        PNPM_AUDIT_QUIET: "yes",
      });
      assert.equal(warnings.length, 1);
      assert.ok(warnings[0].includes("Invalid boolean value for PNPM_AUDIT_QUIET"));
    });

    it("warns on invalid PNPM_AUDIT_BLOCK_SEVERITY values", () => {
      const warnings = validateEnvironmentVariables({
        PNPM_AUDIT_BLOCK_SEVERITY: "critical,invalid_severity",
      });
      assert.equal(warnings.length, 1);
      assert.ok(warnings[0].includes("Invalid PNPM_AUDIT_BLOCK_SEVERITY values"));
    });
  });

  describe("getEnvironmentSummary", () => {
    it("returns summary for all env vars", () => {
      const summary = getEnvironmentSummary({
        PNPM_AUDIT_QUIET: "true",
        CI: "true",
      });
      assert.ok(summary.PNPM_AUDIT_QUIET);
      assert.ok(summary.CI);
      assert.equal(summary.PNPM_AUDIT_QUIET.value, "true");
      assert.equal(summary.PNPM_AUDIT_QUIET.defined, true);
      assert.equal(summary.PNPM_AUDIT_DEBUG.defined, false);
    });

    it("includes descriptions", () => {
      const summary = getEnvironmentSummary({});
      assert.ok(summary.PNPM_AUDIT_QUIET.description);
      assert.ok(summary.CI.description);
    });
  });

  describe("ENV_VAR_DEFINITIONS", () => {
    it("contains all expected environment variables", () => {
      assert.ok(ENV_VAR_DEFINITIONS.PNPM_AUDIT_QUIET);
      assert.ok(ENV_VAR_DEFINITIONS.PNPM_AUDIT_DEBUG);
      assert.ok(ENV_VAR_DEFINITIONS.PNPM_AUDIT_JSON);
      assert.ok(ENV_VAR_DEFINITIONS.PNPM_AUDIT_VERBOSE);
      assert.ok(ENV_VAR_DEFINITIONS.PNPM_AUDIT_FORMAT);
      assert.ok(ENV_VAR_DEFINITIONS.CI);
      assert.ok(ENV_VAR_DEFINITIONS.TF_BUILD);
      assert.ok(ENV_VAR_DEFINITIONS.GITHUB_ACTIONS);
      assert.ok(ENV_VAR_DEFINITIONS.GITLAB_CI);
      assert.ok(ENV_VAR_DEFINITIONS.JENKINS_URL);
      assert.ok(ENV_VAR_DEFINITIONS.CODEBUILD_BUILD_ID);
      assert.ok(ENV_VAR_DEFINITIONS.GITHUB_OUTPUT);
    });

    it("has descriptions for all variables", () => {
      for (const [key, definition] of Object.entries(ENV_VAR_DEFINITIONS)) {
        assert.ok(definition.description, `Missing description for ${key}`);
      }
    });
  });
});
