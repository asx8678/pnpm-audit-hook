/**
 * Test helpers barrel export.
 *
 * Import everything from here for convenient access to all test utilities.
 *
 * @example
 * ```ts
 * import {
 *   createMockCache,
 *   createMockFinding,
 *   assertValidAuditResult,
 *   setupTempDir,
 * } from "../helpers/index";
 * ```
 */

// Assertions
export {
  assertValidAuditResult,
  assertAuditBlocked,
  assertAuditPassed,
  assertAuditHasWarnings,
  assertValidFinding,
  assertFindingExists,
  assertFindingNotExists,
  assertAllFindingsSeverity,
  assertValidConfig,
  assertConfigBlockSeverities,
  assertValidPackageRef,
  assertLength,
  assertNotEmpty,
  assertUnique,
  assertThrowsAsync,
  assertThrowsWithNameAsync,
} from "./assertions";

// Mocks
export {
  createMockCache,
  createMockHttpClient,
  createMockFinding,
  createMockFindings,
  createMockConfig,
  mockEnv,
  sleep,
} from "./mocks";

export type { MockCache, MockHttpClient } from "./mocks";

// Fixtures
export {
  loadJsonFixture,
  loadYamlFixture,
  loadTextFixture,
  loadVulnerabilityFixture,
  loadConfigFixture,
  loadLockfileFixture,
  loadResponseFixture,
  loadStaticDbFixture,
  generateMinimalLockfile,
  generateLockfileWithDeps,
  generateGitHubAdvisoryResponse,
  generateOsvResponse,
} from "./fixtures";

// Setup
export {
  setupTempDir,
  setupTempDirWithConfig,
  setupTempDirWithLockfile,
  setupTestProject,
  setupConsoleSpy,
  setupProcessExitSpy,
} from "./setup";

export type { TestContext, ConsoleSpy, ProcessExitSpy } from "./setup";

// Teardown
export { safeRemove, safeRemoveAll, createTeardown } from "./teardown";
