/**
 * Custom assertion helpers for testing.
 *
 * Provides typed assertion functions that give clear error messages
 * and work with the project's type definitions.
 */
import assert from "node:assert/strict";
import type {
  AuditConfig,
  AuditResult,
  VulnerabilityFinding,
  PackageRef,
} from "../../src/types";

// ─── Audit Result Assertions ─────────────────────────────────────────────────

/**
 * Assert that a value is a valid AuditResult with all required fields.
 */
export function assertValidAuditResult(result: unknown): asserts result is AuditResult {
  assert(result !== null && result !== undefined, "AuditResult should not be null or undefined");
  assert(typeof result === "object", "AuditResult should be an object");

  const obj = result as Record<string, unknown>;

  const requiredFields = [
    "blocked",
    "warnings",
    "decisions",
    "exitCode",
    "findings",
    "sourceStatus",
    "totalPackages",
    "durationMs",
  ];

  for (const field of requiredFields) {
    assert(field in obj, `AuditResult missing required field: ${field}`);
  }

  assert(typeof obj.blocked === "boolean", "blocked should be a boolean");
  assert(typeof obj.warnings === "boolean", "warnings should be a boolean");
  assert(typeof obj.exitCode === "number", "exitCode should be a number");
  assert(Array.isArray(obj.decisions), "decisions should be an array");
  assert(Array.isArray(obj.findings), "findings should be an array");
  assert(typeof obj.totalPackages === "number", "totalPackages should be a number");
  assert(typeof obj.durationMs === "number", "durationMs should be a number");
  assert(obj.durationMs >= 0, "durationMs should be non-negative");
}

/**
 * Assert that an AuditResult is blocked (exit code != 0).
 */
export function assertAuditBlocked(result: AuditResult): void {
  assertValidAuditResult(result);
  assert(result.blocked === true, "Expected audit to be blocked");
  assert(result.exitCode !== 0, `Expected non-zero exit code, got ${result.exitCode}`);
}

/**
 * Assert that an AuditResult is not blocked (exit code 0).
 */
export function assertAuditPassed(result: AuditResult): void {
  assertValidAuditResult(result);
  assert(result.blocked === false, "Expected audit to pass");
  assert(result.exitCode === 0, `Expected exit code 0, got ${result.exitCode}`);
}

/**
 * Assert that an AuditResult has warnings.
 */
export function assertAuditHasWarnings(result: AuditResult): void {
  assertValidAuditResult(result);
  assert(result.warnings === true, "Expected audit to have warnings");
  assert(result.decisions.some((d) => d.action === "warn"), "Expected at least one warn decision");
}

// ─── Finding Assertions ──────────────────────────────────────────────────────

/**
 * Assert that a value is a valid VulnerabilityFinding.
 */
export function assertValidFinding(finding: unknown): asserts finding is VulnerabilityFinding {
  assert(finding !== null && finding !== undefined, "Finding should not be null or undefined");
  assert(typeof finding === "object", "Finding should be an object");

  const obj = finding as Record<string, unknown>;
  const requiredFields = ["id", "source", "packageName", "packageVersion", "severity"];

  for (const field of requiredFields) {
    assert(field in obj, `Finding missing required field: ${field}`);
  }

  const validSeverities = ["critical", "high", "medium", "low", "unknown"];
  assert(
    validSeverities.includes(obj.severity as string),
    `Invalid severity: ${obj.severity}. Must be one of: ${validSeverities.join(", ")}`
  );
}

/**
 * Assert that findings contain a vulnerability for a specific package.
 */
export function assertFindingExists(
  findings: VulnerabilityFinding[],
  packageName: string,
  options: { severity?: string; source?: string } = {}
): void {
  const matching = findings.filter((f) => {
    if (f.packageName !== packageName) return false;
    if (options.severity && f.severity !== options.severity) return false;
    if (options.source && f.source !== options.source) return false;
    return true;
  });

  assert(
    matching.length > 0,
    `Expected to find vulnerability for ${packageName}` +
      (options.severity ? ` with severity ${options.severity}` : "") +
      (options.source ? ` from source ${options.source}` : "") +
      `. Actual findings: ${JSON.stringify(findings.map((f) => f.packageName))}`
  );
}

/**
 * Assert that findings do NOT contain a vulnerability for a specific package.
 */
export function assertFindingNotExists(
  findings: VulnerabilityFinding[],
  packageName: string
): void {
  const matching = findings.filter((f) => f.packageName === packageName);
  assert(
    matching.length === 0,
    `Expected no vulnerability for ${packageName}, but found: ${JSON.stringify(matching)}`
  );
}

/**
 * Assert that all findings have the expected severity.
 */
export function assertAllFindingsSeverity(
  findings: VulnerabilityFinding[],
  severity: string
): void {
  for (const finding of findings) {
    assert.equal(
      finding.severity,
      severity,
      `Expected finding ${finding.id} to have severity ${severity}, got ${finding.severity}`
    );
  }
}

// ─── Config Assertions ───────────────────────────────────────────────────────

/**
 * Assert that a value is a valid AuditConfig.
 */
export function assertValidConfig(config: unknown): asserts config is AuditConfig {
  assert(config !== null && config !== undefined, "Config should not be null or undefined");
  assert(typeof config === "object", "Config should be an object");

  const obj = config as Record<string, unknown>;

  assert("policy" in obj, "Config missing policy");
  assert("sources" in obj, "Config missing sources");

  const policy = obj.policy as Record<string, unknown>;
  assert(Array.isArray(policy.block), "policy.block should be an array");
  assert(Array.isArray(policy.warn), "policy.warn should be an array");
  assert(Array.isArray(policy.allowlist), "policy.allowlist should be an array");

  const sources = obj.sources as Record<string, unknown>;
  assert("github" in sources || "nvd" in sources || "osv" in sources, "At least one source must be defined");
}

/**
 * Assert that a config has expected policy block severities.
 */
export function assertConfigBlockSeverities(
  config: AuditConfig,
  expected: string[]
): void {
  assert.deepEqual(
    [...config.policy.block].sort(),
    [...expected].sort(),
    `Expected block severities [${expected.join(", ")}], got [${config.policy.block.join(", ")}]`
  );
}

// ─── Package Assertions ──────────────────────────────────────────────────────

/**
 * Assert that a value is a valid PackageRef.
 */
export function assertValidPackageRef(pkg: unknown): asserts pkg is PackageRef {
  assert(pkg !== null && pkg !== undefined, "PackageRef should not be null or undefined");
  assert(typeof pkg === "object", "PackageRef should be an object");

  const obj = pkg as Record<string, unknown>;
  assert("name" in obj, "PackageRef missing name");
  assert("version" in obj, "PackageRef missing version");
  assert(typeof obj.name === "string", "PackageRef.name should be a string");
  assert(typeof obj.version === "string", "PackageRef.version should be a string");
  assert(obj.name.length > 0, "PackageRef.name should not be empty");
  assert(obj.version.length > 0, "PackageRef.version should not be empty");
}

// ─── Collection Assertions ───────────────────────────────────────────────────

/**
 * Assert that an array contains exactly the expected number of items.
 */
export function assertLength<T>(arr: T[], expected: number, label?: string): void {
  assert(
    Array.isArray(arr),
    `Expected an array${label ? ` for ${label}` : ""}, got ${typeof arr}`
  );
  assert.equal(
    arr.length,
    expected,
    `Expected ${expected} items${label ? ` in ${label}` : ""}, got ${arr.length}`
  );
}

/**
 * Assert that an array is not empty.
 */
export function assertNotEmpty<T>(arr: T[], label?: string): void {
  assert(Array.isArray(arr), `Expected an array${label ? ` for ${label}` : ""}`);
  assert(
    arr.length > 0,
    `Expected non-empty array${label ? ` for ${label}` : ""}`
  );
}

/**
 * Assert that an array contains unique items based on a key function.
 */
export function assertUnique<T>(arr: T[], keyFn: (item: T) => string, label?: string): void {
  const seen = new Set<string>();
  const duplicates: string[] = [];

  for (const item of arr) {
    const key = keyFn(item);
    if (seen.has(key)) {
      duplicates.push(key);
    }
    seen.add(key);
  }

  assert(
    duplicates.length === 0,
    `Expected unique items${label ? ` in ${label}` : ""}, found duplicates: ${duplicates.join(", ")}`
  );
}

// ─── Error Assertions ────────────────────────────────────────────────────────

/**
 * Assert that a function throws an error with a specific message.
 */
export async function assertThrowsAsync(
  fn: () => Promise<unknown>,
  expectedMessage?: string | RegExp
): Promise<Error> {
  try {
    await fn();
    assert.fail("Expected function to throw, but it did not");
    return undefined as never; // unreachable, satisfies TS
  } catch (error) {
    assert(error instanceof Error, `Expected Error, got ${typeof error}`);

    if (expectedMessage !== undefined) {
      if (typeof expectedMessage === "string") {
        assert(
          error.message.includes(expectedMessage),
          `Expected error message to contain "${expectedMessage}", got "${error.message}"`
        );
      } else {
        assert(
          expectedMessage.test(error.message),
          `Expected error message to match ${expectedMessage}, got "${error.message}"`
        );
      }
    }

    return error;
  }
}

/**
 * Assert that a function throws with a specific error type/name.
 */
export async function assertThrowsWithNameAsync(
  fn: () => Promise<unknown>,
  expectedName: string
): Promise<Error> {
  try {
    await fn();
    assert.fail("Expected function to throw, but it did not");
    return undefined as never;
  } catch (error) {
    assert(error instanceof Error, `Expected Error, got ${typeof error}`);
    assert.equal(
      error.name,
      expectedName,
      `Expected error name "${expectedName}", got "${error.name}"`
    );
    return error;
  }
}
