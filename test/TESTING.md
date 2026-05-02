# Testing Guide

This document provides guidelines and best practices for writing tests in the pnpm-audit-hook project.

## Table of Contents

- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Test Helpers](#test-helpers)
- [Writing Tests](#writing-tests)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Quick Start

```typescript
import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import {
  createMockCache,
  createMockHttpClient,
  createMockFinding,
  assertValidAuditResult,
  setupTempDir,
} from "../helpers/index.js";

describe("My Feature", () => {
  let cache: ReturnType<typeof createMockCache>;

  beforeEach(() => {
    cache = createMockCache();
  });

  it("should do something", async () => {
    // Arrange
    const finding = createMockFinding({ packageName: "lodash" });

    // Act
    const result = await myFunction(cache, finding);

    // Assert
    assertValidAuditResult(result);
  });
});
```

## Project Structure

```
test/
├── fixtures/                    # Test fixture files
│   ├── lockfiles/              # Lockfile samples
│   │   ├── pnpm-v6.yaml
│   │   ├── pnpm-v7.yaml
│   │   ├── pnpm-v9.yaml
│   │   ├── empty.yaml
│   │   └── large-lockfile.yaml
│   ├── configs/                # Configuration samples
│   │   ├── basic.yaml
│   │   ├── advanced.yaml
│   │   └── edge-cases.yaml
│   ├── vulnerabilities/        # Vulnerability data
│   │   ├── critical.json
│   │   ├── high.json
│   │   └── medium.json
│   ├── responses/              # API response samples
│   │   ├── github-advisory.json
│   │   ├── osv-api.json
│   │   └── nvd-api.json
│   └── static-db/              # Static database fixtures
├── helpers/                    # Test utilities
│   ├── index.ts               # Barrel export
│   ├── assertions.ts          # Custom assertions
│   ├── mocks.ts               # Mock factories
│   ├── fixtures.ts            # Fixture loaders
│   ├── setup.ts               # Test setup utilities
│   ├── teardown.ts            # Test teardown utilities
│   └── test-utils.ts          # Legacy utilities
├── integration/                # Integration tests
│   ├── cli/
│   ├── audit/
│   ├── ci-cd/
│   └── helpers/
├── databases/                  # Database connector tests
├── utils/                      # Utility function tests
├── static-db/                  # Static DB tests
└── *.test.ts                   # Top-level tests
```

## Test Helpers

### Mock Factories (`mocks.ts`)

#### `createMockCache()`

Creates a mock Cache implementation with automatic TTL expiry:

```typescript
const cache = createMockCache();

// Set a value
await cache.set("key", { data: "value" }, 3600);

// Get a value
const entry = await cache.get("key");
assert.deepEqual(entry?.value, { data: "value" });

// Check store directly
assert.equal(cache.store.size, 1);

// Reset statistics
cache.resetStats();
```

#### `createMockHttpClient()`

Creates a mock HTTP client that records requests:

```typescript
const http = createMockHttpClient();

// Mock a response
http.mockResponse("https://api.osv.dev", {
  status: 200,
  data: { vulns: [] },
  headers: {},
});

// Make a request
const response = await http.get("https://api.osv.dev/vulnerabilities");

// Assert on recorded requests
assert.equal(http.requests.length, 1);
assert.equal(http.requests[0].method, "GET");
```

#### `createMockFinding(overrides?)`

Creates a vulnerability finding with sensible defaults:

```typescript
// Default finding
const vuln = createMockFinding();

// Customized finding
const criticalVuln = createMockFinding({
  packageName: "lodash",
  severity: "critical",
  id: "GHSA-specific-id",
});
```

#### `createMockConfig(overrides?)`

Creates an AuditConfig with sensible defaults:

```typescript
const config = createMockConfig({
  policy: {
    block: ["critical"],  // Only block critical
    warn: ["high", "medium", "low", "unknown"],
    allowlist: [{ package: "test-pkg", reason: "Accepted risk" }],
  },
});
```

#### `mockEnv(vars)`

Temporarily override environment variables:

```typescript
{
  using env = mockEnv({ GITHUB_TOKEN: "test-token" });
  // process.env.GITHUB_TOKEN is "test-token"
  // Automatically restored when the block exits
}
```

### Fixture Loaders (`fixtures.ts`)

```typescript
// Load typed fixtures
const vulns = await loadVulnerabilityFixture("critical");
const config = await loadConfigFixture("advanced");
const lockfile = await loadLockfileFixture("pnpm-v9");
const response = await loadResponseFixture("github-advisory");

// Generate fixtures in memory
const lockfile = generateMinimalLockfile([
  { name: "lodash", version: "4.17.21" },
  { name: "express", version: "4.18.2" },
]);

const ghResponse = generateGitHubAdvisoryResponse([
  {
    ghsaId: "GHSA-1234-5678",
    package: "lodash",
    severity: "high",
    vulnerableRange: "< 4.17.21",
    fixedVersion: "4.17.21",
  },
]);
```

### Assertions (`assertions.ts`)

```typescript
// Audit result assertions
assertValidAuditResult(result);  // Type-safe validation
assertAuditBlocked(result);      // Expect blocked
assertAuditPassed(result);       // Expect pass
assertAuditHasWarnings(result);  // Expect warnings

// Finding assertions
assertValidFinding(finding);
assertFindingExists(findings, "lodash", { severity: "high" });
assertFindingNotExists(findings, "safe-package");
assertAllFindingsSeverity(findings, "critical");

// Config assertions
assertValidConfig(config);
assertConfigBlockSeverities(config, ["critical", "high"]);

// Collection assertions
assertLength(array, 3, "findings");
assertNotEmpty(array, "vulnerabilities");
assertUnique(array, (f) => f.id, "findings");

// Error assertions
await assertThrowsAsync(
  () => myFunction(),
  "Expected error message"
);
```

### Setup & Teardown (`setup.ts`, `teardown.ts`)

```typescript
// Temporary directories
const ctx = await setupTempDir("test-");
// ... test ...
await ctx.cleanup();

// Temporary directory with config
const ctx = await setupTempDirWithConfig({ failOnNoSources: false });
const config = ctx.config;

// Complete test project
const project = await setupTestProject({
  configOverrides: { failOnSourceError: true },
  packages: [
    { name: "lodash", version: "4.17.20" },
  ],
});
// project.configPath, project.lockfilePath available

// Console spy
const spy = setupConsoleSpy();
// ... test code that console.logs ...
assert(spy.logs.length > 0);
spy.restore();

// Teardown manager
const teardown = createTeardown();
teardown.add(() => cleanup());
teardown.add(() => restoreMocks());
await teardown.run();  // Runs all in reverse order
```

## Writing Tests

### The AAA Pattern

Always follow Arrange-Act-Assert:

```typescript
it("should block on critical vulnerabilities", async () => {
  // Arrange
  const cache = createMockCache();
  const findings = [
    createMockFinding({ severity: "critical", packageName: "vuln-pkg" }),
  ];
  const config = createMockConfig({
    policy: { block: ["critical"], warn: [], allowlist: [] },
  });

  // Act
  const result = evaluateFindings(findings, config);

  // Assert
  assertAuditBlocked(result);
  assert.equal(result.findings.length, 1);
});
```

### Test Isolation

Each test should be independent:

```typescript
describe("My Feature", () => {
  let cache: ReturnType<typeof createMockCache>;

  // Setup fresh mocks for each test
  beforeEach(() => {
    cache = createMockCache();
  });

  it("test 1", async () => {
    // Uses fresh cache
  });

  it("test 2", async () => {
    // Uses fresh cache (not affected by test 1)
  });
});
```

### Naming Conventions

```typescript
describe("FeatureOrModule", () => {
  describe("methodName", () => {
    it("should handle normal case", () => {});
    it("should handle edge case X", () => {});
    it("should throw on invalid input", () => {});
    it("should return Y when Z", () => {});
  });
});
```

### Async Tests

```typescript
it("should fetch data", async () => {
  const result = await fetchData();
  assert(result);
});

it("should timeout", async () => {
  await assertThrowsAsync(
    () => fetchData({ timeout: 1 }),
    /timeout/i
  );
});
```

## Best Practices

### DO

1. **Use shared helpers** - Import from `helpers/index.js` instead of duplicating
2. **Follow AAA pattern** - Arrange, Act, Assert
3. **Test one thing per test** - Each `it` block tests one behavior
4. **Use meaningful names** - `should block on critical vulnerabilities`, not `test 1`
5. **Clean up resources** - Use `afterEach` or teardown helpers
6. **Use type-safe assertions** - `assertValidAuditResult(result)` over manual checks
7. **Test edge cases** - Empty inputs, null values, boundary conditions
8. **Use fixtures for data** - Load from `fixtures/` instead of inline data

### DON'T

1. **Don't share mutable state** between tests
2. **Don't rely on test execution order** - Tests should work in any order
3. **Don't use `console.log` for debugging** - Use `setupConsoleSpy()` instead
4. **Don't hardcode file paths** - Use `setupTempDir()` for temp files
5. **Don't skip cleanup** - Always clean up temp files and mocks
6. **Don't test implementation details** - Test behavior, not internal workings
7. **Don't write overly long tests** - Split into multiple `it` blocks if >50 lines
8. **Don't use `any` type** - Use proper type assertions

### Testing Patterns

#### Pattern: Fixture-Based Testing

```typescript
it("should parse pnpm-v9 lockfile", async () => {
  const lockfile = await loadLockfileFixture("pnpm-v9");
  const result = parseLockfile(lockfile);
  assert.equal(result.version, "9.0");
});
```

#### Pattern: Mock Chain

```typescript
it("should fetch and cache vulnerability data", async () => {
  const cache = createMockCache();
  const http = createMockHttpClient();

  http.mockResponse("https://api.osv.dev", {
    status: 200,
    data: { vulns: [] },
    headers: {},
  });

  await fetchVulnerabilities(cache, http, "lodash");

  // Verify cache was populated
  assert.equal(cache.store.size, 1);
  // Verify correct HTTP call
  assert.equal(http.requests.length, 1);
});
```

#### Pattern: Parametrized Tests

```typescript
const testCases = [
  { severity: "critical", shouldBlock: true },
  { severity: "high", shouldBlock: true },
  { severity: "medium", shouldBlock: false },
  { severity: "low", shouldBlock: false },
];

for (const { severity, shouldBlock } of testCases) {
  it(`should ${shouldBlock ? "block" : "pass"} on ${severity}`, () => {
    const config = createMockConfig({
      policy: { block: ["critical", "high"], warn: ["medium", "low", "unknown"], allowlist: [] },
    });
    const findings = [createMockFinding({ severity })];
    const result = evaluateFindings(findings, config);
    assert.equal(result.blocked, shouldBlock);
  });
}
```

## Troubleshooting

### Tests leak state

- Ensure `beforeEach` creates fresh mocks
- Use `afterEach` for cleanup
- Check for global state modifications

### Temp files not cleaned up

- Always call `ctx.cleanup()` in `afterEach`
- Use the `teardown` helper for complex cleanup

### Mock responses not found

- Check URL patterns match exactly (or use regex)
- Ensure `mockResponse` is called before the request
- Reset mocks between tests with `http.reset()`

### Tests pass locally but fail in CI

- Check for hardcoded paths
- Check for timezone assumptions
- Check for flaky async timing (use `sleep` sparingly)
- Check environment variable dependencies
