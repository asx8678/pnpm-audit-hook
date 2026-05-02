/**
 * Shared test utilities for integration tests.
 *
 * Provides helper functions for creating test fixtures, mocking, and common assertions.
 */
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import type { AuditConfig, PackageRef } from "../../../src/types";

// ─── Lockfile Helpers ────────────────────────────────────────────────────────

/**
 * Create a minimal lockfile structure for testing
 */
export function createLockfile(packages: PackageRef[]): Record<string, unknown> {
  const pkgSnapshots: Record<string, object> = {};
  for (const p of packages) {
    pkgSnapshots[`/${p.name}@${p.version}`] = {
      resolution: { integrity: `sha512-test-${p.name}-${p.version}` },
    };
  }
  return {
    lockfileVersion: "9.0",
    packages: pkgSnapshots,
  };
}

/**
 * Create a lockfile with dependencies
 */
export function createLockfileWithDeps(
  packages: Array<{
    name: string;
    version: string;
    dependencies?: Record<string, string>;
  }>
): Record<string, unknown> {
  const pkgSnapshots: Record<string, object> = {};
  for (const p of packages) {
    pkgSnapshots[`/${p.name}@${p.version}`] = {
      resolution: { integrity: `sha512-test-${p.name}-${p.version}` },
      dependencies: p.dependencies,
    };
  }
  return {
    lockfileVersion: "9.0",
    packages: pkgSnapshots,
  };
}

/**
 * Create a large lockfile for performance testing
 */
export function createLargeLockfile(count: number): Record<string, unknown> {
  const packages: Record<string, object> = {};
  for (let i = 0; i < count; i++) {
    packages[`/package-${i}@${i}.0.0`] = {
      resolution: { integrity: `sha512-test-${i}` },
    };
  }
  return {
    lockfileVersion: "9.0",
    packages,
  };
}

// ─── Config Helpers ──────────────────────────────────────────────────────────

/**
 * Create a minimal config for testing
 */
export function createConfig(overrides: Partial<AuditConfig> = {}): AuditConfig {
  return {
    policy: {
      block: ["critical", "high"],
      warn: ["medium", "low", "unknown"],
      allowlist: [],
    },
    sources: {
      github: { enabled: true },
      nvd: { enabled: true },
      osv: { enabled: true },
    },
    performance: { timeoutMs: 15000 },
    cache: { ttlSeconds: 3600 },
    failOnNoSources: true,
    failOnSourceError: true,
    ...overrides,
  };
}

/**
 * Write config file to disk
 */
export async function writeConfigFile(
  dir: string,
  config: Record<string, unknown>
): Promise<void> {
  const yaml = await import("yaml");
  await fs.writeFile(
    path.join(dir, ".pnpm-audit.yaml"),
    yaml.stringify(config)
  );
}

// ─── Finding Helpers ─────────────────────────────────────────────────────────

/**
 * Create a vulnerability finding for testing
 */
export function createFinding(overrides: Record<string, unknown> = {}) {
  return {
    id: "CVE-2025-0001",
    source: "github",
    packageName: "test-pkg",
    packageVersion: "1.0.0",
    severity: "high",
    title: "Test vulnerability",
    description: "Test description",
    fixedVersion: "1.0.1",
    ...overrides,
  };
}

/**
 * Create multiple findings for testing
 */
export function createFindings(
  count: number,
  baseOverrides: Record<string, unknown> = {}
) {
  return Array.from({ length: count }, (_, i) =>
    createFinding({
      ...baseOverrides,
      id: `CVE-2025-${String(i).padStart(4, "0")}`,
      packageName: `package-${i}`,
    })
  );
}

// ─── Temp Directory Helpers ──────────────────────────────────────────────────

/**
 * Create a temporary directory for testing
 */
export async function createTempDir(prefix: string = "integration-test-"): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), prefix));
}

/**
 * Clean up a temporary directory
 */
export async function cleanupTempDir(dir: string): Promise<void> {
  try {
    await fs.rm(dir, { recursive: true, force: true });
  } catch {
    // Ignore cleanup errors
  }
}

// ─── Assertion Helpers ───────────────────────────────────────────────────────

/**
 * Assert that a value is a valid audit result
 */
export function assertValidAuditResult(result: any): void {
  if (!result || typeof result !== "object") {
    throw new Error("Expected audit result to be an object");
  }

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
    if (!(field in result)) {
      throw new Error(`Expected audit result to have field: ${field}`);
    }
  }

  if (typeof result.blocked !== "boolean") {
    throw new Error("Expected 'blocked' to be a boolean");
  }

  if (typeof result.warnings !== "boolean") {
    throw new Error("Expected 'warnings' to be a boolean");
  }

  if (!Array.isArray(result.decisions)) {
    throw new Error("Expected 'decisions' to be an array");
  }

  if (!Array.isArray(result.findings)) {
    throw new Error("Expected 'findings' to be an array");
  }

  if (typeof result.totalPackages !== "number") {
    throw new Error("Expected 'totalPackages' to be a number");
  }

  if (typeof result.durationMs !== "number") {
    throw new Error("Expected 'durationMs' to be a number");
  }
}

/**
 * Assert that a finding has the correct structure
 */
export function assertValidFinding(finding: any): void {
  if (!finding || typeof finding !== "object") {
    throw new Error("Expected finding to be an object");
  }

  const requiredFields = ["id", "source", "packageName", "packageVersion", "severity"];

  for (const field of requiredFields) {
    if (!(field in finding)) {
      throw new Error(`Expected finding to have field: ${field}`);
    }
  }
}

// ─── Mock Helpers ────────────────────────────────────────────────────────────

/**
 * Create a mock HTTP client for testing
 */
export function createMockHttpClient() {
  const responses = new Map<string, any>();

  return {
    responses,
    setResponse(url: string, response: any) {
      responses.set(url, response);
    },
    async get(url: string) {
      const response = responses.get(url);
      if (!response) {
        throw new Error(`No mock response for URL: ${url}`);
      }
      return response;
    },
    async post(url: string, body: any) {
      const response = responses.get(url);
      if (!response) {
        throw new Error(`No mock response for URL: ${url}`);
      }
      return response;
    },
  };
}

/**
 * Create a mock cache for testing
 */
export function createMockCache() {
  const store = new Map<string, any>();

  return {
    store,
    async get(key: string) {
      return store.get(key) || null;
    },
    async set(key: string, value: any) {
      store.set(key, value);
    },
    async delete(key: string) {
      return store.delete(key);
    },
    async has(key: string) {
      return store.has(key);
    },
    async clear() {
      store.clear();
    },
  };
}
