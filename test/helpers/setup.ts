/**
 * Test setup utilities.
 *
 * Provides functions for setting up test environments,
 * creating temporary directories, and managing test state.
 */
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { createMockConfig } from "./mocks";
import type { AuditConfig } from "../../src/types";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface TestContext {
  /** Path to a temporary directory that exists for the test */
  tempDir: string;
  /** Cleanup function to remove the temp dir */
  cleanup: () => Promise<void>;
}

// ─── Temporary Directory Management ──────────────────────────────────────────

/**
 * Create a temporary directory for testing.
 *
 * Returns a TestContext with the path and a cleanup function.
 *
 * @example
 * ```ts
 * let ctx: TestContext;
 *
 * beforeEach(async () => {
 *   ctx = await setupTempDir("audit-test-");
 * });
 *
 * afterEach(async () => {
 *   await ctx.cleanup();
 * });
 * ```
 */
export async function setupTempDir(
  prefix = "test-"
): Promise<TestContext> {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));

  return {
    tempDir,
    async cleanup() {
      try {
        await fs.rm(tempDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors
      }
    },
  };
}

/**
 * Create a temporary directory with a config file.
 */
export async function setupTempDirWithConfig(
  configOverrides: Partial<AuditConfig> = {},
  configName = ".pnpm-audit.yaml"
): Promise<TestContext & { configPath: string; config: AuditConfig }> {
  const ctx = await setupTempDir("config-test-");
  const config = createMockConfig(configOverrides);
  const configPath = path.join(ctx.tempDir, configName);

  const yaml = await import("yaml");
  await fs.writeFile(configPath, yaml.stringify(config));

  return {
    ...ctx,
    configPath,
    config,
  };
}

/**
 * Create a temporary directory with a lockfile.
 */
export async function setupTempDirWithLockfile(
  lockfileName = "pnpm-lock.yaml",
  lockfileContent?: string
): Promise<TestContext & { lockfilePath: string }> {
  const ctx = await setupTempDir("lockfile-test-");
  const lockfilePath = path.join(ctx.tempDir, lockfileName);

  const defaultContent = lockfileContent ?? `lockfileVersion: '9.0'\n\npackages:\n  /test@1.0.0:\n    resolution: {integrity: sha512-test}\n`;
  await fs.writeFile(lockfilePath, defaultContent);

  return {
    ...ctx,
    lockfilePath,
  };
}

/**
 * Create a complete test environment with config and lockfile.
 */
export async function setupTestProject(
  options: {
    configOverrides?: Partial<AuditConfig>;
    packages?: Array<{ name: string; version: string }>;
  } = {}
): Promise<
  TestContext & {
    configPath: string;
    lockfilePath: string;
    config: AuditConfig;
  }
> {
  const ctx = await setupTempDir("project-test-");

  // Write config
  const config = createMockConfig(options.configOverrides);
  const yaml = await import("yaml");
  const configPath = path.join(ctx.tempDir, ".pnpm-audit.yaml");
  await fs.writeFile(configPath, yaml.stringify(config));

  // Write lockfile
  const lockfilePath = path.join(ctx.tempDir, "pnpm-lock.yaml");
  const packages = options.packages ?? [{ name: "test-pkg", version: "1.0.0" }];
  const pkgSnapshots: Record<string, object> = {};
  for (const p of packages) {
    pkgSnapshots[`/${p.name}@${p.version}`] = {
      resolution: { integrity: `sha512-${p.name}-${p.version}` },
    };
  }
  const lockfile = {
    lockfileVersion: "9.0",
    packages: pkgSnapshots,
  };
  await fs.writeFile(lockfilePath, yaml.stringify(lockfile));

  return {
    ...ctx,
    configPath,
    lockfilePath,
    config,
  };
}

// ─── Console Spy Setup ───────────────────────────────────────────────────────

export interface ConsoleSpy {
  logs: string[];
  errors: string[];
  warnings: string[];
  restore(): void;
}

/**
 * Spy on console output for testing.
 *
 * Captures all console.log, console.error, and console.warn calls.
 */
export function setupConsoleSpy(): ConsoleSpy {
  const logs: string[] = [];
  const errors: string[] = [];
  const warnings: string[] = [];

  const originalLog = console.log;
  const originalError = console.error;
  const originalWarn = console.warn;

  console.log = (...args: unknown[]) => {
    logs.push(args.map(String).join(" "));
  };
  console.error = (...args: unknown[]) => {
    errors.push(args.map(String).join(" "));
  };
  console.warn = (...args: unknown[]) => {
    warnings.push(args.map(String).join(" "));
  };

  return {
    logs,
    errors,
    warnings,
    restore() {
      console.log = originalLog;
      console.error = originalError;
      console.warn = originalWarn;
    },
  };
}

// ─── Process Mock ────────────────────────────────────────────────────────────

export interface ProcessExitSpy {
  exits: Array<{ code: number }>;
  restore(): void;
}

/**
 * Spy on process.exit to prevent test runner from exiting.
 *
 * Use this when testing code that calls process.exit().
 */
export function setupProcessExitSpy(): ProcessExitSpy {
  const exits: Array<{ code: number }> = [];
  const original = process.exit;

  // We can't actually prevent process.exit in tests,
  // but we can track the calls
  process.exit = ((code?: number) => {
    exits.push({ code: code ?? 0 });
    // Don't actually exit
  }) as typeof process.exit;

  return {
    exits,
    restore() {
      process.exit = original;
    },
  };
}
