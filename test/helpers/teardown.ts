/**
 * Test teardown utilities.
 *
 * Provides functions for cleaning up after tests,
 * including file cleanup, mock restoration, and state reset.
 */
import fs from "node:fs/promises";

// ─── File Cleanup ────────────────────────────────────────────────────────────

/**
 * Safely remove a file or directory.
 *
 * Ignores errors if the path doesn't exist.
 */
export async function safeRemove(filePath: string): Promise<void> {
  try {
    await fs.rm(filePath, { recursive: true, force: true });
  } catch {
    // Ignore cleanup errors
  }
}

/**
 * Clean up multiple paths at once.
 */
export async function safeRemoveAll(paths: string[]): Promise<void> {
  await Promise.allSettled(paths.map((p) => safeRemove(p)));
}

// ─── Mock Restoration ────────────────────────────────────────────────────────

/**
 * Create a teardown function that restores multiple mocks/spies.
 *
 * @example
 * ```ts
 * const teardown = createTeardown();
 *
 * const spy = setupConsoleSpy();
 * teardown.add(() => spy.restore());
 *
 * const envMock = mockEnv({ TOKEN: "test" });
 * teardown.add(() => envMock[Symbol.dispose]());
 *
 * // ... test ...
 *
 * await teardown.run();
 * ```
 */
export function createTeardown() {
  const cleanups: Array<() => void | Promise<void>> = [];

  return {
    /**
     * Add a cleanup function to run on teardown.
     */
    add(fn: () => void | Promise<void>) {
      cleanups.push(fn);
    },

    /**
     * Run all cleanup functions in reverse order.
     */
    async run(): Promise<void> {
      const errors: Error[] = [];

      // Run in reverse order (LIFO) to respect dependencies
      for (const cleanup of cleanups.reverse()) {
        try {
          await cleanup();
        } catch (error) {
          if (error instanceof Error) {
            errors.push(error);
          }
        }
      }

      if (errors.length > 0) {
        const message = errors.map((e) => `  - ${e.message}`).join("\n");
        console.warn(`Teardown completed with ${errors.length} error(s):\n${message}`);
      }
    },
  };
}

// ─── State Reset ─────────────────────────────────────────────────────────────

/**
 * Clear all module caches to ensure test isolation.
 *
 * Useful for tests that dynamically import modules.
 *
 * **Warning**: This clears ALL cached modules, not just yours.
 * Use sparingly and prefer dependency injection over this.
 */
export function clearModuleCache(): void {
  // For ESM, there's no equivalent of require.cache clearing
  // This is mainly a documentation stub for awareness
  // In practice, use dependency injection instead
}

/**
 * Reset global state that might leak between tests.
 */
export function resetGlobalState(): void {
  // Reset any global variables your code might set
  // Add project-specific resets here as needed
}
