/**
 * Async utility functions for common asynchronous patterns.
 *
 * NOTE: `sleep` and `mapWithConcurrency` already exist in `src/utils/concurrency.ts`.
 * This module provides complementary async utilities.
 */

/**
 * Execute a function with a timeout.
 *
 * @example
 * ```ts
 * const result = await withTimeout(fetchData(), 5000, "Request timed out");
 * ```
 */
export async function withTimeout<T>(
  fn: () => Promise<T>,
  timeoutMs: number,
  errorMessage = "Operation timed out",
): Promise<T> {
  return Promise.race([
    fn(),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error(errorMessage)), timeoutMs),
    ),
  ]);
}

/**
 * Batch process items with a concurrency limit.
 *
 * Unlike `mapWithConcurrency`, this preserves order and provides a simpler API.
 * Use this for side-effect-oriented processing; use `mapWithConcurrency` for
 * ordered transform-and-collect patterns.
 *
 * @example
 * ```ts
 * await batchProcess(urls, async (url) => {
 *   await downloadFile(url);
 * }, 5);
 * ```
 */
export async function batchProcess<T>(
  items: T[],
  processor: (item: T) => Promise<void>,
  concurrency: number = 5,
): Promise<void> {
  const executing: Promise<void>[] = [];

  for (const item of items) {
    const p = processor(item);
    executing.push(p);

    if (executing.length >= concurrency) {
      await Promise.race(executing);
      // Remove the settled promise
      for (let i = 0; i < executing.length; i++) {
        const settled = await Promise.race([
          executing[i]!.then(() => true),
          Promise.resolve(false),
        ]);
        if (settled) {
          executing.splice(i, 1);
          break;
        }
      }
    }
  }

  await Promise.all(executing);
}

/**
 * Debounce a function - delays execution until after `delay` ms have passed
 * since the last invocation.
 *
 * @example
 * ```ts
 * const debouncedLog = debounce((msg: string) => console.log(msg), 300);
 * debouncedLog("hello"); // only executes after 300ms of no calls
 * ```
 */
export function debounce<T extends (...args: unknown[]) => unknown>(
  fn: T,
  delay: number,
): (...args: Parameters<T>) => void {
  let timeoutId: ReturnType<typeof setTimeout> | null = null;

  return (...args: Parameters<T>) => {
    if (timeoutId !== null) {
      clearTimeout(timeoutId);
    }

    timeoutId = setTimeout(() => {
      fn(...args);
      timeoutId = null;
    }, delay);
  };
}

/**
 * Throttle a function - ensures it's called at most once per `limit` ms.
 *
 * @example
 * ```ts
 * const throttledLog = throttle((msg: string) => console.log(msg), 1000);
 * throttledLog("a"); // executes immediately
 * throttledLog("b"); // ignored (within 1000ms)
 * ```
 */
export function throttle<T extends (...args: unknown[]) => unknown>(
  fn: T,
  limit: number,
): (...args: Parameters<T>) => void {
  let inThrottle = false;

  return (...args: Parameters<T>) => {
    if (!inThrottle) {
      fn(...args);
      inThrottle = true;
      setTimeout(() => {
        inThrottle = false;
      }, limit);
    }
  };
}

/**
 * Create a lazily-initialized async value.
 * The factory is called at most once, and the result is cached.
 *
 * @example
 * ```ts
 * const dbConnection = createLazyAsync(async () => {
 *   return await connectToDatabase();
 * });
 * // Both calls use the same connection
 * const conn1 = await dbConnection.get();
 * const conn2 = await dbConnection.get();
 * ```
 */
export function createLazyAsync<T>(factory: () => Promise<T>): {
  get: () => Promise<T>;
  reset: () => void;
} {
  let cached: Promise<T> | null = null;

  return {
    get: () => {
      if (cached === null) {
        cached = factory();
      }
      return cached;
    },
    reset: () => {
      cached = null;
    },
  };
}
