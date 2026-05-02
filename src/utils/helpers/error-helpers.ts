/**
 * Error handling utilities.
 *
 * NOTE: `errorMessage` and `isNodeError` already exist in `src/utils/error.ts`.
 * This module provides complementary error utilities.
 */

/**
 * Create a typed error with additional properties.
 *
 * @example
 * ```ts
 * const error = createError<{ code: string; statusCode: number }>(
 *   "Not found",
 *   { code: "NOT_FOUND", statusCode: 404 }
 * );
 * error.code // "NOT_FOUND"
 * ```
 */
export function createError<T extends Record<string, unknown>>(
  message: string,
  properties: T = {} as T,
): Error & T {
  const error = new Error(message) as Error & T;
  Object.assign(error, properties);
  return error;
}

/**
 * Wrap an error with additional context.
 *
 * @example
 * ```ts
 * try {
 *   await fetchData();
 * } catch (e) {
 *   throw wrapError(e as Error, "Failed to fetch data", { url, timeout });
 * }
 * ```
 */
export function wrapError(
  originalError: Error,
  message: string,
  context?: Record<string, unknown>,
): Error {
  const wrappedError = new Error(`${message}: ${originalError.message}`);
  // Preserve the original stack
  if (originalError.stack) {
    wrappedError.stack = originalError.stack;
  }

  if (context) {
    Object.assign(wrappedError, context);
  }

  return wrappedError;
}

/**
 * Check if an error is of a specific type.
 *
 * @example
 * ```ts
 * if (isErrorType(err, TypeError)) {
 *   // handle TypeError
 * }
 * ```
 */
export function isErrorType(
  error: unknown,
  type: new (...args: unknown[]) => Error,
): boolean {
  return error instanceof type;
}

/**
 * Get error message safely from any error type.
 *
 * This is similar to `errorMessage` in `src/utils/error.ts` but includes
 * a fallback message parameter.
 *
 * @example
 * ```ts
 * getErrorMessage(err, "Unknown error occurred")
 * ```
 */
export function getErrorMessage(
  error: unknown,
  fallback = "An unknown error occurred",
): string {
  if (error instanceof Error) {
    return error.message;
  }

  if (typeof error === "string") {
    return error;
  }

  return fallback;
}

/**
 * Get error stack safely from any error type.
 */
export function getErrorStack(error: unknown): string | undefined {
  if (error instanceof Error) {
    return error.stack;
  }

  return undefined;
}

/**
 * Check if an error is a network-related error.
 *
 * @example
 * ```ts
 * try {
 *   await fetch(url);
 * } catch (e) {
 *   if (isNetworkError(e)) {
 *     // retry the request
 *   }
 * }
 * ```
 */
export function isNetworkError(error: unknown): boolean {
  if (error instanceof Error) {
    const message = error.message.toLowerCase();
    return (
      message.includes("network") ||
      message.includes("timeout") ||
      message.includes("connection") ||
      message.includes("econnrefused") ||
      message.includes("enotfound") ||
      message.includes("fetch failed")
    );
  }

  return false;
}

/**
 * Check if an error is a validation error.
 */
export function isValidationError(error: unknown): boolean {
  if (error instanceof Error) {
    return error.name === "ValidationError";
  }

  return false;
}

/**
 * Check if an error is a "not found" error.
 */
export function isNotFoundError(error: unknown): boolean {
  if (error instanceof Error) {
    return (
      error.name === "NotFoundError" ||
      error.message.toLowerCase().includes("not found")
    );
  }

  return false;
}

/**
 * Create a validation error with field context.
 *
 * @example
 * ```ts
 * throw createValidationError("email", "is not a valid email address", "invalid@");
 * ```
 */
export function createValidationError(
  field: string,
  message: string,
  value?: unknown,
): Error & { field: string; value?: unknown } {
  return createError(`Validation error for ${field}: ${message}`, {
    field,
    value,
  });
}

/**
 * Create a "not found" error with resource context.
 *
 * @example
 * ```ts
 * throw createNotFoundError("Package", "lodash");
 * ```
 */
export function createNotFoundError(
  resource: string,
  identifier: string | number,
): Error & { resource: string; identifier: string | number } {
  return createError(`${resource} with identifier '${identifier}' not found`, {
    resource,
    identifier,
  });
}

/**
 * Safely execute an async function, returning undefined on error.
 *
 * @example
 * ```ts
 * const result = await safeAsync(() => fetchData());
 * if (result !== undefined) {
 *   // handle success
 * }
 * ```
 */
export async function safeAsync<T>(
  fn: () => Promise<T>,
): Promise<T | undefined> {
  try {
    return await fn();
  } catch {
    return undefined;
  }
}

/**
 * Safely execute an async function with a fallback value on error.
 *
 * @example
 * ```ts
 * const data = await safeAsyncWithFallback(
 *   () => fetchData(),
 *   { items: [] }
 * );
 * ```
 */
export async function safeAsyncWithFallback<T>(
  fn: () => Promise<T>,
  fallback: T,
): Promise<T> {
  try {
    return await fn();
  } catch {
    return fallback;
  }
}
