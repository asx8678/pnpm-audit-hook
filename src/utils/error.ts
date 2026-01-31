/**
 * Extract error message from unknown error type.
 * Common pattern for catch blocks.
 */
export const errorMessage = (e: unknown): string =>
  e instanceof Error ? e.message : String(e);
