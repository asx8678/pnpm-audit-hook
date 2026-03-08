/**
 * Extract error message from unknown error type.
 * Common pattern for catch blocks.
 */
export const errorMessage = (e: unknown): string =>
  e instanceof Error ? e.message : String(e);

/** Type guard for NodeJS.ErrnoException */
export function isNodeError(e: unknown): e is NodeJS.ErrnoException {
  return e instanceof Error && "code" in e;
}
