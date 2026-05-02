/**
 * Type validation utilities.
 *
 * These provide runtime type checking with proper TypeScript type narrowing.
 * Use these instead of inline `typeof x === "string"` checks for clarity and
 * consistency across the codebase.
 */

/**
 * Validate that a value is a string.
 */
export function isString(value: unknown): value is string {
  return typeof value === "string";
}

/**
 * Validate that a value is a number (excluding NaN).
 */
export function isNumber(value: unknown): value is number {
  return typeof value === "number" && !Number.isNaN(value);
}

/**
 * Validate that a value is a boolean.
 */
export function isBoolean(value: unknown): value is boolean {
  return typeof value === "boolean";
}

/**
 * Validate that a value is a plain object (not null, not an array).
 */
export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Validate that a value is an array.
 */
export function isArray(value: unknown): value is unknown[] {
  return Array.isArray(value);
}

/**
 * Validate that a value is a non-empty string (after trimming).
 */
export function isNonEmptyString(value: unknown): value is string {
  return isString(value) && value.trim().length > 0;
}

/**
 * Validate that a value is defined (not null or undefined).
 */
export function isDefined<T>(value: T | null | undefined): value is T {
  return value !== null && value !== undefined;
}

/**
 * Validate that a string matches a regex pattern.
 */
export function matchesPattern(value: string, pattern: RegExp): boolean {
  return pattern.test(value);
}

/**
 * Validate email format (basic check).
 */
export function isEmail(value: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(value);
}

/**
 * Validate URL format.
 */
export function isUrl(value: string): boolean {
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validate semver format (e.g., "1.2.3", "1.0.0-beta.1").
 */
export function isSemver(value: string): boolean {
  const semverRegex = /^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$/;
  return semverRegex.test(value);
}

/**
 * Validate npm package name format.
 * Supports both scoped (@scope/name) and unscoped (name) packages.
 */
export function isPackageName(value: string): boolean {
  // Basic npm package name validation
  const packageNameRegex = /^(@[^/]+\/)?[^@\s]+$/;
  return packageNameRegex.test(value);
}

/**
 * Validate that a value is one of the specified enum values.
 *
 * @example
 * ```ts
 * const severity = "high" as unknown;
 * if (isOneOf(severity, ["low", "medium", "high", "critical"])) {
 *   // severity is narrowed to the union type
 * }
 * ```
 */
export function isOneOf<T extends readonly unknown[]>(
  value: unknown,
  validValues: T,
): value is T[number] {
  return (validValues as readonly unknown[]).includes(value);
}

/**
 * Validate that a value is a positive number.
 */
export function isPositiveNumber(value: unknown): value is number {
  return isNumber(value) && value > 0;
}

/**
 * Validate that a value is a non-negative number.
 */
export function isNonNegativeNumber(value: unknown): value is number {
  return isNumber(value) && value >= 0;
}

/**
 * Validate that a value is an integer.
 */
export function isInteger(value: unknown): value is number {
  return isNumber(value) && Number.isInteger(value);
}

/**
 * Validate that a string is a valid ISO 8601 date string.
 */
export function isIsoDateString(value: string): boolean {
  const date = new Date(value);
  return !Number.isNaN(date.getTime()) && value === date.toISOString();
}

/**
 * Validate that a string looks like a date (YYYY-MM-DD).
 */
export function isDateString(value: string): boolean {
  const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
  if (!dateRegex.test(value)) return false;
  const date = new Date(value);
  return !Number.isNaN(date.getTime());
}
