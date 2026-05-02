/**
 * Type guard utilities.
 *
 * These provide TypeScript type guards for runtime type checking.
 * While similar to validation-helpers, these focus specifically on type narrowing
 * and are designed to be used in conditional checks.
 */

/**
 * Type guard for string.
 */
export function isString(value: unknown): value is string {
  return typeof value === "string";
}

/**
 * Type guard for number (excluding NaN).
 */
export function isNumber(value: unknown): value is number {
  return typeof value === "number" && !Number.isNaN(value);
}

/**
 * Type guard for boolean.
 */
export function isBoolean(value: unknown): value is boolean {
  return typeof value === "boolean";
}

/**
 * Type guard for plain object (not null, not array).
 */
export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Type guard for array.
 */
export function isArray(value: unknown): value is unknown[] {
  return Array.isArray(value);
}

/**
 * Type guard for null.
 */
export function isNull(value: unknown): value is null {
  return value === null;
}

/**
 * Type guard for undefined.
 */
export function isUndefined(value: unknown): value is undefined {
  return value === undefined;
}

/**
 * Type guard for null or undefined.
 */
export function isNullOrUndefined(value: unknown): value is null | undefined {
  return value === null || value === undefined;
}

/**
 * Type guard for defined value (not null and not undefined).
 */
export function isDefined<T>(value: T | null | undefined): value is T {
  return value !== null && value !== undefined;
}

/**
 * Type guard for function.
 */
export function isFunction(value: unknown): value is Function {
  return typeof value === "function";
}

/**
 * Type guard for Date instance (valid date).
 */
export function isDate(value: unknown): value is Date {
  return value instanceof Date && !Number.isNaN(value.getTime());
}

/**
 * Type guard for RegExp.
 */
export function isRegExp(value: unknown): value is RegExp {
  return value instanceof RegExp;
}

/**
 * Type guard for Promise (thenable).
 */
export function isPromise(value: unknown): value is Promise<unknown> {
  return (
    value instanceof Promise ||
    (typeof value === "object" &&
      value !== null &&
      typeof (value as Record<string, unknown>).then === "function")
  );
}

/**
 * Type guard for Error.
 */
export function isError(value: unknown): value is Error {
  return value instanceof Error;
}

/**
 * Type guard for Buffer.
 */
export function isBuffer(value: unknown): value is Buffer {
  return Buffer.isBuffer(value);
}

/**
 * Type guard for empty string.
 */
export function isEmptyString(value: unknown): value is "" {
  return typeof value === "string" && value.length === 0;
}

/**
 * Type guard for empty array.
 */
export function isEmptyArray(value: unknown): value is unknown[] {
  return Array.isArray(value) && value.length === 0;
}

/**
 * Type guard for empty object (no own enumerable properties).
 */
export function isEmptyObject(
  value: unknown,
): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length === 0
  );
}

/**
 * Type guard for non-empty array.
 */
export function isNonEmptyArray<T>(value: T[] | unknown): value is T[] {
  return Array.isArray(value) && value.length > 0;
}

/**
 * Type guard for non-empty string (not just whitespace).
 */
export function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

/**
 * Type guard for a value that is an object with a specific key.
 *
 * @example
 * ```ts
 * if (hasKey(obj, "id") && typeof obj.id === "string") {
 *   // obj.id is guaranteed to exist
 * }
 * ```
 */
export function hasKey<K extends string>(
  obj: unknown,
  key: K,
): obj is Record<K, unknown> {
  return typeof obj === "object" && obj !== null && key in obj;
}

/**
 * Type guard for a value that is an object with multiple specific keys.
 *
 * @example
 * ```ts
 * if (hasKeys(obj, ["id", "name"])) {
 *   // obj.id and obj.name are guaranteed to exist
 * }
 * ```
 */
export function hasKeys<K extends string>(
  obj: unknown,
  keys: K[],
): obj is Record<K, unknown> {
  if (typeof obj !== "object" || obj === null) return false;
  return keys.every((key) => key in obj);
}

/**
 * Type guard for Node.js.ErrnoException.
 */
export function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return (
    error instanceof Error &&
    "code" in error &&
    typeof (error as Record<string, unknown>).code === "string"
  );
}

/**
 * Assert that a condition is true, throwing an error if not.
 *
 * @example
 * ```ts
 * assert(typeof value === "string", "Value must be a string");
 * ```
 */
export function assert(
  condition: boolean,
  message: string = "Assertion failed",
): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

/**
 * Assert that a value is defined (not null or undefined).
 *
 * @example
 * ```ts
 * const config = assertNotNull(maybeConfig, "Config is required");
 * ```
 */
export function assertNotNull<T>(
  value: T | null | undefined,
  message: string = "Expected value to be defined",
): asserts value is T {
  if (value === null || value === undefined) {
    throw new Error(message);
  }
}

/**
 * Narrow a value to a specific type, throwing if the condition is not met.
 *
 * @example
 * ```ts
 * const config = narrow<Config>(rawConfig, isConfig, "Invalid config format");
 * ```
 */
export function narrow<T>(
  value: unknown,
  guard: (value: unknown) => value is T,
  message: string = "Type assertion failed",
): T {
  if (!guard(value)) {
    throw new Error(message);
  }
  return value;
}
