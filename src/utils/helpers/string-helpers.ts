/**
 * String manipulation utilities.
 *
 * These provide common string transformations that are useful across the codebase.
 */

/**
 * Capitalize the first letter of a string.
 *
 * @example
 * ```ts
 * capitalize("hello") // "Hello"
 * capitalize("HELLO") // "HELLO"
 * ```
 */
export function capitalize(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 * Convert a string to kebab-case.
 *
 * @example
 * ```ts
 * toKebabCase("helloWorld") // "hello-world"
 * toKebabCase("HelloWorld") // "hello-world"
 * toKebabCase("hello_world") // "hello-world"
 * ```
 */
export function toKebabCase(str: string): string {
  return str
    .replace(/([a-z])([A-Z])/g, "$1-$2")
    .replace(/([A-Z])([A-Z][a-z])/g, "$1-$2")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/**
 * Convert a string to camelCase.
 *
 * @example
 * ```ts
 * toCamelCase("hello-world") // "helloWorld"
 * toCamelCase("Hello World") // "helloWorld"
 * ```
 */
export function toCamelCase(str: string): string {
  return str
    .replace(/[^a-zA-Z0-9]+(.)/g, (_, char: string) => char.toUpperCase())
    .replace(/^[A-Z]/, (char: string) => char.toLowerCase());
}

/**
 * Convert a string to snake_case.
 *
 * @example
 * ```ts
 * toSnakeCase("helloWorld") // "hello_world"
 * toSnakeCase("HelloWorld") // "hello_world"
 * ```
 */
export function toSnakeCase(str: string): string {
  return str
    .replace(/([a-z])([A-Z])/g, "$1_$2")
    .replace(/([A-Z])([A-Z][a-z])/g, "$1_$2")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

/**
 * Truncate a string to a maximum length, appending a suffix if truncated.
 *
 * @example
 * ```ts
 * truncate("hello world", 8) // "hello..."
 * truncate("hello", 10) // "hello" (not truncated)
 * ```
 */
export function truncate(str: string, maxLength: number, suffix = "..."): string {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength - suffix.length) + suffix;
}

/**
 * Remove all whitespace from a string.
 *
 * @example
 * ```ts
 * removeWhitespace("hello world") // "helloworld"
 * ```
 */
export function removeWhitespace(str: string): string {
  return str.replace(/\s+/g, "");
}

/**
 * Check if a string contains a substring (case-insensitive).
 *
 * @example
 * ```ts
 * containsIgnoreCase("Hello World", "hello") // true
 * ```
 */
export function containsIgnoreCase(str: string, substring: string): boolean {
  return str.toLowerCase().includes(substring.toLowerCase());
}

/**
 * Extract a substring between two markers.
 *
 * @example
 * ```ts
 * extractBetween("[hello]", "[", "]") // "hello"
 * extractBetween("prefix::value::suffix", "::", "::") // "value"
 * ```
 */
export function extractBetween(
  str: string,
  startMarker: string,
  endMarker: string,
): string | null {
  const startIdx = str.indexOf(startMarker);
  if (startIdx === -1) return null;

  const contentStart = startIdx + startMarker.length;
  const endIdx = str.indexOf(endMarker, contentStart);
  if (endIdx === -1) return null;

  return str.slice(contentStart, endIdx);
}

/**
 * Indent all lines of a string by a given number of spaces.
 *
 * @example
 * ```ts
 * indent("line1\nline2", 2) // "  line1\n  line2"
 * ```
 */
export function indent(str: string, spaces: number): string {
  const prefix = " ".repeat(spaces);
  return str
    .split("\n")
    .map((line) => (line.length > 0 ? prefix + line : line))
    .join("\n");
}

/**
 * Pluralize a word based on count.
 *
 * @example
 * ```ts
 * pluralize(1, "error") // "error"
 * pluralize(2, "error") // "errors"
 * pluralize(0, "item", "items") // "items"
 * ```
 */
export function pluralize(
  count: number,
  singular: string,
  plural?: string,
): string {
  return count === 1 ? singular : (plural ?? singular + "s");
}

/**
 * Format a byte count into a human-readable string.
 *
 * @example
 * ```ts
 * formatBytes(1024) // "1.0 KB"
 * formatBytes(1048576) // "1.0 MB"
 * ```
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const k = 1024;
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const value = bytes / Math.pow(k, i);
  return `${value.toFixed(1)} ${units[i]}`;
}

/**
 * Format a duration in milliseconds to a human-readable string.
 *
 * @example
 * ```ts
 * formatDuration(1500) // "1.5s"
 * formatDuration(500) // "500ms"
 * ```
 */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = Math.round(seconds % 60);
  return `${minutes}m ${remainingSeconds}s`;
}
