/**
 * Object manipulation utilities.
 *
 * These provide common object operations that are useful across the codebase.
 */

/**
 * Check if an object is a plain object (not null, not an array).
 */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Deep merge two objects.
 *
 * Source values override target values. Nested objects are recursively merged.
 *
 * @example
 * ```ts
 * deepMerge({a: 1, b: {c: 2}}, {b: {d: 3}, e: 4})
 * // {a: 1, b: {c: 2, d: 3}, e: 4}
 * ```
 */
export function deepMerge<T extends Record<string, unknown>>(
  target: T,
  source: Partial<T>,
): T {
  const result = { ...target };

  for (const key in source) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      const targetVal = result[key];
      const sourceVal = source[key];

      if (isPlainObject(targetVal) && isPlainObject(sourceVal)) {
        (result as Record<string, unknown>)[key] = deepMerge(
          targetVal as Record<string, unknown>,
          sourceVal as Record<string, unknown>,
        );
      } else {
        (result as Record<string, unknown>)[key] = sourceVal;
      }
    }
  }

  return result;
}

/**
 * Pick specific keys from an object.
 *
 * @example
 * ```ts
 * pick({a: 1, b: 2, c: 3}, ["a", "c"]) // {a: 1, c: 3}
 * ```
 */
export function pick<T extends object, K extends keyof T>(obj: T, keys: K[]): Pick<T, K> {
  const result = {} as Pick<T, K>;
  for (const key of keys) {
    if (key in obj) {
      result[key] = obj[key];
    }
  }
  return result;
}

/**
 * Omit specific keys from an object.
 *
 * @example
 * ```ts
 * omit({a: 1, b: 2, c: 3}, ["b"]) // {a: 1, c: 3}
 * ```
 */
export function omit<T extends object, K extends keyof T>(obj: T, keys: K[]): Omit<T, K> {
  const result = { ...obj } as Record<string, unknown>;
  for (const key of keys) {
    delete result[key as string];
  }
  return result as Omit<T, K>;
}

/**
 * Get typed object keys.
 *
 * @example
 * ```ts
 * const obj = {a: 1, b: 2};
 * keys(obj) // ["a", "b"] (typed as ("a" | "b")[])
 * ```
 */
export function keys<T extends object>(obj: T): Array<keyof T> {
  return Object.keys(obj) as Array<keyof T>;
}

/**
 * Get typed object values.
 *
 * @example
 * ```ts
 * const obj = {a: 1, b: 2};
 * values(obj) // [1, 2] (typed as number[])
 * ```
 */
export function values<T extends object>(obj: T): Array<T[keyof T]> {
  return Object.values(obj) as Array<T[keyof T]>;
}

/**
 * Get typed object entries.
 *
 * @example
 * ```ts
 * const obj = {a: 1, b: 2};
 * entries(obj) // [["a", 1], ["b", 2]]
 * ```
 */
export function entries<T extends object>(
  obj: T,
): Array<[keyof T, T[keyof T]]> {
  return Object.entries(obj) as Array<[keyof T, T[keyof T]]>;
}

/**
 * Check if an object has a property (own or inherited).
 */
export function hasProperty<T extends object>(
  obj: T,
  key: string | number | symbol,
): key is keyof T {
  return key in obj;
}

/**
 * Get a nested value by dot-separated path.
 *
 * @example
 * ```ts
 * getNestedValue({a: {b: {c: 42}}}, "a.b.c") // 42
 * getNestedValue({a: {b: 1}}, "a.x.y") // undefined
 * ```
 */
export function getNestedValue(
  obj: Record<string, unknown>,
  path: string,
): unknown {
  const keys = path.split(".");
  let current: unknown = obj;

  for (const key of keys) {
    if (current === null || current === undefined) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[key];
  }

  return current;
}

/**
 * Set a nested value by dot-separated path.
 * Creates intermediate objects as needed.
 *
 * @example
 * ```ts
 * const obj = {};
 * setNestedValue(obj as Record<string, unknown>, "a.b.c", 42);
 * // obj is now {a: {b: {c: 42}}}
 * ```
 */
export function setNestedValue(
  obj: Record<string, unknown>,
  path: string,
  value: unknown,
): void {
  const keys = path.split(".");
  let current = obj;

  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i]!;
    if (!(key in current) || typeof current[key] !== "object") {
      current[key] = {};
    }
    current = current[key] as Record<string, unknown>;
  }

  current[keys[keys.length - 1]!] = value;
}

/**
 * Flatten a nested object into a single-level object with dot-separated keys.
 *
 * @example
 * ```ts
 * flattenObject({a: {b: 1, c: {d: 2}}})
 * // {"a.b": 1, "a.c.d": 2}
 * ```
 */
export function flattenObject(
  obj: Record<string, unknown>,
  prefix = "",
): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  for (const key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      const newKey = prefix ? `${prefix}.${key}` : key;
      const value = obj[key];

      if (isPlainObject(value)) {
        Object.assign(result, flattenObject(value, newKey));
      } else {
        result[newKey] = value;
      }
    }
  }

  return result;
}

/**
 * Check if two objects are deeply equal.
 *
 * @example
 * ```ts
 * deepEqual({a: {b: 1}}, {a: {b: 1}}) // true
 * deepEqual({a: 1}, {a: 2}) // false
 * ```
 */
export function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;

  if (a === null || b === null) return false;
  if (typeof a !== typeof b) return false;

  if (typeof a !== "object") return false;

  if (Array.isArray(a) !== Array.isArray(b)) return false;

  if (Array.isArray(a)) {
    if (a.length !== (b as unknown[]).length) return false;
    return a.every((item, index) => deepEqual(item, (b as unknown[])[index]));
  }

  const keysA = Object.keys(a as Record<string, unknown>);
  const keysB = Object.keys(b as Record<string, unknown>);

  if (keysA.length !== keysB.length) return false;

  return keysA.every((key) =>
    deepEqual(
      (a as Record<string, unknown>)[key],
      (b as Record<string, unknown>)[key],
    ),
  );
}

/**
 * Create a shallow clone of an object with only specified keys removed.
 * Useful for creating exclusion patterns.
 *
 * @example
 * ```ts
 * filterObject({a: 1, b: 2, c: 3}, (key, value) => value > 1)
 * // {b: 2, c: 3}
 * ```
 */
export function filterObject<T extends Record<string, unknown>>(
  obj: T,
  predicate: (key: keyof T, value: T[keyof T]) => boolean,
): Partial<T> {
  const result: Record<string, unknown> = {};

  for (const key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      if (predicate(key, obj[key])) {
        result[key as string] = obj[key];
      }
    }
  }

  return result as Partial<T>;
}

/**
 * Map over object values, transforming each value.
 *
 * @example
 * ```ts
 * mapValues({a: 1, b: 2}, (val) => val * 2) // {a: 2, b: 4}
 * ```
 */
export function mapValues<T extends Record<string, unknown>, R>(
  obj: T,
  transform: (value: T[keyof T], key: keyof T) => R,
): Record<keyof T, R> {
  const result = {} as Record<keyof T, R>;

  for (const key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      result[key] = transform(obj[key], key);
    }
  }

  return result;
}
