/**
 * Array manipulation utilities.
 *
 * These provide common array operations that are useful across the codebase.
 */

/**
 * Get unique values from an array.
 *
 * @example
 * ```ts
 * unique([1, 2, 2, 3]) // [1, 2, 3]
 * ```
 */
export function unique<T>(array: T[]): T[] {
  return [...new Set(array)];
}

/**
 * Flatten a nested array one level deep.
 *
 * @example
 * ```ts
 * flatten([[1, 2], [3, [4]]]) // [1, 2, 3, [4]]
 * ```
 */
export function flatten<T>(array: (T | T[])[]): T[] {
  const result: T[] = [];
  for (const item of array) {
    if (Array.isArray(item)) {
      result.push(...item);
    } else {
      result.push(item);
    }
  }
  return result;
}

/**
 * Chunk an array into groups of a specified size.
 *
 * @example
 * ```ts
 * chunk([1, 2, 3, 4, 5], 2) // [[1, 2], [3, 4], [5]]
 * ```
 */
export function chunk<T>(array: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }
  return chunks;
}

/**
 * Group array items by a key function or property name.
 *
 * @example
 * ```ts
 * groupBy([{type: "a", val: 1}, {type: "b", val: 2}, {type: "a", val: 3}], "type")
 * // { a: [{type: "a", val: 1}, {type: "a", val: 3}], b: [{type: "b", val: 2}] }
 *
 * groupBy([1, 2, 3, 4], n => n % 2 === 0 ? "even" : "odd")
 * // { odd: [1, 3], even: [2, 4] }
 * ```
 */
export function groupBy<T>(
  array: T[],
  keyFn: keyof T | ((item: T) => string),
): Record<string, T[]> {
  return array.reduce(
    (groups, item) => {
      const key =
        typeof keyFn === "function" ? keyFn(item) : String(item[keyFn]);
      if (!groups[key]) {
        groups[key] = [];
      }
      groups[key].push(item);
      return groups;
    },
    {} as Record<string, T[]>,
  );
}

/**
 * Sort array by a key function or property name.
 *
 * @example
 * ```ts
 * sortBy([{name: "b"}, {name: "a"}], "name") // [{name: "a"}, {name: "b"}]
 * ```
 */
export function sortBy<T>(
  array: T[],
  keyFn: keyof T | ((item: T) => string | number),
  order: "asc" | "desc" = "asc",
): T[] {
  return [...array].sort((a, b) => {
    const aVal = typeof keyFn === "function" ? keyFn(a) : (a[keyFn] as string | number);
    const bVal = typeof keyFn === "function" ? keyFn(b) : (b[keyFn] as string | number);

    if (aVal < bVal) return order === "asc" ? -1 : 1;
    if (aVal > bVal) return order === "asc" ? 1 : -1;
    return 0;
  });
}

/**
 * Pick specific keys from an array of objects.
 *
 * @example
 * ```ts
 * pick([{a: 1, b: 2, c: 3}, {a: 4, b: 5, c: 6}], ["a", "c"])
 * // [{a: 1, c: 3}, {a: 4, c: 6}]
 * ```
 */
export function pick<T, K extends keyof T>(array: T[], keys: K[]): Pick<T, K>[] {
  return array.map((item) => {
    const picked = {} as Pick<T, K>;
    for (const key of keys) {
      picked[key] = item[key];
    }
    return picked;
  });
}

/**
 * Omit specific keys from an array of objects.
 *
 * @example
 * ```ts
 * omit([{a: 1, b: 2, c: 3}, {a: 4, b: 5, c: 6}], ["b"])
 * // [{a: 1, c: 3}, {a: 4, c: 6}]
 * ```
 */
export function omit<T, K extends keyof T>(array: T[], keys: K[]): Omit<T, K>[] {
  return array.map((item) => {
    const omitted = { ...item } as Record<string, unknown>;
    for (const key of keys) {
      delete omitted[key as string];
    }
    return omitted as Omit<T, K>;
  });
}

/**
 * Get the first element of an array, or undefined if empty.
 */
export function head<T>(array: T[]): T | undefined {
  return array[0];
}

/**
 * Get the last element of an array, or undefined if empty.
 */
export function tail<T>(array: T[]): T | undefined {
  return array[array.length - 1];
}

/**
 * Get a random element from an array.
 */
export function sample<T>(array: T[]): T | undefined {
  return array[Math.floor(Math.random() * array.length)];
}

/**
 * Shuffle an array (Fisher-Yates algorithm).
 */
export function shuffle<T>(array: T[]): T[] {
  const shuffled = [...array];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j]!, shuffled[i]!];
  }
  return shuffled;
}

/**
 * Partition an array into two arrays based on a predicate.
 *
 * @example
 * ```ts
 * partition([1, 2, 3, 4, 5], n => n % 2 === 0)
 * // [[2, 4], [1, 3, 5]]
 * ```
 */
export function partition<T>(
  array: T[],
  predicate: (item: T) => boolean,
): [T[], T[]] {
  const truthy: T[] = [];
  const falsy: T[] = [];

  for (const item of array) {
    if (predicate(item)) {
      truthy.push(item);
    } else {
      falsy.push(item);
    }
  }

  return [truthy, falsy];
}

/**
 * Compact an array by removing falsy values.
 *
 * @example
 * ```ts
 * compact([0, 1, false, 2, "", 3, null, undefined]) // [1, 2, 3]
 * ```
 */
export function compact<T>(array: (T | null | undefined | false | 0 | "")[]): T[] {
  return array.filter(Boolean) as T[];
}

/**
 * Count occurrences of each element in an array.
 *
 * @example
 * ```ts
 * countBy(["a", "b", "a", "c", "b", "a"]) // { a: 3, b: 2, c: 1 }
 * ```
 */
export function countBy<T extends string | number>(array: T[]): Record<T, number> {
  return array.reduce(
    (counts, item) => {
      counts[item] = (counts[item] ?? 0) + 1;
      return counts;
    },
    {} as Record<T, number>,
  );
}

/**
 * Deduplicate an array by a key function.
 *
 * @example
 * ```ts
 * const items = [{id: 1, name: "a"}, {id: 2, name: "b"}, {id: 1, name: "c"}];
 * deduplicateBy(items, item => item.id)
 * // [{id: 1, name: "a"}, {id: 2, name: "b"}]
 * ```
 */
export function deduplicateBy<T>(array: T[], keyFn: (item: T) => string | number): T[] {
  const seen = new Set<string | number>();
  return array.filter((item) => {
    const key = keyFn(item);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Sort an array of numbers in ascending or descending order.
 * Convenience function for simple numeric sorting.
 */
export function sortNumbers(array: number[], order: "asc" | "desc" = "asc"): number[] {
  return [...array].sort((a, b) => (order === "asc" ? a - b : b - a));
}
