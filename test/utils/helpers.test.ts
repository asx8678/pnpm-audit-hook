import { describe, it } from "node:test";
import assert from "node:assert";

// Import from the new helpers
import {
  isString,
  isNumber,
  isBoolean,
  isObject,
  isArray,
  isNonEmptyString,
  isDefined,
  isOneOf,
} from "../../src/utils/helpers/validation-helpers";

import {
  capitalize,
  toKebabCase,
  toCamelCase,
  toSnakeCase,
  truncate,
  formatBytes,
  formatDuration,
  pluralize,
} from "../../src/utils/helpers/string-helpers";

import {
  unique,
  flatten,
  chunk,
  groupBy,
  sortBy,
  partition,
  compact,
  deduplicateBy,
} from "../../src/utils/helpers/array-helpers";

import {
  deepMerge,
  pick,
  omit,
  getNestedValue,
  setNestedValue,
  deepEqual,
  filterObject,
  mapValues,
} from "../../src/utils/helpers/object-helpers";

import {
  createError,
  wrapError,
  getErrorMessage,
  isNetworkError,
  safeAsync,
  safeAsyncWithFallback,
} from "../../src/utils/helpers/error-helpers";

import {
  isDate,
  isPromise,
  hasKey,
  assertNotNull,
  narrow,
} from "../../src/utils/helpers/type-helpers";

import {
  withTimeout,
  debounce,
  throttle,
  createLazyAsync,
} from "../../src/utils/helpers/async-helpers";

describe("Validation Helpers", () => {
  it("isString", () => {
    assert.strictEqual(isString("hello"), true);
    assert.strictEqual(isString(123), false);
    assert.strictEqual(isString(null), false);
    assert.strictEqual(isString(undefined), false);
  });

  it("isNumber", () => {
    assert.strictEqual(isNumber(123), true);
    assert.strictEqual(isNumber(3.14), true);
    assert.strictEqual(isNumber(NaN), false);
    assert.strictEqual(isNumber("123"), false);
  });

  it("isNonEmptyString", () => {
    assert.strictEqual(isNonEmptyString("hello"), true);
    assert.strictEqual(isNonEmptyString("  "), false);
    assert.strictEqual(isNonEmptyString(""), false);
    assert.strictEqual(isNonEmptyString(123), false);
  });

  it("isDefined", () => {
    assert.strictEqual(isDefined(0), true);
    assert.strictEqual(isDefined(""), true);
    assert.strictEqual(isDefined(false), true);
    assert.strictEqual(isDefined(null), false);
    assert.strictEqual(isDefined(undefined), false);
  });

  it("isOneOf", () => {
    assert.strictEqual(isOneOf("a", ["a", "b", "c"]), true);
    assert.strictEqual(isOneOf("d", ["a", "b", "c"]), false);
    assert.strictEqual(isOneOf(1, [1, 2, 3]), true);
  });
});

describe("String Helpers", () => {
  it("capitalize", () => {
    assert.strictEqual(capitalize("hello"), "Hello");
    assert.strictEqual(capitalize("HELLO"), "HELLO");
    assert.strictEqual(capitalize(""), "");
  });

  it("toKebabCase", () => {
    assert.strictEqual(toKebabCase("helloWorld"), "hello-world");
    assert.strictEqual(toKebabCase("HelloWorld"), "hello-world");
    assert.strictEqual(toKebabCase("hello_world"), "hello-world");
  });

  it("toCamelCase", () => {
    assert.strictEqual(toCamelCase("hello-world"), "helloWorld");
    assert.strictEqual(toCamelCase("Hello World"), "helloWorld");
  });

  it("toSnakeCase", () => {
    assert.strictEqual(toSnakeCase("helloWorld"), "hello_world");
    assert.strictEqual(toSnakeCase("HelloWorld"), "hello_world");
  });

  it("truncate", () => {
    assert.strictEqual(truncate("hello world", 8), "hello...");
    assert.strictEqual(truncate("hello", 10), "hello");
    assert.strictEqual(truncate("hello world", 8, "!"), "hello w!");
  });

  it("formatBytes", () => {
    assert.strictEqual(formatBytes(0), "0 B");
    assert.strictEqual(formatBytes(1024), "1.0 KB");
    assert.strictEqual(formatBytes(1048576), "1.0 MB");
  });

  it("formatDuration", () => {
    assert.strictEqual(formatDuration(500), "500ms");
    assert.strictEqual(formatDuration(1500), "1.5s");
    assert.strictEqual(formatDuration(65000), "1m 5s");
  });

  it("pluralize", () => {
    assert.strictEqual(pluralize(1, "error"), "error");
    assert.strictEqual(pluralize(2, "error"), "errors");
    assert.strictEqual(pluralize(0, "item", "items"), "items");
  });
});

describe("Array Helpers", () => {
  it("unique", () => {
    assert.deepStrictEqual(unique([1, 2, 2, 3]), [1, 2, 3]);
    assert.deepStrictEqual(unique(["a", "b", "a"]), ["a", "b"]);
  });

  it("flatten", () => {
    assert.deepStrictEqual(flatten([[1, 2], [3, 4]]), [1, 2, 3, 4]);
    assert.deepStrictEqual(flatten([[1, 2], 3, [4]]), [1, 2, 3, 4]);
  });

  it("chunk", () => {
    assert.deepStrictEqual(chunk([1, 2, 3, 4, 5], 2), [[1, 2], [3, 4], [5]]);
    assert.deepStrictEqual(chunk([1, 2, 3], 5), [[1, 2, 3]]);
  });

  it("groupBy", () => {
    const items = [{ type: "a", val: 1 }, { type: "b", val: 2 }, { type: "a", val: 3 }];
    const grouped = groupBy(items, "type");
    assert.deepStrictEqual(grouped, {
      a: [{ type: "a", val: 1 }, { type: "a", val: 3 }],
      b: [{ type: "b", val: 2 }],
    });
  });

  it("partition", () => {
    const [evens, odds] = partition([1, 2, 3, 4, 5], (n) => n % 2 === 0);
    assert.deepStrictEqual(evens, [2, 4]);
    assert.deepStrictEqual(odds, [1, 3, 5]);
  });

  it("compact", () => {
    assert.deepStrictEqual(compact([0, 1, false, 2, "", 3]), [1, 2, 3]);
  });

  it("deduplicateBy", () => {
    const items = [{ id: 1, name: "a" }, { id: 2, name: "b" }, { id: 1, name: "c" }];
    const result = deduplicateBy(items, (item) => item.id);
    assert.deepStrictEqual(result, [{ id: 1, name: "a" }, { id: 2, name: "b" }]);
  });
});

describe("Object Helpers", () => {
  it("deepMerge", () => {
    const result = deepMerge({ a: 1, b: { c: 2 } }, { b: { d: 3 }, e: 4 });
    assert.deepStrictEqual(result, { a: 1, b: { c: 2, d: 3 }, e: 4 });
  });

  it("pick", () => {
    const result = pick({ a: 1, b: 2, c: 3 }, ["a", "c"]);
    assert.deepStrictEqual(result, { a: 1, c: 3 });
  });

  it("omit", () => {
    const result = omit({ a: 1, b: 2, c: 3 }, ["b"]);
    assert.deepStrictEqual(result, { a: 1, c: 3 });
  });

  it("getNestedValue", () => {
    const obj = { a: { b: { c: 42 } } };
    assert.strictEqual(getNestedValue(obj, "a.b.c"), 42);
    assert.strictEqual(getNestedValue(obj, "a.x.y"), undefined);
  });

  it("setNestedValue", () => {
    const obj = {} as Record<string, unknown>;
    setNestedValue(obj, "a.b.c", 42);
    assert.deepStrictEqual(obj, { a: { b: { c: 42 } } });
  });

  it("deepEqual", () => {
    assert.strictEqual(deepEqual({ a: { b: 1 } }, { a: { b: 1 } }), true);
    assert.strictEqual(deepEqual({ a: 1 }, { a: 2 }), false);
    assert.strictEqual(deepEqual([1, 2], [1, 2]), true);
    assert.strictEqual(deepEqual([1, 2], [1, 3]), false);
  });

  it("filterObject", () => {
    const result = filterObject({ a: 1, b: 2, c: 3 }, (_key, value) => value > 1);
    assert.deepStrictEqual(result, { b: 2, c: 3 });
  });

  it("mapValues", () => {
    const result = mapValues({ a: 1, b: 2 }, (val) => val * 2);
    assert.deepStrictEqual(result, { a: 2, b: 4 });
  });
});

describe("Error Helpers", () => {
  it("createError", () => {
    const error = createError<{ code: string }>("Test error", { code: "TEST" });
    assert.strictEqual(error.message, "Test error");
    assert.strictEqual((error as { code: string }).code, "TEST");
  });

  it("wrapError", () => {
    const original = new Error("Original error");
    const wrapped = wrapError(original, "Wrapped", { extra: "data" });
    assert.strictEqual(wrapped.message, "Wrapped: Original error");
    assert.strictEqual((wrapped as { extra: string }).extra, "data");
  });

  it("getErrorMessage", () => {
    assert.strictEqual(getErrorMessage(new Error("test")), "test");
    assert.strictEqual(getErrorMessage("string error"), "string error");
    assert.strictEqual(getErrorMessage(null, "fallback"), "fallback");
  });

  it("isNetworkError", () => {
    assert.strictEqual(isNetworkError(new Error("network error")), true);
    assert.strictEqual(isNetworkError(new Error("timeout")), true);
    assert.strictEqual(isNetworkError(new Error("ECONNREFUSED")), true);
    assert.strictEqual(isNetworkError(new Error("other error")), false);
  });

  it("safeAsync", async () => {
    const result1 = await safeAsync(async () => 42);
    assert.strictEqual(result1, 42);

    const result2 = await safeAsync(async () => {
      throw new Error("fail");
    });
    assert.strictEqual(result2, undefined);
  });

  it("safeAsyncWithFallback", async () => {
    const result = await safeAsyncWithFallback(async () => {
      throw new Error("fail");
    }, "fallback");
    assert.strictEqual(result, "fallback");
  });
});

describe("Type Helpers", () => {
  it("isDate", () => {
    assert.strictEqual(isDate(new Date()), true);
    assert.strictEqual(isDate(new Date("invalid")), false);
    assert.strictEqual(isDate("2024-01-01"), false);
  });

  it("isPromise", () => {
    assert.strictEqual(isPromise(Promise.resolve()), true);
    assert.strictEqual(isPromise({ then: () => {} }), true);
    assert.strictEqual(isPromise({}), false);
  });

  it("hasKey", () => {
    assert.strictEqual(hasKey({ id: 1 }, "id"), true);
    assert.strictEqual(hasKey({ id: 1 }, "name"), false);
  });

  it("assertNotNull", () => {
    assertNotNull("value");
    assertNotNull(0);
    assertNotNull(false);
    assert.throws(() => assertNotNull(null));
    assert.throws(() => assertNotNull(undefined));
  });

  it("narrow", () => {
    const isString = (v: unknown): v is string => typeof v === "string";
    assert.strictEqual(narrow("hello", isString), "hello");
    assert.throws(() => narrow(123, isString, "Expected string"));
  });
});

describe("Async Helpers", () => {
  it("withTimeout", async () => {
    const result = await withTimeout(async () => 42, 1000);
    assert.strictEqual(result, 42);

    await assert.rejects(
      () => withTimeout(async () => {
        await new Promise((r) => setTimeout(r, 100));
        return 42;
      }, 10),
      /Operation timed out/,
    );
  });

  it("createLazyAsync", async () => {
    let callCount = 0;
    const lazy = createLazyAsync(async () => {
      callCount++;
      return 42;
    });

    assert.strictEqual(callCount, 0);
    const result1 = await lazy.get();
    assert.strictEqual(result1, 42);
    assert.strictEqual(callCount, 1);

    const result2 = await lazy.get();
    assert.strictEqual(result2, 42);
    assert.strictEqual(callCount, 1); // Still 1, not called again

    lazy.reset();
    await lazy.get();
    assert.strictEqual(callCount, 2); // Called again after reset
  });
});
