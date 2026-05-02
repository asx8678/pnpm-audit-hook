/**
 * Common helper utilities.
 *
 * This module provides reusable utility functions organized by domain.
 * Import from here for convenient access to all helpers:
 *
 * ```ts
 * import { isString, deepMerge, unique } from "./utils/helpers";
 * ```
 *
 * Or import specific helpers directly for better tree-shaking:
 *
 * ```ts
 * import { isString } from "./utils/helpers/validation-helpers";
 * ```
 */

// Async helpers
export {
  withTimeout,
  batchProcess,
  debounce,
  throttle,
  createLazyAsync,
} from "./async-helpers";

// Validation helpers
export {
  isString,
  isNumber,
  isBoolean,
  isObject,
  isArray,
  isNonEmptyString,
  isDefined,
  matchesPattern,
  isEmail,
  isUrl,
  isSemver,
  isPackageName,
  isOneOf,
  isPositiveNumber,
  isNonNegativeNumber,
  isInteger,
  isIsoDateString,
  isDateString,
} from "./validation-helpers";

// String helpers
export {
  capitalize,
  toKebabCase,
  toCamelCase,
  toSnakeCase,
  truncate,
  removeWhitespace,
  containsIgnoreCase,
  extractBetween,
  indent,
  pluralize,
  formatBytes,
  formatDuration,
} from "./string-helpers";

// Array helpers
export {
  unique,
  flatten,
  chunk,
  groupBy,
  sortBy,
  pick as pickArray,
  omit as omitArray,
  head,
  tail,
  sample,
  shuffle,
  partition,
  compact,
  countBy,
  deduplicateBy,
  sortNumbers,
} from "./array-helpers";

// Object helpers
export {
  deepMerge,
  pick as pickObject,
  omit as omitObject,
  keys,
  values,
  entries,
  hasProperty,
  getNestedValue,
  setNestedValue,
  flattenObject,
  deepEqual,
  filterObject,
  mapValues,
} from "./object-helpers";

// Error helpers
export {
  createError,
  wrapError,
  isErrorType,
  getErrorMessage,
  getErrorStack,
  isNetworkError,
  isValidationError,
  isNotFoundError,
  createValidationError,
  createNotFoundError,
  safeAsync,
  safeAsyncWithFallback,
} from "./error-helpers";

// Type helpers (re-exported with explicit names to avoid conflicts)
export {
  isString as isStringType,
  isNumber as isNumberType,
  isBoolean as isBooleanType,
  isObject as isObjectType,
  isArray as isArrayType,
  isNull,
  isUndefined,
  isNullOrUndefined,
  isDefined as isDefinedType,
  isFunction,
  isDate,
  isRegExp,
  isPromise,
  isError as isErrorType2,
  isBuffer,
  isEmptyString,
  isEmptyArray,
  isEmptyObject,
  isNonEmptyArray,
  isNonEmptyString as isNonEmptyStringType,
  hasKey,
  hasKeys,
  isNodeError,
  assert,
  assertNotNull,
  narrow,
} from "./type-helpers";
