/**
 * Security utilities for input validation, SSRF protection, XSS prevention,
 * and malicious content detection.
 *
 * Centralizes security checks to ensure consistent protection across the codebase.
 */

import path from "node:path";
import { URL } from "node:url";
import { logger } from "./logger.js";
import { isNonEmptyString, isObject } from "./helpers/validation-helpers.js";

// ─────────────────────────────────────────────────────
// §1  Path Traversal Prevention
// ─────────────────────────────────────────────────────

/** Characters that are dangerous in file paths */
const DANGEROUS_PATH_CHARS = /[\0\x00-\x1f]/g;

/**
 * Validate a relative path is safe to resolve.
 *
 * Prevents:
 * - Absolute path injection (/etc/passwd, C:\Windows\System32)
 * - Directory traversal (../../../etc/passwd)
 * - Null byte injection
 * - Backslash traversal on POSIX (..\\..\\etc\\passwd)
 *
 * @returns true if the path is safe to use in path.resolve(base, p)
 */
export function isSafeRelativePath(p: string): boolean {
  if (typeof p !== "string" || p.length === 0) return false;
  if (p.length > 4096) return false; // sanity limit

  // Reject null bytes / control characters
  if (DANGEROUS_PATH_CHARS.test(p)) return false;

  // Reject absolute paths
  if (path.isAbsolute(p)) return false;

  // Normalize to forward slashes and resolve
  const normalized = path.posix.normalize(p.replace(/\\/g, "/"));

  // After normalization, check for traversal segments
  const segments = normalized.split("/");
  for (const seg of segments) {
    if (seg === ".." || seg === "") continue;
    // Reject segments with control characters or special OS names
    if (DANGEROUS_PATH_CHARS.test(seg)) return false;
  }

  // Must not start with traversal
  if (segments.includes("..")) return false;

  return true;
}

/**
 * Resolve a base path and relative path safely.
 * Throws if the resulting path escapes the base directory.
 */
export function safePathResolve(base: string, relative: string): string {
  if (!isSafeRelativePath(relative)) {
    throw new SecurityError(`Path traversal or unsafe path rejected: ${relative}`);
  }
  const resolved = path.resolve(base, relative);
  const normalizedBase = path.resolve(base);

  // Ensure the resolved path is within the base directory
  if (!resolved.startsWith(normalizedBase + path.sep) && resolved !== normalizedBase) {
    throw new SecurityError(
      `Path escapes base directory: ${relative} resolves outside ${normalizedBase}`,
    );
  }
  return resolved;
}

// ─────────────────────────────────────────────────────
// §2  Lockfile Structure Integrity Validation
// ─────────────────────────────────────────────────────

/** Maximum allowed lockfile size (100 MB) to prevent DoS */
const MAX_LOCKFILE_SIZE_BYTES = 100 * 1024 * 1024;

/** Maximum depth of nested objects in lockfile */
const MAX_NESTING_DEPTH = 10;

/**
 * Validate the structural integrity of a parsed lockfile object.
 *
 * Checks:
 * - Is a non-null object
 * - Has reasonable property counts (not bloated)
 * - Package keys don't contain control characters
 * - No prototype pollution indicators (__proto__, constructor)
 * - Package entries have expected shape
 * - Nesting depth is bounded
 *
 * Returns a validation result with any warnings found.
 */
export interface LockfileValidationResult {
  valid: boolean;
  warnings: string[];
  packageCount: number;
}

const LOCKFILE_WARN_KEYS = new Set([
  "constructor",
  "prototype",
]);

/** Regex to match any key segment containing __proto__ (e.g., "node_modules/__proto__/evil") */
const PROTO_POLUTION_KEY_RE = /(^|[\/\\])__proto__([\/\\]|$|@)/;

export function validateLockfileStructure(
  lockfile: unknown,
): LockfileValidationResult {
  const warnings: string[] = [];

  if (lockfile === null || lockfile === undefined || typeof lockfile !== "object") {
    return { valid: false, warnings: ["Lockfile is not an object"], packageCount: 0 };
  }

  if (Array.isArray(lockfile)) {
    return { valid: false, warnings: ["Lockfile is an array, expected an object"], packageCount: 0 };
  }

  const obj = lockfile as Record<string, unknown>;

  // Check for prototype pollution via Object.setPrototypeOf or Object.assign
  // Note: __proto__ as a literal key in object literal { __proto__: ... } is a JS
  // language feature, not an actual property — Object.keys() won't list it.
  // Real attacks use Object.assign(obj, userInput) or JSON.parse (reviver).
  // We check for dangerous keys that ARE enumerable.
  for (const key of Object.keys(obj)) {
    if (LOCKFILE_WARN_KEYS.has(key)) {
      warnings.push(`Suspicious top-level key "${key}" detected — potential prototype pollution`);
    }
  }

  // Validate packages section
  const packages = obj.packages;
  let packageCount = 0;

  if (packages !== undefined && packages !== null) {
    if (typeof packages !== "object" || Array.isArray(packages)) {
      warnings.push("lockfile.packages is not a plain object");
    } else {
      const pkgRecord = packages as Record<string, unknown>;
      const keys = Object.keys(pkgRecord);
      packageCount = keys.length;

      // Check for unreasonable package count
      if (packageCount > 500_000) {
        warnings.push(`Unusually large lockfile: ${packageCount} packages — possible DoS attempt`);
      }

      // Validate individual keys for control characters
      for (let i = 0; i < Math.min(keys.length, 1000); i++) {
        const k = keys[i]!;
        if (DANGEROUS_PATH_CHARS.test(k)) {
          warnings.push(`Package key contains control characters: "${k.slice(0, 50)}"`);
          break; // one warning is enough
        }
        // Check for prototype pollution in package keys (e.g., "node_modules/__proto__/evil@1.0.0")
        if (PROTO_POLUTION_KEY_RE.test(k) || k.includes("constructor.prototype")) {
          warnings.push(`Prototype pollution indicator in package key: "${k.slice(0, 50)}"`);
          break;
        }
      }

      // Sample-validate a few package entries
      const sampleSize = Math.min(10, keys.length);
      for (let i = 0; i < sampleSize; i++) {
        const k = keys[i]!;
        const entry = pkgRecord[k];
        if (entry !== null && entry !== undefined) {
          if (typeof entry !== "object" || Array.isArray(entry)) {
            warnings.push(`Package entry "${k.slice(0, 30)}" is not an object`);
          }
        }
      }
    }
  }

  // Validate importers section
  const importers = obj.importers;
  if (importers !== undefined && importers !== null) {
    if (typeof importers !== "object" || Array.isArray(importers)) {
      warnings.push("lockfile.importers is not a plain object");
    } else {
      const impRecord = importers as Record<string, unknown>;
      for (const k of Object.keys(impRecord)) {
        if (DANGEROUS_PATH_CHARS.test(k)) {
          warnings.push(`Importer key contains control characters: "${k.slice(0, 50)}"`);
          break;
        }
      }
    }
  }

  // Validate lockfileVersion exists and is reasonable
  const lockfileVersion = obj.lockfileVersion;
  if (lockfileVersion !== undefined) {
    const v = typeof lockfileVersion === "number" ? lockfileVersion : parseFloat(String(lockfileVersion));
    if (Number.isNaN(v) || v < 0 || v > 100) {
      warnings.push(`Unusual lockfileVersion: ${lockfileVersion}`);
    }
  }

  // Check nesting depth of the packages section
  if (isObject(packages)) {
    const depth = measureNestingDepth(packages, 0);
    if (depth > MAX_NESTING_DEPTH) {
      warnings.push(`Excessive nesting depth in packages: ${depth} (max ${MAX_NESTING_DEPTH})`);
    }
  }

  return {
    valid: warnings.filter(w => w.includes("not an object") || w.includes("array")).length === 0,
    warnings,
    packageCount,
  };
}

/** Recursively measure object nesting depth */
function measureNestingDepth(obj: Record<string, unknown>, current: number): number {
  if (current > MAX_NESTING_DEPTH + 5) return current; // bail early
  let maxDepth = current;
  const keys = Object.keys(obj);
  for (let i = 0; i < Math.min(keys.length, 50); i++) {
    const val = obj[keys[i]!];
    if (val !== null && typeof val === "object" && !Array.isArray(val)) {
      const d = measureNestingDepth(val as Record<string, unknown>, current + 1);
      if (d > maxDepth) maxDepth = d;
    }
  }
  return maxDepth;
}

// ─────────────────────────────────────────────────────
// §3  SSRF Protection
// ─────────────────────────────────────────────────────

/** Private IPv4 ranges (RFC 1918, loopback, link-local, etc.) */
const PRIVATE_IP_RANGES = [
  /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,                          // 10.0.0.0/8
  /^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/,               // 172.16.0.0/12
  /^192\.168\.\d{1,3}\.\d{1,3}$/,                               // 192.168.0.0/16
  /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,                          // 127.0.0.0/8 (loopback)
  /^169\.254\.\d{1,3}\.\d{1,3}$/,                               // 169.254.0.0/16 (link-local)
  /^0\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,                            // 0.0.0.0/8
  /^192\.0\.0\.\d{1,3}$/,                                       // 192.0.0.0/24
  /^192\.0\.2\.\d{1,3}$/,                                       // 192.0.2.0/24 (documentation)
  /^198\.51\.100\.\d{1,3}$/,                                     // 198.51.100.0/24 (documentation)
  /^203\.0\.113\.\d{1,3}$/,                                     // 203.0.113.0/24 (documentation)
  /^224\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,                           // 224.0.0.0/8 (multicast)
];

/** Hostnames that should be blocked */
const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",          // GCP metadata
  "169.254.169.254",                   // AWS/GCP/Azure metadata
  "instance-data.google.internal",     // GCP metadata
  "169.254.169.254.xip.io",           // AWS metadata via xip
]);

/** Allowed URL protocols */
const ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);

/**
 * Validate a URL is safe to fetch (SSRF protection).
 *
 * Blocks:
 * - Non-HTTP(S) protocols (file://, ftp://, gopher://, etc.)
 * - Private/internal IP addresses (10.x, 192.168.x, 127.x, etc.)
 * - Cloud metadata endpoints (169.254.169.254)
 * - localhost and internal hostnames
 * - IPv6 loopback and link-local
 */
export function isSafeUrl(urlString: string): { safe: boolean; reason?: string } {
  let parsed: URL;
  try {
    parsed = new URL(urlString);
  } catch {
    return { safe: false, reason: "Invalid URL format" };
  }

  // Protocol check
  if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
    return { safe: false, reason: `Protocol "${parsed.protocol}" is not allowed (only http/https)` };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Check blocked hostnames
  if (BLOCKED_HOSTNAMES.has(hostname)) {
    return { safe: false, reason: `Hostname "${hostname}" is blocked` };
  }

  // Localhost variants
  if (hostname === "localhost" || hostname === "[::1]" || hostname === "0.0.0.0") {
    return { safe: false, reason: "Localhost is not allowed" };
  }

  // IPv4 address check
  const ipv4Match = hostname.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const parts = ipv4Match.map(Number);
    const a = parts[0] ?? 0;
    const b = parts[1] ?? 0;
    const c = parts[2] ?? 0;
    const d = parts[3] ?? 0;
    if (a > 255 || b > 255 || c > 255 || d > 255) {
      return { safe: false, reason: "Invalid IPv4 address" };
    }
    for (const range of PRIVATE_IP_RANGES) {
      if (range.test(hostname)) {
        return { safe: false, reason: `Private/reserved IP address: ${hostname}` };
      }
    }
  }

  // IPv6 check for loopback and link-local
  if (hostname.startsWith("[") || hostname.includes(":")) {
    const cleaned = hostname.replace(/[\[\]]/g, "");
    if (cleaned === "::1" || cleaned === "::" || cleaned.startsWith("fe80:") || cleaned.startsWith("fc") || cleaned.startsWith("fd")) {
      return { safe: false, reason: `IPv6 private/loopback address: ${cleaned}` };
    }
  }

  // Blocked patterns in hostname
  if (hostname.includes(".internal") || hostname.includes(".local")) {
    return { safe: false, reason: `Internal/local hostname blocked: ${hostname}` };
  }

  return { safe: true };
}

// ─────────────────────────────────────────────────────
// §4  XSS Prevention / Output Sanitization
// ─────────────────────────────────────────────────────

/** HTML special characters map */
const HTML_ESCAPE_MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

/**
 * Escape a string for safe inclusion in HTML output.
 * Prevents XSS by escaping all HTML-significant characters.
 */
export function escapeHtml(str: string): string {
  return str.replace(/[&<>"']/g, (c) => HTML_ESCAPE_MAP[c] ?? c);
}

/**
 * Sanitize a string for safe use in terminal/console output.
 * Strips ANSI escape codes and control characters.
 */
const ANSI_ESCAPE_RE = /\x1B\[[0-9;]*[a-zA-Z]/g;
const CONTROL_CHAR_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;

export function sanitizeTerminalOutput(str: string): string {
  return str
    .replace(ANSI_ESCAPE_RE, "")
    .replace(CONTROL_CHAR_RE, "")
    .trim();
}

/**
 * Sanitize a string for safe inclusion in log messages and error output.
 * Prevents log injection by stripping control characters and newlines.
 */
const LOG_INJECTION_CHARS = /[\r\n\x00-\x08\x0B\x0C\x0E-\x1F]/g;

export function sanitizeLogMessage(str: string): string {
  return str.replace(LOG_INJECTION_CHARS, "").trim();
}

// ─────────────────────────────────────────────────────
// §5  Malicious Content Detection
// ─────────────────────────────────────────────────────

/** Patterns that indicate potential prototype pollution */
const PROTOTYPE_POLLUTION_PATTERNS = [
  /__proto__/,
  /constructor\.prototype/,
  /\bprototype\s*=/,
  /Object\.assign\s*\(\s*\{/,
];

/** Patterns that indicate command injection attempts */
const COMMAND_INJECTION_PATTERNS = [
  /[;&|`$(){}]/,                    // Shell metacharacters
  /\$\{.*\}/,                       // Template literals
  /<script/i,                       // Script injection
  /javascript:/i,                    // JavaScript protocol
  /data:.*base64/i,                 // Data URI with base64
  /\\x[0-9a-f]{2}/i,              // Hex escapes
  /\\u[0-9a-f]{4}/i,              // Unicode escapes
];

/**
 * Check a string for potentially malicious patterns.
 * Returns an array of threat descriptions, or empty if clean.
 */
export function detectMaliciousContent(
  content: string,
  context: "package-name" | "url" | "config-value" | "lockfile-key" = "config-value",
): string[] {
  const threats: string[] = [];

  // Prototype pollution
  for (const pattern of PROTOTYPE_POLLUTION_PATTERNS) {
    if (pattern.test(content)) {
      threats.push(`Prototype pollution pattern: ${pattern.source}`);
      break;
    }
  }

  // Command injection (relaxed for URLs and package names)
  if (context === "config-value" || context === "lockfile-key") {
    for (const pattern of COMMAND_INJECTION_PATTERNS) {
      if (pattern.test(content)) {
        threats.push(`Suspicious pattern: ${pattern.source}`);
        break;
      }
    }
  }

  // Null byte injection
  if (content.includes("\0") || content.includes("%00")) {
    threats.push("Null byte injection detected");
  }

  // Excessively long strings (potential buffer overflow or DoS)
  if (content.length > 10_000) {
    threats.push(`String exceeds safe length: ${content.length} chars`);
  }

  return threats;
}

/**
 * Validate a package name for security.
 * Returns true if the name is safe to use in file paths and network requests.
 */
export function isSecurePackageName(name: string): boolean {
  if (!isNonEmptyString(name)) return false;
  if (name.length > 214) return false; // npm max length

  // No control characters
  if (DANGEROUS_PATH_CHARS.test(name)) return false;

  // No traversal sequences
  if (name.includes("..") || name.includes("../") || name.includes("..\\")) return false;

  // No shell metacharacters
  if (/[;&|`$(){}[\]!#~<>]/.test(name)) return false;

  // Scoped package validation
  if (name.startsWith("@")) {
    const parts = name.split("/");
    if (parts.length !== 2) return false;
    if (!parts[0] || parts[0].length < 2) return false; // @ + at least one char
    if (!parts[1]) return false;
  }

  // Must be lowercase (npm convention, but allow mixed for compat)
  // Only alphanumeric, hyphens, underscores, dots, and @ /
  if (/[^a-zA-Z0-9._\-/@]/.test(name.replace(/^@[^/]+\//, ""))) return false;

  return true;
}

// ─────────────────────────────────────────────────────
// §6  Security Error Class
// ─────────────────────────────────────────────────────

/**
 * Custom error class for security violations.
 * Distinguishes security errors from operational errors.
 */
export class SecurityError extends Error {
  readonly securityType: string;

  constructor(message: string, securityType = "input-validation") {
    super(message);
    this.name = "SecurityError";
    this.securityType = securityType;
  }
}

// ─────────────────────────────────────────────────────
// §7  Comprehensive Input Validator
// ─────────────────────────────────────────────────────

/**
 * Validate and sanitize a config value (string).
 * Returns the sanitized string or null if the input is unsafe.
 */
export function validateConfigString(
  value: unknown,
  fieldName: string,
  options: { maxLength?: number; pattern?: RegExp; allowEmpty?: boolean } = {},
): string | null {
  const { maxLength = 1000, pattern, allowEmpty = false } = options;

  if (value === null || value === undefined) return null;
  if (typeof value !== "string") return null;

  const trimmed = value.trim();
  if (!allowEmpty && trimmed.length === 0) return null;

  // Length check
  if (trimmed.length > maxLength) {
    logger.warn(
      `Config field "${fieldName}" exceeds max length (${trimmed.length} > ${maxLength}), truncating`,
    );
    return trimmed.slice(0, maxLength);
  }

  // Pattern check
  if (pattern && !pattern.test(trimmed)) {
    logger.warn(`Config field "${fieldName}" does not match required pattern`);
    return null;
  }

  // Malicious content detection
  const threats = detectMaliciousContent(trimmed, "config-value");
  if (threats.length > 0) {
    logger.warn(
      `Config field "${fieldName}" flagged for security: ${threats.join("; ")}`,
    );
    return null;
  }

  return trimmed;
}

/**
 * Validate a URL from config.
 * Returns the URL string if safe, null otherwise.
 */
export function validateConfigUrl(
  value: unknown,
  fieldName: string,
): string | null {
  const str = validateConfigString(value, fieldName, { maxLength: 2048 });
  if (!str) return null;

  const urlCheck = isSafeUrl(str);
  if (!urlCheck.safe) {
    logger.warn(`Config URL "${fieldName}" rejected: ${urlCheck.reason}`);
    return null;
  }

  return str;
}
