/**
 * @module config
 * Configuration loading and validation for pnpm-audit-hook.
 *
 * This module handles loading YAML configuration files, applying environment
 * variable overrides, validating values, and providing sensible defaults.
 *
 * @example
 * ```typescript
 * import { loadConfig } from 'pnpm-audit-hook/config';
 *
 * const config = await loadConfig({
 *   cwd: process.cwd(),
 *   env: process.env,
 * });
 *
 * console.log(config.policy.block);  // ['critical', 'high']
 * ```
 */

import fs from "node:fs/promises";
import path from "node:path";
import semver from "semver";
import YAML from "yaml";
import type { AllowlistEntry, AuditConfig, Severity, StaticBaselineConfig } from "./types";
import { errorMessage, isNodeError } from "./utils/error";
import { logger } from "./utils/logger";
import { getEnvironmentVariables } from "./utils/env-manager";
import { isNonEmptyString, isObject, isArray, isDefined } from "./utils/helpers/validation-helpers";
import { isSafeRelativePath as isSafePath, detectMaliciousContent } from "./utils/security";

/** Maximum allowed timeout in milliseconds (5 minutes) */
const MAX_TIMEOUT_MS = 300000;
/** Maximum allowed cache TTL in seconds (24 hours) */
const MAX_CACHE_TTL_SECONDS = 86400;
const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "unknown"]);
const VALID_SEVERITIES_ARRAY = [...VALID_SEVERITIES];

/** Documentation link shown in config error messages */
const DOCS_URL = "https://github.com/asx8678/pnpm-audit-hook#configuration";

/** Known top-level config keys — used to warn on typos */
const KNOWN_TOP_LEVEL_KEYS = new Set([
  "policy", "sources", "performance", "cache",
  "failOnNoSources", "failOnSourceError", "offline", "staticBaseline",
]);

/** Compute Levenshtein distance between two strings (for typo suggestions) */
function levenshtein(a: string, b: string): number {
  const la = a.length;
  const lb = b.length;
  const d: number[][] = Array.from({ length: la + 1 }, () => Array(lb + 1).fill(Infinity));
  for (let i = 0; i <= la; i++) d[i]![0] = i;
  for (let j = 0; j <= lb; j++) d[0]![j] = j;
  for (let i = 1; i <= la; i++) {
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i]![j] = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
    }
  }
  return d[la]![lb]!;
}

/**
 * Suggest similar values from a valid set.
 * Returns up to `limit` suggestions sorted by distance, only including
 * values within `maxDist` edit distance of the input.
 */
export function suggestSimilar(
  value: string,
  validValues: readonly string[],
  { limit = 3, maxDist = 3 } = {},
): string[] {
  return validValues
    .map((v) => ({ v, dist: levenshtein(value.toLowerCase(), v.toLowerCase()) }))
    .filter(({ dist }) => dist <= maxDist && dist > 0)
    .sort((a, b) => a.dist - b.dist)
    .slice(0, limit)
    .map(({ v }) => v);
}

/** Get a non-empty string property from an object, or null */
function getString(obj: object, key: string): string | null {
  const value = (obj as Record<string, unknown>)[key];
  return isNonEmptyString(value) ? value : null;
}

/** Validate an allowlist entry from user config, logging warnings for invalid entries */
function validateAllowlistEntry(e: unknown): AllowlistEntry | null {
  if (!e || !isObject(e)) {
    logger.warn(`Allowlist entry filtered: not an object`);
    return null;
}

  const obj = e as Record<string, unknown>;

  // Must have either id or package as a non-empty string
  const id = getString(e, "id");
  const pkg = getString(e, "package");
  if (!id && !pkg) {
    logger.warn(`Allowlist entry filtered: missing required 'id' or 'package' field`);
    return null;
  }

  // Optional fields must be strings if present
  if (obj.version !== undefined && !isNonEmptyString(obj.version) && obj.version !== "") {
    logger.warn(`Allowlist entry filtered: 'version' must be a string (got ${typeof obj.version})`);
    return null;
  }
  if (obj.reason !== undefined && !isNonEmptyString(obj.reason) && obj.reason !== "") {
    logger.warn(`Allowlist entry filtered: 'reason' must be a string (got ${typeof obj.reason})`);
    return null;
  }

  // expires must be a valid date string if present
  if (obj.expires !== undefined) {
    if (typeof obj.expires !== "string") {
      logger.warn(`Allowlist entry filtered: 'expires' must be a string (got ${typeof obj.expires})`);
      return null;
    }
    if (isNaN(Date.parse(obj.expires))) {
      logger.warn(`Allowlist entry filtered: 'expires' is not a valid date ("${obj.expires}")`);
      return null;
    }
  }

  // Pre-validate version range if provided
  if (isNonEmptyString(obj.version)) {
    if (!semver.validRange(obj.version)) {
      logger.warn(`Allowlist entry: invalid semver range "${obj.version}" — will never match (fail-closed)`);
    }
  }

  // Build the validated entry explicitly to avoid type assertions
  const version = getString(e, "version");
  const reason = getString(e, "reason");
  const expires = getString(e, "expires");
  const directOnly = obj.directOnly === true ? true : undefined;

  // Construct base entry with validated required fields
  const baseEntry: { version?: string; reason?: string; expires?: string; directOnly?: boolean } = {};
  if (version) baseEntry.version = version;
  if (reason) baseEntry.reason = reason;
  if (expires) baseEntry.expires = expires;
  if (directOnly) baseEntry.directOnly = directOnly;

  if (id) {
    return {
      id,
      ...(pkg ? { package: pkg } : {}),
      ...baseEntry,
    };
  }

  // pkg must be non-null at this point
  return {
    package: pkg!,
    ...baseEntry,
  };
}

/**
 * Read the cutoff date from the bundled static DB index.json.
 * Returns null if the index cannot be read.
 */
function readStaticDbCutoffDate(): string | null {
  try {
    const fs = require("node:fs");
    const indexPath = path.resolve(__dirname, "static-db", "data", "index.json");
    const raw = fs.readFileSync(indexPath, "utf-8");
    const parsed = JSON.parse(raw);
    // Support both optimized ('cut') and standard ('cutoffDate') formats
    const cutoff = parsed.cutoffDate ?? parsed.cut;
    return typeof cutoff === "string" ? cutoff : null;
  } catch {
    return null;
  }
}

/** Default cutoff date for static baseline — derived from bundled DB at load time */
export const DEFAULT_CUTOFF_DATE: string = readStaticDbCutoffDate() ?? "2025-12-31";

const DEFAULT_STATIC_BASELINE: StaticBaselineConfig = {
  enabled: true,
  cutoffDate: DEFAULT_CUTOFF_DATE,
};

export const DEFAULT_CONFIG: AuditConfig = {
  policy: {
    block: ["critical", "high"],
    warn: ["medium", "low", "unknown"],
    allowlist: [],
  },
  sources: {
    github: { enabled: true },
    nvd: { enabled: true },
    osv: { enabled: true },
  },
  performance: { timeoutMs: 15000 },
  cache: { ttlSeconds: 3600 },
  failOnNoSources: true,
  failOnSourceError: true,
  offline: false,
  staticBaseline: DEFAULT_STATIC_BASELINE,
};

/**
 * Options for the {@link loadConfig} function.
 */
export interface LoadConfigOptions {
  /** Working directory for config file resolution */
  cwd: string;
  /** Environment variables for overrides (typically process.env) */
  env: Record<string, string | undefined>;
}

/**
 * Validate a path to prevent path traversal attacks.
 * Delegates to the centralized security module.
 */
function isValidRelativePath(p: string): boolean {
  return isSafePath(p);
}

/**
 * Loads and validates the audit configuration.
 *
 * Reads configuration from `.pnpm-audit.yaml` (or custom path via
 * `PNPM_AUDIT_CONFIG_PATH`), applies environment variable overrides,
 * validates all values, and returns fully-resolved config.
 *
 * @param opts - Options containing cwd and env
 * @returns Fully-resolved configuration with all defaults applied
 *
 * @example
 * ```typescript
 * import { loadConfig } from 'pnpm-audit-hook/config';
 *
 * const config = await loadConfig({
 *   cwd: '/path/to/project',
 *   env: process.env,
 * });
 *
 * if (config.policy.block.includes('critical')) {
 *   console.log('Critical vulnerabilities will block installation');
 * }
 * ```
 *
 * @throws {Error} If YAML syntax is invalid
 * @throws {Error} If config contains security violations
 */
export async function loadConfig(opts: LoadConfigOptions): Promise<AuditConfig> {
  let configPath: string;
  if (opts.env.PNPM_AUDIT_CONFIG_PATH) {
    if (!isValidRelativePath(opts.env.PNPM_AUDIT_CONFIG_PATH)) {
      throw new Error(
        `Invalid PNPM_AUDIT_CONFIG_PATH: path traversal or absolute paths not allowed`
      );
    }
    // Additional malicious content check on config path
    const threats = detectMaliciousContent(opts.env.PNPM_AUDIT_CONFIG_PATH, "config-value");
    if (threats.length > 0) {
      throw new Error(
        `Invalid PNPM_AUDIT_CONFIG_PATH: security check failed — ${threats.join(", ")}`
      );
    }
    configPath = path.resolve(opts.cwd, opts.env.PNPM_AUDIT_CONFIG_PATH);
  } else {
    configPath = path.resolve(opts.cwd, ".pnpm-audit.yaml");
  }

  let raw: Record<string, unknown> = {};
  try {
    raw = YAML.parse(await fs.readFile(configPath, "utf-8")) ?? {};
  } catch (e: unknown) {
    if (isNodeError(e) && e.code === "ENOENT") {
      logger.debug(`No config file found at ${configPath}, using defaults`);
    } else {
      // Preserve YAML parse error details (line/column) for user debugging
      const detail = e instanceof YAML.YAMLParseError
        ? `${e.message} (line ${e.linePos?.[0]?.line ?? "?"})`
        : errorMessage(e);
      throw new Error(`Failed to read config at ${configPath}: ${detail}`);
    }
  }

  // Warn on unrecognized top-level keys (catches typos like "polciy")
  for (const key of Object.keys(raw)) {
    if (!KNOWN_TOP_LEVEL_KEYS.has(key)) {
      const knownArray = [...KNOWN_TOP_LEVEL_KEYS];
      const suggestions = suggestSimilar(key, knownArray);
      const hint = suggestions.length > 0
        ? `did you mean "${suggestions[0]}"?`
        : `valid keys: ${knownArray.join(", ")}`;
      logger.warn(
        `Unrecognized config key "${key}" — ${hint}` +
        `\n  See ${DOCS_URL} for valid configuration options.`
      );
    }
  }

  const validSeverities = VALID_SEVERITIES;
  const asSeverities = (v: unknown, fallback: Severity[]): Severity[] => {
    if (!Array.isArray(v)) return fallback;
    const normalized = v.map((s) => String(s).toLowerCase());
    const invalid = normalized.filter((s) => !validSeverities.has(s));
    if (invalid.length > 0) {
      const allSuggestions = invalid
        .map((v) => ({ v, suggestions: suggestSimilar(v, VALID_SEVERITIES_ARRAY) }))
        .map(({ v, suggestions }) =>
          suggestions.length > 0 ? `"${v}" -> did you mean "${suggestions[0]}"?` : `"${v}"`
        );
      logger.warn(
        `Invalid severity values ignored: ${invalid.join(", ")}` +
        `\n  Suggestions: ${allSuggestions.join(", ")}` +
        `\n  Valid severities: ${VALID_SEVERITIES_ARRAY.join(", ")}`
      );
    }
    return normalized.filter((s): s is Severity => validSeverities.has(s));
  };

  const asRecord = (v: unknown): Record<string, unknown> | undefined =>
    v && typeof v === "object" && !Array.isArray(v) ? v as Record<string, unknown> : undefined;
  const policy = asRecord(raw.policy);
  const sources = asRecord(raw.sources);
  const cache = asRecord(raw.cache);
  const performance = asRecord(raw.performance);
  const staticBaselineRaw = asRecord(raw.staticBaseline);

  const parseStaticBaseline = (v: Record<string, unknown> | undefined): StaticBaselineConfig => {
    if (!v) return DEFAULT_STATIC_BASELINE;

    const enabled = v.enabled !== false; // default true

    // Validate cutoffDate: must be valid ISO date and not in the future
    let cutoffDate = DEFAULT_CUTOFF_DATE;
    if (typeof v.cutoffDate === "string") {
      const parsed = Date.parse(v.cutoffDate);
      const now = Date.now();
      if (isNaN(parsed)) {
        logger.warn(
          `Invalid staticBaseline.cutoffDate format: "${v.cutoffDate}"` +
          `\n  Expected an ISO 8601 date string (e.g. "2025-01-15" or "2025-01-15T00:00:00Z")` +
          `\n  Falling back to default cutoff date: ${DEFAULT_CUTOFF_DATE}`
        );
      } else if (parsed > now) {
        const formattedNow = new Date(now).toISOString().slice(0, 10);
        logger.warn(
          `staticBaseline.cutoffDate "${v.cutoffDate}" is in the future (today is ${formattedNow})` +
          `\n  The cutoff date must be in the past to match against known vulnerabilities` +
          `\n  Falling back to default cutoff date: ${DEFAULT_CUTOFF_DATE}`
        );
      } else {
        cutoffDate = v.cutoffDate;
      }
    }

    let dataPath: string | undefined = undefined;
    if (isNonEmptyString(v.dataPath)) {
      if (!isValidRelativePath(v.dataPath)) {
        logger.warn(
          `Invalid staticBaseline.dataPath: path traversal or absolute paths not allowed, ignoring`
        );
      } else {
        dataPath = v.dataPath;
      }
    }

    return { enabled, cutoffDate, dataPath };
  };

  const asAllowlist = (v: unknown): AllowlistEntry[] => {
    if (!Array.isArray(v)) return [];
    const validEntries: AllowlistEntry[] = [];
    for (const item of v) {
      const entry = validateAllowlistEntry(item);
      if (entry) validEntries.push(entry);
    }
    return validEntries;
  };

  const isSourceEnabled = (v: unknown): boolean => {
    if (v === false) return false;
    if (typeof v === "object" && v !== null && "enabled" in v) {
      return (v as { enabled?: boolean }).enabled !== false;
    }
    return true; // default enabled
  };

  const blockSeverities = asSeverities(policy?.block, DEFAULT_CONFIG.policy.block);
  const warnSeverities = asSeverities(policy?.warn, DEFAULT_CONFIG.policy.warn);
  // Env var overrides for fail-on flags
  const failOnNoSources = opts.env.PNPM_AUDIT_FAIL_ON_NO_SOURCES !== undefined
    ? opts.env.PNPM_AUDIT_FAIL_ON_NO_SOURCES !== "false"
    : raw.failOnNoSources !== false;

  const failOnSourceError = opts.env.PNPM_AUDIT_FAIL_ON_SOURCE_ERROR !== undefined
    ? opts.env.PNPM_AUDIT_FAIL_ON_SOURCE_ERROR !== "false"
    : raw.failOnSourceError !== false;

  // Offline mode: env var or config
  const offline = opts.env.PNPM_AUDIT_OFFLINE === "true" || raw.offline === true;

  // SBOM configuration: env var or config
  const sbomRaw = asRecord(raw.sbom);
  const sbomEnabled = opts.env.PNPM_AUDIT_SBOM === "true" || sbomRaw?.enabled === true;
  const sbomFormat = (opts.env.PNPM_AUDIT_SBOM_FORMAT as string) || (sbomRaw?.format as string) || "cyclonedx";
  const sbomOutputPath = opts.env.PNPM_AUDIT_SBOM_OUTPUT || sbomRaw?.outputPath as string | undefined;

  // Validate SBOM format
  const validSbomFormats = new Set(["cyclonedx", "spdx"]);
  const finalSbomFormat = validSbomFormats.has(sbomFormat) ? sbomFormat as "cyclonedx" | "spdx" : "cyclonedx";
  if (!validSbomFormats.has(sbomFormat)) {
    logger.warn(`Invalid SBOM format: "${sbomFormat}", using "cyclonedx" (valid: cyclonedx, spdx)`);
  }

  // Env var override for block severities (comma-separated, e.g. "critical,high")
  const blockSeverityEnv = opts.env.PNPM_AUDIT_BLOCK_SEVERITY;
  const finalBlockSeverities = blockSeverityEnv
    ? asSeverities(blockSeverityEnv.split(",").map(s => s.trim()), DEFAULT_CONFIG.policy.block)
    : blockSeverities;
  const overlap = finalBlockSeverities.filter(s => warnSeverities.includes(s));
  if (overlap.length > 0) {
    logger.warn(`Severity overlap in policy: ${overlap.join(", ")} appears in both block and warn (block takes precedence)`);
  }

  const transitiveSeverityOverride = policy?.transitiveSeverityOverride === 'downgrade-by-one'
    ? 'downgrade-by-one' as const
    : undefined;

  return {
    ...DEFAULT_CONFIG,
    policy: {
      block: finalBlockSeverities,
      warn: warnSeverities,
      allowlist: asAllowlist(policy?.allowlist),
      transitiveSeverityOverride,
    },
    sources: {
      github: { enabled: isSourceEnabled(sources?.github) },
      nvd: { enabled: isSourceEnabled(sources?.nvd) },
      osv: { enabled: isSourceEnabled(sources?.osv) },
    },
    performance: {
      timeoutMs:
        typeof performance?.timeoutMs === "number" &&
        performance.timeoutMs > 0 &&
        performance.timeoutMs <= MAX_TIMEOUT_MS
          ? performance.timeoutMs
          : DEFAULT_CONFIG.performance.timeoutMs,
    },
    cache: {
      ttlSeconds:
        typeof cache?.ttlSeconds === "number" &&
        cache.ttlSeconds > 0 &&
        cache.ttlSeconds <= MAX_CACHE_TTL_SECONDS
          ? cache.ttlSeconds
          : DEFAULT_CONFIG.cache.ttlSeconds,
    },
    failOnNoSources,
    failOnSourceError,
    offline,
    staticBaseline: parseStaticBaseline(staticBaselineRaw),
    sbom: sbomEnabled ? {
      enabled: true,
      format: finalSbomFormat,
      outputPath: sbomOutputPath,
      includeVulnerabilities: sbomRaw?.includeVulnerabilities !== false,
      projectName: sbomRaw?.projectName as string | undefined,
      projectVersion: sbomRaw?.projectVersion as string | undefined,
    } : undefined,
  };
}
