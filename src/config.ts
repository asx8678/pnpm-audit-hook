import fs from "node:fs/promises";
import path from "node:path";
import semver from "semver";
import YAML from "yaml";
import type { AllowlistEntry, AuditConfig, Severity, StaticBaselineConfig } from "./types";
import { errorMessage, isNodeError } from "./utils/error";
import { logger } from "./utils/logger";

/** Maximum allowed timeout in milliseconds (5 minutes) */
const MAX_TIMEOUT_MS = 300000;
/** Maximum allowed cache TTL in seconds (24 hours) */
const MAX_CACHE_TTL_SECONDS = 86400;
const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "unknown"]);

/** Known top-level config keys — used to warn on typos */
const KNOWN_TOP_LEVEL_KEYS = new Set([
  "policy", "sources", "performance", "cache",
  "failOnNoSources", "failOnSourceError", "offline", "staticBaseline",
]);

/** Get a non-empty string property from an object, or null */
function getString(obj: object, key: string): string | null {
  const value = (obj as Record<string, unknown>)[key];
  return typeof value === "string" && value.length > 0 ? value : null;
}

/** Validate an allowlist entry from user config, logging warnings for invalid entries */
function validateAllowlistEntry(e: unknown): AllowlistEntry | null {
  if (!e || typeof e !== "object") {
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
  if (obj.version !== undefined && typeof obj.version !== "string") {
    logger.warn(`Allowlist entry filtered: 'version' must be a string (got ${typeof obj.version})`);
    return null;
  }
  if (obj.reason !== undefined && typeof obj.reason !== "string") {
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
  if (typeof obj.version === "string" && obj.version.length > 0) {
    if (!semver.validRange(obj.version)) {
      logger.warn(`Allowlist entry: invalid semver range "${obj.version}" — will never match (fail-closed)`);
    }
  }

  // Build the validated entry explicitly to avoid type assertions
  const version = getString(e, "version");
  const reason = getString(e, "reason");
  const expires = getString(e, "expires");

  // Construct base entry with validated required fields
  const baseEntry: { version?: string; reason?: string; expires?: string } = {};
  if (version) baseEntry.version = version;
  if (reason) baseEntry.reason = reason;
  if (expires) baseEntry.expires = expires;

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
  },
  performance: { timeoutMs: 15000 },
  cache: { ttlSeconds: 3600 },
  failOnNoSources: true,
  failOnSourceError: true,
  offline: false,
  staticBaseline: DEFAULT_STATIC_BASELINE,
};

export interface LoadConfigOptions {
  cwd: string;
  env: Record<string, string | undefined>;
}

/**
 * Validate a path to prevent path traversal attacks.
 * Rejects absolute paths or any path containing ".." segments.
 */
function isValidRelativePath(p: string): boolean {
  if (path.isAbsolute(p)) return false;
  const normalized = path.posix.normalize(p.replace(/\\/g, "/"));
  const segments = normalized.split("/");
  return !segments.includes("..");
}

export async function loadConfig(opts: LoadConfigOptions): Promise<AuditConfig> {
  let configPath: string;
  if (opts.env.PNPM_AUDIT_CONFIG_PATH) {
    if (!isValidRelativePath(opts.env.PNPM_AUDIT_CONFIG_PATH)) {
      throw new Error(
        `Invalid PNPM_AUDIT_CONFIG_PATH: path traversal or absolute paths not allowed`
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
      logger.warn(`Unrecognized config key "${key}" — did you mean one of: ${[...KNOWN_TOP_LEVEL_KEYS].join(", ")}?`);
    }
  }

  const validSeverities = VALID_SEVERITIES;
  const asSeverities = (v: unknown, fallback: Severity[]): Severity[] => {
    if (!Array.isArray(v)) return fallback;
    const normalized = v.map((s) => String(s).toLowerCase());
    const invalid = normalized.filter((s) => !validSeverities.has(s));
    if (invalid.length > 0) {
      logger.warn(`Invalid severity values ignored: ${invalid.join(", ")}`);
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
        logger.warn(`Invalid staticBaseline.cutoffDate format: "${v.cutoffDate}", using default: ${DEFAULT_CUTOFF_DATE}`);
      } else if (parsed > now) {
        logger.warn(`staticBaseline.cutoffDate "${v.cutoffDate}" is in the future, using default: ${DEFAULT_CUTOFF_DATE}`);
      } else {
        cutoffDate = v.cutoffDate;
      }
    }

    let dataPath: string | undefined = undefined;
    if (typeof v.dataPath === "string" && v.dataPath.length > 0) {
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
  const overlap = blockSeverities.filter(s => warnSeverities.includes(s));
  if (overlap.length > 0) {
    logger.warn(`Severity overlap in policy: ${overlap.join(", ")} appears in both block and warn (block takes precedence)`);
  }

  // Env var overrides for fail-on flags
  const failOnNoSources = opts.env.PNPM_AUDIT_FAIL_ON_NO_SOURCES !== undefined
    ? opts.env.PNPM_AUDIT_FAIL_ON_NO_SOURCES !== "false"
    : raw.failOnNoSources !== false;

  const failOnSourceError = opts.env.PNPM_AUDIT_FAIL_ON_SOURCE_ERROR !== undefined
    ? opts.env.PNPM_AUDIT_FAIL_ON_SOURCE_ERROR !== "false"
    : raw.failOnSourceError !== false;

  // Offline mode: env var or config
  const offline = opts.env.PNPM_AUDIT_OFFLINE === "true" || raw.offline === true;

  return {
    ...DEFAULT_CONFIG,
    policy: {
      block: blockSeverities,
      warn: warnSeverities,
      allowlist: asAllowlist(policy?.allowlist),
    },
    sources: {
      github: { enabled: isSourceEnabled(sources?.github) },
      nvd: { enabled: isSourceEnabled(sources?.nvd) },
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
  };
}
