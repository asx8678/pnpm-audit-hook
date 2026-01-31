import fs from "node:fs/promises";
import path from "node:path";
import YAML from "yaml";
import type { AllowlistEntry, AuditConfig, Severity, StaticBaselineConfig } from "./types";
import { errorMessage } from "./utils/error";
import { logger } from "./utils/logger";

/** Maximum allowed timeout in milliseconds (5 minutes) */
const MAX_TIMEOUT_MS = 300000;
/** Maximum allowed cache TTL in seconds (24 hours) */
const MAX_CACHE_TTL_SECONDS = 86400;

/** Type guard for NodeJS.ErrnoException */
function isNodeError(e: unknown): e is NodeJS.ErrnoException {
  return e instanceof Error && "code" in e;
}

/** Type guard for unknown object access */
function hasStringProp(obj: object, key: string): boolean {
  return key in obj && typeof (obj as Record<string, unknown>)[key] === "string";
}

/** Get optional string property from object, returns undefined if not a string */
function getOptionalString(obj: object, key: string): string | undefined {
  const value = (obj as Record<string, unknown>)[key];
  return typeof value === "string" ? value : undefined;
}

/** Validate an allowlist entry from user config, logging warnings for invalid entries */
function validateAllowlistEntry(e: unknown): AllowlistEntry | null {
  if (!e || typeof e !== "object") {
    logger.warn(`Allowlist entry filtered: not an object`);
    return null;
  }

  const obj = e as Record<string, unknown>;

  // Must have either id or package as a string
  const hasId = hasStringProp(e, "id");
  const hasPackage = hasStringProp(e, "package");
  if (!hasId && !hasPackage) {
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

  // Build the validated entry explicitly to avoid type assertions
  const version = getOptionalString(e, "version");
  const reason = getOptionalString(e, "reason");
  const expires = getOptionalString(e, "expires");

  // Construct base entry with validated required fields
  const baseEntry: { version?: string; reason?: string; expires?: string } = {};
  if (version) baseEntry.version = version;
  if (reason) baseEntry.reason = reason;
  if (expires) baseEntry.expires = expires;

  if (hasId) {
    return {
      id: obj.id as string,
      ...(hasPackage ? { package: obj.package as string } : {}),
      ...baseEntry,
    };
  }

  // hasPackage must be true at this point
  return {
    package: obj.package as string,
    ...baseEntry,
  };
}

/** Default cutoff date for static baseline */
export const DEFAULT_CUTOFF_DATE = "2025-12-31";

/**
 * Check if a published date is before the cutoff date.
 * Both dates should be ISO date strings (YYYY-MM-DD or full ISO timestamp).
 * Returns true if publishedDate is before cutoffDate.
 */
export function isBeforeCutoff(publishedDate: string, cutoffDate: string): boolean {
  const published = new Date(publishedDate);
  const cutoff = new Date(cutoffDate);

  // Invalid dates return false (fail-closed)
  if (isNaN(published.getTime()) || isNaN(cutoff.getTime())) {
    logger.debug(
      `Invalid date in isBeforeCutoff: publishedDate="${publishedDate}" (valid=${!isNaN(published.getTime())}), ` +
      `cutoffDate="${cutoffDate}" (valid=${!isNaN(cutoff.getTime())})`
    );
    return false;
  }

  return published.getTime() < cutoff.getTime();
}

export const DEFAULT_STATIC_BASELINE: StaticBaselineConfig = {
  enabled: true,
  cutoffDate: DEFAULT_CUTOFF_DATE,
  dataPath: undefined,
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
      throw new Error(`Failed to read config: ${errorMessage(e)}`);
    }
  }

  const validSeverities = new Set(["critical", "high", "medium", "low", "unknown"]);
  const asSeverities = (v: unknown, fallback: Severity[]): Severity[] => {
    if (!Array.isArray(v)) return fallback;
    const normalized = v.map((s) => String(s).toLowerCase());
    const invalid = normalized.filter((s) => !validSeverities.has(s));
    if (invalid.length > 0) {
      logger.warn(`Invalid severity values ignored: ${invalid.join(", ")}`);
    }
    return normalized.filter((s): s is Severity => validSeverities.has(s));
  };

  const policy = raw.policy as Record<string, unknown> | undefined;
  const sources = raw.sources as Record<string, unknown> | undefined;
  const cache = raw.cache as Record<string, unknown> | undefined;
  const performance = raw.performance as Record<string, unknown> | undefined;
  const staticBaselineRaw = raw.staticBaseline as Record<string, unknown> | undefined;

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

  return {
    ...DEFAULT_CONFIG,
    policy: {
      block: asSeverities(policy?.block, DEFAULT_CONFIG.policy.block),
      warn: asSeverities(policy?.warn, DEFAULT_CONFIG.policy.warn),
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
          : 15000,
    },
    cache: {
      ttlSeconds:
        typeof cache?.ttlSeconds === "number" &&
        cache.ttlSeconds > 0 &&
        cache.ttlSeconds <= MAX_CACHE_TTL_SECONDS
          ? cache.ttlSeconds
          : 3600,
    },
    failOnNoSources: raw.failOnNoSources !== false,
    failOnSourceError: raw.failOnSourceError !== false,
    staticBaseline: parseStaticBaseline(staticBaselineRaw),
  };
}
