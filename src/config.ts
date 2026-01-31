import fs from "node:fs/promises";
import path from "node:path";
import YAML from "yaml";
import type { AllowlistEntry, AuditConfig, Severity } from "./types";

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
};

export interface LoadConfigOptions {
  cwd: string;
  env: Record<string, string | undefined>;
}

export async function loadConfig(opts: LoadConfigOptions): Promise<AuditConfig> {
  const configPath = opts.env.PNPM_AUDIT_CONFIG_PATH
    ? path.resolve(opts.cwd, opts.env.PNPM_AUDIT_CONFIG_PATH)
    : path.resolve(opts.cwd, ".pnpm-audit.yaml");

  let raw: Record<string, unknown> = {};
  try {
    raw = YAML.parse(await fs.readFile(configPath, "utf-8")) ?? {};
  } catch (e: unknown) {
    const err = e as { code?: string; message?: string };
    if (err.code !== "ENOENT") {
      throw new Error(`Failed to read config: ${err.message ?? String(e)}`);
    }
  }

  const validSeverities = new Set(["critical", "high", "medium", "low", "unknown"]);
  const asSeverities = (v: unknown, fallback: Severity[]): Severity[] =>
    Array.isArray(v)
      ? v.map((s) => String(s).toLowerCase()).filter((s): s is Severity => validSeverities.has(s))
      : fallback;

  const policy = raw.policy as Record<string, unknown> | undefined;
  const sources = raw.sources as Record<string, unknown> | undefined;
  const cache = raw.cache as Record<string, unknown> | undefined;
  const performance = raw.performance as Record<string, unknown> | undefined;

  const asAllowlist = (v: unknown): AllowlistEntry[] =>
    Array.isArray(v)
      ? v.filter((e): e is AllowlistEntry =>
          e && typeof e === "object" && ("id" in e || "package" in e))
      : [];

  return {
    ...DEFAULT_CONFIG,
    policy: {
      block: asSeverities(policy?.block, DEFAULT_CONFIG.policy.block),
      warn: asSeverities(policy?.warn, DEFAULT_CONFIG.policy.warn),
      allowlist: asAllowlist(policy?.allowlist),
    },
    sources: {
      github: { enabled: sources?.github !== false },
      nvd: { enabled: sources?.nvd !== false },
    },
    performance: {
      timeoutMs:
        typeof performance?.timeoutMs === "number" && performance.timeoutMs > 0
          ? performance.timeoutMs
          : 15000,
    },
    cache: {
      ttlSeconds:
        typeof cache?.ttlSeconds === "number" && cache.ttlSeconds > 0
          ? cache.ttlSeconds
          : 3600,
    },
    failOnNoSources: raw.failOnNoSources !== false,
    failOnSourceError: raw.failOnSourceError !== false,
  };
}
