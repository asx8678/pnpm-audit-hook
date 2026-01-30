import fs from "node:fs/promises";
import path from "node:path";
import YAML from "yaml";
import type { AuditConfig, Severity } from "./types";

export const DEFAULT_CONFIG: AuditConfig = {
  policy: {
    block: ["critical", "high"],
    warn: ["medium", "low", "unknown"],
  },
  sources: {
    osv: { enabled: true },
    npm: { enabled: true },
    github: { enabled: true },
    nvd: { enabled: true },
    depsdev: { enabled: true },
  },
  performance: { timeoutMs: 15000 },
  cache: { ttlSeconds: 3600 },
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
  } catch (e: any) {
    if (e?.code !== "ENOENT") {
      throw new Error(`Failed to read config: ${e?.message ?? e}`);
    }
  }

  const asSeverities = (v: unknown, fallback: Severity[]): Severity[] =>
    Array.isArray(v) ? v.map((s) => String(s).toLowerCase() as Severity) : fallback;

  const policy = raw.policy as Record<string, unknown> | undefined;
  const sources = raw.sources as Record<string, unknown> | undefined;
  const cache = raw.cache as Record<string, unknown> | undefined;

  return {
    ...DEFAULT_CONFIG,
    policy: {
      block: asSeverities(policy?.block, DEFAULT_CONFIG.policy.block),
      warn: asSeverities(policy?.warn, DEFAULT_CONFIG.policy.warn),
    },
    sources: {
      osv: { enabled: sources?.osv !== false },
      npm: { enabled: sources?.npm !== false },
      github: { enabled: sources?.github !== false },
      nvd: { enabled: sources?.nvd !== false },
      depsdev: { enabled: sources?.depsdev !== false },
    },
    cache: {
      ttlSeconds: typeof cache?.ttlSeconds === "number" ? cache.ttlSeconds : 3600,
    },
  };
}
