import fs from "node:fs/promises";
import path from "node:path";
import Ajv from "ajv";
import YAML from "yaml";
import { configSchema } from "./schema";
import type { AuditConfig, Severity } from "./types";
import { parseBool } from "./utils/env";

const DEFAULT_CONFIG: AuditConfig = {
  version: 1,
  policies: {
    block: ["critical", "high"],
    warn: ["medium", "low"],
    gracePeriod: 7,
    unknownVulnData: "warn",
    networkPolicy: "fail-open",
    allowlist: [],
    blocklist: ["event-stream", "flatmap-stream"],
  },
  sources: {
    osv: { enabled: true },
    github: { enabled: true },
    npm: { enabled: true },
    nvd: { enabled: true },
    ossIndex: { enabled: false },
  },
  integrity: {
    requireSha512Integrity: true,
  },
  performance: {
    concurrency: 8,
    timeoutMs: 15000,
    earlyExitOnBlock: true,
  },
  cache: {
    ttlSeconds: 3600,
    dir: ".pnpm-audit-cache",
    allowStale: true,
  },
  reporting: {
    formats: ["json", "html", "sarif"],
    outputDir: ".",
    basename: ".pnpm-audit-report",
  },
  azureDevOps: {
    prComment: { enabled: false },
    logAnalytics: { enabled: false },
  },
};

function deepMerge<T>(base: T, override: Partial<T>): T {
  if (override === undefined || override === null) return base;
  const out: any = Array.isArray(base)
    ? [...(base as any)]
    : { ...(base as any) };
  for (const [k, v] of Object.entries(override as any)) {
    if (v === undefined) continue;
    if (Array.isArray(v)) out[k] = v;
    else if (v && typeof v === "object" && !Array.isArray(v)) {
      out[k] = deepMerge((base as any)[k] ?? {}, v);
    } else {
      out[k] = v;
    }
  }
  return out;
}

function normalizeSeverity(v: string): Severity | null {
  const s = v.toLowerCase().trim();
  if (
    s === "critical" ||
    s === "high" ||
    s === "medium" ||
    s === "low" ||
    s === "unknown"
  )
    return s;
  return null;
}

function applyThreshold(cfg: AuditConfig, threshold: Severity): AuditConfig {
  const order: Severity[] = ["critical", "high", "medium", "low", "unknown"];
  const idx = order.indexOf(threshold);
  if (idx === -1) return cfg;

  const block = order.slice(0, idx + 1).filter((s) => s !== "unknown");
  const warn = order.slice(idx + 1).filter((s) => s !== "unknown");
  return deepMerge(cfg, { policies: { block, warn } } as any);
}

export interface LoadConfigOptions {
  cwd: string;
  env: Record<string, string | undefined>;
}

export async function loadConfig(
  opts: LoadConfigOptions,
): Promise<AuditConfig> {
  const cwd = opts.cwd;
  const env = opts.env;

  const configPath = env.PNPM_AUDIT_CONFIG_PATH
    ? path.resolve(cwd, env.PNPM_AUDIT_CONFIG_PATH)
    : path.resolve(cwd, ".pnpm-audit.yaml");

  let fileCfg: Partial<AuditConfig> = {};
  try {
    const raw = await fs.readFile(configPath, "utf-8");
    fileCfg = YAML.parse(raw) as Partial<AuditConfig>;
  } catch (e: any) {
    if (e?.code !== "ENOENT") {
      throw new Error(
        `Failed to read config file ${configPath}: ${e?.message ?? String(e)}`,
      );
    }
    // ENOENT: no config file -> use defaults
  }

  let cfg = deepMerge(DEFAULT_CONFIG, fileCfg);

  // Env overrides
  const ttl = env.PNPM_AUDIT_CACHE_TTL
    ? Number(env.PNPM_AUDIT_CACHE_TTL)
    : undefined;
  if (ttl !== undefined && !Number.isNaN(ttl) && ttl >= 0) {
    cfg = deepMerge(cfg, { cache: { ttlSeconds: ttl } } as any);
  }

  const conc = env.PNPM_AUDIT_CONCURRENCY
    ? Number(env.PNPM_AUDIT_CONCURRENCY)
    : undefined;
  if (conc !== undefined && !Number.isNaN(conc) && conc >= 1 && conc <= 64) {
    cfg = deepMerge(cfg, { performance: { concurrency: conc } } as any);
  }

  const timeout = env.PNPM_AUDIT_TIMEOUT_MS
    ? Number(env.PNPM_AUDIT_TIMEOUT_MS)
    : undefined;
  if (
    timeout !== undefined &&
    !Number.isNaN(timeout) &&
    timeout >= 1000 &&
    timeout <= 600000
  ) {
    cfg = deepMerge(cfg, { performance: { timeoutMs: timeout } } as any);
  }

  const offline = parseBool(env.PNPM_AUDIT_OFFLINE_MODE);
  if (offline !== undefined)
    cfg = deepMerge(cfg, {
      /* runtime-only; handled elsewhere */
    } as any);

  const netPol = env.PNPM_AUDIT_NETWORK_POLICY;
  if (netPol === "fail-open" || netPol === "fail-closed")
    cfg = deepMerge(cfg, { policies: { networkPolicy: netPol } } as any);

  const thresholdRaw = env.PNPM_AUDIT_SEVERITY_THRESHOLD;
  if (thresholdRaw) {
    const sev = normalizeSeverity(thresholdRaw);
    if (sev) cfg = applyThreshold(cfg, sev);
  }

  const outDir = env.PNPM_AUDIT_OUTPUT_DIR;
  if (outDir) cfg = deepMerge(cfg, { reporting: { outputDir: outDir } } as any);

  const baseName = env.PNPM_AUDIT_BASENAME;
  if (baseName)
    cfg = deepMerge(cfg, { reporting: { basename: baseName } } as any);

  const formats = env.PNPM_AUDIT_REPORT_FORMAT;
  if (formats) {
    const list = formats
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (list.length)
      cfg = deepMerge(cfg, { reporting: { formats: list } } as any);
  }

  // Validate
  const ajv = new Ajv({ allErrors: true });
  const validate = ajv.compile(configSchema);
  const ok = validate(cfg);
  if (!ok) {
    const msg = ajv.errorsText(validate.errors, { separator: "\n" });
    throw new Error(`Invalid .pnpm-audit.yaml configuration:\n${msg}`);
  }

  return cfg;
}
