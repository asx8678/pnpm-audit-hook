export type LogLevel = "silent" | "error" | "warn" | "info" | "debug";

export interface Logger {
  level: LogLevel;
  debug(msg: string, meta?: unknown): void;
  info(msg: string, meta?: unknown): void;
  warn(msg: string, meta?: unknown): void;
  error(msg: string, meta?: unknown): void;
}

const LEVEL_NUM: Record<LogLevel, number> = { silent: 0, error: 1, warn: 2, info: 3, debug: 4 };

const formatMeta = (meta: unknown) => {
  if (meta === undefined) return "";
  try {
    return " " + JSON.stringify(meta);
  } catch {
    return " [meta:unstringifiable]";
  }
};

export function createLogger(level: LogLevel): Logger {
  const threshold = LEVEL_NUM[level] ?? 3;
  const should = (l: LogLevel) => (LEVEL_NUM[l] ?? 3) <= threshold;

  return {
    level,
    debug: (msg, meta) => should("debug") && console.log(`[pnpm-audit][debug] ${msg}${formatMeta(meta)}`),
    info: (msg, meta) => should("info") && console.log(`[pnpm-audit] ${msg}${formatMeta(meta)}`),
    warn: (msg, meta) => should("warn") && console.warn(`[pnpm-audit][warn] ${msg}${formatMeta(meta)}`),
    error: (msg, meta) => should("error") && console.error(`[pnpm-audit][error] ${msg}${formatMeta(meta)}`),
  };
}

export function envLogLevel(env: Record<string, string | undefined>): LogLevel {
  const v = (env.PNPM_AUDIT_LOG_LEVEL || env.LOG_LEVEL || "").toLowerCase() as LogLevel;
  return LEVEL_NUM[v] !== undefined ? v : "info";
}
