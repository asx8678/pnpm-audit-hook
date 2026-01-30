export type LogLevel = "silent" | "error" | "warn" | "info" | "debug";

export interface Logger {
  level: LogLevel;
  debug(msg: string, meta?: unknown): void;
  info(msg: string, meta?: unknown): void;
  warn(msg: string, meta?: unknown): void;
  error(msg: string, meta?: unknown): void;
}

function levelToNumber(level: LogLevel): number {
  switch (level) {
    case "silent":
      return 0;
    case "error":
      return 1;
    case "warn":
      return 2;
    case "info":
      return 3;
    case "debug":
      return 4;
    default:
      return 3;
  }
}

function formatMeta(meta: unknown): string {
  if (meta === undefined) return "";
  try {
    return " " + JSON.stringify(meta);
  } catch {
    // Circular reference or other stringify error
    return " [meta:unstringifiable]";
  }
}

export function createLogger(level: LogLevel): Logger {
  const threshold = levelToNumber(level);
  const should = (l: LogLevel) => levelToNumber(l) <= threshold;

  return {
    level,
    debug(msg, meta) {
      if (!should("debug")) return;
      // eslint-disable-next-line no-console
      console.log(`[pnpm-audit][debug] ${msg}${formatMeta(meta)}`);
    },
    info(msg, meta) {
      if (!should("info")) return;
      // eslint-disable-next-line no-console
      console.log(`[pnpm-audit] ${msg}${formatMeta(meta)}`);
    },
    warn(msg, meta) {
      if (!should("warn")) return;
      // eslint-disable-next-line no-console
      console.warn(`[pnpm-audit][warn] ${msg}${formatMeta(meta)}`);
    },
    error(msg, meta) {
      if (!should("error")) return;
      // eslint-disable-next-line no-console
      console.error(`[pnpm-audit][error] ${msg}${formatMeta(meta)}`);
    },
  };
}

export function envLogLevel(env: Record<string, string | undefined>): LogLevel {
  const v = (env.PNPM_AUDIT_LOG_LEVEL || env.LOG_LEVEL || "").toLowerCase();
  if (
    v === "silent" ||
    v === "error" ||
    v === "warn" ||
    v === "info" ||
    v === "debug"
  )
    return v;
  return "info";
}
