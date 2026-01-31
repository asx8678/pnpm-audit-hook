const PREFIX = "[pnpm-audit]";
const QUIET = process.env.PNPM_AUDIT_QUIET === "true";
const DEBUG = process.env.PNPM_AUDIT_DEBUG === "true";

export const logger = {
  debug: (msg: string) => DEBUG && console.log(`${PREFIX}[debug] ${msg}`),
  info: (msg: string) => !QUIET && console.log(`${PREFIX} ${msg}`),
  warn: (msg: string) => !QUIET && console.warn(`${PREFIX}[warn] ${msg}`),
  error: (msg: string) => console.error(`${PREFIX}[error] ${msg}`),
};
