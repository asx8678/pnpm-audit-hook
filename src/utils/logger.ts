const PREFIX = "[pnpm-audit]";

// All env vars are cached at module load for hot-path performance
// (thousands of log calls per audit). These values never change at runtime.
const QUIET = process.env.PNPM_AUDIT_QUIET === "true";
const DEBUG = process.env.PNPM_AUDIT_DEBUG === "true";
const JSON_MODE = process.env.PNPM_AUDIT_JSON === "true";
const VERBOSE =
  process.env.PNPM_AUDIT_VERBOSE === "true" ||
  process.env.CI === "true" ||
  process.env.TF_BUILD === "True" ||
  process.env.GITHUB_ACTIONS === "true" ||
  process.env.GITLAB_CI === "true" ||
  process.env.JENKINS_URL !== undefined;

export function isJsonMode(): boolean {
  return JSON_MODE;
}

export function isVerbose(): boolean {
  return VERBOSE;
}

export const logger = {
  debug: (msg: string) => {
    if (isJsonMode()) return;
    DEBUG && console.log(`${PREFIX}[debug] ${msg}`);
  },
  info: (msg: string) => {
    if (isJsonMode()) return;
    !QUIET && console.log(`${PREFIX} ${msg}`);
  },
  warn: (msg: string) => {
    if (isJsonMode()) return;
    !QUIET && console.warn(`${PREFIX}[warn] ${msg}`);
  },
  error: (msg: string) => {
    if (isJsonMode()) return;
    console.error(`${PREFIX}[error] ${msg}`);
  },
  json: (data: unknown) => {
    if (isJsonMode()) console.log(JSON.stringify(data));
  },
  verbose: (msg: string) => {
    if (isJsonMode()) return;
    if (isVerbose() && !QUIET) {
      console.log(`${PREFIX}[verbose] ${msg}`);
    }
  },
  progress: (current: number, total: number, label: string) => {
    if (isJsonMode() || QUIET) return;
    if (!isVerbose()) return;
    const percent = total > 0 ? Math.round((current / total) * 100) : 0;
    const bar = "=".repeat(Math.floor(percent / 5)).padEnd(20, " ");
    process.stdout.write(`\r${PREFIX} [${bar}] ${percent}% ${label}`);
    if (current >= total) {
      process.stdout.write("\n");
    }
  },
};
