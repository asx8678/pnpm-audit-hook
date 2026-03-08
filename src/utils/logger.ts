const PREFIX = "[pnpm-audit]";

// Cached at module load for hot-path performance (thousands of log calls per audit).
// isJsonMode and isVerbose remain functions because they are exported and
// callers may need consistent dynamic behavior in test harnesses.
const QUIET = process.env.PNPM_AUDIT_QUIET === "true";
const DEBUG = process.env.PNPM_AUDIT_DEBUG === "true";

export function isJsonMode(): boolean {
  return process.env.PNPM_AUDIT_JSON === "true";
}

export function isVerbose(): boolean {
  return (
    process.env.PNPM_AUDIT_VERBOSE === "true" ||
    process.env.CI === "true" ||
    process.env.TF_BUILD === "True" ||
    process.env.GITHUB_ACTIONS === "true" ||
    process.env.GITLAB_CI === "true" ||
    process.env.JENKINS_URL !== undefined
  );
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
