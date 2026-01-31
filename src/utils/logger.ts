const PREFIX = "[pnpm-audit]";
const QUIET = process.env.PNPM_AUDIT_QUIET === "true";
const DEBUG = process.env.PNPM_AUDIT_DEBUG === "true";
const JSON_MODE = process.env.PNPM_AUDIT_JSON === "true";
const VERBOSE = process.env.PNPM_AUDIT_VERBOSE === "true";

export function isJsonMode(): boolean {
  return JSON_MODE;
}

export function isVerbose(): boolean {
  return (
    VERBOSE ||
    process.env.CI === "true" ||
    process.env.TF_BUILD === "True" ||
    process.env.GITHUB_ACTIONS === "true" ||
    process.env.GITLAB_CI === "true" ||
    process.env.JENKINS_URL !== undefined
  );
}

export type OutputFormat = "human" | "azure" | "json";

export function getOutputFormat(): OutputFormat {
  if (JSON_MODE) {
    return "json";
  }
  if (process.env.PNPM_AUDIT_FORMAT === "azure" || process.env.TF_BUILD === "True") {
    return "azure";
  }
  return "human";
}

export const logger = {
  debug: (msg: string) => {
    if (JSON_MODE) return;
    DEBUG && console.log(`${PREFIX}[debug] ${msg}`);
  },
  info: (msg: string) => {
    if (JSON_MODE) return;
    !QUIET && console.log(`${PREFIX} ${msg}`);
  },
  warn: (msg: string) => {
    if (JSON_MODE) return;
    !QUIET && console.warn(`${PREFIX}[warn] ${msg}`);
  },
  error: (msg: string) => {
    if (JSON_MODE) return;
    console.error(`${PREFIX}[error] ${msg}`);
  },
  json: (data: unknown) => {
    if (JSON_MODE) console.log(JSON.stringify(data));
  },
  verbose: (msg: string) => {
    if (JSON_MODE) return;
    if (isVerbose() && !QUIET) {
      console.log(`${PREFIX}[verbose] ${msg}`);
    }
  },
  progress: (current: number, total: number, label: string) => {
    if (JSON_MODE || QUIET) return;
    if (!isVerbose()) return;
    const percent = total > 0 ? Math.round((current / total) * 100) : 0;
    const bar = "=".repeat(Math.floor(percent / 5)).padEnd(20, " ");
    process.stdout.write(`\r${PREFIX} [${bar}] ${percent}% ${label}`);
    if (current >= total) {
      process.stdout.write("\n");
    }
  },
};
