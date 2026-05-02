import { getEnvironmentVariables, isVerboseMode } from "./env-manager";
import { StructuredLogger, structuredLogger, createLogger, getChildLogger } from "./structured-logger";
import { ProgressReporter, formatProgressBar, renderProgressBar } from "./progress-reporter";
import { detectCIPlatform, emitWarning, emitError, emitNotice, setCIOutput, isCI, getCIPlatformName, getCIIntegration } from "./ci-integration";
import { supportsColor, BOLD, RED, GREEN, YELLOW, RESET, DIM } from "./color-utils";

// Re-export structured logging utilities
export { StructuredLogger, structuredLogger, createLogger, getChildLogger } from "./structured-logger";
export { ProgressReporter, SubProgressReporter, formatProgressBar, renderProgressBar } from "./progress-reporter";
export type { LogMetadata, LogEntry, LogLevel, ProgressStep, ProgressReport, ProgressReporterOptions } from "./logger-types";
export { detectCIPlatform, emitWarning, emitError, emitNotice, setCIOutput, isCI, getCIPlatformName, getCIIntegration } from "./ci-integration";
export { supportsColor } from "./color-utils";

const PREFIX = "[pnpm-audit]";

// All env vars are cached at module load for hot-path performance
// (thousands of log calls per audit). These values never change at runtime.
const { PNPM_AUDIT_QUIET: QUIET, PNPM_AUDIT_DEBUG: DEBUG, PNPM_AUDIT_JSON: JSON_MODE } = getEnvironmentVariables();
const VERBOSE = isVerboseMode();

export function isJsonMode(): boolean {
  return JSON_MODE;
}

export function isVerbose(): boolean {
  return VERBOSE;
}

/**
 * Backward-compatible logger interface.
 * 
 * All existing code using `logger.debug()`, `logger.info()`, etc. will
 * continue to work without any changes. For new code, prefer using
 * `structuredLogger` for enhanced metadata support.
 */
export const logger = {
  debug: (msg: string) => {
    if (isJsonMode()) return;
    DEBUG && console.log(`${DIM}${PREFIX}[debug] ${msg}${RESET}`);
  },
  info: (msg: string) => {
    if (isJsonMode()) return;
    !QUIET && console.log(`${PREFIX} ${msg}`);
  },
  warn: (msg: string) => {
    if (isJsonMode()) return;
    !QUIET && console.warn(`${YELLOW}${PREFIX}[warn] ${msg}${RESET}`);
  },
  error: (msg: string) => {
    if (isJsonMode()) return;
    console.error(`${RED}${PREFIX}[error] ${msg}${RESET}`);
  },
  json: (data: unknown) => {
    if (isJsonMode()) console.log(JSON.stringify(data));
  },
  verbose: (msg: string) => {
    if (isJsonMode()) return;
    if (isVerbose() && !QUIET) {
      console.log(`${DIM}${PREFIX}[verbose] ${msg}${RESET}`);
    }
  },
  progress: (current: number, total: number, label: string) => {
    if (isJsonMode() || QUIET) return;
    if (!isVerbose()) return;
    const percent = total > 0 ? Math.round((current / total) * 100) : 0;
    const barLength = 20;
    const filled = Math.round((current / total) * barLength);
    const bar = '█'.repeat(filled) + '░'.repeat(barLength - filled);
    process.stdout.write(`\r${BOLD}${PREFIX}${RESET} [${GREEN}${bar}${RESET}] ${percent}% ${label}`);
    if (current >= total) {
      process.stdout.write("\n");
    }
  },

  // Enhanced methods for structured logging (backed by structuredLogger)
  debugWithMeta: (msg: string, metadata: Record<string, unknown>) => {
    if (isJsonMode()) return;
    DEBUG && structuredLogger.debug(msg, metadata);
  },
  infoWithMeta: (msg: string, metadata: Record<string, unknown>) => {
    if (isJsonMode()) return;
    !QUIET && structuredLogger.info(msg, metadata);
  },
  warnWithMeta: (msg: string, metadata: Record<string, unknown>) => {
    if (isJsonMode()) return;
    !QUIET && structuredLogger.warn(msg, metadata);
  },
  errorWithMeta: (msg: string, metadata: Record<string, unknown>) => {
    if (isJsonMode()) return;
    structuredLogger.error(msg, metadata);
  },
  timing: (label: string, durationMs: number) => {
    structuredLogger.timing(label, durationMs);
  },
  startTimer: () => {
    return structuredLogger.startTimer('operation');
  },
};
