import type { AuditConfig } from "../types.js";
import type { Logger } from "./logger.js";
import { HttpClient } from "./http.js";

const DEFAULTS = { timeoutMs: 15000, retries: 2, userAgent: "pnpm-audit-hook" } as const;

/** Create HttpClient for audit operations. */
export function createAuditHttpClient(cfg: AuditConfig, logger: Logger): HttpClient {
  return new HttpClient({
    timeoutMs: cfg.performance?.timeoutMs ?? DEFAULTS.timeoutMs,
    userAgent: DEFAULTS.userAgent,
    logger,
    retries: DEFAULTS.retries,
  });
}

/** Create HttpClient for integration services (Azure DevOps, webhooks, etc.). */
export function createIntegrationHttpClient(
  timeoutMs: number,
  logger: Logger,
  headers?: Record<string, string>,
): HttpClient {
  return new HttpClient({ timeoutMs, userAgent: DEFAULTS.userAgent, logger, retries: DEFAULTS.retries, headers });
}
