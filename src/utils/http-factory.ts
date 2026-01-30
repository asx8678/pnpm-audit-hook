import type { AuditConfig } from "../types.js";
import type { Logger } from "./logger.js";
import { HttpClient } from "./http.js";

const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_RETRIES = 2;
const USER_AGENT = "pnpm-audit-hook";

/**
 * Create a configured HttpClient for audit operations.
 */
export function createAuditHttpClient(
  cfg: AuditConfig,
  logger: Logger,
): HttpClient {
  return new HttpClient({
    timeoutMs: cfg.performance?.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    userAgent: USER_AGENT,
    logger,
    retries: DEFAULT_RETRIES,
  });
}

/**
 * Create a configured HttpClient for integration services (Azure DevOps, webhooks, etc.).
 */
export function createIntegrationHttpClient(
  timeoutMs: number,
  logger: Logger,
  headers?: Record<string, string>,
): HttpClient {
  return new HttpClient({
    timeoutMs,
    userAgent: USER_AGENT,
    logger,
    retries: DEFAULT_RETRIES,
    headers,
  });
}
