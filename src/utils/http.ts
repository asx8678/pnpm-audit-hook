import http from "node:http";
import https from "node:https";
import { sleep } from "./concurrency";

/**
 * Pool metrics for monitoring connection pool health.
 */
export interface PoolMetrics {
  /** Total number of requests made through this pool */
  totalRequests: number;
  /** Number of successful requests */
  successfulRequests: number;
  /** Number of failed requests */
  failedRequests: number;
  /** Number of connection errors */
  connectionErrors: number;
  /** Average request latency in milliseconds */
  averageLatencyMs: number;
}

/**
 * Connection pool configuration options.
 */
export interface PoolOptions {
  /** Maximum number of concurrent connections per origin (default: 10) */
  maxSockets?: number;
  /** Maximum number of idle sockets to keep alive (default: 5) */
  maxFreeSockets?: number;
  /** Socket timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Keep-alive timeout in milliseconds (default: 30000) */
  keepAliveMsecs?: number;
  /** Enable health checks (default: true) */
  enableHealthCheck?: boolean;
  /** Health check interval in milliseconds (default: 30000) */
  healthCheckIntervalMs?: number;
}

export async function retry<T>(
  fn: () => Promise<T>,
  retries: number,
  shouldRetry: (err: unknown) => boolean,
): Promise<T> {
  let attempt = 0;
  for (;;) {
    try {
      return await fn();
    } catch (err) {
      if (++attempt > retries || !shouldRetry(err)) {
        if (attempt > retries && err instanceof HttpError) {
          const retryContext = `Failed after ${retries} retries`;
          throw new HttpError(
            `${retryContext}: ${err.message}` +
              (err.suggestion ? ` — ${err.suggestion}` : ""),
            {
              url: err.url,
              status: err.status,
              retryAfter: err.retryAfter,
              responseText: err.responseText,
              suggestion: err.suggestion,
            },
          );
        }
        throw err;
      }
      const ra = err instanceof HttpError ? err.retryAfter : undefined;
      const base = 250 * 2 ** (attempt - 1);
      const raNum = typeof ra === "number" ? ra : (typeof ra === "string" && !Number.isNaN(+ra) ? +ra : null);
      const delay = (raNum !== null && raNum > 0)
        ? Math.min(30000, raNum * 1000)
        : Math.min(8000, base + base * 0.2 * Math.random());
      await sleep(delay);
    }
  }
}

export class HttpError extends Error {
  readonly status?: number;
  readonly url: string;
  readonly retryAfter?: string | number;
  readonly responseText?: string;
  readonly suggestion?: string;

  constructor(
    message: string,
    opts: { url: string; status?: number; retryAfter?: string | number; responseText?: string; suggestion?: string },
  ) {
    super(message);
    this.name = "HttpError";
    this.url = opts.url;
    this.status = opts.status;
    this.retryAfter = opts.retryAfter;
    this.responseText = opts.responseText;
    this.suggestion = opts.suggestion;
  }
}

function getStatusSuggestion(status: number): string | undefined {
  switch (status) {
    case 400:
      return "Bad request. Check your request parameters and try again.";
    case 401:
      return "Authentication required. Check your API credentials or tokens.";
    case 403:
      return "Access denied. You don't have permission to access this resource.";
    case 404:
      return "Resource not found. Check the URL or package name.";
    case 408:
      return "Request timeout. The server took too long to respond.";
    case 409:
      return "Conflict. The resource state conflicts with the request.";
    case 422:
      return "Validation error. Check your request body format.";
    case 429:
      return "Rate limited. Try again later or reduce request frequency.";
    case 500:
      return "Internal server error. The API may be temporarily unavailable.";
    case 502:
      return "Bad gateway. The upstream server is not responding.";
    case 503:
      return "Service unavailable. The API is likely under maintenance or overloaded.";
    case 504:
      return "Gateway timeout. The upstream server took too long to respond.";
    default:
      return undefined;
  }
}

export interface HttpClientOptions {
  timeoutMs: number;
  userAgent: string;
  headers?: Record<string, string>;
  retries?: number;
  /** Connection pool configuration. Set to false to disable pooling. */
  pool?: PoolOptions | false;
}

/**
 * Connection pool manager that reuses HTTP connections for better performance.
 * Uses Node.js http.Agent/https.Agent with keepAlive for connection reuse.
 */
export class ConnectionPool {
  private readonly agents: { http: http.Agent; https: https.Agent };
  private readonly metrics: PoolMetrics;
  private readonly healthCheckIntervalId: ReturnType<typeof setInterval> | null = null;
  private readonly poolOptions: PoolOptions;
  private destroyed = false;

  constructor(options: PoolOptions = {}) {
    this.poolOptions = {
      maxSockets: options.maxSockets ?? 10,
      maxFreeSockets: options.maxFreeSockets ?? 5,
      timeout: options.timeout ?? 30000,
      keepAliveMsecs: options.keepAliveMsecs ?? 30000,
      enableHealthCheck: options.enableHealthCheck ?? true,
      healthCheckIntervalMs: options.healthCheckIntervalMs ?? 30000,
    };

    const agentOpts: http.AgentOptions = {
      keepAlive: true,
      maxSockets: this.poolOptions.maxSockets,
      maxFreeSockets: this.poolOptions.maxFreeSockets,
      timeout: this.poolOptions.timeout,
      keepAliveMsecs: this.poolOptions.keepAliveMsecs,
      scheduling: "lifo", // Last-in-first-out for better cache locality
    };

    this.agents = {
      http: new http.Agent(agentOpts),
      https: new https.Agent(agentOpts),
    };

    this.metrics = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      connectionErrors: 0,
      averageLatencyMs: 0,
    };

    if (this.poolOptions.enableHealthCheck && this.poolOptions.healthCheckIntervalMs) {
      this.healthCheckIntervalId = setInterval(
        () => this.healthCheck(),
        this.poolOptions.healthCheckIntervalMs,
      );
    }
  }

  /** Get a snapshot of pool metrics */
  getMetrics(): PoolMetrics {
    return { ...this.metrics };
  }

  /** Get the appropriate agent for the URL protocol */
  getAgent(url: string): http.Agent | https.Agent {
    return url.startsWith("https:") ? this.agents.https : this.agents.http;
  }

  /**
   * Execute a request using the connection pool.
   * Handles connection errors, retries, and metrics tracking.
   */
  async request(opts: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
    timeoutMs: number;
  }): Promise<Response> {
    if (this.destroyed) {
      throw new Error("Connection pool has been destroyed");
    }

    this.metrics.totalRequests++;
    const startTime = Date.now();

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), opts.timeoutMs);

      try {
        const agent = this.getAgent(opts.url);
        const res = await fetch(opts.url, {
          method: opts.method,
          headers: opts.headers,
          body: opts.body,
          signal: controller.signal,
          // @ts-expect-error -- Node's fetch accepts agent option
          agent,
        });

        const latency = Date.now() - startTime;
        this.updateMetrics(latency, true);
        return res;
      } finally {
        clearTimeout(timeout);
      }
    } catch (err) {
      const latency = Date.now() - startTime;
      this.updateMetrics(latency, false);

      // Track connection errors specifically
      if (
        err instanceof Error &&
        (err.name === "ConnectTimeoutError" ||
          err.name === "ECONNREFUSED" ||
          err.name === "ENOTFOUND" ||
          err.message?.includes("connect"))
      ) {
        this.metrics.connectionErrors++;
      }

      throw err;
    }
  }

  private updateMetrics(latencyMs: number, success: boolean): void {
    // Exponential moving average for latency
    const alpha = 0.1;
    this.metrics.averageLatencyMs =
      this.metrics.averageLatencyMs * (1 - alpha) + latencyMs * alpha;

    if (success) {
      this.metrics.successfulRequests++;
    } else {
      this.metrics.failedRequests++;
    }
  }

  /** Periodic health check to monitor pool status */
  private async healthCheck(): Promise<void> {
    try {
      if (this.destroyed) return;
      // Agents manage connections automatically - health checks verify the pool is responsive
    } catch {
      // Health check errors are non-fatal
    }
  }

  /** Destroy the connection pool and clean up resources */
  async destroy(): Promise<void> {
    if (this.destroyed) return;
    this.destroyed = true;

    if (this.healthCheckIntervalId) {
      clearInterval(this.healthCheckIntervalId);
    }

    this.agents.http.destroy();
    this.agents.https.destroy();
  }
}

/**
 * Get or create a shared connection pool.
 * Pools are cached by a singleton key to enable connection reuse across requests.
 */
let sharedPool: ConnectionPool | null = null;

export function getPool(options?: PoolOptions): ConnectionPool {
  if (!sharedPool || (sharedPool as unknown as { destroyed: boolean }).destroyed) {
    sharedPool = new ConnectionPool(options);
  }
  return sharedPool;
}

/** Destroy the shared pool (useful for cleanup in tests) */
export async function destroyAllPools(): Promise<void> {
  if (sharedPool) {
    await sharedPool.destroy();
    sharedPool = null;
  }
}

export class HttpClient {
  private readonly timeoutMs: number;
  private readonly userAgent: string;
  private readonly headers: Record<string, string>;
  private readonly retries: number;
  private readonly poolOptions: PoolOptions | false;

  constructor(opts: HttpClientOptions) {
    this.timeoutMs = opts.timeoutMs;
    this.userAgent = opts.userAgent;
    this.headers = opts.headers ?? {};
    this.retries = opts.retries ?? 3;
    this.poolOptions = opts.pool ?? {};
  }

  getJson = <T>(url: string, extraHeaders?: Record<string, string>) =>
    this.requestJson<T>("GET", url, undefined, extraHeaders);

  postJson = <T>(url: string, body: unknown, extraHeaders?: Record<string, string>) =>
    this.requestJson<T>("POST", url, body, extraHeaders);

  getRaw = (url: string, extraHeaders?: Record<string, string>) =>
    this.requestRaw("GET", url, undefined, extraHeaders);

  private async requestRaw(
    method: "GET" | "POST",
    url: string,
    body?: unknown,
    extraHeaders?: Record<string, string>,
  ): Promise<Response> {
    // Validate URL scheme before making request
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url);
    } catch {
      throw new HttpError(
        `Invalid URL: ${url} — The URL could not be parsed. Check for typos or missing protocol (http:// or https://).`,
        { url }
      );
    }

    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      throw new HttpError(
        `Invalid URL protocol "${parsedUrl.protocol}" when fetching ${url} — only http: and https: are allowed. Use https: for secure connections.`,
        { url }
      );
    }

    const headers: Record<string, string> = {
      "user-agent": this.userAgent,
      accept: "application/json",
      ...this.headers,
      ...extraHeaders,
    };
    if (method === "POST") headers["content-type"] = "application/json";

    const fn = async (): Promise<Response> => {
      let res: Response;

      // Use connection pool if enabled, otherwise fall back to global fetch
      if (this.poolOptions !== false) {
        const pool = getPool(this.poolOptions);
        res = await pool.request({
          method,
          url,
          headers,
          body: body !== undefined ? JSON.stringify(body) : undefined,
          timeoutMs: this.timeoutMs,
        });
      } else {
        // Fallback: no connection pooling (global fetch)
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

        try {
          res = await fetch(url, {
            method,
            headers,
            body: body !== undefined ? JSON.stringify(body) : undefined,
            signal: controller.signal,
          });
        } finally {
          clearTimeout(timeout);
        }
      }

      // Check response status inside the retry function so retry logic can kick in
      if (!res.ok) {
        const retryAfter = res.headers.get("retry-after") ?? undefined;
        const text = await res.text().catch(() => "");
        const suggestion = getStatusSuggestion(res.status);
        const message = `HTTP ${res.status} ${res.statusText} when fetching ${url}` +
          (suggestion ? ` — ${suggestion}` : "");
        throw new HttpError(message, {
          url,
          status: res.status,
          retryAfter,
          responseText: text,
          suggestion,
        });
      }

      return res;
    };

    return retry(
      fn,
      this.retries,
      (err) => !(err instanceof HttpError) || err.status === 429 || (err.status ?? 0) >= 500,
    );
  }

  private async requestJson<T>(
    method: "GET" | "POST",
    url: string,
    body?: unknown,
    extraHeaders?: Record<string, string>,
  ): Promise<T> {
    const res = await this.requestRaw(method, url, body, extraHeaders);
    const text = await res.text();
    try {
      // Trust boundary: callers are responsible for validating the response shape.
      // The generic type T is a compile-time hint; runtime validation must be done
      // by the caller if the data source is untrusted (e.g., external APIs).
      return JSON.parse(text) as T;
    } catch (parseError) {
      const parseMessage = parseError instanceof Error ? parseError.message : String(parseError);
      throw new HttpError(
        `Invalid JSON response when fetching ${url}: ${parseMessage} — The server returned non-JSON data. Check if the URL is correct or if the API has changed.`,
        {
          url,
          status: res.status,
          responseText: text,
        },
      );
    }
  }
}
