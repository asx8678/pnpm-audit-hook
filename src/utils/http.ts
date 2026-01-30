import { retry } from "./retry";
import type { Logger } from "./logger";

export class HttpError extends Error {
  public readonly status?: number;
  public readonly url: string;
  public readonly retryAfter?: string | number;
  public readonly responseText?: string;

  constructor(
    message: string,
    opts: {
      url: string;
      status?: number;
      retryAfter?: string | number;
      responseText?: string;
    },
  ) {
    super(message);
    this.name = "HttpError";
    this.url = opts.url;
    this.status = opts.status;
    this.retryAfter = opts.retryAfter;
    this.responseText = opts.responseText;
  }
}

export interface HttpClientOptions {
  timeoutMs: number;
  userAgent: string;
  logger: Logger;
  headers?: Record<string, string>;
  retries?: number;
}

export class HttpClient {
  private readonly timeoutMs: number;
  private readonly userAgent: string;
  private readonly logger: Logger;
  private readonly headers: Record<string, string>;
  private readonly retries: number;

  constructor(opts: HttpClientOptions) {
    this.timeoutMs = opts.timeoutMs;
    this.userAgent = opts.userAgent;
    this.logger = opts.logger;
    this.headers = opts.headers ?? {};
    this.retries = opts.retries ?? 3;
  }

  async getJson<T>(
    url: string,
    extraHeaders?: Record<string, string>,
  ): Promise<T> {
    return this.requestJson<T>("GET", url, undefined, extraHeaders);
  }

  async postJson<T>(
    url: string,
    body: unknown,
    extraHeaders?: Record<string, string>,
  ): Promise<T> {
    return this.requestJson<T>("POST", url, body, extraHeaders);
  }

  private async requestJson<T>(
    method: "GET" | "POST",
    url: string,
    body?: unknown,
    extraHeaders?: Record<string, string>,
  ): Promise<T> {
    const headers: Record<string, string> = {
      "user-agent": this.userAgent,
      accept: "application/json",
      ...this.headers,
      ...extraHeaders,
    };
    if (method === "POST") headers["content-type"] = "application/json";

    const fn = async (): Promise<T> => {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const res = await fetch(url, {
          method,
          headers,
          body: body !== undefined ? JSON.stringify(body) : undefined,
          signal: controller.signal,
        });

        if (!res.ok) {
          const retryAfter = res.headers.get("retry-after") ?? undefined;
          const text = await res.text().catch(() => "");
          throw new HttpError(`HTTP ${res.status} ${res.statusText}`, {
            url,
            status: res.status,
            retryAfter,
            responseText: text,
          });
        }

        const text = await res.text();
        try {
          return JSON.parse(text) as T;
        } catch (e) {
          throw new HttpError(`Invalid JSON response`, {
            url,
            status: res.status,
            responseText: text,
          });
        }
      } finally {
        clearTimeout(timeout);
      }
    };

    return retry(fn, {
      retries: this.retries,
      minDelayMs: 250,
      maxDelayMs: 8000,
      factor: 2,
      jitter: 0.2,
      retryOn: (err) => {
        if (!(err instanceof HttpError)) return true;
        const status = err.status;
        return status === 429 || (typeof status === "number" && status >= 500);
      },
    }).catch((err) => {
      // Best-effort debug log (avoid huge response bodies).
      const e = err as any;
      this.logger.debug(`HTTP ${method} failed: ${url}`, {
        status: e?.status,
        name: e?.name,
        message: e?.message,
      });
      throw err;
    });
  }
}
