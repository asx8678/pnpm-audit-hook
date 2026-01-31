export const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

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
      if (++attempt > retries || !shouldRetry(err)) throw err;
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

  constructor(
    message: string,
    opts: { url: string; status?: number; retryAfter?: string | number; responseText?: string },
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
  headers?: Record<string, string>;
  retries?: number;
}

export class HttpClient {
  private readonly timeoutMs: number;
  private readonly userAgent: string;
  private readonly headers: Record<string, string>;
  private readonly retries: number;

  constructor(opts: HttpClientOptions) {
    this.timeoutMs = opts.timeoutMs;
    this.userAgent = opts.userAgent;
    this.headers = opts.headers ?? {};
    this.retries = opts.retries ?? 3;
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
      throw new HttpError(`Invalid URL: ${url}`, { url });
    }

    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      throw new HttpError(
        `Invalid URL protocol "${parsedUrl.protocol}": only http: and https: are allowed`,
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

        return res;
      } finally {
        clearTimeout(timeout);
      }
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
      throw new HttpError(`Invalid JSON response: ${parseMessage}`, {
        url,
        status: res.status,
        responseText: text,
      });
    }
  }
}
