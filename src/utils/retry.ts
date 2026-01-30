export interface RetryOptions {
  retries: number;
  minDelayMs: number;
  maxDelayMs: number;
  factor: number;
  jitter: number; // 0..1
  retryOn?: (err: unknown) => boolean;
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function defaultRetryOn(err: unknown): boolean {
  if (!err) return false;
  if (typeof err === "object" && err !== null) {
    const anyErr = err as any;
    const status = anyErr.status as number | undefined;
    if (typeof status === "number") {
      // retry on common transient errors + rate limiting
      return status === 429 || (status >= 500 && status <= 599);
    }
    // Node fetch network error typically has code
    const code = anyErr.code as string | undefined;
    if (
      code &&
      ["ECONNRESET", "ETIMEDOUT", "EAI_AGAIN", "ENOTFOUND"].includes(code)
    )
      return true;
  }
  return false;
}

export async function retry<T>(
  fn: () => Promise<T>,
  opts: RetryOptions,
): Promise<T> {
  const retryOn = opts.retryOn ?? defaultRetryOn;

  let attempt = 0;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    try {
      return await fn();
    } catch (err) {
      attempt += 1;
      if (attempt > opts.retries || !retryOn(err)) throw err;

      // Honor Retry-After if present (common for 429)
      let waitMs: number | undefined;
      const anyErr = err as any;
      const retryAfter = anyErr.retryAfter as string | number | undefined;
      if (retryAfter !== undefined) {
        if (typeof retryAfter === "number") waitMs = retryAfter * 1000;
        if (typeof retryAfter === "string") {
          const n = Number(retryAfter);
          if (!Number.isNaN(n)) waitMs = n * 1000;
        }
      }

      const exp = Math.min(
        opts.maxDelayMs,
        opts.minDelayMs * Math.pow(opts.factor, attempt - 1),
      );
      const jitter = exp * opts.jitter * Math.random();
      const delay = waitMs ?? Math.min(opts.maxDelayMs, exp + jitter);
      await sleep(delay);
    }
  }
}
