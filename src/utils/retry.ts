export interface RetryOptions {
  retries: number;
  minDelayMs: number;
  maxDelayMs: number;
  factor: number;
  jitter: number;
  retryOn?: (err: unknown) => boolean;
}

export const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

const RETRY_CODES = new Set(["ECONNRESET", "ETIMEDOUT", "EAI_AGAIN", "ENOTFOUND"]);

function defaultRetryOn(err: unknown): boolean {
  if (!err || typeof err !== "object") return false;
  const { status, code } = err as any;
  if (typeof status === "number") return status === 429 || (status >= 500 && status <= 599);
  return typeof code === "string" && RETRY_CODES.has(code);
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

      const ra = (err as any).retryAfter;
      const waitMs = (typeof ra === "number" || (typeof ra === "string" && !Number.isNaN(+ra))) ? +ra * 1000 : undefined;

      const exp = Math.min(opts.maxDelayMs, opts.minDelayMs * opts.factor ** (attempt - 1));
      await sleep(waitMs ?? Math.min(opts.maxDelayMs, exp + exp * opts.jitter * Math.random()));
    }
  }
}
