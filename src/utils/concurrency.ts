/** Process items concurrently with worker pool */
export async function processWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  processor: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  if (!items.length) return [];

  const results: R[] = new Array(items.length);
  let idx = 0;

  const workers = Array.from(
    { length: Math.min(Math.max(1, concurrency), items.length) },
    async () => {
      let i: number;
      while ((i = idx++) < items.length) {
        results[i] = await processor(items[i]!, i);
      }
    },
  );

  await Promise.all(workers);
  return results;
}

/** Process items concurrently, flatten results */
export async function processWithConcurrencyFlat<T, R>(
  items: T[],
  concurrency: number,
  processor: (item: T, index: number) => Promise<R[]>,
): Promise<R[]> {
  return (await processWithConcurrency(items, concurrency, processor)).flat();
}

/** Process items concurrently (side effects only) */
export async function processWithConcurrencyVoid<T>(
  items: T[],
  concurrency: number,
  processor: (item: T, index: number) => Promise<void>,
): Promise<void> {
  if (!items.length) return;

  let idx = 0;

  await Promise.all(
    Array.from(
      { length: Math.min(Math.max(1, concurrency), items.length) },
      async () => {
        let i: number;
        while ((i = idx++) < items.length) {
          await processor(items[i]!, i);
        }
      },
    ),
  );
}
