/**
 * Process items concurrently with a worker pool.
 * Uses atomic index access to prevent race conditions.
 *
 * @param items - Array of items to process
 * @param concurrency - Maximum number of concurrent workers
 * @param processor - Async function to process each item
 * @returns Array of results in the same order as input items
 */
export async function processWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  processor: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  if (items.length === 0) return [];

  const results: R[] = new Array(items.length);
  let idx = 0;
  const getNextIndex = () => idx++;

  const workers = new Array(Math.min(Math.max(1, concurrency), items.length))
    .fill(0)
    .map(async () => {
      let myIdx: number;
      while ((myIdx = getNextIndex()) < items.length) {
        results[myIdx] = await processor(items[myIdx]!, myIdx);
      }
    });

  await Promise.all(workers);
  return results;
}

/**
 * Process items concurrently, collecting results into a single array.
 * Useful when each item produces zero or more results.
 *
 * @param items - Array of items to process
 * @param concurrency - Maximum number of concurrent workers
 * @param processor - Async function that returns an array of results for each item
 * @returns Flattened array of all results
 */
export async function processWithConcurrencyFlat<T, R>(
  items: T[],
  concurrency: number,
  processor: (item: T, index: number) => Promise<R[]>,
): Promise<R[]> {
  const results = await processWithConcurrency(items, concurrency, processor);
  return results.flat();
}

/**
 * Process items concurrently without collecting results.
 * Useful for side-effect operations like populating a Map or Set.
 *
 * @param items - Array of items to process
 * @param concurrency - Maximum number of concurrent workers
 * @param processor - Async function to process each item
 */
export async function processWithConcurrencyVoid<T>(
  items: T[],
  concurrency: number,
  processor: (item: T, index: number) => Promise<void>,
): Promise<void> {
  if (items.length === 0) return;

  let idx = 0;
  const getNextIndex = () => idx++;

  const workers = new Array(Math.min(Math.max(1, concurrency), items.length))
    .fill(0)
    .map(async () => {
      let myIdx: number;
      while ((myIdx = getNextIndex()) < items.length) {
        await processor(items[myIdx]!, myIdx);
      }
    });

  await Promise.all(workers);
}
