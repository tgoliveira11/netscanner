/** Run an async mapper over items with a bounded worker pool. */
export async function mapPool<T>(
  items: readonly T[],
  limit: number,
  worker: (item: T) => Promise<void>,
  signal?: AbortSignal,
): Promise<void> {
  let index = 0;
  const size = Math.max(1, limit);
  const runners = Array.from({ length: Math.min(size, items.length) }, async () => {
    while (index < items.length) {
      if (signal?.aborted) return;
      const current = items[index++]!;
      await worker(current);
    }
  });
  await Promise.all(runners);
}
