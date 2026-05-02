/**
 * Static Database Optimizer Runner
 *
 * Runs after copy-static-db.js to:
 *  1. Optimize the index (compact field names, enum-based severity/source)
 *  2. Compress package shards and index with gzip (.json.gz)
 *
 * Reader.ts already handles both .json.gz and .json transparently.
 */

const path = require("node:path");
const fs = require("node:fs/promises");
const crypto = require("node:crypto");

const DATA_DIR = path.join(__dirname, "..", "dist", "static-db", "data");

async function optimizeStaticDb() {
  // Lazy-import the compiled optimizer from dist/
  const { optimizeIndex, compressDatabase } = require(path.join(
    __dirname,
    "..",
    "dist",
    "static-db",
    "optimizer",
  ));

  // ------------------------------------------------------------------
  // 1. Optimize the index (compact format with short keys)
  // ------------------------------------------------------------------
  const indexPath = path.join(DATA_DIR, "index.json");
  let stats;

  try {
    stats = await fs.stat(indexPath);
  } catch (err) {
    console.error("Index file not found at", indexPath);
    throw err;
  }

  const raw = JSON.parse(await fs.readFile(indexPath, "utf-8"));
  const optimized = optimizeIndex(raw);

  await fs.writeFile(indexPath, JSON.stringify(optimized));
  const savedBytes = stats.size - Buffer.byteLength(JSON.stringify(optimized), "utf-8");

  console.log(
    `Optimized index: ${stats.size} → ${Buffer.byteLength(JSON.stringify(optimized), "utf-8")} bytes` +
      (savedBytes > 0 ? ` (saved ${savedBytes} bytes)` : ""),
  );

  // ------------------------------------------------------------------
  // 2. Compress the database (gzip .json → .json.gz)
  // ------------------------------------------------------------------
  const result = await compressDatabase(DATA_DIR);

  const ratio = (result.compressionRatio * 100).toFixed(1);
  console.log(
    `Compressed DB: ${result.filesProcessed} files, ` +
      `${result.bytesOriginal} → ${result.bytesCompressed} bytes ` +
      `(${ratio}% of original)`,
  );

  // ------------------------------------------------------------------
  // 3. Compute SHA-256 integrity hashes for all shard files
  // ------------------------------------------------------------------
  const { readMaybeCompressed: readDb, writeMaybeCompressed: writeDb, computeShardHash } = require(
    path.join(__dirname, "..", "dist", "static-db", "optimizer"),
  );

  const integrity = {};

  /**
   * Recursively walk the data directory and hash every shard file.
   * Skips index.json / index.json.gz — only package shards are hashed.
   */
  async function hashShardFiles(dir, prefix = "") {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      const relPath = prefix ? `${prefix}/${entry.name}` : entry.name;

      if (entry.isDirectory()) {
        await hashShardFiles(fullPath, relPath);
      } else if (
        entry.isFile() &&
        (entry.name.endsWith(".json.gz") || entry.name.endsWith(".json")) &&
        !entry.name.startsWith("index.")
      ) {
        const raw = await fs.readFile(fullPath);
        integrity[relPath] = computeShardHash(raw);
      }
    }
  }

  await hashShardFiles(DATA_DIR);
  console.log(`Computed integrity hashes for ${Object.keys(integrity).length} shard files`);

  // ------------------------------------------------------------------
  // 4. Inject integrity map into the index and write back
  // ------------------------------------------------------------------
  // The index is in optimized format (short keys like `ver`, `p`, etc.),
  // so we use the short key `int` for the integrity map.
  const optimizedIndex = await readDb(indexPath);
  if (optimizedIndex) {
    optimizedIndex.int = integrity;
    await writeDb(indexPath, optimizedIndex, { compress: true });
    console.log("Injected integrity map into index");
  }
}

optimizeStaticDb().catch((err) => {
  console.error(`Optimization failed: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
