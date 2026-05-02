/**
 * File Compression Utilities
 *
 * Provides gzip compression and decompression for static vulnerability database files.
 * Handles transparent read/write of both compressed (.gz) and uncompressed formats.
 */

import { createReadStream, createWriteStream } from "fs";
import { readFile, writeFile, readdir, stat, unlink, access } from "fs/promises";
import { createGzip, createGunzip, constants as zlibConstants } from "zlib";
import { pipeline } from "stream/promises";
import { join } from "path";
import type { StorageStats, ReadWithRawResult } from "./types";
import { errorMessage, isNodeError } from "../../utils/error";

// ============================================================================
// Constants
// ============================================================================

const COMPRESSION_THRESHOLD = 1024; // 1KB

// ============================================================================
// Internal Helpers
// ============================================================================

/**
 * Check if a file exists.
 */
async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch (err) {
    if (isNodeError(err) && err.code === "ENOENT") {
      return false;
    }
    console.warn(`Unexpected error checking file existence for ${path}: ${errorMessage(err)}`);
    return false;
  }
}

/**
 * Decompress a gzip buffer.
 */
async function decompressBuffer(buffer: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const gunzip = createGunzip();
    const chunks: Buffer[] = [];

    gunzip.on("data", (chunk: Buffer) => chunks.push(chunk));
    gunzip.on("end", () => resolve(Buffer.concat(chunks)));
    gunzip.on("error", (err) => {
      gunzip.destroy();
      reject(new Error(`Gzip decompression failed: ${errorMessage(err)}`));
    });

    gunzip.write(buffer);
    gunzip.end();
  });
}

/**
 * Compress a buffer with gzip.
 */
async function compressBuffer(buffer: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const gzip = createGzip({
      level: zlibConstants.Z_BEST_COMPRESSION,
    });
    const chunks: Buffer[] = [];

    gzip.on("data", (chunk: Buffer) => chunks.push(chunk));
    gzip.on("end", () => resolve(Buffer.concat(chunks)));
    gzip.on("error", (err) => {
      gzip.destroy();
      reject(err);
    });

    gzip.write(buffer);
    gzip.end();
  });
}

/**
 * Process a single shard file for compression.
 */
async function processShardFile(filePath: string): Promise<{
  processed: boolean;
  originalSize: number;
  compressedSize: number;
}> {
  const stats = await stat(filePath);
  const originalSize = stats.size;

  if (originalSize <= COMPRESSION_THRESHOLD) {
    return { processed: false, originalSize, compressedSize: originalSize };
  }

  const content = await readFile(filePath, "utf-8");
  const data = JSON.parse(content);
  const result = await writeMaybeCompressed(filePath, data, { compress: true });

  return {
    processed: true,
    originalSize,
    compressedSize: result.size,
  };
}

// ============================================================================
// File Compression
// ============================================================================

/**
 * Compress a file using gzip.
 */
export async function compressFile(inputPath: string): Promise<string> {
  const outputPath = `${inputPath}.gz`;

  const source = createReadStream(inputPath);
  const destination = createWriteStream(outputPath);
  const gzip = createGzip({
    level: zlibConstants.Z_BEST_COMPRESSION,
  });

  await pipeline(source, gzip, destination);

  return outputPath;
}

/**
 * Decompress a gzip file.
 */
export async function decompressFile(inputPath: string): Promise<string> {
  if (!inputPath.endsWith(".gz")) {
    throw new Error("File must have .gz extension");
  }

  const outputPath = inputPath.slice(0, -3);

  const source = createReadStream(inputPath);
  const destination = createWriteStream(outputPath);
  const gunzip = createGunzip();

  await pipeline(source, gunzip, destination);

  return outputPath;
}

// ============================================================================
// Smart Read/Write (Transparent Compression)
// ============================================================================

/**
 * Read a file, handling both compressed and uncompressed formats.
 * Also returns the raw file bytes and actual path for integrity verification.
 */
export async function readMaybeCompressedWithRaw<T>(
  basePath: string,
): Promise<ReadWithRawResult<T> | null> {
  // Try compressed version first (more efficient)
  const gzPath = `${basePath}.gz`;
  try {
    const rawBytes = await readFile(gzPath);
    const decompressed = await decompressBuffer(rawBytes);
    return {
      data: JSON.parse(decompressed.toString("utf-8")) as T,
      rawBytes,
      actualPath: gzPath,
    };
  } catch (err) {
    if (!isNodeError(err) || err.code !== "ENOENT") {
      throw err;
    }
  }

  // Fall back to uncompressed
  try {
    const rawBytes = await readFile(basePath);
    return {
      data: JSON.parse(rawBytes.toString("utf-8")) as T,
      rawBytes,
      actualPath: basePath,
    };
  } catch (err) {
    if (!isNodeError(err) || err.code !== "ENOENT") {
      throw err;
    }
  }

  return null;
}

/**
 * Read a file, handling both compressed and uncompressed formats.
 */
export async function readMaybeCompressed<T>(basePath: string): Promise<T | null> {
  // Try compressed version first (more efficient)
  // Use try/catch on readFile directly instead of pre-checking with fileExists
  const gzPath = `${basePath}.gz`;
  try {
    const gzBuffer = await readFile(gzPath);
    const decompressed = await decompressBuffer(gzBuffer);
    return JSON.parse(decompressed.toString("utf-8")) as T;
  } catch (err) {
    if (!isNodeError(err) || err.code !== "ENOENT") {
      throw err;
    }
  }

  // Fall back to uncompressed
  try {
    const content = await readFile(basePath, "utf-8");
    return JSON.parse(content) as T;
  } catch (err) {
    if (!isNodeError(err) || err.code !== "ENOENT") {
      throw err;
    }
  }

  return null;
}

/**
 * Write a file, optionally compressing if above threshold.
 */
export async function writeMaybeCompressed(
  basePath: string,
  data: unknown,
  options?: { compress?: boolean; threshold?: number }
): Promise<{ compressed: boolean; size: number }> {
  const json = JSON.stringify(data);
  const buffer = Buffer.from(json, "utf-8");
  const threshold = options?.threshold ?? COMPRESSION_THRESHOLD;

  // Determine if we should compress
  const shouldCompress = options?.compress ?? buffer.length > threshold;

  if (shouldCompress) {
    const gzPath = `${basePath}.gz`;
    const compressedBuffer = await compressBuffer(buffer);

    // Only use compressed if it's actually smaller
    if (compressedBuffer.length < buffer.length) {
      await writeFile(gzPath, compressedBuffer);

      // Remove uncompressed version if it exists
      if (await fileExists(basePath)) {
        await unlink(basePath);
      }

      return { compressed: true, size: compressedBuffer.length };
    }
  }

  // Write uncompressed
  await writeFile(basePath, buffer);

  // Remove compressed version if it exists
  const gzPath = `${basePath}.gz`;
  if (await fileExists(gzPath)) {
    await unlink(gzPath);
  }

  return { compressed: false, size: buffer.length };
}

// ============================================================================
// Database-Level Operations
// ============================================================================

/**
 * Compress the entire static database.
 */
export async function compressDatabase(dataPath: string): Promise<{
  filesProcessed: number;
  bytesOriginal: number;
  bytesCompressed: number;
  compressionRatio: number;
}> {
  let filesProcessed = 0;
  let bytesOriginal = 0;
  let bytesCompressed = 0;

  // Process index file
  const indexPath = join(dataPath, "index.json");
  if (await fileExists(indexPath)) {
    const stats = await stat(indexPath);
    bytesOriginal += stats.size;

    if (stats.size > COMPRESSION_THRESHOLD) {
      const content = await readFile(indexPath, "utf-8");
      const data = JSON.parse(content);
      const result = await writeMaybeCompressed(indexPath, data, { compress: true });
      bytesCompressed += result.size;
      filesProcessed++;
    } else {
      bytesCompressed += stats.size;
    }
  }

  // Process all package shards
  const entries = await readdir(dataPath, { withFileTypes: true });

  for (const entry of entries) {
    if (entry.isDirectory()) {
      // Handle scoped packages (@scope/)
      const scopedPath = join(dataPath, entry.name);
      const scopedEntries = await readdir(scopedPath, { withFileTypes: true });

      for (const scopedEntry of scopedEntries) {
        if (scopedEntry.isFile() && scopedEntry.name.endsWith(".json")) {
          const filePath = join(scopedPath, scopedEntry.name);
          const result = await processShardFile(filePath);
          filesProcessed += result.processed ? 1 : 0;
          bytesOriginal += result.originalSize;
          bytesCompressed += result.compressedSize;
        }
      }
    } else if (entry.isFile() && entry.name.endsWith(".json") && entry.name !== "index.json") {
      const filePath = join(dataPath, entry.name);
      const result = await processShardFile(filePath);
      filesProcessed += result.processed ? 1 : 0;
      bytesOriginal += result.originalSize;
      bytesCompressed += result.compressedSize;
    }
  }

  return {
    filesProcessed,
    bytesOriginal,
    bytesCompressed,
    compressionRatio: bytesOriginal > 0 ? bytesCompressed / bytesOriginal : 1,
  };
}

/**
 * Calculate storage statistics for the database.
 */
export async function getStorageStats(dataPath: string): Promise<StorageStats> {
  let totalBytes = 0;
  let shardCount = 0;
  let compressedCount = 0;
  let uncompressedCount = 0;
  let indexSize = 0;
  let shardSize = 0;
  let compressedSize = 0;
  let originalSizeEstimate = 0;

  // Check index files
  const indexJsonPath = join(dataPath, "index.json");
  const indexGzPath = join(dataPath, "index.json.gz");

  if (await fileExists(indexGzPath)) {
    const stats = await stat(indexGzPath);
    indexSize = stats.size;
    compressedCount++;
    compressedSize += stats.size;
    // Estimate original size (typical JSON compression ratio ~3-5x)
    originalSizeEstimate += stats.size * 4;
  } else if (await fileExists(indexJsonPath)) {
    const stats = await stat(indexJsonPath);
    indexSize = stats.size;
    uncompressedCount++;
  }
  totalBytes += indexSize;

  // Process all shard files
  const processDirectory = async (dirPath: string): Promise<void> => {
    let entries: { name: string; isDirectory(): boolean; isFile(): boolean }[];
    try {
      entries = await readdir(dirPath, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const entryName = String(entry.name);
      const fullPath = join(dirPath, entryName);

      if (entry.isDirectory()) {
        await processDirectory(fullPath);
      } else if (entry.isFile()) {
        const stats = await stat(fullPath);

        if (entryName.endsWith(".json.gz")) {
          shardCount++;
          compressedCount++;
          compressedSize += stats.size;
          shardSize += stats.size;
          totalBytes += stats.size;
          originalSizeEstimate += stats.size * 4;
        } else if (entryName.endsWith(".json") && entryName !== "index.json") {
          shardCount++;
          uncompressedCount++;
          shardSize += stats.size;
          totalBytes += stats.size;
          originalSizeEstimate += stats.size;
        }
      }
    }
  };

  await processDirectory(dataPath);

  return {
    totalBytes,
    shardCount,
    compressedCount,
    uncompressedCount,
    breakdown: {
      index: indexSize,
      shards: shardSize,
      compressed: compressedSize,
    },
    avgShardSize: shardCount > 0 ? Math.round(shardSize / shardCount) : 0,
    compressionRatio:
      compressedSize > 0 && originalSizeEstimate > 0
        ? compressedSize / originalSizeEstimate
        : undefined,
  };
}
