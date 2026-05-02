import crypto from "node:crypto";

/**
 * Compute a SHA-256 integrity hash from raw file bytes.
 * Returns the hash in "sha256-<hex>" format, matching SRI conventions.
 */
export function computeShardHash(rawBytes: Buffer): string {
  const hex = crypto.createHash("sha256").update(rawBytes).digest("hex");
  return `sha256-${hex}`;
}
