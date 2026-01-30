import crypto from "node:crypto";

export function sha256Hex(input: string): string {
  return crypto.createHash("sha256").update(input).digest("hex");
}

export function isSha512Integrity(integrity: string): boolean {
  return integrity.startsWith("sha512-");
}

export function parseSubresourceIntegrity(
  integrity: string,
): { algorithm: string; digestBase64: string } | null {
  const idx = integrity.indexOf("-");
  if (idx <= 0) return null;
  const algorithm = integrity.slice(0, idx);
  const digestBase64 = integrity.slice(idx + 1);
  if (!algorithm || !digestBase64) return null;
  return { algorithm, digestBase64 };
}
