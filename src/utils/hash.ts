import crypto from "node:crypto";

export const sha256Hex = (input: string) =>
  crypto.createHash("sha256").update(input).digest("hex");

export const isSha512Integrity = (integrity: string) => integrity.startsWith("sha512-");

export function parseSubresourceIntegrity(
  integrity: string,
): { algorithm: string; digestBase64: string } | null {
  const idx = integrity.indexOf("-");
  if (idx <= 0) return null;
  return { algorithm: integrity.slice(0, idx), digestBase64: integrity.slice(idx + 1) };
}
