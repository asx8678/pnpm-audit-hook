import crypto from "node:crypto";

export const sha256Hex = (input: string) =>
  crypto.createHash("sha256").update(input).digest("hex");

export const isSha512Integrity = (integrity: string | null | undefined): boolean =>
  typeof integrity === "string" && integrity.startsWith("sha512-");
