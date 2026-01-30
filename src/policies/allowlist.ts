import type { AuditConfig, VulnerabilityFinding } from "../types";

export interface AllowlistMatch {
  approvedBy: string;
  reason: string;
  expires: string;
}

const normalizeId = (id: string): string => id.trim().toUpperCase();

export function isAllowlistEntryExpired(expires: string, now: Date = new Date()): boolean {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(expires);
  if (!m) return true;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const exp = new Date(y, mo - 1, d, 23, 59, 59, 999);
  return now.getTime() > exp.getTime();
}

export function matchAllowlist(
  finding: VulnerabilityFinding,
  cfg: AuditConfig["policies"],
  now: Date = new Date(),
): AllowlistMatch | null {
  const fid = normalizeId(finding.id);
  const pkg = finding.packageName;

  for (const entry of cfg.allowlist) {
    if (entry.package !== pkg) continue;

    const entryId = entry.cve ?? entry.id;
    if (!entryId) continue;
    if (normalizeId(entryId) !== fid) continue;

    if (isAllowlistEntryExpired(entry.expires, now)) continue;

    return {
      approvedBy: entry.approvedBy,
      reason: entry.reason,
      expires: entry.expires,
    };
  }

  return null;
}
