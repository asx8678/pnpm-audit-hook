import type { AuditConfig, VulnerabilityFinding } from "../types";

export interface AllowlistMatch {
  approvedBy: string;
  reason: string;
  expires: string;
}

function normalizeId(id: string): string {
  return id.trim().toUpperCase();
}

export function isAllowlistEntryExpired(
  expires: string,
  now: Date = new Date(),
): boolean {
  // expires in YYYY-MM-DD, treat as end of that day in local time
  const m = expires.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!m) return true;
  const y = Number(m[1]);
  const mo = Number(m[2]) - 1;
  const d = Number(m[3]);
  const exp = new Date(y, mo, d, 23, 59, 59, 999);
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
