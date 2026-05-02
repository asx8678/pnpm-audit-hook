import type { AffectedVersionRange } from "../types";

/**
 * Merge affected version ranges to remove overlaps.
 * Returns a single combined range string.
 */
export function mergeAffectedRanges(ranges: AffectedVersionRange[]): string {
  if (ranges.length === 0) return "*";
  if (ranges.length === 1) return ranges[0]?.range ?? "*";

  // Collect unique ranges, preserving order
  const uniqueRanges = new Set<string>();
  for (const r of ranges) {
    if (r.range && r.range.trim()) {
      uniqueRanges.add(r.range.trim());
    }
  }

  // Join with " || " for semver union
  return Array.from(uniqueRanges).join(" || ");
}

/**
 * Get the first fixed version from affected ranges.
 */
export function getFirstFixedVersion(ranges: AffectedVersionRange[]): string | undefined {
  for (const r of ranges) {
    if (r.fixed) return r.fixed;
  }
  return undefined;
}
