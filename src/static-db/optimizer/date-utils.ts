// ============================================================================
// Date Compression
// ============================================================================

/**
 * Convert ISO 8601 timestamp to YYYY-MM-DD format.
 */
export function compressDate(isoDate: string | undefined): string | undefined {
  if (!isoDate) return undefined;

  // Already in YYYY-MM-DD format
  if (/^\d{4}-\d{2}-\d{2}$/.test(isoDate)) {
    return isoDate;
  }

  // Parse ISO 8601 and extract date portion
  const match = isoDate.match(/^(\d{4}-\d{2}-\d{2})/);
  if (match) {
    return match[1];
  }

  // Try parsing as Date
  const date = new Date(isoDate);
  if (!isNaN(date.getTime())) {
    return date.toISOString().slice(0, 10);
  }

  return isoDate;
}

/**
 * Expand YYYY-MM-DD to ISO 8601 format (midnight UTC).
 */
export function expandDate(compressedDate: string | undefined): string | undefined {
  if (!compressedDate) return undefined;

  // Already in ISO format
  if (compressedDate.includes("T")) {
    return compressedDate;
  }

  // YYYY-MM-DD to ISO 8601
  if (/^\d{4}-\d{2}-\d{2}$/.test(compressedDate)) {
    return `${compressedDate}T00:00:00.000Z`;
  }

  return compressedDate;
}
