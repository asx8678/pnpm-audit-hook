/**
 * Constants and enum mappings for the static database optimizer.
 */

import type { Severity, FindingSource } from "../../types";

// ============================================================================
// Enum Mappings
// ============================================================================

/**
 * Maps severity strings to numeric indices for compact storage.
 */
export const SEVERITY_TO_INDEX: Record<Severity, number> = {
  unknown: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/**
 * Maps numeric indices back to severity strings.
 */
export const INDEX_TO_SEVERITY: Severity[] = ["unknown", "low", "medium", "high", "critical"];

/**
 * Maps finding source strings to numeric indices for compact storage.
 */
export const SOURCE_TO_INDEX: Record<FindingSource, number> = {
  github: 0,
  nvd: 1,
  osv: 2,
};

/**
 * Maps numeric indices back to finding source strings.
 */
export const INDEX_TO_SOURCE: FindingSource[] = ["github", "nvd", "osv"];

// ============================================================================
// Compression Constants
// ============================================================================

/**
 * Minimum file size in bytes before compression is applied.
 */
export const COMPRESSION_THRESHOLD = 1024; // 1KB