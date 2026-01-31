/**
 * Static Vulnerability Database Types
 *
 * Schema for storing historical npm vulnerabilities (2020-2025) in a static,
 * file-based database optimized for fast lookups and efficient storage.
 */

import type { Severity, VulnerabilityIdentifier, FindingSource } from "../types";

// ============================================================================
// Core Vulnerability Types
// ============================================================================

/**
 * Represents a single affected version range for a vulnerability.
 * Stored compactly to minimize duplication across packages.
 */
export interface AffectedVersionRange {
  /** Semver range (e.g., ">=1.0.0 <1.2.6", "<2.0.0") */
  range: string;
  /** First patched version, if known */
  fixed?: string;
}

/**
 * A single vulnerability entry in the static database.
 * Compatible with VulnerabilityFinding from src/types.ts.
 */
export interface StaticVulnerability {
  /** Canonical vulnerability ID (e.g., CVE-2021-44228, GHSA-xxxx-xxxx-xxxx) */
  id: string;
  /** Package name this vulnerability affects */
  packageName: string;
  /** Severity level */
  severity: Severity;
  /** ISO date string when vulnerability was published */
  publishedAt?: string;
  /** ISO date string when vulnerability was last modified */
  modifiedAt?: string;
  /** Affected version ranges for this package */
  affectedVersions: AffectedVersionRange[];
  /** Original data source */
  source: FindingSource;
  /** Human-readable title/summary */
  title?: string;
  /** URL for more information */
  url?: string;
  /** Description of the vulnerability */
  description?: string;
  /** Additional identifiers (CVE, GHSA, etc.) */
  identifiers?: VulnerabilityIdentifier[];
}

// ============================================================================
// Package Shard Types (individual package files)
// ============================================================================

/**
 * Package vulnerability file structure.
 * Stored as: data/{package-name}.json (scoped: data/@scope/package.json)
 */
export interface StaticPackageData {
  /** Package name (for validation) */
  name: string;
  /** ISO date string when this package's data was last updated */
  lastUpdated: string;
  /** List of vulnerabilities affecting this package, sorted by publishedAt desc */
  vulnerabilities: StaticVulnerability[];
}

/**
 * Alias for StaticPackageData - used by optimizer for expanded format.
 * A single package shard file containing all vulnerabilities for one package.
 */
export interface PackageShard {
  /** Package name (for validation) */
  packageName: string;
  /** ISO date string when this shard was last updated */
  lastUpdated: string;
  /** All vulnerabilities affecting this package, sorted by publishedAt desc */
  vulnerabilities: StaticVulnerability[];
}

// ============================================================================
// Index Types (for fast O(1) lookups)
// ============================================================================

/**
 * Entry in the package index for quick existence checks and filtering.
 */
export interface PackageIndexEntry {
  /** Number of known vulnerabilities for this package */
  count: number;
  /** ISO date string of most recent vulnerability */
  latestVuln?: string;
  /** Highest severity among all vulnerabilities */
  maxSeverity: Severity;
}

/**
 * Main index file containing metadata and package listing.
 * Stored as: data/index.json
 */
export interface StaticDbIndex {
  /** Schema version for forward compatibility */
  schemaVersion: number;
  /** ISO date string when the database was last built */
  lastUpdated: string;
  /** ISO date string - vulnerabilities published before this date are included */
  cutoffDate: string;
  /** Total number of vulnerabilities in the database */
  totalVulnerabilities: number;
  /** Total number of packages with vulnerabilities */
  totalPackages: number;
  /**
   * Map of package names to their index entries.
   * Enables O(1) lookup to check if a package has known vulnerabilities.
   */
  packages: Record<string, PackageIndexEntry>;
  /** Build metadata (optional) */
  buildInfo?: {
    /** Tool/script that generated this database */
    generator?: string;
    /** Source databases used (e.g., ["github-advisory"]) */
    sources?: string[];
    /** Build duration in milliseconds */
    durationMs?: number;
  };
}

// ============================================================================
// Runtime Database Interface
// ============================================================================

/**
 * Query options for looking up vulnerabilities.
 */
export interface StaticDbQueryOptions {
  /** Only return vulnerabilities published after this ISO date */
  publishedAfter?: string;
  /** Only return vulnerabilities published before this ISO date */
  publishedBefore?: string;
  /** Filter by minimum severity level */
  minSeverity?: Severity;
  /** Specific package version to match against affected ranges */
  version?: string;
}

/**
 * Result from a static database query.
 */
export interface StaticDbQueryResult {
  /** Matching vulnerabilities */
  vulnerabilities: StaticVulnerability[];
  /** Whether the package was found in the index */
  found: boolean;
  /** Time to execute query in milliseconds */
  durationMs: number;
}

// Re-export severity utilities from the canonical location
export { severityRank as severityLevel } from "../utils/severity";
