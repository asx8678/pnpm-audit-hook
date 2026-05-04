/**
 * Index Optimization Functions
 *
 * Provides functions to optimize and expand database index entries,
 * converting between the verbose PackageIndexEntry/StaticDbIndex formats
 * and the compact OptimizedIndexEntry/OptimizedIndex formats.
 */

import type { PackageIndexEntry, StaticDbIndex } from "../types";
import type { OptimizedIndexEntry, OptimizedIndex } from "./types";
import { SEVERITY_TO_INDEX, INDEX_TO_SEVERITY } from "./constants";
import { compressDate, expandDate } from "./date-utils";

// ============================================================================
// Index Entry Optimization
// ============================================================================

/**
 * Optimize an index entry.
 */
export function optimizeIndexEntry(entry: PackageIndexEntry): OptimizedIndexEntry {
  const opt: OptimizedIndexEntry = {
    c: entry.count,
    s: SEVERITY_TO_INDEX[entry.maxSeverity] ?? 0,
  };

  if (entry.latestVuln) {
    opt.l = compressDate(entry.latestVuln);
  }

  return opt;
}

/**
 * Expand an optimized index entry.
 */
export function expandIndexEntry(opt: OptimizedIndexEntry): PackageIndexEntry {
  const entry: PackageIndexEntry = {
    count: opt.c,
    maxSeverity: INDEX_TO_SEVERITY[opt.s] ?? "unknown",
  };

  if (opt.l) {
    entry.latestVuln = expandDate(opt.l);
  }

  return entry;
}

// ============================================================================
// Full Index Optimization
// ============================================================================

/**
 * Optimize the full database index.
 */
export function optimizeIndex(index: StaticDbIndex): OptimizedIndex {
  const packages: Record<string, OptimizedIndexEntry> = {};
  const pkgList: string[] = [];

  for (const [name, entry] of Object.entries(index.packages)) {
    packages[name] = optimizeIndexEntry(entry);
    pkgList.push(name);
  }

  // Sort package list for binary search
  pkgList.sort();

  const optimized: OptimizedIndex = {
    ver: index.schemaVersion,
    upd: compressDate(index.lastUpdated) ?? "",
    cut: compressDate(index.cutoffDate) ?? "",
    tv: index.totalVulnerabilities,
    tp: index.totalPackages,
    p: packages,
    pkgList,
  };

  if (index.coverage) {
    optimized.cov = index.coverage;
  }

  if (index.integrity) {
    optimized.int = index.integrity;
  }

  return optimized;
}

/**
 * Expand an optimized index back to full format.
 */
export function expandIndex(opt: OptimizedIndex): StaticDbIndex {
  const packages: Record<string, PackageIndexEntry> = {};

  for (const [name, entry] of Object.entries(opt.p)) {
    packages[name] = expandIndexEntry(entry);
  }

  const index: StaticDbIndex = {
    schemaVersion: opt.ver,
    lastUpdated: expandDate(opt.upd) ?? "",
    cutoffDate: expandDate(opt.cut) ?? "",
    totalVulnerabilities: opt.tv,
    totalPackages: opt.tp,
    packages,
  };

  if (opt.cov) {
    index.coverage = opt.cov;
  }

  if (opt.int) {
    index.integrity = opt.int;
  }

  return index;
}
