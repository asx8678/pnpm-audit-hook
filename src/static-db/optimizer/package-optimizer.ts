/**
 * Package Optimization Functions
 *
 * Provides functions to convert between full package shard data
 * and compact optimized package data for storage efficiency.
 */

import type { StaticVulnerability, PackageShard } from "../types";
import type { OptimizedPackageData } from "./types";
import { compressDate, expandDate } from "./date-utils";
import { optimizeVulnerability, expandVulnerability } from "./vulnerability-optimizer";

// ============================================================================
// Package Optimization Functions
// ============================================================================

/**
 * Optimize a package's vulnerability data.
 */
export function optimizePackageData(vulns: StaticVulnerability[]): OptimizedPackageData {
  if (vulns.length === 0) {
    return {
      pkg: "",
      upd: compressDate(new Date().toISOString()) ?? "",
      v: [],
    };
  }

  const firstVuln = vulns[0];
  const packageName = firstVuln?.packageName ?? "";
  const optimizedVulns = vulns.map((v) => optimizeVulnerability(v));

  // Sort by publication date descending
  optimizedVulns.sort((a, b) => (b.pub || "").localeCompare(a.pub || ""));

  return {
    pkg: packageName,
    upd: compressDate(new Date().toISOString()) ?? "",
    v: optimizedVulns,
  };
}

/**
 * Expand optimized package data back to full format.
 */
export function expandPackageData(opt: OptimizedPackageData): PackageShard {
  return {
    packageName: opt.pkg,
    lastUpdated: expandDate(opt.upd) ?? "",
    vulnerabilities: opt.v.map((v) => expandVulnerability(v, opt.pkg)),
  };
}
