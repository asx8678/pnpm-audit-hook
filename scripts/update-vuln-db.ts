#!/usr/bin/env tsx
/**
 * Static Vulnerability Database Builder
 *
 * Fetches npm package vulnerabilities from GitHub Advisory Database
 * and builds a static database for offline/fast lookups.
 *
 * Usage:
 *   npm run update-vuln-db                    # Full rebuild
 *   npm run update-vuln-db:incremental        # Update since last run
 *   npm run update-vuln-db -- --sample        # Generate sample data only
 *
 * Environment:
 *   GITHUB_TOKEN - GitHub PAT for higher rate limits (recommended)
 */

import * as fs from "fs";
import * as path from "path";

// Import canonical types from src/
import type {
  StaticVulnerability,
  StaticPackageData,
  StaticDbIndex,
  PackageIndexEntry,
  AffectedVersionRange,
} from "../src/static-db/types";
import type { Severity, VulnerabilityIdentifier } from "../src/types";

// Import pure helpers (extracted for testability)
import {
  mapSeverity,
  convertAdvisory,
  normalizePackageData,
  SEVERITY_RANK,
} from "./utils/update-vuln-db-helpers";
import type { GitHubAdvisory } from "./utils/update-vuln-db-helpers";

interface GraphQLResponse {
  data?: {
    securityAdvisories: {
      pageInfo: { hasNextPage: boolean; endCursor: string | null };
      nodes: GitHubAdvisory[];
    };
  };
  errors?: { message: string }[];
}

// Configuration
const DATA_DIR = path.join(__dirname, "..", "src", "static-db", "data");
/**
 * Shard path encoding scheme (must match src/static-db/reader.ts getShardPath):
 *   - Unscoped packages:  DATA_DIR/{name}.json          e.g. data/lodash.json
 *   - Scoped packages:    DATA_DIR/@scope/{name}.json    e.g. data/@angular/core.json
 */
const INDEX_FILE = path.join(DATA_DIR, "index.json");
const GITHUB_API = "https://api.github.com/graphql";
const DEFAULT_CUTOFF = "2025-12-31T23:59:59Z";
const BATCH_SIZE = 100;
const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 5000;

// Parse CLI args
const args = process.argv.slice(2);
const isIncremental = args.includes("--incremental");
const isSampleMode = args.includes("--sample");
const customCutoff = args.find((a) => a.startsWith("--cutoff="))?.split("=")[1];
const sinceDate = args.find((a) => a.startsWith("--since="))?.split("=")[1]; // Filter vulns published after this date

// Get GitHub token
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

function log(message: string): void {
  console.log(`[update-vuln-db] ${message}`);
}

function warn(message: string): void {
  console.warn(`[update-vuln-db] WARNING: ${message}`);
}

function error(message: string): void {
  console.error(`[update-vuln-db] ERROR: ${message}`);
}

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Fetch advisories from GitHub Advisory Database using GraphQL
 */
async function fetchAdvisories(
  cursor: string | null,
  updatedSince?: string,
): Promise<GraphQLResponse> {
  // GitHub Advisory GraphQL API - ecosystem filter only applies to vulnerabilities subquery
  const query = `
    query($first: Int!, $after: String${updatedSince ? ", $updatedSince: DateTime" : ""}) {
      securityAdvisories(
        first: $first
        after: $after
        ${updatedSince ? "updatedSince: $updatedSince" : ""}
        orderBy: { field: UPDATED_AT, direction: DESC }
      ) {
        pageInfo {
          hasNextPage
          endCursor
        }
        nodes {
          ghsaId
          summary
          description
          severity
          publishedAt
          updatedAt
          permalink
          identifiers {
            type
            value
          }
          vulnerabilities(first: 100, ecosystem: NPM) {
            nodes {
              package {
                name
                ecosystem
              }
              vulnerableVersionRange
              firstPatchedVersion {
                identifier
              }
            }
          }
        }
      }
    }
  `;

  const variables: Record<string, unknown> = {
    first: BATCH_SIZE,
    after: cursor,
  };

  if (updatedSince) {
    variables.updatedSince = updatedSince;
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "User-Agent": "pnpm-audit-hook/vuln-db-builder",
  };

  if (GITHUB_TOKEN) {
    headers["Authorization"] = `Bearer ${GITHUB_TOKEN}`;
  }

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const response = await fetch(GITHUB_API, {
        method: "POST",
        headers,
        body: JSON.stringify({ query, variables }),
      });

      if (response.status === 401) {
        throw new Error(
          "GitHub API authentication failed. Check your GITHUB_TOKEN.",
        );
      }

      if (response.status === 403) {
        const remaining = response.headers.get("x-ratelimit-remaining");
        const reset = response.headers.get("x-ratelimit-reset");
        if (remaining === "0" && reset) {
          const resetTime = new Date(parseInt(reset) * 1000);
          throw new Error(
            `Rate limited. Resets at ${resetTime.toISOString()}. Use GITHUB_TOKEN for higher limits.`,
          );
        }
        throw new Error("GitHub API forbidden. Check your token permissions.");
      }

      if (!response.ok) {
        throw new Error(`GitHub API error: ${response.status}`);
      }

      return (await response.json()) as GraphQLResponse;
    } catch (err) {
      if (attempt === MAX_RETRIES) {
        throw err;
      }
      warn(`Attempt ${attempt} failed, retrying in ${RETRY_DELAY_MS}ms...`);
      await sleep(RETRY_DELAY_MS);
    }
  }

  throw new Error("Max retries exceeded");
}

// mapSeverity, SEVERITY_RANK, and convertAdvisory are now imported from ./utils/update-vuln-db-helpers

/**
 * Load existing index if available
 */
function loadExistingIndex(): StaticDbIndex | null {
  try {
    if (fs.existsSync(INDEX_FILE)) {
      return JSON.parse(fs.readFileSync(INDEX_FILE, "utf-8"));
    }
  } catch {
    // Ignore errors, will rebuild
  }
  return null;
}

/**
 * Load existing package data if available
 */
function getPackageShardPath(packageName: string): string {
  // Scoped packages use a subdirectory: @scope/name -> DATA_DIR/@scope/name.json
  if (packageName.startsWith("@")) {
    const slashIdx = packageName.indexOf("/");
    if (slashIdx !== -1) {
      const scope = packageName.slice(0, slashIdx);
      const name = packageName.slice(slashIdx + 1);
      return path.join(DATA_DIR, scope, `${name}.json`);
    }
  }
  // Unscoped packages live directly in DATA_DIR: name -> DATA_DIR/name.json
  return path.join(DATA_DIR, `${packageName}.json`);
}

function loadExistingPackageData(packageName: string): StaticPackageData | null {
  const filePath = getPackageShardPath(packageName);
  try {
    if (fs.existsSync(filePath)) {
      const raw = JSON.parse(fs.readFileSync(filePath, "utf-8")) as unknown;
      return normalizePackageData(raw, packageName);
    }
  } catch {
    // Ignore errors
  }
  return null;
}

// normalizePackageData is now imported from ./utils/update-vuln-db-helpers

/**
 * Save package data to file
 */
function savePackageData(data: StaticPackageData): void {
  const filePath = getPackageShardPath(data.packageName);
  // Ensure parent directory exists (needed for scoped packages like @scope/)
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

/**
 * Load sample vulnerability data from fixture file (for testing without API calls)
 */
function generateSampleData(): Map<string, StaticVulnerability[]> {
  const vulns = new Map<string, StaticVulnerability[]>();
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const sampleVulns: Array<{
    pkg: string;
    vulns: Array<{
      id: string;
      title?: string;
      description?: string;
      severity: "critical" | "high" | "medium" | "low" | "unknown";
      url?: string;
      publishedAt?: string;
      modifiedAt?: string;
      identifiers?: { type: string; value: string }[];
      affectedRange: string;
      fixedVersion?: string;
    }>;
  }> = require("./fixtures/sample-vulns.json");

  for (const item of sampleVulns) {
    const normalized: StaticVulnerability[] = item.vulns.map((v) => ({
      id: v.id,
      packageName: item.pkg,
      title: v.title,
      description: v.description,
      severity: v.severity as StaticVulnerability["severity"],
      url: v.url,
      publishedAt: v.publishedAt,
      modifiedAt: v.modifiedAt,
      identifiers: v.identifiers as VulnerabilityIdentifier[] | undefined,
      affectedVersions: [
        {
          range: v.affectedRange,
          ...(v.fixedVersion !== undefined ? { fixed: v.fixedVersion } : {}),
        } as AffectedVersionRange,
      ],
      source: "github" as const,
    }));
    vulns.set(item.pkg, normalized);
  }

  return vulns;
}

/**
 * Main function to build or update the static vulnerability database
 */
async function main(): Promise<void> {
  const startTime = Date.now();
  const cutoffDate = customCutoff || DEFAULT_CUTOFF;

  log(`Starting vulnerability database build`);
  log(`  Mode: ${isIncremental ? "incremental" : isSampleMode ? "sample" : "full"}`);
  log(`  Cutoff date: ${cutoffDate}`);
  if (sinceDate) {
    log(`  Only including vulns published after: ${sinceDate}`);
  }
  log(`  GitHub token: ${GITHUB_TOKEN ? "configured" : "not set (rate limits apply)"}`);

  // Ensure directories exist
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  // DATA_DIR is created above; scope subdirectories are created on demand by savePackageData

  // Load existing index for incremental updates
  const existingIndex = loadExistingIndex();
  let updatedSince: string | undefined;

  if (isIncremental && existingIndex) {
    updatedSince = existingIndex.lastUpdated;
    log(`  Incremental update from: ${updatedSince}`);
  }

  // Map to accumulate vulnerabilities by package
  const packageVulns = new Map<string, StaticVulnerability[]>();

  // If incremental, load existing package data
  if (isIncremental && existingIndex) {
    for (const pkgName of Object.keys(existingIndex.packages)) {
      const existingData = loadExistingPackageData(pkgName);
      if (existingData) {
        packageVulns.set(pkgName, existingData.vulnerabilities);
      }
    }
  }

  if (isSampleMode) {
    // Use sample data instead of API
    log("Using sample vulnerability data (50 popular packages)");
    const sampleData = generateSampleData();
    for (const [pkg, vulns] of sampleData) {
      const existing = packageVulns.get(pkg) || [];
      const existingIds = new Set(existing.map((v) => v.id));
      for (const v of vulns) {
        if (!existingIds.has(v.id)) {
          existing.push(v);
          existingIds.add(v.id);
        }
      }
      packageVulns.set(pkg, existing);
    }
  } else {
    // Fetch from GitHub Advisory Database
    let cursor: string | null = null;
    let totalAdvisories = 0;
    let page = 1;

    do {
      log(`Fetching page ${page}...`);
      let response: GraphQLResponse;

      try {
        response = await fetchAdvisories(cursor, updatedSince);
      } catch (err) {
        error(String(err));
        if (!GITHUB_TOKEN) {
          log("Tip: Set GITHUB_TOKEN environment variable for higher rate limits.");
          log("Falling back to sample data mode...");
          const sampleData = generateSampleData();
          for (const [pkg, vulns] of sampleData) {
            packageVulns.set(pkg, vulns);
          }
          break;
        }
        throw err;
      }

      if (response.errors) {
        error(`GraphQL errors: ${JSON.stringify(response.errors)}`);
        break;
      }

      if (!response.data) {
        error("No data in response");
        break;
      }

      const advisories = response.data.securityAdvisories;

      for (const advisory of advisories.nodes) {
        // Skip advisories published before --since date
        if (sinceDate && advisory.publishedAt && advisory.publishedAt < sinceDate) {
          continue;
        }

        // Filter for NPM packages only
        const npmVulns = advisory.vulnerabilities.nodes.filter(
          (v) => v.package.ecosystem === "NPM",
        );

        for (const vuln of npmVulns) {
          const { packageName, entry } = convertAdvisory(advisory, vuln);
          const existing = packageVulns.get(packageName) || [];

          // Check for duplicate
          if (!existing.some((e) => e.id === entry.id)) {
            existing.push(entry);
            packageVulns.set(packageName, existing);
          }
        }

        totalAdvisories++;
      }

      cursor = advisories.pageInfo.endCursor;
      page++;

      // Progress logging
      if (totalAdvisories % 500 === 0) {
        log(`  Processed ${totalAdvisories} advisories, ${packageVulns.size} packages`);
      }

      // Rate limit protection - small delay between requests
      if (!GITHUB_TOKEN) {
        await sleep(100);
      }
    } while (cursor);

    log(`Fetched ${totalAdvisories} advisories affecting ${packageVulns.size} packages`);
  }

  // Calculate totals
  let totalVulns = 0;
  for (const vulns of packageVulns.values()) {
    totalVulns += vulns.length;
  }

  // Save package files
  const now = new Date().toISOString();
  const packagesIndex: Record<string, PackageIndexEntry> = {};

  for (const [pkgName, vulns] of packageVulns) {
    const pkgData: StaticPackageData = {
      packageName: pkgName,
      lastUpdated: now,
      vulnerabilities: vulns,
    };
    savePackageData(pkgData);
    const maxSeverity = vulns.reduce<Severity>(
      (max, v) => (SEVERITY_RANK[v.severity] > SEVERITY_RANK[max] ? v.severity : max),
      "unknown",
    );
    const latestVuln = vulns.reduce<string | undefined>((latest, v) => {
      const candidate = v.publishedAt ?? v.modifiedAt;
      if (!candidate) return latest;
      if (!latest) return candidate;
      return new Date(candidate).getTime() > new Date(latest).getTime() ? candidate : latest;
    }, undefined);
    packagesIndex[pkgName] = {
      count: vulns.length,
      latestVuln,
      maxSeverity,
    };
  }

  // Save index file
  const index: StaticDbIndex = {
    schemaVersion: 1,
    lastUpdated: now,
    cutoffDate,
    totalVulnerabilities: totalVulns,
    totalPackages: packageVulns.size,
    packages: packagesIndex,
    buildInfo: {
      generator: "pnpm-audit-hook/update-vuln-db",
      sources: ["github-advisory"],
      durationMs: Date.now() - startTime,
    },
  };

  fs.writeFileSync(INDEX_FILE, JSON.stringify(index, null, 2));

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);
  log(`Database build complete!`);
  log(`  Packages: ${packageVulns.size}`);
  log(`  Vulnerabilities: ${totalVulns}`);
  log(`  Duration: ${duration}s`);
  log(`  Output: ${DATA_DIR}`);
}

main().catch((err) => {
  error(String(err));
  process.exit(1);
});
