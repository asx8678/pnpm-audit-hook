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

// Types matching src/static-db/types.ts
interface StaticVulnerabilityEntry {
  id: string;
  packageName: string;
  title?: string;
  description?: string;
  severity: "critical" | "high" | "medium" | "low" | "unknown";
  url?: string;
  publishedAt?: string;
  modifiedAt?: string;
  identifiers?: { type: string; value: string }[];
  affectedVersions: { range: string; fixed?: string }[];
  source: "github";
}

interface StaticPackageData {
  packageName: string;
  lastUpdated: string;
  vulnerabilities: StaticVulnerabilityEntry[];
}

interface StaticDbIndex {
  schemaVersion: number;
  lastUpdated: string;
  cutoffDate: string;
  totalVulnerabilities: number;
  totalPackages: number;
  packages: Record<
    string,
    { count: number; latestVuln?: string; maxSeverity: "critical" | "high" | "medium" | "low" | "unknown" }
  >;
  buildInfo: {
    generator: string;
    sources: string[];
    durationMs: number;
  };
}

// GitHub Advisory GraphQL types
interface GitHubAdvisory {
  ghsaId: string;
  summary: string;
  description: string;
  severity: string;
  publishedAt: string;
  updatedAt: string;
  permalink: string;
  identifiers: { type: string; value: string }[];
  vulnerabilities: {
    nodes: {
      package: { name: string; ecosystem: string };
      vulnerableVersionRange: string;
      firstPatchedVersion: { identifier: string } | null;
    }[];
  };
}

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
const PACKAGES_DIR = path.join(DATA_DIR, "packages");
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

/**
 * Map GitHub severity to our severity type
 */
function mapSeverity(
  ghSeverity: string,
): "critical" | "high" | "medium" | "low" | "unknown" {
  const severity = ghSeverity.toLowerCase();
  if (severity === "critical") return "critical";
  if (severity === "high") return "high";
  if (severity === "moderate" || severity === "medium") return "medium";
  if (severity === "low") return "low";
  return "unknown";
}

const SEVERITY_RANK: Record<StaticVulnerabilityEntry["severity"], number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  unknown: 0,
};

/**
 * Convert GitHub advisory to our vulnerability entry format
 */
function convertAdvisory(
  advisory: GitHubAdvisory,
  vuln: GitHubAdvisory["vulnerabilities"]["nodes"][0],
): { packageName: string; entry: StaticVulnerabilityEntry } {
  return {
    packageName: vuln.package.name,
    entry: {
      id: advisory.ghsaId,
      packageName: vuln.package.name,
      title: advisory.summary,
      description: advisory.description?.slice(0, 500), // Truncate long descriptions
      severity: mapSeverity(advisory.severity),
      url: advisory.permalink,
      publishedAt: advisory.publishedAt,
      modifiedAt: advisory.updatedAt,
      identifiers: advisory.identifiers.map((id) => ({
        type: id.type,
        value: id.value,
      })),
      affectedVersions: [
        {
          range: vuln.vulnerableVersionRange,
          fixed: vuln.firstPatchedVersion?.identifier,
        },
      ],
      source: "github",
    },
  };
}

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
function loadExistingPackageData(packageName: string): StaticPackageData | null {
  const safeName = packageName.replace(/\//g, "__");
  const filePath = path.join(PACKAGES_DIR, `${safeName}.json`);
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

function normalizePackageData(raw: unknown, packageName: string): StaticPackageData | null {
  if (!raw || typeof raw !== "object") return null;
  const obj = raw as Record<string, unknown>;
  const name =
    typeof obj.packageName === "string"
      ? obj.packageName
      : typeof obj.name === "string"
        ? obj.name
        : packageName;

  if (!name) return null;

  const vulnerabilitiesRaw = Array.isArray(obj.vulnerabilities) ? obj.vulnerabilities : [];
  const vulnerabilities: StaticVulnerabilityEntry[] = [];

  for (const vuln of vulnerabilitiesRaw) {
    if (!vuln || typeof vuln !== "object") continue;
    const v = vuln as Record<string, unknown>;
    const id = typeof v.id === "string" ? v.id : "";
    if (!id) continue;
    const affectedVersions = Array.isArray(v.affectedVersions)
      ? (v.affectedVersions as Array<{ range?: unknown; fixed?: unknown }>)
          .map((av) => {
            const range = typeof av?.range === "string" ? av.range : "";
            if (!range) return null;
            const fixed = typeof av.fixed === "string" ? av.fixed : undefined;
            return { range, fixed };
          })
          .filter((av): av is { range: string; fixed?: string } => av !== null)
      : typeof v.affectedRange === "string"
        ? [
            {
              range: v.affectedRange,
              fixed: typeof v.fixedVersion === "string" ? v.fixedVersion : undefined,
            },
          ]
        : [];

    vulnerabilities.push({
      id,
      packageName: typeof v.packageName === "string" ? v.packageName : name,
      title: typeof v.title === "string" ? v.title : undefined,
      description: typeof v.description === "string" ? v.description : undefined,
      severity: mapSeverity(typeof v.severity === "string" ? v.severity : "unknown"),
      url: typeof v.url === "string" ? v.url : undefined,
      publishedAt: typeof v.publishedAt === "string" ? v.publishedAt : undefined,
      modifiedAt: typeof v.modifiedAt === "string" ? v.modifiedAt : undefined,
      identifiers: Array.isArray(v.identifiers)
        ? v.identifiers
            .map((idEntry) => {
              if (!idEntry || typeof idEntry !== "object") return null;
              const idObj = idEntry as Record<string, unknown>;
              const type = typeof idObj.type === "string" ? idObj.type : "";
              const value = typeof idObj.value === "string" ? idObj.value : "";
              if (!type || !value) return null;
              return { type, value };
            })
            .filter((i): i is { type: string; value: string } => i !== null)
        : undefined,
      affectedVersions,
      source: "github",
    });
  }

  return {
    packageName: name,
    lastUpdated: typeof obj.lastUpdated === "string" ? obj.lastUpdated : new Date().toISOString(),
    vulnerabilities,
  };
}

/**
 * Save package data to file
 */
function savePackageData(data: StaticPackageData): void {
  const safeName = data.packageName.replace(/\//g, "__");
  const filePath = path.join(PACKAGES_DIR, `${safeName}.json`);
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

/**
 * Generate sample data for popular packages (for testing without API calls)
 */
function generateSampleData(): Map<string, StaticVulnerabilityEntry[]> {
  const vulns = new Map<string, StaticVulnerabilityEntry[]>();

  // Real vulnerability data for popular packages
  type SampleVulnerability = {
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
  };
  const sampleVulns: Array<{
    pkg: string;
    vulns: SampleVulnerability[];
  }> = [
    {
      pkg: "lodash",
      vulns: [
        {
          id: "GHSA-35jh-r3h4-6jhm",
          title: "Prototype Pollution in lodash",
          severity: "high",
          url: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
          publishedAt: "2020-07-15T19:15:00Z",
          modifiedAt: "2023-09-13T19:54:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-35jh-r3h4-6jhm" },
            { type: "CVE", value: "CVE-2020-8203" },
          ],
          affectedRange: "<4.17.19",
          fixedVersion: "4.17.19",
        },
        {
          id: "GHSA-p6mc-m468-83gw",
          title: "Prototype Pollution in lodash",
          severity: "high",
          url: "https://github.com/advisories/GHSA-p6mc-m468-83gw",
          publishedAt: "2021-05-06T16:05:00Z",
          modifiedAt: "2023-09-08T19:55:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-p6mc-m468-83gw" },
            { type: "CVE", value: "CVE-2021-23337" },
          ],
          affectedRange: "<4.17.21",
          fixedVersion: "4.17.21",
        },
        {
          id: "GHSA-29mw-wpgm-hmr9",
          title: "Regular Expression Denial of Service (ReDoS) in lodash",
          severity: "high",
          url: "https://github.com/advisories/GHSA-29mw-wpgm-hmr9",
          publishedAt: "2021-05-06T16:05:00Z",
          modifiedAt: "2023-09-11T22:03:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-29mw-wpgm-hmr9" },
            { type: "CVE", value: "CVE-2020-28500" },
          ],
          affectedRange: "<4.17.21",
          fixedVersion: "4.17.21",
        },
        {
          id: "GHSA-jf85-cpcp-j695",
          title: "Prototype Pollution in lodash",
          severity: "critical",
          url: "https://github.com/advisories/GHSA-jf85-cpcp-j695",
          publishedAt: "2019-07-10T19:45:00Z",
          modifiedAt: "2023-09-08T19:55:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-jf85-cpcp-j695" },
            { type: "CVE", value: "CVE-2019-10744" },
          ],
          affectedRange: "<4.17.12",
          fixedVersion: "4.17.12",
        },
      ],
    },
    {
      pkg: "axios",
      vulns: [
        {
          id: "GHSA-wf5p-g6vw-rhxx",
          title: "Server-Side Request Forgery in axios",
          severity: "high",
          url: "https://github.com/advisories/GHSA-wf5p-g6vw-rhxx",
          publishedAt: "2023-11-08T14:43:00Z",
          modifiedAt: "2024-01-31T20:36:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-wf5p-g6vw-rhxx" },
            { type: "CVE", value: "CVE-2023-45857" },
          ],
          affectedRange: ">=0.8.1 <1.6.0",
          fixedVersion: "1.6.0",
        },
        {
          id: "GHSA-4w2v-q235-vp99",
          title: "Axios Cross-Site Request Forgery Vulnerability",
          severity: "medium",
          url: "https://github.com/advisories/GHSA-4w2v-q235-vp99",
          publishedAt: "2024-08-12T15:30:00Z",
          modifiedAt: "2024-09-06T18:25:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-4w2v-q235-vp99" },
            { type: "CVE", value: "CVE-2024-39338" },
          ],
          affectedRange: ">=1.3.2 <1.7.4",
          fixedVersion: "1.7.4",
        },
      ],
    },
    {
      pkg: "express",
      vulns: [
        {
          id: "GHSA-rv95-896h-c2vc",
          title: "Express.js Open Redirect vulnerability",
          severity: "medium",
          url: "https://github.com/advisories/GHSA-rv95-896h-c2vc",
          publishedAt: "2024-03-25T19:40:00Z",
          modifiedAt: "2024-03-26T16:57:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-rv95-896h-c2vc" },
            { type: "CVE", value: "CVE-2024-29041" },
          ],
          affectedRange: "<4.19.2",
          fixedVersion: "4.19.2",
        },
      ],
    },
    {
      pkg: "minimist",
      vulns: [
        {
          id: "GHSA-xvch-5gv4-984h",
          title: "Prototype Pollution in minimist",
          severity: "critical",
          url: "https://github.com/advisories/GHSA-xvch-5gv4-984h",
          publishedAt: "2022-03-17T00:00:00Z",
          modifiedAt: "2023-09-11T22:36:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-xvch-5gv4-984h" },
            { type: "CVE", value: "CVE-2021-44906" },
          ],
          affectedRange: "<1.2.6",
          fixedVersion: "1.2.6",
        },
        {
          id: "GHSA-vh95-rmgr-6w4m",
          title: "Prototype Pollution in minimist",
          severity: "medium",
          url: "https://github.com/advisories/GHSA-vh95-rmgr-6w4m",
          publishedAt: "2020-03-11T23:00:00Z",
          modifiedAt: "2023-09-11T22:01:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-vh95-rmgr-6w4m" },
            { type: "CVE", value: "CVE-2020-7598" },
          ],
          affectedRange: "<0.2.1",
          fixedVersion: "0.2.1",
        },
      ],
    },
    {
      pkg: "node-fetch",
      vulns: [
        {
          id: "GHSA-r683-j2x4-v87g",
          title: "node-fetch is vulnerable to Exposure of Sensitive Information",
          severity: "high",
          url: "https://github.com/advisories/GHSA-r683-j2x4-v87g",
          publishedAt: "2022-01-14T21:04:00Z",
          modifiedAt: "2023-09-11T22:17:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-r683-j2x4-v87g" },
            { type: "CVE", value: "CVE-2022-0235" },
          ],
          affectedRange: "<2.6.7",
          fixedVersion: "2.6.7",
        },
      ],
    },
    {
      pkg: "tar",
      vulns: [
        {
          id: "GHSA-r628-mhmh-qjhw",
          title: "Arbitrary File Creation/Overwrite via insufficient symlink protection",
          severity: "high",
          url: "https://github.com/advisories/GHSA-r628-mhmh-qjhw",
          publishedAt: "2021-08-31T16:02:00Z",
          modifiedAt: "2023-09-11T22:14:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-r628-mhmh-qjhw" },
            { type: "CVE", value: "CVE-2021-37701" },
          ],
          affectedRange: "<6.1.7",
          fixedVersion: "6.1.7",
        },
        {
          id: "GHSA-9r2w-394v-53qc",
          title: "Arbitrary File Creation/Overwrite on Windows",
          severity: "high",
          url: "https://github.com/advisories/GHSA-9r2w-394v-53qc",
          publishedAt: "2021-08-31T16:01:00Z",
          modifiedAt: "2023-09-11T22:14:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-9r2w-394v-53qc" },
            { type: "CVE", value: "CVE-2021-37712" },
          ],
          affectedRange: "<6.1.9",
          fixedVersion: "6.1.9",
        },
      ],
    },
    {
      pkg: "glob-parent",
      vulns: [
        {
          id: "GHSA-ww39-953v-wcq6",
          title: "Regular expression denial of service",
          severity: "high",
          url: "https://github.com/advisories/GHSA-ww39-953v-wcq6",
          publishedAt: "2021-05-06T16:05:00Z",
          modifiedAt: "2023-09-11T22:03:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-ww39-953v-wcq6" },
            { type: "CVE", value: "CVE-2020-28469" },
          ],
          affectedRange: "<5.1.2",
          fixedVersion: "5.1.2",
        },
      ],
    },
    {
      pkg: "json5",
      vulns: [
        {
          id: "GHSA-9c47-m6qq-7p4h",
          title: "Prototype Pollution in JSON5 via Parse Method",
          severity: "high",
          url: "https://github.com/advisories/GHSA-9c47-m6qq-7p4h",
          publishedAt: "2022-12-26T06:30:00Z",
          modifiedAt: "2023-09-07T21:33:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-9c47-m6qq-7p4h" },
            { type: "CVE", value: "CVE-2022-46175" },
          ],
          affectedRange: "<1.0.2",
          fixedVersion: "1.0.2",
        },
      ],
    },
    {
      pkg: "qs",
      vulns: [
        {
          id: "GHSA-hrpp-h998-j3pp",
          title: "qs vulnerable to Prototype Pollution",
          severity: "high",
          url: "https://github.com/advisories/GHSA-hrpp-h998-j3pp",
          publishedAt: "2022-11-28T00:00:00Z",
          modifiedAt: "2023-09-07T21:31:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-hrpp-h998-j3pp" },
            { type: "CVE", value: "CVE-2022-24999" },
          ],
          affectedRange: ">=6.0.0 <6.5.3",
          fixedVersion: "6.5.3",
        },
      ],
    },
    {
      pkg: "semver",
      vulns: [
        {
          id: "GHSA-c2qf-rxjj-qqgw",
          title: "semver vulnerable to Regular Expression Denial of Service",
          severity: "high",
          url: "https://github.com/advisories/GHSA-c2qf-rxjj-qqgw",
          publishedAt: "2023-06-21T18:31:00Z",
          modifiedAt: "2024-06-21T21:33:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-c2qf-rxjj-qqgw" },
            { type: "CVE", value: "CVE-2022-25883" },
          ],
          affectedRange: ">=6.0.0 <6.3.1",
          fixedVersion: "6.3.1",
        },
      ],
    },
    {
      pkg: "path-to-regexp",
      vulns: [
        {
          id: "GHSA-9wv6-86v2-598j",
          title: "path-to-regexp outputs backtracking regular expressions",
          severity: "high",
          url: "https://github.com/advisories/GHSA-9wv6-86v2-598j",
          publishedAt: "2024-09-09T19:06:00Z",
          modifiedAt: "2024-09-13T18:34:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-9wv6-86v2-598j" },
            { type: "CVE", value: "CVE-2024-45296" },
          ],
          affectedRange: "<0.1.10",
          fixedVersion: "0.1.10",
        },
      ],
    },
    {
      pkg: "ansi-regex",
      vulns: [
        {
          id: "GHSA-93q8-gq69-wqmw",
          title: "Inefficient Regular Expression Complexity in ansi-regex",
          severity: "high",
          url: "https://github.com/advisories/GHSA-93q8-gq69-wqmw",
          publishedAt: "2021-09-20T23:09:00Z",
          modifiedAt: "2023-09-11T22:16:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-93q8-gq69-wqmw" },
            { type: "CVE", value: "CVE-2021-3807" },
          ],
          affectedRange: ">=3.0.0 <5.0.1",
          fixedVersion: "5.0.1",
        },
      ],
    },
    {
      pkg: "minimatch",
      vulns: [
        {
          id: "GHSA-f8q6-p94x-37v3",
          title: "minimatch ReDoS vulnerability",
          severity: "high",
          url: "https://github.com/advisories/GHSA-f8q6-p94x-37v3",
          publishedAt: "2022-10-18T18:22:00Z",
          modifiedAt: "2023-09-11T22:20:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-f8q6-p94x-37v3" },
            { type: "CVE", value: "CVE-2022-3517" },
          ],
          affectedRange: "<3.0.5",
          fixedVersion: "3.0.5",
        },
      ],
    },
    {
      pkg: "tough-cookie",
      vulns: [
        {
          id: "GHSA-72xf-g2v4-qvf3",
          title: "Prototype Pollution in tough-cookie",
          severity: "medium",
          url: "https://github.com/advisories/GHSA-72xf-g2v4-qvf3",
          publishedAt: "2023-07-06T21:14:00Z",
          modifiedAt: "2024-03-07T17:33:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-72xf-g2v4-qvf3" },
            { type: "CVE", value: "CVE-2023-26136" },
          ],
          affectedRange: "<4.1.3",
          fixedVersion: "4.1.3",
        },
      ],
    },
    {
      pkg: "word-wrap",
      vulns: [
        {
          id: "GHSA-j8xg-fqg3-53r7",
          title: "word-wrap Regular Expression Denial of Service vulnerability",
          severity: "medium",
          url: "https://github.com/advisories/GHSA-j8xg-fqg3-53r7",
          publishedAt: "2023-06-22T21:30:00Z",
          modifiedAt: "2024-01-09T20:27:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-j8xg-fqg3-53r7" },
            { type: "CVE", value: "CVE-2023-26115" },
          ],
          affectedRange: "<1.2.4",
          fixedVersion: "1.2.4",
        },
      ],
    },
    {
      pkg: "json-schema",
      vulns: [
        {
          id: "GHSA-896r-f27r-55mw",
          title: "Prototype pollution in json-schema",
          severity: "critical",
          url: "https://github.com/advisories/GHSA-896r-f27r-55mw",
          publishedAt: "2021-03-18T19:24:00Z",
          modifiedAt: "2023-09-08T19:54:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-896r-f27r-55mw" },
            { type: "CVE", value: "CVE-2021-3918" },
          ],
          affectedRange: "<0.4.0",
          fixedVersion: "0.4.0",
        },
      ],
    },
    {
      pkg: "shell-quote",
      vulns: [
        {
          id: "GHSA-g4rg-993r-mgx7",
          title: "Improper Neutralization of Special Elements used in a Command",
          severity: "critical",
          url: "https://github.com/advisories/GHSA-g4rg-993r-mgx7",
          publishedAt: "2022-06-24T00:00:00Z",
          modifiedAt: "2023-09-08T19:54:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-g4rg-993r-mgx7" },
            { type: "CVE", value: "CVE-2021-42740" },
          ],
          affectedRange: "<1.7.3",
          fixedVersion: "1.7.3",
        },
      ],
    },
    {
      pkg: "decode-uri-component",
      vulns: [
        {
          id: "GHSA-w573-4hg7-7wgq",
          title: "decode-uri-component vulnerable to Denial of Service (DoS)",
          severity: "high",
          url: "https://github.com/advisories/GHSA-w573-4hg7-7wgq",
          publishedAt: "2022-11-29T03:30:00Z",
          modifiedAt: "2023-09-07T21:31:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-w573-4hg7-7wgq" },
            { type: "CVE", value: "CVE-2022-38900" },
          ],
          affectedRange: "<0.2.1",
          fixedVersion: "0.2.1",
        },
      ],
    },
    {
      pkg: "ajv",
      vulns: [
        {
          id: "GHSA-v88g-cgmw-v5xw",
          title: "Prototype Pollution in Ajv",
          severity: "high",
          url: "https://github.com/advisories/GHSA-v88g-cgmw-v5xw",
          publishedAt: "2020-07-16T22:36:00Z",
          modifiedAt: "2023-09-13T19:45:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-v88g-cgmw-v5xw" },
            { type: "CVE", value: "CVE-2020-15366" },
          ],
          affectedRange: "<6.12.3",
          fixedVersion: "6.12.3",
        },
      ],
    },
    {
      pkg: "y18n",
      vulns: [
        {
          id: "GHSA-c4w7-xm78-47vh",
          title: "Prototype Pollution in y18n",
          severity: "high",
          url: "https://github.com/advisories/GHSA-c4w7-xm78-47vh",
          publishedAt: "2021-04-06T17:23:00Z",
          modifiedAt: "2023-09-08T19:54:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-c4w7-xm78-47vh" },
            { type: "CVE", value: "CVE-2020-7774" },
          ],
          affectedRange: "<3.2.2",
          fixedVersion: "3.2.2",
        },
      ],
    },
    {
      pkg: "set-value",
      vulns: [
        {
          id: "GHSA-4jqc-8m5r-9rpr",
          title: "Prototype Pollution in set-value",
          severity: "high",
          url: "https://github.com/advisories/GHSA-4jqc-8m5r-9rpr",
          publishedAt: "2020-09-11T19:10:00Z",
          modifiedAt: "2023-09-11T22:28:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-4jqc-8m5r-9rpr" },
            { type: "CVE", value: "CVE-2021-23440" },
          ],
          affectedRange: "<2.0.1",
          fixedVersion: "2.0.1",
        },
      ],
    },
    {
      pkg: "underscore",
      vulns: [
        {
          id: "GHSA-cf4h-3jhx-xvhq",
          title: "Arbitrary Code Execution in underscore",
          severity: "critical",
          url: "https://github.com/advisories/GHSA-cf4h-3jhx-xvhq",
          publishedAt: "2021-07-12T21:15:00Z",
          modifiedAt: "2023-09-08T19:54:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-cf4h-3jhx-xvhq" },
            { type: "CVE", value: "CVE-2021-23358" },
          ],
          affectedRange: "<1.13.0-2",
          fixedVersion: "1.13.0-2",
        },
      ],
    },
    {
      pkg: "handlebars",
      vulns: [
        {
          id: "GHSA-f2jv-r9rf-7988",
          title: "Prototype Pollution in handlebars",
          severity: "critical",
          url: "https://github.com/advisories/GHSA-f2jv-r9rf-7988",
          publishedAt: "2021-05-10T15:19:00Z",
          modifiedAt: "2023-09-08T19:54:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-f2jv-r9rf-7988" },
            { type: "CVE", value: "CVE-2021-23369" },
          ],
          affectedRange: "<4.7.7",
          fixedVersion: "4.7.7",
        },
        {
          id: "GHSA-765h-qjxv-5f44",
          title: "Remote code execution in handlebars",
          severity: "critical",
          url: "https://github.com/advisories/GHSA-765h-qjxv-5f44",
          publishedAt: "2020-09-04T17:52:00Z",
          modifiedAt: "2023-09-13T19:53:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-765h-qjxv-5f44" },
            { type: "CVE", value: "CVE-2019-20920" },
          ],
          affectedRange: ">=4.0.0 <4.5.3",
          fixedVersion: "4.5.3",
        },
      ],
    },
    {
      pkg: "serialize-javascript",
      vulns: [
        {
          id: "GHSA-h9rv-jmmf-4pgx",
          title: "Cross-site Scripting in serialize-javascript",
          severity: "critical",
          url: "https://github.com/advisories/GHSA-h9rv-jmmf-4pgx",
          publishedAt: "2022-05-24T17:11:00Z",
          modifiedAt: "2023-09-08T19:54:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-h9rv-jmmf-4pgx" },
            { type: "CVE", value: "CVE-2020-7660" },
          ],
          affectedRange: "<3.1.0",
          fixedVersion: "3.1.0",
        },
      ],
    },
    {
      pkg: "merge-deep",
      vulns: [
        {
          id: "GHSA-r75c-c2vw-p9hx",
          title: "Prototype pollution in merge-deep",
          severity: "critical",
          url: "https://github.com/advisories/GHSA-r75c-c2vw-p9hx",
          publishedAt: "2022-02-10T20:22:00Z",
          modifiedAt: "2023-09-08T19:54:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-r75c-c2vw-p9hx" },
            { type: "CVE", value: "CVE-2021-23447" },
          ],
          affectedRange: "<3.0.3",
          fixedVersion: "3.0.3",
        },
      ],
    },
    {
      pkg: "got",
      vulns: [
        {
          id: "GHSA-pfrx-2q88-qq97",
          title: "Got allows a redirect to a UNIX socket",
          severity: "medium",
          url: "https://github.com/advisories/GHSA-pfrx-2q88-qq97",
          publishedAt: "2022-05-24T19:01:00Z",
          modifiedAt: "2023-09-08T19:54:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-pfrx-2q88-qq97" },
            { type: "CVE", value: "CVE-2022-33987" },
          ],
          affectedRange: "<11.8.5",
          fixedVersion: "11.8.5",
        },
      ],
    },
    {
      pkg: "immer",
      vulns: [
        {
          id: "GHSA-33f9-j839-rf8h",
          title: "Prototype Pollution in immer",
          severity: "critical",
          url: "https://github.com/advisories/GHSA-33f9-j839-rf8h",
          publishedAt: "2021-02-01T19:40:00Z",
          modifiedAt: "2023-09-08T19:54:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-33f9-j839-rf8h" },
            { type: "CVE", value: "CVE-2021-23436" },
          ],
          affectedRange: "<9.0.6",
          fixedVersion: "9.0.6",
        },
      ],
    },
    {
      pkg: "ws",
      vulns: [
        {
          id: "GHSA-6fc8-4gx4-v693",
          title: "ws affected by a DoS when handling a request with many HTTP headers",
          severity: "high",
          url: "https://github.com/advisories/GHSA-6fc8-4gx4-v693",
          publishedAt: "2024-06-17T15:09:00Z",
          modifiedAt: "2024-06-20T16:07:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-6fc8-4gx4-v693" },
            { type: "CVE", value: "CVE-2024-37890" },
          ],
          affectedRange: "<5.2.4",
          fixedVersion: "5.2.4",
        },
      ],
    },
    {
      pkg: "ini",
      vulns: [
        {
          id: "GHSA-qqgx-2p2h-9c37",
          title: "Prototype Pollution in ini",
          severity: "high",
          url: "https://github.com/advisories/GHSA-qqgx-2p2h-9c37",
          publishedAt: "2020-12-10T21:36:00Z",
          modifiedAt: "2023-09-13T19:51:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-qqgx-2p2h-9c37" },
            { type: "CVE", value: "CVE-2020-7788" },
          ],
          affectedRange: "<1.3.6",
          fixedVersion: "1.3.6",
        },
      ],
    },
    {
      pkg: "flat",
      vulns: [
        {
          id: "GHSA-2j2x-2gpw-g8fm",
          title: "Prototype Pollution in flat",
          severity: "critical",
          url: "https://github.com/advisories/GHSA-2j2x-2gpw-g8fm",
          publishedAt: "2022-12-06T00:30:00Z",
          modifiedAt: "2023-09-07T21:33:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-2j2x-2gpw-g8fm" },
            { type: "CVE", value: "CVE-2020-36632" },
          ],
          affectedRange: "<5.0.1",
          fixedVersion: "5.0.1",
        },
      ],
    },
    {
      pkg: "postcss",
      vulns: [
        {
          id: "GHSA-566m-qj78-rww5",
          title: "PostCSS line return parsing error",
          severity: "medium",
          url: "https://github.com/advisories/GHSA-566m-qj78-rww5",
          publishedAt: "2021-09-23T23:09:00Z",
          modifiedAt: "2023-09-11T22:17:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-566m-qj78-rww5" },
            { type: "CVE", value: "CVE-2021-23382" },
          ],
          affectedRange: "<7.0.36",
          fixedVersion: "7.0.36",
        },
      ],
    },
    {
      pkg: "nanoid",
      vulns: [
        {
          id: "GHSA-qrpm-p2h7-hrv2",
          title: "Exposure of Sensitive Information to an Unauthorized Actor in nanoid",
          severity: "medium",
          url: "https://github.com/advisories/GHSA-qrpm-p2h7-hrv2",
          publishedAt: "2022-01-14T21:04:00Z",
          modifiedAt: "2023-09-11T22:17:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-qrpm-p2h7-hrv2" },
            { type: "CVE", value: "CVE-2021-23566" },
          ],
          affectedRange: "<3.1.31",
          fixedVersion: "3.1.31",
        },
      ],
    },
    {
      pkg: "node-forge",
      vulns: [
        {
          id: "GHSA-5rrq-pxf6-6jx5",
          title: "Improper Verification of Cryptographic Signature in node-forge",
          severity: "high",
          url: "https://github.com/advisories/GHSA-5rrq-pxf6-6jx5",
          publishedAt: "2022-01-12T22:16:00Z",
          modifiedAt: "2023-09-11T22:17:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-5rrq-pxf6-6jx5" },
            { type: "CVE", value: "CVE-2022-0122" },
          ],
          affectedRange: "<1.0.0",
          fixedVersion: "1.0.0",
        },
        {
          id: "GHSA-cfm4-qjh2-4765",
          title: "Prototype Pollution in node-forge",
          severity: "critical",
          url: "https://github.com/advisories/GHSA-cfm4-qjh2-4765",
          publishedAt: "2022-03-18T00:01:00Z",
          modifiedAt: "2023-09-07T21:28:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-cfm4-qjh2-4765" },
            { type: "CVE", value: "CVE-2022-0144" },
          ],
          affectedRange: "<1.0.0",
          fixedVersion: "1.0.0",
        },
      ],
    },
    {
      pkg: "follow-redirects",
      vulns: [
        {
          id: "GHSA-jchw-25xp-jwwc",
          title: "follow-redirects Exposure of Sensitive Information",
          severity: "high",
          url: "https://github.com/advisories/GHSA-jchw-25xp-jwwc",
          publishedAt: "2022-02-09T22:09:00Z",
          modifiedAt: "2023-09-11T22:19:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-jchw-25xp-jwwc" },
            { type: "CVE", value: "CVE-2022-0155" },
          ],
          affectedRange: "<1.14.7",
          fixedVersion: "1.14.7",
        },
        {
          id: "GHSA-cxjh-pqwp-8mfp",
          title: "follow-redirects Improper Input Validation",
          severity: "medium",
          url: "https://github.com/advisories/GHSA-cxjh-pqwp-8mfp",
          publishedAt: "2024-01-11T06:30:00Z",
          modifiedAt: "2024-01-23T14:42:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-cxjh-pqwp-8mfp" },
            { type: "CVE", value: "CVE-2024-28849" },
          ],
          affectedRange: "<1.15.4",
          fixedVersion: "1.15.4",
        },
      ],
    },
    {
      pkg: "http-cache-semantics",
      vulns: [
        {
          id: "GHSA-rc47-6667-2j5j",
          title: "http-cache-semantics vulnerable to Regular Expression Denial of Service",
          severity: "high",
          url: "https://github.com/advisories/GHSA-rc47-6667-2j5j",
          publishedAt: "2023-01-31T06:30:00Z",
          modifiedAt: "2023-09-07T21:34:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-rc47-6667-2j5j" },
            { type: "CVE", value: "CVE-2022-25881" },
          ],
          affectedRange: "<4.1.1",
          fixedVersion: "4.1.1",
        },
      ],
    },
    {
      pkg: "ip",
      vulns: [
        {
          id: "GHSA-78xj-cgh5-2h22",
          title: "ip SSRF improper categorization in isPublic",
          severity: "high",
          url: "https://github.com/advisories/GHSA-78xj-cgh5-2h22",
          publishedAt: "2024-02-02T00:31:00Z",
          modifiedAt: "2024-02-09T00:36:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-78xj-cgh5-2h22" },
            { type: "CVE", value: "CVE-2024-29415" },
          ],
          affectedRange: "<=2.0.1",
        },
      ],
    },
    {
      pkg: "undici",
      vulns: [
        {
          id: "GHSA-3787-6prv-h9w3",
          title: "Undici's Proxy-Authorization header is not cleared in cross-origin redirects",
          severity: "high",
          url: "https://github.com/advisories/GHSA-3787-6prv-h9w3",
          publishedAt: "2024-03-13T17:25:00Z",
          modifiedAt: "2024-03-14T20:55:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-3787-6prv-h9w3" },
            { type: "CVE", value: "CVE-2024-30260" },
          ],
          affectedRange: "<5.28.4",
          fixedVersion: "5.28.4",
        },
      ],
    },
    {
      pkg: "request",
      vulns: [
        {
          id: "GHSA-p8p7-x288-28g6",
          title: "Server-Side Request Forgery in Request",
          severity: "medium",
          url: "https://github.com/advisories/GHSA-p8p7-x288-28g6",
          publishedAt: "2023-05-26T12:39:00Z",
          modifiedAt: "2023-09-11T21:56:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-p8p7-x288-28g6" },
            { type: "CVE", value: "CVE-2023-28155" },
          ],
          affectedRange: "<=2.88.2",
        },
      ],
    },
    {
      pkg: "highlight.js",
      vulns: [
        {
          id: "GHSA-7wwv-vh3v-89cq",
          title: "ReDOS vulnerabilty in highlight.js",
          severity: "medium",
          url: "https://github.com/advisories/GHSA-7wwv-vh3v-89cq",
          publishedAt: "2020-12-04T16:48:00Z",
          modifiedAt: "2023-09-13T19:50:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-7wwv-vh3v-89cq" },
            { type: "CVE", value: "CVE-2020-26237" },
          ],
          affectedRange: ">=9.0.0 <9.18.5",
          fixedVersion: "9.18.5",
        },
      ],
    },
    {
      pkg: "clean-css",
      vulns: [
        {
          id: "GHSA-wxhq-pm8v-cw75",
          title: "Regular expression denial of service in clean-css",
          severity: "medium",
          url: "https://github.com/advisories/GHSA-wxhq-pm8v-cw75",
          publishedAt: "2024-01-02T06:30:00Z",
          modifiedAt: "2024-01-11T14:54:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-wxhq-pm8v-cw75" },
            { type: "CVE", value: "CVE-2024-21534" },
          ],
          affectedRange: "<4.1.11",
          fixedVersion: "4.1.11",
        },
      ],
    },
    {
      pkg: "yargs-parser",
      vulns: [
        {
          id: "GHSA-p9pc-299p-vxgp",
          title: "Prototype Pollution in yargs-parser",
          severity: "medium",
          url: "https://github.com/advisories/GHSA-p9pc-299p-vxgp",
          publishedAt: "2020-05-27T16:36:00Z",
          modifiedAt: "2023-09-11T22:00:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-p9pc-299p-vxgp" },
            { type: "CVE", value: "CVE-2020-7608" },
          ],
          affectedRange: "<13.1.2",
          fixedVersion: "13.1.2",
        },
      ],
    },
    {
      pkg: "kind-of",
      vulns: [
        {
          id: "GHSA-6c8f-qphg-qjgp",
          title: "Validation Bypass in kind-of",
          severity: "high",
          url: "https://github.com/advisories/GHSA-6c8f-qphg-qjgp",
          publishedAt: "2020-03-06T18:49:00Z",
          modifiedAt: "2023-09-11T22:00:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-6c8f-qphg-qjgp" },
            { type: "CVE", value: "CVE-2019-20149" },
          ],
          affectedRange: ">=6.0.0 <6.0.3",
          fixedVersion: "6.0.3",
        },
      ],
    },
    {
      pkg: "elliptic",
      vulns: [
        {
          id: "GHSA-f7q4-pwc6-w24p",
          title: "Use of a Broken or Risky Cryptographic Algorithm in elliptic",
          severity: "medium",
          url: "https://github.com/advisories/GHSA-f7q4-pwc6-w24p",
          publishedAt: "2021-04-06T17:09:00Z",
          modifiedAt: "2023-09-08T19:54:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-f7q4-pwc6-w24p" },
            { type: "CVE", value: "CVE-2020-13822" },
          ],
          affectedRange: "<6.5.3",
          fixedVersion: "6.5.3",
        },
      ],
    },
    {
      pkg: "micromatch",
      vulns: [
        {
          id: "GHSA-952p-6rrq-rcjv",
          title: "micromatch ReDoS vulnerability",
          severity: "medium",
          url: "https://github.com/advisories/GHSA-952p-6rrq-rcjv",
          publishedAt: "2024-08-21T06:32:00Z",
          modifiedAt: "2024-08-23T03:52:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-952p-6rrq-rcjv" },
            { type: "CVE", value: "CVE-2024-4067" },
          ],
          affectedRange: "<4.0.8",
          fixedVersion: "4.0.8",
        },
      ],
    },
    {
      pkg: "braces",
      vulns: [
        {
          id: "GHSA-grv7-fg5c-xmjg",
          title: "Uncontrolled resource consumption in braces",
          severity: "medium",
          url: "https://github.com/advisories/GHSA-grv7-fg5c-xmjg",
          publishedAt: "2024-03-05T21:20:00Z",
          modifiedAt: "2024-08-26T19:03:00Z",
          identifiers: [
            { type: "GHSA", value: "GHSA-grv7-fg5c-xmjg" },
            { type: "CVE", value: "CVE-2024-4068" },
          ],
          affectedRange: "<3.0.3",
          fixedVersion: "3.0.3",
        },
      ],
    },
  ];

  for (const item of sampleVulns) {
    const normalized = item.vulns.map((v) => ({
      id: v.id,
      packageName: item.pkg,
      title: v.title,
      description: v.description,
      severity: v.severity,
      url: v.url,
      publishedAt: v.publishedAt,
      modifiedAt: v.modifiedAt,
      identifiers: v.identifiers,
      affectedVersions: [
        {
          range: v.affectedRange,
          fixed: v.fixedVersion,
        },
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
  if (!fs.existsSync(PACKAGES_DIR)) {
    fs.mkdirSync(PACKAGES_DIR, { recursive: true });
  }

  // Load existing index for incremental updates
  const existingIndex = loadExistingIndex();
  let updatedSince: string | undefined;

  if (isIncremental && existingIndex) {
    updatedSince = existingIndex.lastUpdated;
    log(`  Incremental update from: ${updatedSince}`);
  }

  // Map to accumulate vulnerabilities by package
  const packageVulns = new Map<string, StaticVulnerabilityEntry[]>();

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
  const packagesIndex: Record<
    string,
    { count: number; latestVuln?: string; maxSeverity: StaticVulnerabilityEntry["severity"] }
  > = {};

  for (const [pkgName, vulns] of packageVulns) {
    const pkgData: StaticPackageData = {
      packageName: pkgName,
      lastUpdated: now,
      vulnerabilities: vulns,
    };
    savePackageData(pkgData);
    const maxSeverity = vulns.reduce<StaticVulnerabilityEntry["severity"]>(
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
