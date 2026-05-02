/**
 * Fixture loader utilities for testing.
 *
 * Provides convenient functions to load test fixtures from disk
 * with type safety and caching.
 */
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

// ─── Paths ───────────────────────────────────────────────────────────────────

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = path.resolve(__dirname, "..", "fixtures");

// ─── Generic Loader ──────────────────────────────────────────────────────────

/**
 * Load a JSON fixture file.
 *
 * @param category - The fixture category (e.g., "vulnerabilities", "responses")
 * @param name - The fixture file name without extension
 * @returns The parsed JSON content
 */
export async function loadJsonFixture<T = unknown>(
  category: string,
  name: string
): Promise<T> {
  const filePath = path.join(FIXTURES_DIR, category, `${name}.json`);
  const content = await fs.readFile(filePath, "utf-8");
  return JSON.parse(content) as T;
}


/**
 * Load a YAML fixture file.
 *
 * @param category - The fixture category (e.g., "lockfiles", "configs")
 * @param name - The fixture file name without extension
 * @returns The parsed YAML content
 */
export async function loadYamlFixture<T = unknown>(
  category: string,
  name: string
): Promise<T> {
  const filePath = path.join(FIXTURES_DIR, category, `${name}.yaml`);
  const content = await fs.readFile(filePath, "utf-8");
  const yaml = await import("yaml");
  return yaml.parse(content) as T;
}

/**
 * Load a raw text fixture file.
 */
export async function loadTextFixture(
  category: string,
  name: string,
  ext = "txt"
): Promise<string> {
  const filePath = path.join(FIXTURES_DIR, category, `${name}.${ext}`);
  return fs.readFile(filePath, "utf-8");
}

// ─── Typed Loaders ───────────────────────────────────────────────────────────

/**
 * Load a vulnerability fixture.
 *
 * @example
 * ```ts
 * const vulns = await loadVulnerabilityFixture("critical");
 * assert.equal(vulns[0].severity, "critical");
 * ```
 */
export async function loadVulnerabilityFixture(
  name: "critical" | "high" | "medium"
): Promise<Array<Record<string, unknown>>> {
  return loadJsonFixture("vulnerabilities", name);
}

/**
 * Load a config fixture.
 */
export async function loadConfigFixture(
  name: "basic" | "advanced" | "edge-cases"
): Promise<Record<string, unknown>> {
  return loadYamlFixture("configs", name);
}

/**
 * Load a lockfile fixture.
 */
export async function loadLockfileFixture(
  name: "pnpm-v6" | "pnpm-v7" | "pnpm-v9" | "empty" | "large-lockfile"
): Promise<Record<string, unknown>> {
  return loadYamlFixture("lockfiles", name);
}

/**
 * Load an API response fixture.
 */
export async function loadResponseFixture(
  name: "github-advisory" | "osv-api" | "nvd-api"
): Promise<Record<string, unknown>> {
  return loadJsonFixture("responses", name);
}

/**
 * Load a static-db fixture.
 */
export async function loadStaticDbFixture(
  name: "index" | "lodash" | "react"
): Promise<Record<string, unknown>> {
  return loadJsonFixture("static-db", name);
}

// ─── Inline Fixture Generators ───────────────────────────────────────────────

/**
 * Generate a minimal pnpm lockfile structure in memory.
 *
 * Useful when you don't need a full lockfile fixture.
 */
export function generateMinimalLockfile(
  packages: Array<{ name: string; version: string }>
): Record<string, unknown> {
  const pkgSnapshots: Record<string, object> = {};
  for (const p of packages) {
    pkgSnapshots[`/${p.name}@${p.version}`] = {
      resolution: { integrity: `sha512-test-${p.name}-${p.version}` },
    };
  }
  return {
    lockfileVersion: "9.0",
    packages: pkgSnapshots,
  };
}

/**
 * Generate a lockfile with dependency chains.
 */
export function generateLockfileWithDeps(
  packages: Array<{
    name: string;
    version: string;
    dependencies?: Record<string, string>;
    dev?: boolean;
  }>
): Record<string, unknown> {
  const pkgSnapshots: Record<string, object> = {};
  for (const p of packages) {
    pkgSnapshots[`/${p.name}@${p.version}`] = {
      resolution: { integrity: `sha512-test-${p.name}-${p.version}` },
      dependencies: p.dependencies,
      dev: p.dev,
    };
  }
  return {
    lockfileVersion: "9.0",
    packages: pkgSnapshots,
  };
}

/**
 * Generate a GitHub Advisory API response fixture.
 */
export function generateGitHubAdvisoryResponse(
  findings: Array<{
    ghsaId: string;
    cveId?: string;
    package: string;
    severity: string;
    vulnerableRange: string;
    fixedVersion?: string;
  }>
): Record<string, unknown> {
  return {
    data: {
      securityVulnerabilities: {
        nodes: findings.map((f) => ({
          advisory: {
            ghsaId: f.ghsaId,
            cveId: f.cveId ?? null,
            severity: f.severity.toUpperCase(),
            publishedAt: new Date().toISOString(),
          },
          package: {
            name: f.package,
            ecosystem: "NPM",
          },
          vulnerableVersionRange: f.vulnerableRange,
          firstPatchedVersion: f.fixedVersion
            ? { identifier: f.fixedVersion }
            : null,
        })),
        pageInfo: {
          hasNextPage: false,
          endCursor: "Y3Vyc29yOjA=",
        },
      },
    },
  };
}

/**
 * Generate an OSV API response fixture.
 */
export function generateOsvResponse(
  vulnId: string,
  packageName: string,
  vulnerableRange: string
): Record<string, unknown> {
  return {
    vulns: [
      {
        id: vulnId,
        summary: `Vulnerability in ${packageName}`,
        affected: [
          {
            package: {
              ecosystem: "npm",
              name: packageName,
            },
            ranges: [
              {
                type: "SEMVER",
                events: [
                  { introduced: "0" },
                  { fixed: vulnerableRange },
                ],
              },
            ],
          },
        ],
      },
    ],
  };
}
