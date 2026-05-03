/**
 * Monorepo SBOM generator.
 *
 * Generates SBOMs for individual workspaces in a pnpm monorepo
 * concurrently, and optionally aggregates them into a root SBOM.
 *
 * Workspace detection is based on the `importers` section of a pnpm
 * lockfile – each key represents a workspace path (e.g. `"."` for the
 * root, `"./packages/pkg1"` for a child workspace).
 *
 * @module sbom/monorepo-generator
 *
 * @example
 * ```typescript
 * import { MonorepoSbomGenerator } from './sbom/monorepo-generator';
 * import { extractPackagesFromLockfile } from './utils/lockfile';
 * import { aggregateVulnerabilities } from './databases/aggregator';
 *
 * const generator = new MonorepoSbomGenerator();
 * const result = await generator.generate(lockfile, findings, {
 *   format: 'cyclonedx',
 *   concurrency: 4,
 *   generateWorkspaceSboms: true,
 *   includeWorkspacesInRoot: true,
 * });
 *
 * console.log(`Generated SBOMs for ${result.stats.totalWorkspaces} workspaces`);
 * ```
 */

import type { PackageRef, VulnerabilityFinding, PnpmLockfile, LockfileImporter } from "../types.js";
import type {
  SbomResult,
  ComponentVulnerabilityMap,
  MonorepoSbomOptions,
  WorkspaceSbomResult,
  WorkspaceSbomError,
  MonorepoSbomResult,
} from "./types.js";
import { generateSbom, buildVulnerabilityMap } from "./generator.js";
import { extractPackagesFromLockfile } from "../utils/lockfile/package-extractor.js";
import { parsePnpmPackageKey } from "../utils/lockfile/package-key-parser.js";
import { mapWithConcurrency } from "../utils/concurrency.js";
import { logger } from "../utils/logger.js";

// Re-export types for backward compatibility
export type { MonorepoSbomOptions, WorkspaceSbomResult, WorkspaceSbomError, MonorepoSbomResult } from "./types.js";

/** Default option values for monorepo SBOM generation */
const DEFAULT_MONOREPO_OPTIONS: Pick<
  MonorepoSbomOptions,
  "concurrency" | "includeWorkspacesInRoot" | "generateWorkspaceSboms"
> = {
  concurrency: 4,
  includeWorkspacesInRoot: true,
  generateWorkspaceSboms: true,
};

// ═══════════════════════════════════════════════════════════════════════════════
// Workspace Info (internal)
// ═══════════════════════════════════════════════════════════════════════════════

/** Internal representation of a detected workspace before generation. */
interface WorkspaceInfo {
  /** Workspace path key from the importers section */
  path: string;
  /** Human-readable workspace name */
  name: string;
  /** Direct dependencies from the importer entry */
  importer: LockfileImporter;
  /** Packages extracted from the lockfile that belong to this workspace */
  packages: PackageRef[];
  /** Whether this is the root workspace */
  isRoot: boolean;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Monorepo SBOM Generator
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Generates SBOMs for pnpm monorepos with concurrent workspace processing.
 *
 * Detects workspaces from the lockfile `importers` section, extracts their
 * dependencies, and generates per-workspace SBOMs in parallel. An aggregated
 * root SBOM combining all workspace results is always produced.
 *
 * ## How it works
 *
 * 1. **Detect workspaces** – iterates `lockfile.importers` keys; `"."` is the
 *    root, everything else is a child workspace.
 * 2. **Extract packages** – for each workspace, walks the full `lockfile.packages`
 *    section and resolves dependencies declared in the importer entry to
 *    concrete `PackageRef` objects.
 * 3. **Generate concurrently** – uses {@link mapWithConcurrency} with the
 *    configured concurrency limit to produce per-workspace SBOMs.
 * 4. **Aggregate** – merges all workspace results into a single root SBOM.
 */
export class MonorepoSbomGenerator {
  // ─── Public API ───────────────────────────────────────────────────────

  /**
   * Generate SBOMs for a monorepo.
   *
   * @param lockfile   - The parsed pnpm lockfile
   * @param findings   - Vulnerability findings (shared across all workspaces)
   * @param options    - SBOM generation options (merged with defaults)
   * @returns Complete monorepo SBOM result with stats
   */
  async generate(
    lockfile: PnpmLockfile,
    findings: VulnerabilityFinding[],
    options: Partial<MonorepoSbomOptions> = {},
  ): Promise<MonorepoSbomResult> {
    const startTime = Date.now();
    const mergedOptions = this.mergeDefaults(options);

    logger.debug("MonorepoSbomGenerator: starting generation");
    logger.debug(`  concurrency=${mergedOptions.concurrency}`);
    logger.debug(`  includeWorkspacesInRoot=${mergedOptions.includeWorkspacesInRoot}`);
    logger.debug(`  generateWorkspaceSboms=${mergedOptions.generateWorkspaceSboms}`);

    // ── Step 1: Detect workspaces ──────────────────────────────────────
    const workspaces = this.detectWorkspaces(lockfile);

    if (workspaces.length === 0) {
      logger.warn("MonorepoSbomGenerator: no workspaces detected – falling back to single SBOM");
      return this.generateSingleSbom(lockfile, findings, mergedOptions, startTime);
    }

    logger.info(
      `MonorepoSbomGenerator: detected ${workspaces.length} workspace(s): ` +
      workspaces.map((w) => w.path).join(", "),
    );

    // ── Step 2: Build shared vulnerability map ─────────────────────────
    const vulnMap = buildVulnerabilityMap(findings);

    // ── Step 3: Generate workspace SBOMs concurrently ──────────────────
    const workspaceResults: WorkspaceSbomResult[] = [];
    const errors: WorkspaceSbomError[] = [];

    if (mergedOptions.generateWorkspaceSboms) {
      const results = await mapWithConcurrency(
        workspaces,
        mergedOptions.concurrency,
        async (workspace, index) => {
          try {
            const wsResult = this.generateWorkspaceSbom(
              workspace,
              findings,
              vulnMap,
              mergedOptions,
            );

            // Progress callback
            mergedOptions.onWorkspaceComplete?.(
              index + 1,
              workspaces.length,
              workspace.path,
            );

            logger.debug(
              `MonorepoSbomGenerator: workspace "${workspace.path}" done ` +
              `(${wsResult.packageCount} packages, ${wsResult.result.componentCount} components)`,
            );

            return { ok: true as const, result: wsResult };
          } catch (err) {
            const error = err instanceof Error ? err : new Error(String(err));
            logger.error(
              `MonorepoSbomGenerator: failed to generate SBOM for workspace "${workspace.path}": ${error.message}`,
            );
            return { ok: false as const, workspacePath: workspace.path, error };
          }
        },
      );

      for (const r of results) {
        if (r.ok) {
          workspaceResults.push(r.result);
        } else {
          errors.push({ workspacePath: r.workspacePath, error: r.error });
        }
      }
    }

    // ── Step 4: Build aggregated root SBOM ─────────────────────────────
    const aggregated = this.buildAggregatedSbom(
      lockfile,
      findings,
      workspaces,
      workspaceResults,
      mergedOptions,
    );

    // ── Step 5: Build root SBOM (may differ from aggregated) ───────────
    const root = mergedOptions.includeWorkspacesInRoot
      ? aggregated
      : this.generateWorkspaceSbom(
          workspaces.find((w) => w.isRoot) ?? workspaces[0]!,
          findings,
          vulnMap,
          mergedOptions,
        ).result;

    // ── Step 6: Collect stats ──────────────────────────────────────────
    const totalComponents = workspaceResults.reduce(
      (sum, ws) => sum + ws.result.componentCount,
      0,
    );
    const totalVulnerabilities = workspaceResults.reduce(
      (sum, ws) => sum + ws.result.vulnerabilityCount,
      0,
    );
    const workspaceComponentCounts: Record<string, number> = {};
    for (const ws of workspaceResults) {
      workspaceComponentCounts[ws.workspacePath] = ws.result.componentCount;
    }

    const stats: MonorepoSbomResult["stats"] = {
      totalWorkspaces: workspaces.length,
      processedWorkspaces: workspaceResults.length,
      totalComponents,
      totalVulnerabilities,
      generationTimeMs: Date.now() - startTime,
      workspaceComponentCounts,
    };

    logger.info(
      `MonorepoSbomGenerator: completed in ${stats.generationTimeMs}ms – ` +
      `${stats.processedWorkspaces}/${stats.totalWorkspaces} workspaces, ` +
      `${stats.totalComponents} components, ` +
      `${stats.totalVulnerabilities} vulnerabilities`,
    );

    return {
      root,
      workspaces: workspaceResults,
      errors,
      aggregated,
      stats,
    };
  }

  // ─── Workspace Detection ─────────────────────────────────────────────

  /**
   * Detect workspaces from the lockfile `importers` section.
   *
   * The root workspace is identified by the key `"."`. All other keys are
   * treated as child workspaces.
   *
   * For each workspace, we resolve the direct dependencies listed in the
   * importer entry to concrete `PackageRef` objects by cross-referencing
   * against `lockfile.packages`.
   *
   * @param lockfile - The parsed pnpm lockfile
   * @returns Array of workspace info objects (root always first)
   */
  detectWorkspaces(lockfile: PnpmLockfile): WorkspaceInfo[] {
    const importers = lockfile.importers;
    if (!importers || Object.keys(importers).length === 0) {
      return [];
    }

    const packageEntries = lockfile.packages ?? {};
    const allPackages = this.extractAllPackages(packageEntries);

    const workspaces: WorkspaceInfo[] = [];

    for (const [path, importer] of Object.entries(importers)) {
      const isRoot = path === ".";
      const name = this.deriveWorkspaceName(path, importer, isRoot);
      const packages = this.resolveWorkspacePackages(importer, packageEntries, allPackages);

      workspaces.push({
        path,
        name,
        importer,
        packages,
        isRoot,
      });
    }

    // Sort: root first
    workspaces.sort((a, b) => {
      if (a.isRoot) return -1;
      if (b.isRoot) return 1;
      return a.path.localeCompare(b.path);
    });

    return workspaces;
  }

  /**
   * Get the list of workspace paths from a lockfile (lightweight check).
   *
   * Useful for checking whether a lockfile is a monorepo without doing
   * full package resolution.
   *
   * @param lockfile - The parsed pnpm lockfile
   * @returns Array of workspace path strings, or empty if not a monorepo
   */
  getWorkspacePaths(lockfile: PnpmLockfile): string[] {
    const importers = lockfile.importers;
    if (!importers) return [];
    return Object.keys(importers);
  }

  /**
   * Check whether a lockfile represents a monorepo (has >1 importer).
   *
   * @param lockfile - The parsed pnpm lockfile
   * @returns `true` if the lockfile has multiple workspaces
   */
  isMonorepo(lockfile: PnpmLockfile): boolean {
    const importers = lockfile.importers;
    return importers !== undefined && Object.keys(importers).length > 1;
  }

  // ─── Private Helpers ─────────────────────────────────────────────────

  /**
   * Merge caller-provided options with sensible defaults.
   */
  private mergeDefaults(
    options: Partial<MonorepoSbomOptions>,
  ): MonorepoSbomOptions {
    return {
      format: options.format ?? "cyclonedx",
      concurrency: options.concurrency ?? DEFAULT_MONOREPO_OPTIONS.concurrency,
      includeWorkspacesInRoot:
        options.includeWorkspacesInRoot ?? DEFAULT_MONOREPO_OPTIONS.includeWorkspacesInRoot,
      generateWorkspaceSboms:
        options.generateWorkspaceSboms ?? DEFAULT_MONOREPO_OPTIONS.generateWorkspaceSboms,
      onWorkspaceComplete: options.onWorkspaceComplete,
      // Pass through base options
      outputPath: options.outputPath,
      includeVulnerabilities: options.includeVulnerabilities,
      includeDependencies: options.includeDependencies,
      projectName: options.projectName,
      projectVersion: options.projectVersion,
      projectDescription: options.projectDescription,
      swidOptions: options.swidOptions,
      xml: options.xml,
    };
  }

  /**
   * Derive a human-readable name for a workspace.
   *
   * If the workspace is root (`"."`), we use the `projectName` option or
   * `"root"`. For child workspaces, we extract the last path segment.
   */
  private deriveWorkspaceName(
    path: string,
    _importer: LockfileImporter,
    isRoot: boolean,
  ): string {
    if (isRoot) return "root";
    // "./packages/pkg1" → "pkg1"
    const segments = path.replace(/^\.\/?/, "").split("/");
    return segments[segments.length - 1] ?? path;
  }

  /**
   * Extract all packages from `lockfile.packages` into a flat map for
   * quick lookup.
   */
  private extractAllPackages(
    packageEntries: Record<string, unknown>,
  ): Map<string, PackageRef> {
    const map = new Map<string, PackageRef>();

    for (const [key, entry] of Object.entries(packageEntries)) {
      const parsed = parsePnpmPackageKey(key);
      if (!parsed) continue;

      const pkg: PackageRef = { name: parsed.name, version: parsed.version };
      const entryObj = entry as Record<string, unknown>;
      const resolution = entryObj.resolution as Record<string, unknown> | undefined;
      if (resolution && typeof resolution.integrity === "string") {
        pkg.integrity = resolution.integrity;
      }

      // Collect dependency names
      const deps = entryObj.dependencies as Record<string, string> | undefined;
      if (deps) {
        pkg.dependencies = Object.keys(deps);
      }

      map.set(`${parsed.name}@${parsed.version}`, pkg);
    }

    return map;
  }

  /**
   * Resolve the packages that belong to a specific workspace.
   *
   * Walks the importer's `dependencies`, `devDependencies`, and
   * `optionalDependencies`, and resolves each to a `PackageRef` from
   * the global packages section.
   *
   * Note: this gives us the *direct* dependencies. Transitive deps are
   * shared across all workspaces in the lockfile's packages section.
   * For the SBOM we want *all* packages that this workspace transitively
   * depends on – but since the lockfile is flat, we include everything
   * for now and let the SBOM deduplicate.
   */
  private resolveWorkspacePackages(
    importer: LockfileImporter,
    packageEntries: Record<string, unknown>,
    allPackages: Map<string, PackageRef>,
  ): PackageRef[] {
    const directDeps: Array<{ name: string; version: string }> = [];

    // Collect all direct dependency entries
    const depSources = [
      importer.dependencies,
      importer.devDependencies,
      importer.optionalDependencies,
    ];

    for (const deps of depSources) {
      if (!deps) continue;
      for (const [name, versionInfo] of Object.entries(deps)) {
        // Handle both plain string and { specifier, version } formats (pnpm v9)
        let version: string;
        let specifier: string | undefined;
        if (typeof versionInfo === "string") {
          version = versionInfo;
        } else if (versionInfo && typeof versionInfo === "object" && "version" in versionInfo) {
          const vInfo = versionInfo as { specifier?: string; version: string };
          version = vInfo.version;
          specifier = vInfo.specifier;
        } else {
          continue;
        }

        // Skip workspace protocol references (check both specifier and version)
        if (version.startsWith("workspace:") || specifier?.startsWith("workspace:")) continue;

        directDeps.push({ name, version });
      }
    }

    // Resolve to PackageRef objects
    const resolved: PackageRef[] = [];
    for (const dep of directDeps) {
      const pkg = allPackages.get(`${dep.name}@${dep.version}`);
      if (pkg) {
        resolved.push(pkg);
      } else {
        // Package not found in global packages – create a minimal entry
        resolved.push({ name: dep.name, version: dep.version });
      }
    }

    return resolved;
  }

  /**
   * Generate an SBOM for a single workspace.
   */
  private generateWorkspaceSbom(
    workspace: WorkspaceInfo,
    findings: VulnerabilityFinding[],
    vulnMap: ComponentVulnerabilityMap,
    options: MonorepoSbomOptions,
  ): WorkspaceSbomResult {
    const startTime = Date.now();

    // Filter findings to those relevant to this workspace
    const workspacePackageNames = new Set(workspace.packages.map((p) => p.name));
    const relevantFindings = findings.filter(
      (f) => workspacePackageNames.has(f.packageName),
    );

    const result = generateSbom(workspace.packages, relevantFindings, {
      format: options.format,
      projectName: options.projectName ?? workspace.name,
      projectVersion: options.projectVersion,
      projectDescription: options.projectDescription,
      includeVulnerabilities: options.includeVulnerabilities,
      includeDependencies: options.includeDependencies,
      swidOptions: options.swidOptions,
      xml: options.xml,
    });

    result.durationMs = Date.now() - startTime;

    return {
      workspacePath: workspace.path,
      workspaceName: workspace.name,
      result,
      packageCount: workspace.packages.length,
    };
  }

  /**
   * Build an aggregated SBOM that combines all workspace results.
   *
   * All packages are deduplicated by name+version. Vulnerabilities from
   * all workspaces are merged.
   */
  private buildAggregatedSbom(
    lockfile: PnpmLockfile,
    findings: VulnerabilityFinding[],
    workspaces: WorkspaceInfo[],
    workspaceResults: WorkspaceSbomResult[],
    options: MonorepoSbomOptions,
  ): SbomResult {
    // Merge all packages, deduplicated by name@version
    const packageMap = new Map<string, PackageRef>();
    for (const ws of workspaces) {
      for (const pkg of ws.packages) {
        const key = `${pkg.name}@${pkg.version}`;
        if (!packageMap.has(key)) {
          packageMap.set(key, pkg);
        }
      }
    }

    const mergedPackages = Array.from(packageMap.values());

    // All findings are already global – just pass them through
    const result = generateSbom(mergedPackages, findings, {
      format: options.format,
      projectName: options.projectName ?? "monorepo-root",
      projectVersion: options.projectVersion,
      projectDescription: options.projectDescription,
      includeVulnerabilities: options.includeVulnerabilities,
      includeDependencies: options.includeDependencies,
      swidOptions: options.swidOptions,
      xml: options.xml,
    });

    return result;
  }

  /**
   * Fallback: when no workspaces are detected, generate a single SBOM.
   */
  private generateSingleSbom(
    lockfile: PnpmLockfile,
    findings: VulnerabilityFinding[],
    options: MonorepoSbomOptions,
    startTime: number,
  ): MonorepoSbomResult {
    const { packages } = extractPackagesFromLockfile(lockfile);
    const result = generateSbom(packages, findings, options);

    return {
      root: result,
      workspaces: [],
      errors: [],
      aggregated: result,
      stats: {
        totalWorkspaces: 1,
        processedWorkspaces: 1,
        totalComponents: result.componentCount,
        totalVulnerabilities: result.vulnerabilityCount,
        generationTimeMs: Date.now() - startTime,
        workspaceComponentCounts: { ".": result.componentCount },
      },
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Convenience Function
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Convenience function for monorepo SBOM generation.
 *
 * Creates a {@link MonorepoSbomGenerator} instance and invokes
 * {@link MonorepoSbomGenerator.generate} with the given parameters.
 *
 * @param lockfile - The parsed pnpm lockfile
 * @param findings - Vulnerability findings from audit
 * @param options  - SBOM generation options (all optional)
 * @returns Complete monorepo SBOM result
 */
export async function generateMonorepoSbom(
  lockfile: PnpmLockfile,
  findings: VulnerabilityFinding[],
  options: Partial<MonorepoSbomOptions> = {},
): Promise<MonorepoSbomResult> {
  const generator = new MonorepoSbomGenerator();
  return generator.generate(lockfile, findings, options);
}
