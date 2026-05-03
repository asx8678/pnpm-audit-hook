/**
 * @module pnpm-audit-hook
 * Pre-download security gate for pnpm that blocks vulnerable packages.
 *
 * This module provides:
 * - {@link createPnpmHooks} for automatic pnpm integration
 * - {@link runAudit} for programmatic audit execution
 * - Type definitions for configuration and results
 * - Color utilities for terminal output
 *
 * @example
 * ```typescript
 * import { createPnpmHooks } from 'pnpm-audit-hook';
 * // Export from .pnpmfile.cjs
 * module.exports = createPnpmHooks();
 * ```
 *
 * @example
 * ```typescript
 * import { runAudit } from 'pnpm-audit-hook';
 * const result = await runAudit(lockfile, runtime);
 * if (result.blocked) process.exit(1);
 * ```
 */

import { runAudit } from "./audit";
import type { PnpmHookContext, PnpmLockfile, VulnerabilityFinding } from "./types";
import { getRegistryUrl } from "./utils/env";

/**
 * Return type for pnpm hooks export.
 *
 * Contains the `hooks` object with lifecycle functions that pnpm calls
 * during package resolution and installation.
 *
 * @see {@link createPnpmHooks} for creating an instance
 */
export interface PnpmHooks {
  hooks: {
    /**
     * Called after all dependencies have been resolved but before download.
     *
     * @param lockfile - The resolved pnpm lockfile structure
     * @param context - Context provided by pnpm (lockfile dir, store dir, registries)
     * @returns The lockfile unchanged if audit passes
     * @throws {Error} If the audit blocks installation
     */
    afterAllResolved: (
      lockfile: PnpmLockfile,
      context: PnpmHookContext
    ) => Promise<PnpmLockfile>;
  };
}

/**
 * Build a rich error message with CVE IDs, severities, and fix info.
 *
 * @param decisions - Policy decisions that resulted in blocking
 * @param findings - All vulnerability findings for context
 * @returns Formatted error message with package details
 */
function buildBlockedErrorMessage(
  decisions: Array<{ action: string; findingId?: string; findingSeverity?: string; packageName?: string; packageVersion?: string }>,
  findings: VulnerabilityFinding[],
): string {
  const blocked = decisions.filter(d => d.action === "block");
  const blockedCount = blocked.length;

  // Build finding details map for quick lookup
  const findingMap = new Map<string, VulnerabilityFinding>();
  for (const f of findings) {
    findingMap.set(`${f.packageName}@${f.packageVersion}:${f.id}`, f);
  }

  // Group by package, include CVE and fix info
  const details: string[] = [];
  const seenPkgs = new Set<string>();
  for (const d of blocked) {
    if (!d.packageName) continue;
    const pkgKey = `${d.packageName}@${d.packageVersion}`;
    const finding = d.findingId
      ? findingMap.get(`${pkgKey}:${d.findingId}`)
      : undefined;

    const sev = d.findingSeverity ?? finding?.severity ?? "";
    const sevStr = sev ? `[${sev.toUpperCase()}]` : "";
    const id = d.findingId ?? "";
    const fix = finding?.fixedVersion ? ` (fix: ${finding.fixedVersion})` : "";
    details.push(`  ${sevStr} ${pkgKey} ${id}${fix}`);
    seenPkgs.add(pkgKey);
  }

  const header = `pnpm-audit-hook blocked installation (${blockedCount} issue${blockedCount !== 1 ? "s" : ""} in ${seenPkgs.size} package${seenPkgs.size !== 1 ? "s" : ""})`;

  if (details.length === 0) return header;
  return `${header}:\n${details.join("\n")}`;
}

/**
 * Creates pnpm hooks for automatic vulnerability auditing.
 *
 * This is the recommended way to integrate pnpm-audit-hook into your project.
 * Export the result from `.pnpmfile.cjs` and pnpm will automatically audit
 * all packages before download.
 *
 * @returns PnpmHooks object to export from .pnpmfile.cjs
 *
 * @example
 * ```javascript
 * // .pnpmfile.cjs
 * const { createPnpmHooks } = require('pnpm-audit-hook');
 * module.exports = createPnpmHooks();
 * ```
 *
 * @example
 * ```typescript
 * // .pnpmfile.ts (with pnpm 9+)
 * import { createPnpmHooks } from 'pnpm-audit-hook';
 * export default createPnpmHooks();
 * ```
 */
export function createPnpmHooks(): PnpmHooks {
  return {
    hooks: {
      afterAllResolved: async (lockfile: PnpmLockfile, context: PnpmHookContext) => {
        const env: Record<string, string | undefined> = process.env;
        const runtime = {
          cwd: context?.lockfileDir ?? process.cwd(),
          env,
          registryUrl: getRegistryUrl(env),
        };
        const result = await runAudit(lockfile, runtime);
        if (result.blocked) {
          throw new Error(
            buildBlockedErrorMessage(result.decisions, result.findings)
          );
        }
        return lockfile;
      },
    },
  };
}

export { runAudit, EXIT_CODES } from "./audit";
export type { AuditResult } from "./audit";
export type {
  AuditConfig,
  AuditConfigInput,
  PackageRef,
  PnpmLockfile,
  PnpmHookContext,
  PolicyDecision,
  RuntimeOptions,
  Severity,
  SourceStatus,
  VulnerabilityFinding,
} from "./types";

// Export color utilities for external use
export {
  supportsColor,
  severityColor,
  severityLabel,
  severityBgColor,
  statusColor,
  statusIcon,
  statusText,
  horizontalLine,
  sectionHeader,
  subsectionHeader,
  indent,
  listItem,
  formatError,
  formatWarning,
  formatSuccess,
  progressBar,
  spinnerChar,
  truncate,
  pad,
  center,
  box,
  RESET,
  BOLD,
  DIM,
  ITALIC,
  UNDERLINE,
  RED,
  GREEN,
  YELLOW,
  BLUE,
  MAGENTA,
  CYAN,
  WHITE,
  BRIGHT_RED,
  BRIGHT_GREEN,
  BRIGHT_YELLOW,
  BRIGHT_BLUE,
  BRIGHT_MAGENTA,
  BRIGHT_CYAN,
  BG_RED,
  BG_GREEN,
  BG_YELLOW,
  BG_BLUE,
  SEVERITY_ORDER,
} from "./utils/color-utils";
