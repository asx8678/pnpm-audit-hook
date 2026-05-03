#!/usr/bin/env tsx
// =============================================================================
// sbom-diff.ts — SBOM Diffing Demo
// =============================================================================
//
// Demonstrates comparing two SBOM documents:
//   - Generating "before" and "after" SBOMs for comparison
//   - Detecting format automatically
//   - Comparing added, removed, and updated packages
//   - Displaying diff summaries
//   - Cross-format comparison (CycloneDX vs SPDX)
//   - Formatting diff output for different use cases
//   - Custom diff options (ignoreVersions, keyFn)
//
// Prerequisites:
//   - Node.js >= 18
//   - Project dependencies installed (`pnpm install`)
//   - Run from project root: npx tsx examples/sbom-diff.ts
// =============================================================================

// ---------------------------------------------------------------------------
// Imports from pnpm-audit-hook source (relative to this file)
// ---------------------------------------------------------------------------
import {
  diffSbom,
  formatDiffResult,
  generateSbom,
} from "../src/index";

import type { PackageRef, VulnerabilityFinding } from "../src/index";
import type { SbomDiffResult } from "../src/sbom/types";

// ---------------------------------------------------------------------------
// Sample "before" packages (v1.0 of a project)
// ---------------------------------------------------------------------------
const PACKAGES_V1: PackageRef[] = [
  { name: "express", version: "4.18.1", dependencies: ["body-parser"] },
  { name: "body-parser", version: "1.20.0" },
  { name: "lodash", version: "4.17.20" },
  { name: "debug", version: "4.3.3", dependencies: ["ms"] },
  { name: "ms", version: "2.1.2" },
  { name: "moment", version: "2.29.4" },
];

// ---------------------------------------------------------------------------
// Sample "after" packages (v2.0 — updated, added, removed)
// ---------------------------------------------------------------------------
const PACKAGES_V2: PackageRef[] = [
  { name: "express", version: "4.18.2", dependencies: ["body-parser"] },   // updated
  { name: "body-parser", version: "1.20.2" },                               // updated
  { name: "lodash", version: "4.17.21" },                                   // updated
  { name: "debug", version: "4.3.4", dependencies: ["ms"] },                // updated
  { name: "ms", version: "2.1.2" },                                         // unchanged
  { name: "helmet", version: "7.1.0" },                                     // added (new)
  { name: "cors", version: "2.8.5" },                                       // added (new)
  // moment removed
];

// ---------------------------------------------------------------------------
// Sample vulnerability findings for the "after" version
// ---------------------------------------------------------------------------
const FINDINGS_V2: VulnerabilityFinding[] = [
  {
    id: "CVE-2021-44228",
    source: "github",
    packageName: "lodash",
    packageVersion: "4.17.21",
    severity: "high",
    cvssScore: 7.5,
  },
];

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║     pnpm-audit-hook — SBOM Diff Example                    ║");
  console.log("╚══════════════════════════════════════════════════════════════╝\n");

  // -------------------------------------------------------------------------
  // Step 1: Generate "before" and "after" SBOMs (simulating two versions)
  // -------------------------------------------------------------------------
  console.log("▸ Step 1: Generating before/after SBOMs…\n");

  const oldSbom = generateSbom(PACKAGES_V1, [], {
    format: "cyclonedx",
    includeDependencies: true,
    projectName: "my-project",
    projectVersion: "1.0.0",
  });

  const newSbom = generateSbom(PACKAGES_V2, FINDINGS_V2, {
    format: "cyclonedx",
    includeDependencies: true,
    includeVulnerabilities: true,
    projectName: "my-project",
    projectVersion: "2.0.0",
  });

  console.log(`  Old SBOM: ${oldSbom.componentCount} components (v1.0)`);
  console.log(`  New SBOM: ${newSbom.componentCount} components (v2.0)\n`);

  // -------------------------------------------------------------------------
  // Step 2: Compare the two SBOMs
  // -------------------------------------------------------------------------
  console.log("▸ Step 2: Comparing SBOMs…\n");

  /**
   * diffSbom() accepts two parsed SBOM documents (any supported format)
   * and returns a structured diff result. Format detection is automatic.
   */
  const oldParsed = JSON.parse(oldSbom.content);
  const newParsed = JSON.parse(newSbom.content);

  const diffResult: SbomDiffResult = diffSbom(oldParsed, newParsed);

  // -------------------------------------------------------------------------
  // Step 3: Display the diff summary
  // -------------------------------------------------------------------------
  console.log("▸ Step 3: Diff summary…\n");

  console.log("  ┌────────────────────────────────────┐");
  console.log("  │ SBOM Diff Summary                  │");
  console.log("  ├────────────────────────────────────┤");
  console.log(`  │ Old format:  ${diffResult.metadata.oldFormat.padEnd(20)}│`);
  console.log(`  │ New format:  ${diffResult.metadata.newFormat.padEnd(20)}│`);
  console.log(`  │ Compared at: ${diffResult.metadata.comparedAt.slice(0, 20).padEnd(20)}│`);
  console.log("  ├────────────────────────────────────┤");
  console.log(`  │ Added:       ${String(diffResult.summary.totalAdded).padEnd(20)}│`);
  console.log(`  │ Removed:     ${String(diffResult.summary.totalRemoved).padEnd(20)}│`);
  console.log(`  │ Updated:     ${String(diffResult.summary.totalUpdated).padEnd(20)}│`);
  console.log(`  │ Unchanged:   ${String(diffResult.summary.totalUnchanged).padEnd(20)}│`);
  console.log("  └────────────────────────────────────┘\n");

  // -------------------------------------------------------------------------
  // Step 4: Show added packages
  // -------------------------------------------------------------------------
  console.log("▸ Step 4: Added packages…\n");

  if (diffResult.added.length > 0) {
    for (const entry of diffResult.added) {
      console.log(`  ➕ ${entry.name}@${entry.version}`);
      if (entry.purl) console.log(`     purl: ${entry.purl}`);
    }
  } else {
    console.log("  (none)");
  }
  console.log();

  // -------------------------------------------------------------------------
  // Step 5: Show removed packages
  // -------------------------------------------------------------------------
  console.log("▸ Step 5: Removed packages…\n");

  if (diffResult.removed.length > 0) {
    for (const entry of diffResult.removed) {
      console.log(`  ➖ ${entry.name}@${entry.version}`);
    }
  } else {
    console.log("  (none)");
  }
  console.log();

  // -------------------------------------------------------------------------
  // Step 6: Show updated packages
  // -------------------------------------------------------------------------
  console.log("▸ Step 6: Updated packages…\n");

  if (diffResult.updated.length > 0) {
    for (const entry of diffResult.updated) {
      console.log(`  🔄 ${entry.name}: ${entry.previousVersion} → ${entry.version}`);
    }
  } else {
    console.log("  (none)");
  }
  console.log();

  // -------------------------------------------------------------------------
  // Step 7: Use formatDiffResult for a formatted string output
  // -------------------------------------------------------------------------
  console.log("▸ Step 7: Formatted diff output…\n");

  /**
   * formatDiffResult() produces a human-readable string from the diff.
   * Useful for logging, PR comments, or CI output.
   */
  const formattedOutput = formatDiffResult(diffResult);
  const lines = formattedOutput.split("\n");
  for (const line of lines.slice(0, 20)) {
    console.log(`  ${line}`);
  }
  if (lines.length > 20) {
    console.log(`  … (${lines.length - 20} more lines)`);
  }
  console.log();

  // -------------------------------------------------------------------------
  // Step 8: Cross-format comparison (CycloneDX vs SPDX)
  // -------------------------------------------------------------------------
  console.log("▸ Step 8: Cross-format comparison (CycloneDX → SPDX)…\n");

  /**
   * diffSbom() normalizes both documents internally, so it can compare
   * CycloneDX against SPDX even though they have different schemas.
   */
  const spdxSbom = generateSbom(PACKAGES_V2, FINDINGS_V2, {
    format: "spdx",
    includeDependencies: true,
    includeVulnerabilities: true,
    projectName: "my-project",
    projectVersion: "2.0.0",
  });

  const spdxParsed = JSON.parse(spdxSbom.content);

  // Compare old CycloneDX with new SPDX
  const crossDiff = diffSbom(oldParsed, spdxParsed);

  console.log("  Comparing CycloneDX (old) vs SPDX (new):");
  console.log(`    Old format: ${crossDiff.metadata.oldFormat}`);
  console.log(`    New format: ${crossDiff.metadata.newFormat}`);
  console.log(`    Added:      ${crossDiff.summary.totalAdded}`);
  console.log(`    Removed:    ${crossDiff.summary.totalRemoved}`);
  console.log(`    Updated:    ${crossDiff.summary.totalUpdated}`);
  console.log(`    Unchanged:  ${crossDiff.summary.totalUnchanged}`);
  console.log();

  // -------------------------------------------------------------------------
  // Step 9: Custom diff options
  // -------------------------------------------------------------------------
  console.log("▸ Step 9: Custom diff options…\n");

  /**
   * ignoreVersions: when true, version bumps are not reported as updates.
   * Useful when you only care about new/removed packages, not upgrades.
   */
  const noVersionDiff = diffSbom(oldParsed, newParsed, {
    ignoreVersions: true,
  });

  console.log("  Diff with ignoreVersions=true (version changes hidden):");
  console.log(`    Added:   ${noVersionDiff.summary.totalAdded}`);
  console.log(`    Removed: ${noVersionDiff.summary.totalRemoved}`);
  console.log(`    Updated: ${noVersionDiff.summary.totalUpdated} (version changes ignored)`);
  console.log(`    Unchanged: ${noVersionDiff.summary.totalUnchanged}`);
  console.log();

  /**
   * keyFn: custom function to build the comparison key for each package.
   * Default uses name+version; here we match by name only.
   */
  const customDiff = diffSbom(oldParsed, newParsed, {
    keyFn: (pkg) => pkg.name,  // Match by name only (ignore version)
  });

  console.log("  Diff with custom keyFn (name-only matching):");
  console.log(`    Added:   ${customDiff.summary.totalAdded}`);
  console.log(`    Removed: ${customDiff.summary.totalRemoved}`);
  console.log(`    Updated: ${customDiff.summary.totalUpdated}`);
  console.log(`    Unchanged: ${customDiff.summary.totalUnchanged}`);
  console.log();

  // -------------------------------------------------------------------------
  // Done!
  // -------------------------------------------------------------------------
  console.log("─".repeat(62));
  console.log("Done! SBOM diffing example completed. 🐶");
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------
main().catch((err) => {
  console.error("Unhandled error:", err);
  process.exit(1);
});
