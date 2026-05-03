#!/usr/bin/env tsx
// =============================================================================
// sbom-generation.ts — SBOM Generation Demo
// =============================================================================
//
// Demonstrates generating Software Bill of Materials documents:
//   - Generating CycloneDX 1.5 JSON SBOMs
//   - Generating CycloneDX XML SBOMs
//   - Generating SPDX 2.3 SBOMs
//   - Generating SWID Tags (ISO/IEC 19770-2)
//   - Writing SBOMs to files
//   - Validating generated SBOMs against schemas
//   - Using the generator factory with different options
//
// Prerequisites:
//   - Node.js >= 18
//   - Project dependencies installed (`pnpm install`)
//   - Run from project root: npx tsx examples/sbom-generation.ts
// =============================================================================

import fs from "node:fs/promises";
import path from "node:path";

// ---------------------------------------------------------------------------
// Imports from pnpm-audit-hook source (relative to this file)
// ---------------------------------------------------------------------------
import {
  generateSbom,
  generateCycloneDX,
  generateCycloneDXSbom,
  serializeCycloneDXToXml,
  generateSwidSbom,
  generateSwidTags,
  serializeSwidTagToXml,
  validateSbom,
  isValidSbom,
} from "../src/index";

import type {
  PackageRef,
  VulnerabilityFinding,
} from "../src/index";

// CycloneDXBom is not re-exported from the top-level barrel — import directly
import type { CycloneDXBom } from "../src/sbom/types";

// ---------------------------------------------------------------------------
// Sample data — in a real project you'd extract these from your lockfile.
// Each PackageRef represents a resolved package with its dependency edges.
// ---------------------------------------------------------------------------
const SAMPLE_PACKAGES: PackageRef[] = [
  {
    name: "express",
    version: "4.18.2",
    dependencies: ["accepts", "body-parser"],
  },
  {
    name: "body-parser",
    version: "1.20.2",
    dependencies: ["bytes", "debug"],
  },
  {
    name: "accepts",
    version: "1.3.8",
    dependencies: ["negotiator"],
  },
  {
    name: "negotiator",
    version: "0.6.3",
  },
  {
    name: "lodash",
    version: "4.17.21",
  },
  {
    name: "debug",
    version: "4.3.4",
    dependencies: ["ms"],
  },
  {
    name: "ms",
    version: "2.1.2",
  },
  {
    name: "bytes",
    version: "3.1.2",
  },
  {
    name: "typescript",
    version: "5.3.3",
  },
];

/** Simulated vulnerability findings — normally produced by runAudit() */
const SAMPLE_FINDINGS: VulnerabilityFinding[] = [
  {
    id: "CVE-2021-44228",
    source: "github",
    packageName: "lodash",
    packageVersion: "4.17.21",
    title: "Prototype Pollution in lodash",
    severity: "high",
    cvssScore: 7.5,
    fixedVersion: "4.17.22",
    url: "https://github.com/advisories/GHSA-jf85-cpcp-j695",
  },
  {
    id: "CVE-2023-26159",
    source: "github",
    packageName: "debug",
    packageVersion: "4.3.4",
    title: "ReDoS in debug module",
    severity: "medium",
    cvssScore: 5.3,
    fixedVersion: "4.3.5",
    url: "https://github.com/advisories/GHSA-gxpj-cx7g-858c",
  },
];

// ---------------------------------------------------------------------------
// Output directory for generated SBOM files
// ---------------------------------------------------------------------------
const OUTPUT_DIR = path.join(process.cwd(), "examples", "sbom-output");

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║     pnpm-audit-hook — SBOM Generation Example              ║");
  console.log("╚══════════════════════════════════════════════════════════════╝\n");

  // Ensure output directory exists
  await fs.mkdir(OUTPUT_DIR, { recursive: true });

  // -------------------------------------------------------------------------
  // Step 1: Generate CycloneDX JSON SBOM (default format)
  // -------------------------------------------------------------------------
  console.log("▸ Step 1: Generating CycloneDX JSON SBOM…\n");

  /**
   * generateSbom() is the main factory — it accepts packages, findings,
   * and options, then dispatches to the appropriate format-specific generator.
   */
  const cyclonedxJson = generateSbom(SAMPLE_PACKAGES, SAMPLE_FINDINGS, {
    format: "cyclonedx",
    includeVulnerabilities: true,
    includeDependencies: true,
    projectName: "my-awesome-project",
    projectVersion: "1.0.0",
  });

  printSbomResult("CycloneDX JSON", cyclonedxJson);

  // Write to file
  const cyclonedxPath = path.join(OUTPUT_DIR, "sbom-cyclonedx.json");
  await fs.writeFile(cyclonedxPath, cyclonedxJson.content, "utf-8");
  console.log(`  📁 Written to: ${cyclonedxPath}\n`);

  // -------------------------------------------------------------------------
  // Step 2: Generate CycloneDX XML SBOM
  // -------------------------------------------------------------------------
  console.log("▸ Step 2: Generating CycloneDX XML SBOM…\n");

  const cyclonedxXml = generateSbom(SAMPLE_PACKAGES, SAMPLE_FINDINGS, {
    format: "cyclonedx-xml",
    includeVulnerabilities: true,
    includeDependencies: true,
    projectName: "my-awesome-project",
    projectVersion: "1.0.0",
  });

  printSbomResult("CycloneDX XML", cyclonedxXml);

  const xmlPath = path.join(OUTPUT_DIR, "sbom-cyclonedx.xml");
  await fs.writeFile(xmlPath, cyclonedxXml.content, "utf-8");
  console.log(`  📁 Written to: ${xmlPath}\n`);

  // -------------------------------------------------------------------------
  // Step 3: Generate SPDX SBOM
  // -------------------------------------------------------------------------
  console.log("▸ Step 3: Generating SPDX 2.3 SBOM…\n");

  const spdxResult = generateSbom(SAMPLE_PACKAGES, SAMPLE_FINDINGS, {
    format: "spdx",
    includeVulnerabilities: true,
    includeDependencies: true,
    projectName: "my-awesome-project",
    projectVersion: "1.0.0",
  });

  printSbomResult("SPDX 2.3", spdxResult);

  const spdxPath = path.join(OUTPUT_DIR, "sbom-spdx.json");
  await fs.writeFile(spdxPath, spdxResult.content, "utf-8");
  console.log(`  📁 Written to: ${spdxPath}\n`);

  // -------------------------------------------------------------------------
  // Step 4: Generate SWID Tags
  // -------------------------------------------------------------------------
  console.log("▸ Step 4: Generating SWID Tags (ISO/IEC 19770-2)…\n");

  /**
   * SWID Tags use a different metadata structure — regid, softwareCreator,
   * and softwareLicensor identify the software vendor.
   */
  const swidResult = generateSbom(SAMPLE_PACKAGES, SAMPLE_FINDINGS, {
    format: "swid",
    includeVulnerabilities: false,
    projectName: "my-awesome-project",
    projectVersion: "1.0.0",
    swidOptions: {
      regid: "com.example.my-project",
      softwareCreator: {
        name: "My Company",
        regid: "com.example",
      },
      softwareLicensor: {
        name: "My Company",
        regid: "com.example",
      },
    },
  });

  printSbomResult("SWID Tags", swidResult);

  const swidPath = path.join(OUTPUT_DIR, "sbom-swid.xml");
  await fs.writeFile(swidPath, swidResult.content, "utf-8");
  console.log(`  📁 Written to: ${swidPath}\n`);

  // -------------------------------------------------------------------------
  // Step 5: Using the generator factory with different options
  // -------------------------------------------------------------------------
  console.log("▸ Step 5: Generator factory — minimal vs. full options…\n");

  // Minimal: no vulnerabilities, no dependencies
  const minimal = generateSbom(SAMPLE_PACKAGES, [], {
    format: "cyclonedx",
    projectName: "minimal-project",
  });

  console.log(`  Minimal SBOM: ${minimal.componentCount} components, ${minimal.vulnerabilityCount} vulnerabilities`);

  // Full: everything enabled
  const full = generateSbom(SAMPLE_PACKAGES, SAMPLE_FINDINGS, {
    format: "cyclonedx",
    includeVulnerabilities: true,
    includeDependencies: true,
    projectName: "full-project",
    projectVersion: "2.0.0",
    projectDescription: "A project with all SBOM features enabled",
  });

  console.log(`  Full SBOM:    ${full.componentCount} components, ${full.vulnerabilityCount} vulnerabilities`);
  console.log();

  // -------------------------------------------------------------------------
  // Step 6: Using lower-level CycloneDX API directly
  // -------------------------------------------------------------------------
  console.log("▸ Step 6: Low-level CycloneDX API…\n");

  /**
   * generateCycloneDXSbom returns a raw CycloneDXBom object — useful when
   * you need to inspect or manipulate the BOM before serialization.
   */
  const cyclonedxBom = generateCycloneDXSbom(SAMPLE_PACKAGES, SAMPLE_FINDINGS, {
    projectName: "low-level-project",
    projectVersion: "1.0.0",
    includeDependencies: true,
    includeVulnerabilities: true,
  });

  console.log(`  BOM format:     ${cyclonedxBom.bomFormat}`);
  console.log(`  Spec version:   ${cyclonedxBom.specVersion}`);
  console.log(`  Components:     ${cyclonedxBom.components?.length ?? 0}`);
  console.log(`  Dependencies:   ${cyclonedxBom.dependencies?.length ?? 0}`);
  console.log(`  Vulnerabilities: ${cyclonedxBom.vulnerabilities?.length ?? 0}`);

  // Serialize to XML
  const xmlString = serializeCycloneDXToXml(cyclonedxBom);
  console.log(`  XML size:       ${xmlString.length} bytes`);
  console.log();

  // -------------------------------------------------------------------------
  // Step 7: Using lower-level SWID API
  // -------------------------------------------------------------------------
  console.log("▸ Step 7: Low-level SWID API…\n");

  /**
   * generateSwidTags returns a SwidTagSet with individual tags per package.
   * Each tag conforms to ISO/IEC 19770-2.
   */
  const swidTagSet = generateSwidTags(SAMPLE_PACKAGES, {
    regid: "com.example.low-level",
    softwareCreator: { name: "Low-Level Demo" },
  });

  console.log(`  Generated ${swidTagSet.tags.length} SWID tag(s):`);
  for (const tag of swidTagSet.tags.slice(0, 3)) {
    console.log(`    • ${tag.name}@${tag.tagVersion} (id: ${tag.tagId.slice(0, 8)}…)`);
  }
  if (swidTagSet.tags.length > 3) {
    console.log(`    … and ${swidTagSet.tags.length - 3} more`);
  }

  // Serialize the first tag to XML
  const tagXml = serializeSwidTagToXml(swidTagSet.tags[0]);
  console.log(`  Tag XML size: ${tagXml.length} bytes`);
  console.log();

  // -------------------------------------------------------------------------
  // Step 8: Validate generated SBOMs
  // -------------------------------------------------------------------------
  console.log("▸ Step 8: Validating generated SBOMs…\n");

  // Validate CycloneDX JSON
  const cyclonedxValidation = validateSbom(cyclonedxJson.content, "cyclonedx");
  printValidationResult("CycloneDX JSON", cyclonedxValidation);

  // Validate SPDX
  const spdxValidation = validateSbom(spdxResult.content, "spdx");
  printValidationResult("SPDX", spdxValidation);

  // Quick validity check
  const isValid = isValidSbom(cyclonedxJson.content, "cyclonedx");
  console.log(`  isValidSbom(cyclonedx, "cyclonedx"): ${isValid}\n`);

  // -------------------------------------------------------------------------
  // Step 9: Inspect the generated CycloneDX structure
  // -------------------------------------------------------------------------
  console.log("▸ Step 9: CycloneDX document structure…\n");

  const parsed: CycloneDXBom = JSON.parse(cyclonedxJson.content);

  console.log(`  bomFormat:      ${parsed.bomFormat}`);
  console.log(`  specVersion:    ${parsed.specVersion}`);
  console.log(`  version:        ${parsed.version}`);
  console.log(`  serialNumber:   ${parsed.serialNumber?.slice(0, 30)}…`);
  console.log(`  timestamp:      ${parsed.metadata?.timestamp}`);

  if (parsed.metadata?.component) {
    const comp = parsed.metadata.component;
    console.log(`  project name:   ${comp.name}`);
    console.log(`  project purl:   ${comp.purl}`);
  }

  if (parsed.components && parsed.components.length > 0) {
    console.log(`\n  Components (${parsed.components.length}):`);
    for (const comp of parsed.components.slice(0, 5)) {
      const vulnCount = parsed.vulnerabilities?.filter((v) =>
        v.affects?.some((a) => a.ref === comp["bom-ref"]),
      ).length ?? 0;
      const vulnStr = vulnCount > 0 ? ` ⚠️ ${vulnCount} vuln(s)` : "";
      console.log(`    • ${comp.name}@${comp.version} (${comp.purl})${vulnStr}`);
    }
    if (parsed.components.length > 5) {
      console.log(`    … and ${parsed.components.length - 5} more`);
    }
  }
  console.log();

  // -------------------------------------------------------------------------
  // Done!
  // -------------------------------------------------------------------------
  console.log("─".repeat(62));
  console.log(`Done! Generated 4 SBOM files in ${OUTPUT_DIR}/ 🐶`);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Print a formatted summary of an SbomResult.
 *
 * @param label  - Human-readable format name
 * @param result - SbomResult returned by generateSbom()
 */
function printSbomResult(label: string, result: { componentCount: number; vulnerabilityCount: number; format: string; durationMs: number; content: string }) {
  console.log(`  ${label}:`);
  console.log(`    Components:       ${result.componentCount}`);
  console.log(`    Vulnerabilities:  ${result.vulnerabilityCount}`);
  console.log(`    Format:           ${result.format}`);
  console.log(`    Duration:         ${result.durationMs}ms`);
  console.log(`    Content size:     ${result.content.length} bytes`);
}

/**
 * Print the result of SBOM schema validation.
 *
 * @param label  - Human-readable format name
 * @param result - Validation result from validateSbom()
 */
function printValidationResult(
  label: string,
  result: { valid: boolean; errors: Array<{ path: string; message: string }>; warnings: Array<{ path: string; message: string }> },
) {
  const icon = result.valid ? "✅" : "❌";
  console.log(`  ${icon} ${label}: ${result.valid ? "valid" : "INVALID"}`);

  if (result.errors.length > 0) {
    console.log("     Errors:");
    for (const err of result.errors) {
      console.log(`       ${err.path}: ${err.message}`);
    }
  }

  if (result.warnings.length > 0) {
    console.log("     Warnings:");
    for (const warn of result.warnings) {
      console.log(`       ${warn.path}: ${warn.message}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------
main().catch((err) => {
  console.error("Unhandled error:", err);
  process.exit(1);
});
