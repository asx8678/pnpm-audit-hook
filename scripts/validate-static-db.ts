#!/usr/bin/env tsx
/**
 * validate-static-db.ts
 *
 * CLI wrapper around the Static DB consistency analyzer.
 * Exits 0 if the DB is consistent, 1 if issues are found.
 *
 * Usage:
 *   tsx scripts/validate-static-db.ts
 *   tsx scripts/validate-static-db.ts --data-path src/static-db/data
 */

import { resolve } from "node:path";
import { analyzeStaticDbConsistency } from "../src/static-db/consistency";

function parseArgs(args: string[]): { dataPath: string } {
  let dataPath = resolve(__dirname, "..", "src", "static-db", "data");

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--data-path" && i + 1 < args.length) {
      dataPath = resolve(process.cwd(), args[++i]);
    }
  }

  return { dataPath };
}

async function main(): Promise<void> {
  const { dataPath } = parseArgs(process.argv.slice(2));

  console.log(`Analyzing static DB consistency: ${dataPath}`);
  console.log("");

  const report = await analyzeStaticDbConsistency(dataPath);

  console.log(`  Index loaded:              ${report.indexLoaded ? "\u2713 Yes" : "\u2717 No"}`);
  console.log(`  Indexed packages:          ${report.indexedPackageCount}`);
  console.log(`  Index totalPackages field: ${report.indexTotalPackages}`);
  console.log(`  Index totalVulns field:    ${report.indexTotalVulnerabilities}`);
  console.log(`  Sum of index counts:       ${report.sumIndexCounts}`);
  console.log(`  Shard files on disk:       ${report.shardFileCount}`);
  console.log(`  Orphan shards:             ${report.orphanShards.length}`);
  console.log(`  Missing shards:            ${report.missingShards.length}`);
  console.log(`  Count mismatches:          ${report.countMismatches.length}`);
  console.log(`  Package name mismatches:   ${report.packageNameMismatches.length}`);
  console.log(`  Metadata mismatches:       ${report.metadataMismatches.length}`);
  console.log(`  Errors:                    ${report.errors.length}`);
  console.log(`  Consistent:                ${report.isConsistent ? "\u2713 Yes" : "\u2717 No"}`);
  console.log("");

  if (report.errors.length > 0) {
    console.log("Errors:");
    for (const e of report.errors) {
      console.log(`  - ${e}`);
    }
    console.log("");
  }

  if (report.metadataMismatches.length > 0) {
    console.log("Metadata mismatches:");
    for (const m of report.metadataMismatches) {
      console.log(`  - ${m.field}: field=${m.expected} actual=${m.actual}`);
    }
    console.log("");
  }

  if (report.orphanShards.length > 0) {
    console.log("Orphan shards (on disk, not in index):");
    for (const s of report.orphanShards.slice(0, 20)) {
      console.log(`  - ${s}`);
    }
    if (report.orphanShards.length > 20) {
      console.log(`  ... and ${report.orphanShards.length - 20} more`);
    }
    console.log("");
  }

  if (report.missingShards.length > 0) {
    console.log("Missing shards (in index, no file on disk):");
    for (const s of report.missingShards) {
      console.log(`  - ${s}`);
    }
    console.log("");
  }

  if (report.countMismatches.length > 0) {
    console.log("Count mismatches:");
    for (const m of report.countMismatches) {
      console.log(`  - ${m.packageName}: index=${m.indexCount} shard=${m.shardCount}`);
    }
    console.log("");
  }

  if (report.packageNameMismatches.length > 0) {
    console.log("Package name mismatches:");
    for (const m of report.packageNameMismatches) {
      console.log(`  - ${m.shardPath}: decoded="${m.decodedName}" actual="${m.actualName}"`);
    }
    console.log("");
  }

  if (report.isConsistent) {
    console.log("\u2713 Static DB is fully consistent.");
    process.exit(0);
  } else {
    console.error("\u2717 Static DB has consistency issues.");
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(`Fatal error: ${(err as Error).message}`);
  process.exit(1);
});
