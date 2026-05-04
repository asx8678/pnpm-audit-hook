#!/usr/bin/env node
"use strict";

/**
 * Thin CLI wrapper — delegates to the TypeScript CLI module.
 * This is the entry point for the pnpm-audit-scan binary.
 */
const path = require("path");

// Resolve the compiled CLI module
const distCli = path.join(__dirname, "..", "dist", "cli.js");

try {
  const { main } = require(distCli);
  main(process.argv.slice(2)).then((exitCode) => {
    process.exit(exitCode);
  }).catch((err) => {
    console.error(`Fatal error: ${err.message || err}`);
    process.exit(1);
  });
} catch (err) {
  console.error(`Fatal error: ${err.message || err}`);
  process.exit(1);
}
