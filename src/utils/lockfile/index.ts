/**
 * Lockfile utilities — modular re-exports.
 *
 * This barrel file re-exports the public API from the sub-modules
 * so consumers can import from "utils/lockfile" as a single entry point.
 */

// Parse caching
export { enableParseCache, disableParseCache } from "./cache.js";

// Package key parsing
export { parsePnpmPackageKey } from "./package-key-parser.js";

// Registry detection and display names
export { getRegistryDisplayName, extractRegistryInfo } from "./registry-detector.js";

// Package extraction from lockfile
export { extractPackagesFromLockfile } from "./package-extractor.js";
export type { LockfileParseResult } from "./package-extractor.js";

// Dependency graph building and chain tracing
export { buildDependencyGraph, traceDependencyChain } from "./graph-builder.js";
