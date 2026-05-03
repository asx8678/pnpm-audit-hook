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
export {
  extractPackagesFromLockfile,
  extractPackagesFromLockfileStreaming,
} from "./package-extractor.js";
export type { LockfileParseResult } from "./package-extractor.js";

// Streaming parser for large lockfiles
export {
  StreamingLockfileParser,
  parseLockfileStreaming,
} from "./streaming-parser.js";
export type {
  StreamingParserOptions,
  StreamingParseResult,
} from "./streaming-parser.js";

// Dependency graph building, chain tracing, and impact analysis
export {
  buildDependencyGraph,
  traceDependencyChain,
  traceAllDependencyChains,
  analyzeImpact,
  getDependencyTree,
  analyzeDependencyChain,
} from "./graph-builder.js";

// Enhanced dependency chain analysis with CVSS integration
export {
  propagateSeverity,
  analyzeVulnerability,
  analyzeAllVulnerabilities,
  sortByRisk,
} from "./dependency-chain-analyzer.js";
