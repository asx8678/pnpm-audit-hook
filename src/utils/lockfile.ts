/**
 * @module lockfile
 *
 * Backward-compatible re-export shim.
 * The implementation has been split into focused modules under lockfile/:
 *   - cache.ts         — Parse caching
 *   - package-key-parser.ts — Package key parsing
 *   - registry-detector.ts  — Registry detection and display names
 *   - graph-builder.ts      — Dependency graph building and chain tracing
 *   - package-extractor.ts  — Package extraction from lockfile
 *   - index.ts              — Barrel re-exports
 *
 * This file re-exports everything so existing imports continue to work.
 */
export {
  enableParseCache,
  disableParseCache,
} from "./lockfile/cache.js";

export {
  parsePnpmPackageKey,
} from "./lockfile/package-key-parser.js";

export {
  getRegistryDisplayName,
  extractRegistryInfo,
} from "./lockfile/registry-detector.js";

export {
  extractPackagesFromLockfile,
  type LockfileParseResult,
} from "./lockfile/package-extractor.js";

export {
  buildDependencyGraph,
  traceDependencyChain,
} from "./lockfile/graph-builder.js";
