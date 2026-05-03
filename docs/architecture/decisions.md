# Architecture Decision Records (ADRs)

This document records the architectural decisions made in `pnpm-audit-hook`.

## Table of Contents

- [ADR Overview](#adr-overview)
- [ADR-001: YAML Configuration Format](#adr-001-yaml-configuration-format)
- [ADR-002: Static Database Schema](#adr-002-static-database-schema)
- [ADR-003: Multi-Source Aggregation](#adr-003-multi-source-aggregation)
- [ADR-004: Zero Runtime Dependencies](#adr-004-zero-runtime-dependencies)
- [ADR-005: Policy Engine Design](#adr-005-policy-engine-design)
- [ADR-006: Output Format Abstraction](#adr-006-output-format-abstraction)
- [ADR-007: Lazy Loading Strategy](#adr-007-lazy-loading-strategy)
- [ADR-008: Cache Implementation](#adr-008-cache-implementation)
- [ADR-009: Error Handling Strategy](#adr-009-error-handling-strategy)
- [ADR-010: TypeScript Type Definitions](#adr-010-typescript-type-definitions)

---

## ADR Overview

Each ADR follows this template:

```
# ADR-XXXX: Title

## Status
Accepted | Superseded | Deprecated

## Context
What is the issue that we're seeing that motivates this decision?

## Decision
What is the change that we're proposing and/or doing?

## Consequences
What becomes easier or more difficult to do because of this change?
```

---

## ADR-001: YAML Configuration Format

**Status**: Accepted

### Context

We needed a configuration format that:
- Is human-readable and writable
- Supports comments for documentation
- Is widely supported in the JavaScript ecosystem
- Can be validated easily

### Decision

Use YAML as the primary configuration format for `.pnpm-audit.yaml`.

**Alternatives Considered**:
1. **JSON**: No comments, harder to read
2. **TOML**: Less ecosystem support in JS
3. **JavaScript config**: Security concerns with eval
4. **Environment variables only**: Harder to manage complex configs

### Consequences

**Positive**:
- Easy to read and write manually
- Supports comments for inline documentation
- Familiar to most developers
- Good library support (yaml package)

**Negative**:
- Indentation-sensitive (can cause errors)
- Requires parsing library (though minimal)
- Potential for syntax errors

**Mitigation**:
- Clear error messages with line numbers
- Typo detection for common mistakes
- Schema validation

---

## ADR-002: Static Database Schema

**Status**: Accepted

### Context

We needed an offline vulnerability database that:
- Supports O(1) package lookups
- Minimizes memory usage
- Enables efficient updates
- Works in air-gapped environments

### Decision

Use a sharded JSON schema with:
- Single `index.json` for metadata and package listing
- Individual `{package}.json` files for each vulnerable package
- Scoped packages in `{scope}/{package}.json` directories

**Schema Structure**:
```
static-db/
├── index.json           # Metadata + package listing
├── lodash.json          # Unscoped package
└── @babel/
    └── core.json        # Scoped package
```

**Alternatives Considered**:
1. **SQLite**: Requires native bindings, complex setup
2. **Single large JSON file**: Slow lookups, high memory
3. **Binary format**: Harder to debug and update
4. **CSV/TSV**: No nested data support

### Consequences

**Positive**:
- O(1) lookup via index
- Memory efficient (load only needed shards)
- Easy to update (incremental builds)
- Human-readable for debugging
- Git-friendly (small diffs)

**Negative**:
- Many small files (mitigated by lazy loading)
- JSON parsing overhead (mitigated by caching)
- No ACID transactions (not needed for read-only)

**Trade-offs**:
- Chose simplicity over performance of binary formats
- Chose readability over storage efficiency

---

## ADR-003: Multi-Source Aggregation

**Status**: Accepted

### Context

No single vulnerability database provides complete coverage. We need to aggregate multiple sources while:
- Handling different API formats
- Managing rate limits
- Deduplicating findings
- Gracefully degrading on failures

### Decision

Implement a strategy pattern with parallel source queries:

```typescript
interface VulnerabilitySource {
  id: FindingSource;
  isEnabled(cfg: AuditConfig, env: Record<string, string | undefined>): boolean;
  query(pkgs: PackageRef[], ctx: SourceContext): Promise<SourceResult>;
}
```

**Sources**:
1. GitHub Advisory (primary)
2. NVD (enrichment)
3. OSV (secondary)
4. Static DB (offline fallback)

**Alternatives Considered**:
1. **Single source (GitHub only)**: Lower coverage
2. **Sequential queries**: Slower execution
3. **External aggregator service**: Adds dependency

### Consequences

**Positive**:
- Better coverage through multiple sources
- Resilience through redundancy
- Graceful degradation on failures
- Parallel execution for speed

**Negative**:
- Deduplication complexity
- Different rate limits per source
- More code to maintain
- Potential for conflicting data

**Mitigation**:
- Canonical deduplication key
- Per-source rate limiting
- Interface abstraction for consistency
- Source priority ordering

---

## ADR-004: Zero Runtime Dependencies

**Status**: Accepted

### Context

As a security tool that intercepts package installation, we need to:
- Minimize supply chain risk
- Reduce installation footprint
- Avoid circular dependencies
- Ensure reliability

### Decision

Minimize runtime dependencies to only essential packages:

**Current Runtime Dependencies** (2):
1. `semver` - Version range matching
2. `yaml` - Configuration parsing

**Built-in Implementations**:
- HTTP client (Node.js `http`/`https`)
- File system operations
- Cryptographic hashing
- Concurrency control

**Alternatives Considered**:
1. **No dependencies**: Would require reimplementing semver parsing
2. **More dependencies**: `axios`, `chalk`, `ora`, etc.
3. **Bundle everything**: Increases attack surface

### Consequences

**Positive**:
- Minimal supply chain risk
- Faster installation
- No dependency conflicts
- Better control over security

**Negative**:
- More code to maintain
- May miss optimizations from battle-tested libs
- `semver` and `yaml` are still dependencies

**Mitigation**:
- Pin dependency versions
- Regular security audits
- Consider vendoring critical deps

---

## ADR-005: Policy Engine Design

**Status**: Accepted

### Context

Users need fine-grained control over:
- Which severities to block vs. warn
- Exception handling for specific packages/CVEs
- Time-based exceptions
- Direct vs. transitive dependency policies

### Decision

Implement a layered policy evaluation:

```
1. Allowlist Check (highest priority)
   ↓ (not matched)
2. Severity Block List
   ↓ (not blocking)
3. Severity Warn List
   ↓ (not warning)
4. Allow (default)
```

**Policy Configuration**:
```yaml
policy:
  block:
    - critical
    - high
  warn:
    - medium

allowlist:
  - id: "CVE-2021-12345"
    reason: "Not exploitable in our context"
    expires: "2025-06-01"
  - package: "lodash"
    version: ">=4.17.0"
    directOnly: true
```

**Alternatives Considered**:
1. **Simple block/warn lists**: No exceptions support
2. **Rule-based engine**: Over-engineered for use case
3. **External policy service**: Adds latency and dependency

### Consequences

**Positive**:
- Flexible exception handling
- Time-based expiration for temporary exemptions
- Direct-only option for transitive dependencies
- Clear priority ordering

**Negative**:
- More complex evaluation logic
- Potential for misconfiguration
- Edge cases in expiration handling

**Mitigation**:
- Comprehensive tests
- Clear documentation
- Validation with helpful error messages

---

## ADR-006: Output Format Abstraction

**Status**: Accepted

### Context

Different CI/CD environments have different annotation formats:
- GitHub Actions: `::error file=...`
- Azure DevOps: `##vso[task.logissue]`
- AWS CodeBuild: CloudWatch format
- Local: Human-readable terminal output

### Decision

Implement a formatter pattern with automatic CI detection:

```typescript
interface OutputFormatter {
  format(data: AuditOutputData): string;
}

// Auto-detect from environment
function getOutputFormatFromEnv(env: Record<string, string | undefined>): OutputFormat {
  if (env.GITHUB_ACTIONS) return 'github-actions';
  if (env.TF_BUILD) return 'azure-devops';
  if (env.CODEBUILD_BUILD_ID) return 'aws-codebuild';
  return 'human';
}
```

**Alternatives Considered**:
1. **Single format**: Poor CI/CD experience
2. **User-specified format**: Extra configuration burden
3. **Plugin system**: Over-engineered

### Consequences

**Positive**:
- Automatic CI/CD integration
- Consistent experience across platforms
- Easy to add new formatters
- Backward compatible

**Negative**:
- Multiple formatters to maintain
- Detection logic may have edge cases
- Platform-specific formatting quirks

**Mitigation**:
- Base formatter with shared logic
- Platform-specific overrides only where needed
- Environment variable override option

---

## ADR-007: Lazy Loading Strategy

**Status**: Accepted

### Context

The static vulnerability database is large (~50MB+). Loading it entirely into memory:
- Increases startup time
- Wastes memory for small projects
- Blocks the event loop

### Decision

Implement lazy loading with:
- Index loaded eagerly (small, needed for lookups)
- Shard files loaded on-demand
- In-memory cache after first load
- Optional pre-loading for performance

```typescript
class LazyStaticDbReader {
  private index: StaticDbIndex;
  private shardCache: Map<string, PackageShard>;
  
  constructor(options: { dataPath: string; cutoffDate?: string }) {
    // Load index eagerly
    this.index = this.loadIndex(options.dataPath);
    this.shardCache = new Map();
  }
  
  async query(packageName: string): Promise<VulnerabilityFinding[]> {
    // Check index first (O(1))
    if (!this.index.packages[packageName]) {
      return [];
    }
    
    // Load shard on demand
    let shard = this.shardCache.get(packageName);
    if (!shard) {
      shard = await this.loadShard(packageName);
      this.shardCache.set(packageName, shard);
    }
    
    return this.processShard(shard);
  }
}
```

**Alternatives Considered**:
1. **Eager loading**: Higher memory, slower startup
2. **No caching**: Repeated file I/O
3. **IndexedDB/browser storage**: Not applicable for Node.js

### Consequences

**Positive**:
- Fast startup time
- Memory efficient for small projects
- Scales to large databases
- No event loop blocking

**Negative**:
- First query slower (shard loading)
- Cache invalidation complexity
- Memory grows over time

**Mitigation**:
- Cache eviction for memory pressure
- Pre-warming option for performance-critical paths
- LRU cache implementation

---

## ADR-008: Cache Implementation

**Status**: Accepted

### Context

API calls to vulnerability sources are:
- Rate-limited
- Network-dependent
- Relatively stable data

We need caching that:
- Persists across runs
- Respects TTL
- Handles concurrent access
- Doesn't corrupt on crashes

### Decision

Implement file-based caching with:
- JSON files per cache key
- Metadata file for TTL management
- Atomic writes (write to temp, then rename)
- Automatic cleanup on startup

**Cache Structure**:
```
.pnpm-audit-cache/
├── github/
│   └── {hash}.json
├── nvd/
│   └── {hash}.json
└── metadata.json
```

**Alternatives Considered**:
1. **In-memory only**: Lost on restart
2. **SQLite**: Adds dependency
3. **Redis**: External dependency
4. **Browser storage**: Not applicable

### Consequences

**Positive**:
- Persistent across runs
- No external dependencies
- Atomic writes prevent corruption
- Simple implementation

**Negative**:
- File I/O overhead
- No built-in concurrency control
- Cache grows over time

**Mitigation**:
- Read/write locking
- Automatic pruning
- TTL-based expiration

---

## ADR-009: Error Handling Strategy

**Status**: Accepted

### Context

Errors can occur at multiple points:
- Configuration loading
- Lockfile parsing
- API calls
- Policy evaluation
- Output generation

We need:
- Clear error messages
- Actionable suggestions
- Graceful degradation
- Consistent exit codes

### Decision

Implement layered error handling:

1. **Component Level**: Catch and wrap errors with context
2. **Source Level**: Return error status, continue aggregation
3. **Audit Level**: Aggregate errors, determine exit code
4. **Hook Level**: Format error message for pnpm

**Error Types**:
```typescript
class ConfigError extends Error { /* validation errors */ }
class HttpError extends Error { /* API errors with retry info */ }
class LockfileError extends Error { /* parse errors */ }
```

**Exit Codes**:
```typescript
const EXIT_CODES = {
  SUCCESS: 0,      // No issues
  BLOCKED: 1,      // Vulnerabilities blocked
  WARNINGS: 2,     // Warnings only
  SOURCE_ERROR: 3, // Source failed
};
```

**Alternatives Considered**:
1. **Throw all errors**: Stops audit on first error
2. **Silent failures**: Hides problems
3. **Panic on errors**: Too aggressive

### Consequences

**Positive**:
- Clear error messages
- Actionable suggestions
- Graceful degradation
- Consistent behavior

**Negative**:
- More code complexity
- Potential for swallowed errors
- Exit code documentation burden

**Mitigation**:
- Exhaustive error logging
- Source status reporting
- Comprehensive tests

---

## ADR-010: TypeScript Type Definitions

**Status**: Accepted

### Context

We need:
- Type safety for all data structures
- Good IDE support
- Documentation through types
- Bundle size consideration

### Decision

Use TypeScript with:
- Strict mode enabled
- Comprehensive interface definitions
- Exported types for consumers
- JSDoc comments for documentation

**Type Export Strategy**:
```typescript
// types.ts - All public types
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';
export interface VulnerabilityFinding { ... }
export interface AuditResult { ... }

// index.ts - Re-export for consumers
export type { VulnerabilityFinding, AuditResult } from './types';
```

**Alternatives Considered**:
1. **JavaScript only**: No type safety
2. **JSDoc types**: Less ergonomic
3. **Flow**: Less ecosystem support

### Consequences

**Positive**:
- Type safety
- Better IDE experience
- Self-documenting code
- Catch errors at compile time

**Negative**:
- Compilation step required
- Learning curve for contributors
- Potential bundle size increase

**Mitigation**:
- Type-only exports (no runtime cost)
- Clear contributing guidelines
- Build scripts for compilation

---

## Summary Table

| ADR | Decision | Status | Key Trade-off |
|-----|----------|--------|---------------|
| 001 | YAML Config | Accepted | Readability vs. Complexity |
| 002 | Sharded Static DB | Accepted | Simplicity vs. Performance |
| 003 | Multi-Source | Accepted | Coverage vs. Complexity |
| 004 | Zero Deps | Accepted | Control vs. Convenience |
| 005 | Layered Policy | Accepted | Flexibility vs. Complexity |
| 006 | Format Abstraction | Accepted | Compatibility vs. Maintenance |
| 007 | Lazy Loading | Accepted | Startup vs. Query Time |
| 008 | File Cache | Accepted | Simplicity vs. Features |
| 009 | Error Handling | Accepted | Robustness vs. Complexity |
| 010 | TypeScript | Accepted | Safety vs. Overhead |

---

## Future Decisions

Potential ADRs to be written:
- ADR-011: Plugin System Architecture
- ADR-012: WebSocket Support for Real-time Updates
- ADR-013: Multi-workspace Support
- ADR-014: Custom Source Implementation