# 🐶 SBOM Enhancement Implementation Plan

**Created**: May 3, 2025  
**Status**: Ready to implement  
**Priority**: High  

---

## 📋 Executive Summary

This plan details the implementation of performance optimizations and enhanced vulnerability data for the SBOM (Software Bill of Materials) feature in pnpm-audit-hook. Based on the SESSION_COMPLETION_SUMMARY.md, these improvements will make the SBOM generation faster, more scalable, and more informative for security teams.

---

## 🎯 Goals

### 1. Performance Optimization
- Add streaming support for large lockfiles (1000+ packages)
- Implement parallel SBOM generation for monorepos
- Cache SBOM components between runs

### 2. Enhanced Vulnerability Data
- Link CVSS vectors to SBOM vulnerabilities
- Add fix recommendations in SBOM output
- Include EPSS (Exploit Prediction Scoring System) data

---

## 📁 Current State Analysis

### Existing Implementation
- **SBOM Formats**: CycloneDX 1.5, SPDX 2.3, SWID Tags
- **Test Coverage**: 101 SBOM-specific tests
- **Performance**: Current implementation loads entire lockfile into memory
- **Vulnerability Data**: CVSS scores and vectors already captured in `VulnerabilityFinding`
- **Fix Recommendations**: `fixedVersion` field exists but not in SBOM output

### Key Files
| File | Purpose |
|------|---------|
| `src/sbom/generator.ts` | Main SBOM generation entry point |
| `src/sbom/cyclonedx-generator.ts` | CycloneDX format generation |
| `src/sbom/types.ts` | SBOM type definitions |
| `src/utils/lockfile/package-extractor.ts` | Lockfile parsing |
| `src/types.ts` | Core vulnerability types |
| `src/utils/performance.ts` | Performance monitoring utilities |

---

## 🔧 Implementation Plan

### Phase 1: Performance Optimization

#### 1.1 Streaming Lockfile Parser
**Goal**: Process large lockfiles without loading everything into memory

**Current Issue**:
```typescript
// Current: Loads entire lockfile into memory
const packageEntries = lockfile?.packages;
const keys = Object.keys(packageEntries); // Can be 1000s of entries
```

**Solution**: Create a streaming parser that processes packages in batches

**Implementation**:
1. Create `src/utils/lockfile/streaming-parser.ts`
2. Implement `StreamingLockfileParser` class with:
   - Batch processing (configurable batch size, default 100)
   - Memory-efficient streaming
   - Progress reporting
   - Backpressure handling

**New Types**:
```typescript
export interface StreamingParserOptions {
  batchSize: number; // Default: 100
  maxMemoryMB: number; // Default: 100
  onProgress?: (processed: number, total: number) => void;
}

export interface StreamingParseResult {
  packages: PackageRef[];
  stats: {
    totalProcessed: number;
    registryPackages: number;
    skippedPackages: number;
    durationMs: number;
    peakMemoryMB: number;
  };
}
```

**Files to Create/Modify**:
- Create: `src/utils/lockfile/streaming-parser.ts`
- Modify: `src/utils/lockfile/package-extractor.ts` (add streaming method)
- Modify: `src/sbom/generator.ts` (use streaming parser for large lockfiles)
- Create: `test/utils/lockfile-streaming.test.ts`

**Success Criteria**:
- Handle lockfiles with 10,000+ packages without exceeding memory limits
- Process in batches with configurable batch size
- Provide progress reporting
- All existing tests pass

---

#### 1.2 Parallel SBOM Generation for Monorepos
**Goal**: Generate SBOMs for multiple workspaces concurrently

**Current Issue**:
- SBOM generation is synchronous
- Monorepos with multiple workspaces process sequentially

**Solution**: Implement parallel SBOM generation with workspace detection

**Implementation**:
1. Create `src/sbom/monorepo-generator.ts`
2. Implement `MonorepoSbomGenerator` class with:
   - Workspace detection from pnpm-workspace.yaml
   - Concurrent SBOM generation for each workspace
   - Aggregated root SBOM combining all workspaces
   - Configurable concurrency limit

**New Types**:
```typescript
export interface MonorepoSbomOptions extends SbomOptions {
  /** Maximum concurrent workspace processing (default: 4) */
  concurrency: number;
  /** Include workspace packages in root SBOM */
  includeWorkspacesInRoot: boolean;
  /** Generate individual workspace SBOMs */
  generateWorkspaceSboms: boolean;
}

export interface WorkspaceSbomResult {
  workspacePath: string;
  workspaceName: string;
  result: SbomResult;
}

export interface MonorepoSbomResult {
  root: SbomResult;
  workspaces: WorkspaceSbomResult[];
  aggregated: SbomResult;
  stats: {
    totalWorkspaces: number;
    totalComponents: number;
    totalVulnerabilities: number;
    generationTimeMs: number;
  };
}
```

**Files to Create/Modify**:
- Create: `src/sbom/monorepo-generator.ts`
- Modify: `src/sbom/index.ts` (export new generator)
- Create: `test/sbom/monorepo-generator.test.ts`

**Success Criteria**:
- Detect pnpm workspaces automatically
- Generate SBOMs concurrently with configurable limit
- Aggregate results into root SBOM
- Handle workspace dependencies correctly
- All tests pass

---

#### 1.3 SBOM Component Caching
**Goal**: Cache generated SBOM components between runs for faster incremental updates

**Current Issue**:
- Every SBOM generation starts from scratch
- Re-processing unchanged packages is wasteful

**Solution**: Implement LRU cache for SBOM components

**Implementation**:
1. Create `src/sbom/component-cache.ts`
2. Implement `SbomComponentCache` class with:
   - LRU cache with configurable size
   - Cache key based on package name + version + integrity hash
   - Persistence to disk (optional)
   - Cache invalidation on integrity mismatch

**New Types**:
```typescript
export interface ComponentCacheOptions {
  /** Maximum cache entries (default: 1000) */
  maxEntries: number;
  /** Cache file path for persistence */
  cacheFilePath?: string;
  /** Cache TTL in milliseconds (default: 24 hours) */
  ttlMs: number;
}

export interface CacheEntry {
  component: SbomComponent;
  timestamp: number;
  integrityHash: string;
}

export interface CacheStats {
  hits: number;
  misses: number;
  size: number;
  hitRate: number;
}
```

**Files to Create/Modify**:
- Create: `src/sbom/component-cache.ts`
- Modify: `src/sbom/generator.ts` (integrate cache)
- Modify: `src/sbom/types.ts` (add cache options)
- Create: `test/sbom/component-cache.test.ts`

**Success Criteria**:
- Cache hit rate > 80% for incremental builds
- Cache invalidation works correctly
- Persistence works across runs
- All tests pass

---

### Phase 2: Enhanced Vulnerability Data

#### 2.1 Link CVSS Vectors to SBOM Vulnerabilities
**Goal**: Ensure full CVSS vector information is properly linked and parsed

**Current State**:
- `VulnerabilityFinding` has `cvssVector` and `cvssScore` fields
- CycloneDX generator includes `vector` in ratings
- CVSS details are parsed in `CvssFindingDetails`

**Enhancement**:
- Add CVSS vector validation
- Include full CVSS metrics in SBOM output
- Link CVSS v3.1 and v4.0 vectors

**Implementation**:
1. Create `src/utils/cvss-validator.ts`
2. Enhance `src/sbom/cyclonedx-generator.ts` with full CVSS details

**New Types**:
```typescript
export interface CvssVectorInfo {
  version: '2.0' | '3.0' | '3.1' | '4.0';
  score: number;
  severity: Severity;
  vector: string;
  metrics: Record<string, string>;
  isValid: boolean;
  validationErrors?: string[];
}
```

**Files to Create/Modify**:
- Create: `src/utils/cvss-validator.ts`
- Modify: `src/sbom/cyclonedx-generator.ts` (enhance CVSS output)
- Modify: `src/sbom/spdx-generator.ts` (add CVSS info)
- Create: `test/utils/cvss-validator.test.ts`

**Success Criteria**:
- CVSS vectors are validated and parsed correctly
- Full CVSS metrics appear in SBOM output
- Support for CVSS v2.0, v3.0, v3.1, and v4.0
- All tests pass

---

#### 2.2 Add Fix Recommendations in SBOM Output
**Goal**: Include fix version recommendations in vulnerability data

**Current State**:
- `VulnerabilityFinding` has `fixedVersion` field
- CycloneDX 1.5 supports `recommendation` field

**Enhancement**:
- Add fix recommendations to CycloneDX vulnerabilities
- Include fix availability status
- Add upgrade path information

**Implementation**:
1. Modify `src/sbom/cyclonedx-generator.ts` to include recommendations
2. Add `recommendation` field to CycloneDX vulnerability format

**New Types**:
```typescript
// In CycloneDXVulnerability
export interface CycloneDXVulnerability {
  // ... existing fields
  recommendation?: string;
  fixAvailable?: boolean;
  fixVersions?: string[];
}
```

**Files to Create/Modify**:
- Modify: `src/sbom/cyclonedx-generator.ts`
- Modify: `src/sbom/types.ts` (add fix fields)
- Create: `test/sbom/fix-recommendations.test.ts`

**Success Criteria**:
- Fix recommendations appear in CycloneDX output
- Fix availability status is accurate
- Upgrade path information is included
- All tests pass

---

#### 2.3 Include EPSS Data
**Goal**: Add Exploit Prediction Scoring System data to vulnerabilities

**Current State**:
- EPSS data not currently included
- FIRST.org provides EPSS API

**Enhancement**:
- Fetch EPSS scores from FIRST.org API
- Include EPSS score and percentile in SBOM
- Add EPSS as a vulnerability rating source

**Implementation**:
1. Create `src/utils/epss-fetcher.ts`
2. Enhance vulnerability types with EPSS data
3. Add EPSS to SBOM vulnerability output

**New Types**:
```typescript
export interface EpssData {
  cveId: string;
  epssScore: number; // 0.0 - 1.0
  epssPercentile: number; // 0.0 - 1.0
  date: string;
  modelVersion: string;
}

// In VulnerabilityFinding
export interface VulnerabilityFinding {
  // ... existing fields
  epss?: EpssData;
}

// In CycloneDXVulnerability
export interface CycloneDXVulnerability {
  // ... existing fields
  ratings: Array<{
    // ... existing fields
    method?: string; // 'epss'
    score?: number; // EPSS score
  }>;
}
```

**Files to Create/Modify**:
- Create: `src/utils/epss-fetcher.ts`
- Modify: `src/types.ts` (add EPSS types)
- Modify: `src/sbom/cyclonedx-generator.ts` (add EPSS ratings)
- Modify: `src/databases/aggregator.ts` (fetch EPSS data)
- Create: `test/utils/epss-fetcher.test.ts`

**Success Criteria**:
- EPSS scores are fetched and included
- EPSS appears as a rating source in SBOM
- Graceful fallback when EPSS API is unavailable
- All tests pass

---

## 📊 Implementation Timeline

### Week 1: Performance Optimization
- **Day 1-2**: Streaming lockfile parser
- **Day 3-4**: Parallel monorepo SBOM generation
- **Day 5**: SBOM component caching

### Week 2: Enhanced Vulnerability Data
- **Day 1-2**: CVSS vector linking and validation
- **Day 3**: Fix recommendations in SBOM output
- **Day 4-5**: EPSS data integration

### Week 3: Testing and Documentation
- **Day 1-3**: Comprehensive testing
- **Day 4-5**: Documentation and examples

---

## 🧪 Testing Strategy

### Unit Tests
- Streaming parser with various lockfile sizes
- Monorepo generator with workspace detection
- Component cache hit/miss scenarios
- CVSS vector validation
- EPSS data fetching with mocking

### Integration Tests
- End-to-end SBOM generation with streaming
- Parallel workspace processing
- Cache persistence across runs
- Full vulnerability data flow

### Performance Tests
- Memory usage with 10,000+ packages
- Generation time benchmarks
- Cache hit rate measurements
- Concurrency scaling tests

---

## 📚 Documentation Updates

### README Updates
- Add performance optimization section
- Document streaming parser usage
- Explain monorepo support
- Add EPSS data examples

### API Documentation
- Update SBOM API docs with new options
- Add streaming parser API reference
- Document cache configuration
- Add EPSS data examples

### Examples
- Large lockfile handling example
- Monorepo SBOM generation example
- Cache usage example
- EPSS integration example

---

## ✅ Success Criteria

### Performance
- [ ] Handle 10,000+ packages without memory issues
- [ ] Parallel processing reduces monorepo generation time by 50%+
- [ ] Cache hit rate > 80% for incremental builds
- [ ] All performance benchmarks pass

### Functionality
- [ ] CVSS vectors properly linked and validated
- [ ] Fix recommendations appear in SBOM output
- [ ] EPSS data included when available
- [ ] All existing tests pass
- [ ] New tests achieve > 90% coverage

### Quality
- [ ] No TypeScript errors
- [ ] All code follows project style guidelines
- [ ] Documentation is complete and accurate
- [ ] Examples are working and tested

---

## 🚀 Next Steps

1. **Start with Phase 1.1**: Streaming lockfile parser
2. **Create feature branch**: `feature/sbom-performance-enhancements`
3. **Implement incrementally**: One feature at a time with tests
4. **Review and merge**: After all tests pass

---

## 📝 Notes

- All implementations should be backward compatible
- Performance optimizations should not break existing functionality
- EPSS fetching should have timeout and error handling
- Cache should be optional and disabled by default
- Streaming parser should fall back to current implementation for small lockfiles

---

**Plan created by Max 🐶**  
**Ready to implement when you give the go-ahead!**