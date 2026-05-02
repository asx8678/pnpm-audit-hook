# Phase 4: Quick Reference Guide

## Overview

This document provides a quick reference for implementing Phase 4 of the pnpm-audit-hook project.

---

## File Structure Changes

### Before (Current)
```
src/
├── static-db/
│   └── optimizer.ts (26.3KB, 988 lines)
└── utils/
    └── lockfile.ts (10.4KB, 413 lines)
```

### After (Target)
```
src/
├── static-db/
│   ├── optimizer/
│   │   ├── types.ts
│   │   ├── constants.ts
│   │   ├── date-utils.ts
│   │   ├── version-utils.ts
│   │   ├── vulnerability-optimizer.ts
│   │   ├── package-optimizer.ts
│   │   ├── index-optimizer.ts
│   │   ├── compression.ts
│   │   ├── bloom-filter.ts
│   │   ├── search.ts
│   │   ├── stats.ts
│   │   ├── hash.ts
│   │   ├── utils.ts
│   │   └── index.ts
│   └── optimizer.ts (re-exports for backward compatibility)
└── utils/
    ├── lockfile/
    │   ├── types.ts
    │   ├── parser.ts
    │   ├── pnpm-parser.ts
    │   ├── package-key-parser.ts
    │   ├── graph-builder.ts
    │   ├── registry-detector.ts
    │   ├── cache.ts
    │   ├── errors.ts
    │   └── index.ts
    ├── helpers/
    │   ├── async-helpers.ts
    │   ├── validation-helpers.ts
    │   ├── string-helpers.ts
    │   ├── array-helpers.ts
    │   ├── object-helpers.ts
    │   ├── error-helpers.ts
    │   ├── type-helpers.ts
    │   └── index.ts
    └── lockfile.ts (re-exports for backward compatibility)
```

---

## Quick Commands

### Create Directories
```bash
# Create optimizer directory
mkdir -p src/static-db/optimizer

# Create lockfile directory
mkdir -p src/utils/lockfile

# Create helpers directory
mkdir -p src/utils/helpers
```

### Create Files
```bash
# Optimizer files
touch src/static-db/optimizer/{types,constants,date-utils,version-utils,vulnerability-optimizer,package-optimizer,index-optimizer,compression,bloom-filter,search,stats,hash,utils,index}.ts

# Lockfile files
touch src/utils/lockfile/{types,parser,pnpm-parser,package-key-parser,graph-builder,registry-detector,cache,errors,index}.ts

# Helper files
touch src/utils/helpers/{async-helpers,validation-helpers,string-helpers,array-helpers,object-helpers,error-helpers,type-helpers,index}.ts
```

### Run Tests
```bash
# Run all tests
npm test

# Run specific tests
node --import tsx --test test/static-db/optimizer.test.ts
node --import tsx --test test/utils/lockfile.test.ts

# Run benchmarks
node --import tsx --test test/static-db/optimizer.bench.ts
node --import tsx --test test/utils/lockfile.bench.ts
```

---

## Import Updates

### Before
```typescript
// Import from monolithic file
import { optimizeVulnerability } from "../static-db/optimizer";
import { parsePnpmPackageKey } from "../utils/lockfile";
import { retry } from "../utils/async-helpers";
```

### After
```typescript
// Option 1: Import from new module (recommended)
import { optimizeVulnerability } from "../static-db/optimizer/vulnerability-optimizer";
import { parsePnpmPackageKey } from "../utils/lockfile/package-key-parser";
import { retry } from "../utils/helpers/async-helpers";

// Option 2: Import from index (backward compatible)
import { optimizeVulnerability } from "../static-db/optimizer";
import { parsePnpmPackageKey } from "../utils/lockfile";
import { retry } from "../utils/helpers";
```

---

## Backward Compatibility

### Strategy
1. **Re-export everything** from original files
2. **Add deprecation notices** to original files
3. **Maintain same API** through re-exports

### Example
```typescript
// src/static-db/optimizer.ts (updated)
/**
 * Static Database Optimizer
 *
 * @deprecated Import from './optimizer/index' instead for better tree-shaking
 * and modular imports.
 */

// Re-export everything from the new modular structure
export * from "./optimizer/index";
```

---

## Testing Checklist

### Unit Tests
- [ ] Test each extracted module independently
- [ ] Test type conversions and validations
- [ ] Test compression/decompression
- [ ] Test Bloom filter operations
- [ ] Test binary search

### Integration Tests
- [ ] Test full optimization pipeline
- [ ] Test backward compatibility
- [ ] Test performance benchmarks
- [ ] Test with real lockfiles

### Regression Tests
- [ ] Run all existing tests
- [ ] Compare output with previous implementation
- [ ] Performance comparison tests

---

## Risk Mitigation

### Breaking Changes
- Maintain backward compatibility through re-exports
- Add deprecation notices for changed APIs
- Provide migration guide

### Performance Regression
- Run performance benchmarks before and after
- Monitor key metrics
- Optimize hot paths

### Import Errors
- Comprehensive testing before and after
- Gradual migration
- Update all imports

---

## Success Metrics

### Quantitative
- [ ] `optimizer.ts` split into <500 line modules
- [ ] `lockfile.ts` simplified and extensible
- [ ] Code duplication reduced by >50%
- [ ] All existing tests pass
- [ ] No performance regression (within 10%)

### Qualitative
- [ ] Improved code readability
- [ ] Better module organization
- [ ] Enhanced developer experience
- [ ] Easier maintenance

---

## Timeline

### Week 1
- **Day 1-2:** Phase 4 Task 4.1 (Analysis and module extraction)
- **Day 3-4:** Phase 4 Task 4.1 (Core logic extraction and testing)
- **Day 5:** Phase 3 Task 3.1 (CLI improvements)

### Week 2
- **Day 1-2:** Phase 4 Task 4.2 (Lockfile parsing simplification)
- **Day 3:** Phase 4 Task 4.3 (Common patterns extraction)
- **Day 4:** Phase 3 Task 3.2 (Troubleshooting guide)
- **Day 5:** Final testing and documentation

### Week 3
- **Day 1:** Final integration, update all imports
- **Day 2:** Comprehensive testing
- **Day 3:** Performance testing and optimization
- **Day 4:** Documentation updates
- **Day 5:** Final review and deployment

---

## Key Files to Update

### Core Files
1. `src/static-db/optimizer.ts` - Add re-exports
2. `src/utils/lockfile.ts` - Add re-exports
3. `test/static-db/optimizer.test.ts` - Update imports
4. `test/utils/lockfile.test.ts` - Update imports

### Import Updates
1. `src/audit.ts` - Update lockfile imports
2. `src/static-db/reader.ts` - Update optimizer imports
3. `src/static-db/lazy-reader.ts` - Update optimizer imports
4. `scripts/optimize-static-db.js` - Update optimizer imports

---

## Common Patterns

### Re-export Pattern
```typescript
// src/static-db/optimizer/index.ts
export * from "./types";
export * from "./constants";
export * from "./date-utils";
// ... etc
```

### Deprecation Notice
```typescript
// src/static-db/optimizer.ts
/**
 * @deprecated Import from './optimizer/index' instead
 */
export * from "./optimizer/index";
```

### Import Update
```typescript
// Before
import { optimizeVulnerability } from "../static-db/optimizer";

// After
import { optimizeVulnerability } from "../static-db/optimizer/vulnerability-optimizer";
```

---

## Debugging Tips

### Test Failures
1. Check import paths
2. Verify re-exports are working
3. Run tests in isolation
4. Check for circular dependencies

### Performance Issues
1. Run benchmarks before and after
2. Profile hot paths
3. Check for unnecessary allocations
4. Optimize critical code paths

### Import Errors
1. Check file paths
2. Verify module structure
3. Update all imports
4. Test backward compatibility

---

## Next Steps

1. **Review this guide**
2. **Set up development environment**
3. **Begin implementation**
4. **Run tests frequently**
5. **Update documentation**

---

## Related Documents

- **Implementation Plan:** `docs/phase-4-implementation-plan.md`
- **Detailed Steps:** `docs/phase-4-detailed-steps.md`
- **Roadmap:** `docs/phase-4-roadmap.md`
- **Summary:** `docs/phase-4-summary.md`
