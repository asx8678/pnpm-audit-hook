# pnpm-audit-hook Improvement Plan

## Overview
This document outlines the improvement plan for pnpm-audit-hook to add AWS CodeBuild support, improve verbosity levels, simplify the output formatter, and enhance CI/CD documentation.

## Current State
- Azure DevOps support: ✅ Implemented
- GitHub Actions support: ✅ Implemented  
- AWS CodeBuild support: ❌ Missing
- Verbosity levels: Basic (quiet, verbose, debug)
- Output formatter: Well-structured but could be simplified

## Phase 1: AWS CodeBuild/CodePipeline Support

### Task 1.1: Add AWS CodeBuild Environment Variable Detection
- **Files**: `src/utils/output-formatter.ts`, `src/utils/logger.ts`
- **Changes**: Add `CODEBUILD_BUILD_ID` environment variable detection in `getOutputFormat()` function
- **Status**: ✅ Completed

### Task 1.2: Create `formatCodeBuild()` Function
- **Files**: `src/utils/output-formatter.ts`
- **Changes**: Implement AWS CodeBuild-compatible output format using `::group::` and `::endgroup::` syntax
- **Status**: ✅ Completed

### Task 1.3: Update `outputResults()` Function
- **Files**: `src/utils/output-formatter.ts`
- **Changes**: Add "aws" case to the switch statement
- **Status**: ✅ Completed

### Task 1.4: Update Type Definitions and Help Text
- **Files**: `src/utils/output-formatter.ts`, `bin/parse-args.js`
- **Changes**: Update `OutputFormat` type definition and help text
- **Status**: ✅ Completed

## Phase 2: Improve Verbosity Levels and Message Display

### Task 2.1: Enhance Logger with Structured Verbosity Levels
- **Files**: `src/utils/logger.ts`
- **Changes**: Add level-based logging (error=0, warn=1, info=2, verbose=3, debug=4)
- **Status**: ✅ Completed

### Task 2.2: Add Context-Aware Logging for CI Environments
- **Files**: `src/utils/logger.ts`
- **Changes**: Enhance CI detection logic to include AWS CodeBuild
- **Status**: ✅ Completed

### Task 2.3: Improve Compact Banner Display
- **Files**: `src/utils/output-formatter.ts`
- **Changes**: Enhance `formatCompactBanner()` with better formatting
- **Status**: ✅ Completed

### Task 2.4: Add Verbosity-Aware Output Truncation
- **Files**: `src/utils/output-formatter.ts`
- **Changes**: Add logic to truncate output in quiet mode and expand in verbose mode
- **Status**: ✅ Completed

## Phase 3: Simplify Output Formatter

### Task 3.1: Extract Common Formatting Logic
- **Files**: `src/utils/output-formatter.ts`
- **Changes**: Create helper functions for severity coloring, source status display
- **Status**: ✅ Completed

### Task 3.2: Create Abstract Base Formatter Class
- **Files**: `src/utils/output-formatter.ts`
- **Changes**: Implement `BaseFormatter` class with shared logic
- **Status**: ✅ Completed

### Task 3.3: Refactor Existing Formatters
- **Files**: `src/utils/output-formatter.ts`
- **Changes**: Refactor `formatAzureDevOps()`, `formatGitHubActions()`, and new `formatCodeBuild()`
- **Status**: ✅ Completed

## Phase 4: Testing and Validation

### Task 4.1: Add Unit Tests for AWS CodeBuild Formatter
- **Files**: `test/utils/output-formatter.test.ts`
- **Status**: ✅ Completed

### Task 4.2: Add Unit Tests for Enhanced Verbosity
- **Files**: `test/utils/logger.test.ts`
- **Status**: ✅ Completed

### Task 4.3: Add Integration Tests for All CI/CD Formats
- **Files**: `test/utils/output-formatter.test.ts`
- **Status**: ✅ Completed

### Task 4.4: Validate Formatter Refactoring
- **Files**: `test/utils/output-formatter.test.ts`
- **Status**: ✅ Completed

## Phase 5: Documentation Updates

### Task 5.1: Update README with AWS CodeBuild Documentation
- **Files**: `README.md`
- **Status**: ✅ Completed

### Task 5.2: Update Environment Variables Table
- **Files**: `README.md`
- **Status**: ✅ Completed

### Task 5.3: Update CLI Help Text
- **Files**: `bin/parse-args.js`
- **Status**: ✅ Completed

### Task 5.4: Add Verbosity Documentation
- **Files**: `README.md`
- **Status**: ✅ Completed

## Phase 6: Final Integration and Testing

### Task 6.1: Run Full Test Suite
- **Status**: ✅ Completed

### Task 6.2: Build and Validate Package
- **Status**: ✅ Completed

## Risks and Mitigations

1. **AWS CodeBuild Output Format**: Need to verify compatibility with actual AWS environments
   - Mitigation: Research AWS CodeBuild documentation and test with sample output

2. **Breaking Changes**: Refactoring could introduce breaking changes
   - Mitigation: Ensure all existing tests pass and add comprehensive test coverage

3. **Performance Impact**: Adding more logging levels could impact performance
   - Mitigation: Keep environment variable checks at module load time

4. **Backward Compatibility**: New format options must maintain backward compatibility
   - Mitigation: Ensure existing format options continue to work

## Implementation Priority

1. AWS CodeBuild support (Phase 1) - High priority
2. Verbosity improvements (Phase 2) - Medium priority
3. Output formatter simplification (Phase 3) - Medium priority
4. Testing and validation (Phase 4) - High priority
5. Documentation updates (Phase 5) - Medium priority
6. Final integration (Phase 6) - High priority

## Estimated Total Time: 7.5 hours
